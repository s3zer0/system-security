"""
컨테이너 이미지 추출 핵심 로직 모듈

Docker/OCI 컨테이너 이미지에서 소스 코드를 추출하는 기능을 제공합니다.
"""

import sys
import tarfile
import json
import os
import shutil
import tempfile
import logging
from typing import Optional, List, Set

from .config import CANDIDATE_APP_PATHS, MESSAGES, ERROR_MESSAGES
from .utils import copy_directory, find_app_path

# 로거 설정
logger = logging.getLogger(__name__)


class SecurityException(Exception):
    """보안 위반 시 발생하는 예외"""
    pass


class ImageExtractor:
    """
    컨테이너 이미지 추출 핸들러 클래스

    이미지 레이어를 병합하고 애플리케이션 소스를 추출합니다.
    """

    def __init__(self, image_tar_path: str, output_dir: str):
        """
        Initialize the ImageExtractor.

        Args:
            image_tar_path: Path to the container image tar file
            output_dir: Directory where the extracted source will be saved
        """
        self.image_tar_path = image_tar_path  # 컨테이너 이미지 tar 파일 경로
        self.output_dir = output_dir  # 추출된 소스가 저장될 디렉토리
        self.temp_dir = None  # 임시 작업 디렉토리
        self.merged_fs = None  # 병합된 파일시스템 디렉토리

    def _safe_extract(self, tar_obj: tarfile.TarFile, member: tarfile.TarInfo, target_dir: str) -> None:
        """
        Safely extract a tar member with comprehensive path validation to prevent:
        - Tar Slip attacks (path traversal)
        - Symlink Traversal attacks (symlink escape)

        Args:
            tar_obj: The TarFile object to extract from
            member: The tar member to extract
            target_dir: Target directory for extraction

        Raises:
            SecurityException: If the member path attempts to escape the target directory
        """
        # 1. 기본 경로 검증 (abspath 기반 - 1차 방어선)
        target_dir_abs = os.path.abspath(target_dir)
        member_path = os.path.join(target_dir, member.name)
        member_path_abs = os.path.abspath(member_path)

        if not member_path_abs.startswith(target_dir_abs + os.sep) and member_path_abs != target_dir_abs:
            attack_msg = (
                f"[SECURITY] Tar Slip attack detected! "
                f"Member '{member.name}' attempts to escape target directory. "
                f"Target: {target_dir_abs}, Attempted: {member_path_abs}"
            )
            logger.critical(attack_msg)
            raise SecurityException(attack_msg)

        # 2. Destination Resolution: 실제 파일시스템 경로 검증 (realpath 기반 - 2차 방어선)
        # 부모 디렉토리의 실제 경로가 샌드박스 내부에 있는지 확인
        target_dir_real = os.path.realpath(target_dir)
        member_parent_dir = os.path.dirname(member_path)

        # 부모 디렉토리가 존재하는 경우에만 realpath 검증 수행
        if os.path.exists(member_parent_dir):
            member_parent_real = os.path.realpath(member_parent_dir)
            if not member_parent_real.startswith(target_dir_real + os.sep) and member_parent_real != target_dir_real:
                attack_msg = (
                    f"[SECURITY] Symlink Traversal attack detected! "
                    f"Member '{member.name}' parent directory resolves outside target. "
                    f"Target (real): {target_dir_real}, Parent (real): {member_parent_real}"
                )
                logger.critical(attack_msg)
                raise SecurityException(attack_msg)

        # 3. Symlink/Hardlink Linkname Check: 링크 대상이 샌드박스 내부인지 검증
        if member.issym() or member.islnk():
            # 링크가 가리키는 대상 경로 계산
            link_target = member.linkname

            # Re-rooting: 절대 경로 링크를 컨테이너 내부 경로로 재해석
            if os.path.isabs(link_target):
                # 절대 경로 링크 (예: /usr/bin)는 컨테이너 루트 기준이므로
                # 호스트의 target_dir 아래로 re-root 해야 함
                # /usr/bin -> target_dir/usr/bin
                link_target_final = os.path.join(target_dir, link_target.lstrip(os.sep))
            else:
                # 상대 경로 링크인 경우: member가 위치할 디렉토리 기준으로 계산
                link_target_final = os.path.join(os.path.dirname(member_path), link_target)

            # 최종 목적지 경로의 정규화 (.. 등의 상대 경로 요소 해결)
            link_target_normalized = os.path.normpath(link_target_final)

            # 실제 파일시스템 경로 검증: realpath로 심볼릭 링크 해결 후 검증
            # 아직 추출 전이므로 경로가 존재하지 않을 수 있음 -> normpath로 먼저 검증
            if not link_target_normalized.startswith(target_dir_abs + os.sep) and link_target_normalized != target_dir_abs:
                attack_msg = (
                    f"[SECURITY] Malicious {'symlink' if member.issym() else 'hardlink'} detected! "
                    f"Member '{member.name}' links to outside target directory. "
                    f"Target: {target_dir_abs}, Link points to: {link_target_normalized}"
                )
                logger.critical(attack_msg)
                raise SecurityException(attack_msg)

            # 추가 검증: 링크 경로의 부모 디렉토리가 이미 존재하고 심볼릭 링크를 포함하는 경우
            # realpath로 실제 경로를 확인하여 샌드박스 탈출 시도 차단
            link_parent = os.path.dirname(link_target_normalized)
            if os.path.exists(link_parent):
                link_parent_real = os.path.realpath(link_parent)
                if not link_parent_real.startswith(target_dir_real + os.sep) and link_parent_real != target_dir_real:
                    attack_msg = (
                        f"[SECURITY] Symlink chain escape detected! "
                        f"Link '{member.name}' target's parent directory resolves outside sandbox. "
                        f"Target (real): {target_dir_real}, Link parent (real): {link_parent_real}"
                    )
                    logger.critical(attack_msg)
                    raise SecurityException(attack_msg)

        # 4. 모든 검증을 통과한 경우에만 안전하게 추출 수행
        # 심볼릭 링크와 하드 링크는 검증 완료 후 수동으로 생성 (tarfile.extract의 제약 우회)
        if member.issym():
            # 심볼릭 링크 수동 생성
            link_target = member.linkname
            # Re-rooting: 절대 경로는 컨테이너 내부 경로로 변환
            if os.path.isabs(link_target):
                # 절대 경로를 상대 경로로 변환하여 생성
                # /usr/bin -> target_dir/usr/bin을 가리키도록
                # member의 위치에서 link_target_final까지의 상대 경로 계산
                link_source = os.path.join(target_dir, member.name)
                link_target_absolute = os.path.join(target_dir, link_target.lstrip(os.sep))
                # 부모 디렉토리 생성
                os.makedirs(os.path.dirname(link_source), exist_ok=True)
                # 상대 경로로 심볼릭 링크 생성
                link_target_relative = os.path.relpath(link_target_absolute, os.path.dirname(link_source))
                os.symlink(link_target_relative, link_source)
            else:
                # 상대 경로 링크는 그대로 생성
                link_source = os.path.join(target_dir, member.name)
                os.makedirs(os.path.dirname(link_source), exist_ok=True)
                os.symlink(link_target, link_source)
        elif member.islnk():
            # 하드 링크 수동 생성
            link_target = member.linkname
            link_source = os.path.join(target_dir, member.name)
            # Re-rooting: 절대 경로 하드 링크 처리
            if os.path.isabs(link_target):
                link_target_absolute = os.path.join(target_dir, link_target.lstrip(os.sep))
            else:
                link_target_absolute = os.path.join(os.path.dirname(link_source), link_target)
            # 부모 디렉토리 생성
            os.makedirs(os.path.dirname(link_source), exist_ok=True)
            # 하드 링크 생성 (대상 파일이 존재해야 함)
            if os.path.exists(link_target_absolute):
                os.link(link_target_absolute, link_source)
        else:
            # 일반 파일은 tarfile.extract()로 추출
            # Python 3.12+ 에서만 filter 파라미터 사용 (deprecation warning 방지)
            if sys.version_info >= (3, 12):
                tar_obj.extract(member, path=target_dir, filter='data')
            else:
                tar_obj.extract(member, path=target_dir)

    def extract_image(self) -> str:
        """
        Extract the container image tar file to a temporary directory.

        Returns:
            Path to the temporary directory containing extracted content
        """
        # 임시 디렉토리 생성
        self.temp_dir = tempfile.mkdtemp()
        print(MESSAGES["extract_start"].format(path=self.image_tar_path))

        # tar 파일 안전하게 추출 (Tar Slip 방지)
        with tarfile.open(self.image_tar_path, "r") as tar:
            for member in tar.getmembers():
                self._safe_extract(tar, member, self.temp_dir)

        return self.temp_dir

    def get_layers(self) -> List[str]:
        """
        Read the manifest.json and get the list of layers.

        Returns:
            List of layer tar file paths

        Raises:
            FileNotFoundError: If manifest.json is not found
        """
        # manifest.json 파일 경로 확인
        manifest_path = os.path.join(self.temp_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(ERROR_MESSAGES["manifest_not_found"])

        # manifest 파일 읽기
        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        # 첫 번째 이미지의 레이어 목록 반환
        return manifest[0]["Layers"]

    def merge_layers(self, layers: List[str]) -> str:
        """
        Merge all layers to create a complete filesystem.
        Handles Docker whiteout files (.wh.*) properly.

        Args:
            layers: List of layer tar file paths

        Returns:
            Path to the merged filesystem directory
        """
        # 병합된 파일시스템 디렉토리 생성
        self.merged_fs = os.path.join(self.temp_dir, "merged_fs")
        os.makedirs(self.merged_fs, exist_ok=True)

        # 각 레이어를 순차적으로 적용
        for layer_tar in layers:
            layer_tar_path = os.path.join(self.temp_dir, layer_tar)
            # whiteout 파일을 처리하면서 레이어 적용
            self._apply_layer_with_whiteouts(layer_tar_path, self.merged_fs)
            print(MESSAGES["layer_applied"].format(layer=layer_tar))

        return self.merged_fs

    def _apply_layer_with_whiteouts(self, layer_tar_path: str, target_dir: str) -> None:
        """
        Apply a single layer to the target directory, handling whiteout files.

        Args:
            layer_tar_path: Path to the layer tar file
            target_dir: Directory where the layer should be applied
        """
        with tarfile.open(layer_tar_path, "r") as layer_tarfile:
            # 첫 번째 패스: whiteout 정보 수집
            whiteout_files: Set[str] = set()  # 일반 whiteout 파일 목록
            opaque_dirs: Set[str] = set()  # opaque 디렉토리 목록

            for member in layer_tarfile.getmembers():
                # Opaque 디렉토리 마커 확인 (.wh..wh..opq)
                if member.name.endswith(".wh..wh..opq"):
                    dir_path = os.path.dirname(member.name)
                    opaque_dirs.add(dir_path)
                # 일반 whiteout 파일 확인 (.wh.로 시작)
                elif "/.wh." in member.name or member.name.startswith(".wh."):
                    whiteout_files.add(member.name)

            # Opaque 디렉토리 처리 (기존 내용 삭제 후 재생성)
            for opaque_dir in opaque_dirs:
                real_dir = os.path.join(target_dir, opaque_dir)
                if os.path.exists(real_dir):
                    shutil.rmtree(real_dir)
                os.makedirs(real_dir, exist_ok=True)

            # 두 번째 패스: 파일 추출 (whiteout 마커 제외)
            for member in layer_tarfile.getmembers():
                # Whiteout 마커 파일 자체는 건너뛰기
                if member.name.endswith(".wh..wh..opq"):
                    continue

                # 일반 whiteout 파일 처리
                if "/.wh." in member.name or member.name.startswith(".wh."):
                    # 삭제해야 할 실제 파일명 추출
                    parts = member.name.rsplit("/.wh.", 1)
                    if len(parts) == 2:
                        deleted_file = os.path.join(parts[0], parts[1])
                    else:
                        # .wh.가 앞에 있는 경우 처리
                        deleted_file = member.name[4:]  # ".wh." 접두사 제거

                    # 해당 파일/디렉토리 삭제
                    target_path = os.path.join(target_dir, deleted_file)
                    if os.path.exists(target_path):
                        if os.path.isdir(target_path):
                            shutil.rmtree(target_path)
                        else:
                            os.remove(target_path)
                    continue

                # 일반 파일 추출 (Tar Slip 방지를 위한 안전한 추출)
                self._safe_extract(layer_tarfile, member, target_dir)

    def extract_app_auto(self, include_filter: Optional[str] = None) -> bool:
        """
        Automatically detect and extract application source.

        Args:
            include_filter: Optional file extension filter

        Returns:
            True if extraction was successful, False otherwise

        Raises:
            FileNotFoundError: If no application source is found
        """
        found = False  # 애플리케이션 찾기 성공 여부

        # 알려진 애플리케이션 경로들을 순차적으로 확인
        for candidate in CANDIDATE_APP_PATHS:
            test_path = os.path.join(self.merged_fs, candidate.lstrip('/'))
            if not os.path.exists(test_path):
                continue

            # 애플리케이션 발견 시 복사
            print(MESSAGES["app_found"].format(path=candidate))
            dest_path = os.path.join(self.output_dir, os.path.basename(candidate.rstrip('/')))
            copy_directory(test_path, dest_path, include_filter)
            print(MESSAGES["copy_complete"].format(src=candidate, dest=dest_path))
            found = True

        # 애플리케이션을 찾지 못한 경우 예외 발생
        if not found:
            raise FileNotFoundError(ERROR_MESSAGES["auto_detect_failed"])

        return found

    def extract_app_manual(self, app_path: str, include_filter: Optional[str] = None) -> None:
        """
        Extract application source from a manually specified path.

        Args:
            app_path: Path to the application source in the container
            include_filter: Optional file extension filter

        Raises:
            FileNotFoundError: If the specified path doesn't exist
        """
        # 지정된 경로에서 애플리케이션 소스 확인
        app_src = os.path.join(self.merged_fs, app_path.lstrip('/'))
        if not os.path.exists(app_src):
            raise FileNotFoundError(ERROR_MESSAGES["app_path_not_found"].format(path=app_path))

        print(MESSAGES["manual_copy_start"].format(path=app_path))

        # 기존 출력 디렉토리가 있으면 삭제
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

        # 애플리케이션 소스 복사
        copy_directory(app_src, self.output_dir, include_filter)
        print(MESSAGES["copy_success"].format(path=self.output_dir))

    def cleanup(self) -> None:
        """
        임시 디렉토리를 정리합니다.
        """
        # 임시 디렉토리가 존재하면 삭제
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)


def extract_app_layer(
    image_tar_path: str,
    output_dir: str,
    app_path: Optional[str] = None,
    auto_detect: bool = False,
    include_filter: Optional[str] = None
) -> None:
    """
    Extract application layer from a container image tar file.

    Args:
        image_tar_path: Path to the container image tar file
        output_dir: Directory where the extracted source will be saved
        app_path: Manual path to the application source (if not auto-detecting)
        auto_detect: Whether to automatically detect the application source path
        include_filter: Optional file extension filter

    Raises:
        FileNotFoundError: If required files or paths are not found
        ValueError: If invalid arguments are provided
    """
    # ImageExtractor 객체 생성
    extractor = ImageExtractor(image_tar_path, output_dir)

    try:
        # 1. 이미지를 임시 디렉토리로 추출
        extractor.extract_image()

        # 2. manifest에서 레이어 목록 가져오기
        layers = extractor.get_layers()

        # 3. 모든 레이어 병합
        extractor.merge_layers(layers)

        # 4. 애플리케이션 소스 추출
        if auto_detect:
            # 자동 감지 모드
            extractor.extract_app_auto(include_filter)
        else:
            # 수동 지정 모드
            if not app_path:
                raise ValueError(ERROR_MESSAGES["app_path_required"])
            extractor.extract_app_manual(app_path, include_filter)

    finally:
        # 항상 임시 디렉토리 정리
        extractor.cleanup()