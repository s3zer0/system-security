"""컨테이너 이미지 소스 추출기를 위한 유틸리티 함수 모음입니다."""

import os
import shutil
from typing import Optional

from common import ensure_dir


def copy_directory(src: str, dest: str, include_filter: Optional[str] = None) -> None:
    """
    선택적 필터를 적용해 디렉터리를 복사합니다.

    Args:
        src: 원본 디렉터리 경로
        dest: 대상 디렉터리 경로
        include_filter: 확장자 필터 (예: '.py')
    """
    if include_filter:
        # 필터가 있으면 조건에 맞는 파일만 복사합니다.
        os.makedirs(dest, exist_ok=True)
        for root, dirs, files in os.walk(src):
            # 원본 기준 상대 경로를 계산합니다.
            rel_path = os.path.relpath(root, src)
            dest_dir = os.path.join(dest, rel_path) if rel_path != '.' else dest

            # 디렉터리 구조를 생성합니다.
            os.makedirs(dest_dir, exist_ok=True)

            # 필터와 일치하는 파일만 복사합니다.
            for file in files:
                if file.endswith(include_filter):
                    src_file = os.path.join(root, file)
                    dest_file = os.path.join(dest_dir, file)
                    shutil.copy2(src_file, dest_file)
    else:
        # 필터가 없으면 모든 파일을 복사합니다.
        shutil.copytree(src, dest, dirs_exist_ok=True)


def find_app_path(merged_fs: str, candidate_paths: list) -> Optional[str]:
    """
    후보 목록에서 애플리케이션 경로를 탐색합니다.

    Args:
        merged_fs: 병합된 파일 시스템 경로
        candidate_paths: 확인할 후보 경로 목록

    Returns:
        발견된 첫 번째 유효 경로 또는 없으면 None
    """
    for candidate in candidate_paths:
        test_path = os.path.join(merged_fs, candidate.lstrip('/'))
        if os.path.exists(test_path):
            return test_path
    return None


def validate_tar_file(file_path: str) -> bool:
    """
    지정된 파일이 유효한 tar 파일인지 검사합니다.

    Args:
        file_path: 검증할 파일 경로

    Returns:
        tar 파일이면 True, 아니면 False
    """
    if not os.path.exists(file_path):
        return False

    if not file_path.endswith(('.tar', '.tar.gz', '.tgz')):
        return False

    return os.path.isfile(file_path)


def ensure_directory(path: str) -> None:
    """
    디렉터리가 존재하도록 보장하고 필요 시 생성합니다.

    Args:
        path: 확인할 디렉터리 경로
    """
    ensure_dir(path)


def safe_remove_directory(path: str) -> None:
    """
    디렉터리가 존재할 경우 안전하게 제거합니다.

    Args:
        path: 삭제할 디렉터리 경로
    """
    if os.path.exists(path) and os.path.isdir(path):
        shutil.rmtree(path)
