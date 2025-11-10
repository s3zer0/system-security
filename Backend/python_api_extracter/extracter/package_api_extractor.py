"""
패키지 API 추출 모듈
"""
import json
import subprocess
import sys
import os
import tempfile
import shutil
from typing import Dict, List

from .config import config


class PackageAPIExtractor:
    """패키지 API 추출을 담당하는 클래스"""

    def __init__(self, use_config=None):
        """
        PackageAPIExtractor 클래스 생성자

        Args:
            use_config: 사용할 설정 객체 (기본값: 전역 설정)
        """
        # 설정 객체 초기화 (주어진 설정 또는 기본 전역 설정 사용)
        self.config = use_config or config

    def extract_api_list(self, pip_name: str, version: str) -> Dict[str, List[str]]:
        """
        임시 가상 환경을 생성하고, 지정된 패키지 버전을 설치한 뒤,
        최상위 모듈을 탐지하고 호출 가능한 API 목록을 추출합니다.

        Args:
            pip_name (str): 설치할 패키지 이름
            version (str): 패키지 버전

        Returns:
            Dict[str, List[str]]: 모듈별 API 목록
        """
        # 패키지 설치 명세 생성 (패키지명==버전)
        spec = f"{pip_name}=={version}"

        # 임시 작업 디렉토리 생성
        workdir = tempfile.mkdtemp(prefix=self.config.temp_dir_prefix)

        # 가상 환경 디렉토리 경로 설정
        venv_dir = os.path.join(workdir, self.config.venv_name)

        try:
            # Python 가상 환경 생성
            subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)

            # OS에 따른 Python 실행 파일 경로 설정 (Windows는 Scripts, 그 외는 bin)
            python_bin = os.path.join(venv_dir, 'Scripts' if os.name=='nt' else 'bin', self.config.python_executable)

            # 설정에 따라 pip 업그레이드 수행
            if self.config.pip_upgrade_on_install:
                # 조용한 설치 모드 설정 확인
                stdout_target = subprocess.DEVNULL if self.config.pip_quiet_install else None
                # pip를 최신 버전으로 업그레이드
                subprocess.run([python_bin, '-m', 'pip', 'install', '--upgrade', 'pip'],
                             check=True, stdout=stdout_target)

            try:
                # 지정된 버전의 패키지 설치
                stdout_target = subprocess.DEVNULL if self.config.pip_quiet_install else None
                subprocess.run([python_bin, '-m', 'pip', 'install', spec],
                             check=True, stdout=stdout_target)
            except subprocess.CalledProcessError:
                # 패키지 설치 실패 시 빈 결과 반환
                return {}

            # 설치된 패키지의 최상위 모듈 탐지
            modules = self._detect_top_level_modules(python_bin, pip_name)

            # 감지된 모듈에서 API 목록 추출
            return self._extract_apis_from_modules(python_bin, modules)

        finally:
            # 작업 완료 후 임시 디렉토리 정리 (오류 무시)
            shutil.rmtree(workdir, ignore_errors=True)

    def _detect_top_level_modules(self, python_bin: str, pip_name: str) -> List[str]:
        """
        패키지의 최상위 모듈을 탐지합니다.

        Args:
            python_bin: Python 실행 파일 경로
            pip_name: 패키지 이름

        Returns:
            최상위 모듈 이름 리스트
        """
        try:
            # 모듈 탐지 스크립트 실행
            out = subprocess.check_output([python_bin, self.config.detect_script_path, pip_name], text=True)
            # JSON 결과 파싱 및 모듈 목록 추출
            return json.loads(out).get('modules', [])
        except Exception:
            # 오류 발생 시 빈 리스트 반환
            return []

    def _extract_apis_from_modules(self, python_bin: str, modules: List[str]) -> Dict[str, List[str]]:
        """
        주어진 모듈들로부터 API를 추출합니다.

        Args:
            python_bin: Python 실행 파일 경로
            modules: 모듈 이름 리스트

        Returns:
            모듈별 API 목록 딕셔너리
        """
        # 결과를 저장할 딕셔너리
        results: Dict[str, List[str]] = {}

        # 각 모듈에 대해 처리
        for mod in modules:
            try:
                # API 추출 스크립트 실행 (stderr는 무시)
                out = subprocess.check_output([python_bin, self.config.extract_script_path, mod],
                                            text=True, stderr=subprocess.DEVNULL)

                # JSON 결과 파싱
                data = json.loads(out)
                funcs = data.get('functions', [])

                # 함수가 있으면 결과에 추가
                if funcs:
                    results[mod] = funcs
            except Exception:
                # 알려진 문제 패키지가 아닌 경우에만 오류 메시지 출력
                if not self.config.is_problematic_package(mod):
                    print(f"  {mod} 모듈에서 API 추출 실패")
                continue

        return results