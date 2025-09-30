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
        # 설정 사용 (기본값: 전역 설정)
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
        spec = f"{pip_name}=={version}"
        workdir = tempfile.mkdtemp(prefix=self.config.temp_dir_prefix)
        venv_dir = os.path.join(workdir, self.config.venv_name)

        try:
            # 가상 환경 생성
            subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
            python_bin = os.path.join(venv_dir, 'Scripts' if os.name=='nt' else 'bin', self.config.python_executable)

            # pip 업그레이드 (설정에 따라)
            if self.config.pip_upgrade_on_install:
                stdout_target = subprocess.DEVNULL if self.config.pip_quiet_install else None
                subprocess.run([python_bin, '-m', 'pip', 'install', '--upgrade', 'pip'],
                             check=True, stdout=stdout_target)

            try:
                # 패키지 설치
                stdout_target = subprocess.DEVNULL if self.config.pip_quiet_install else None
                subprocess.run([python_bin, '-m', 'pip', 'install', spec],
                             check=True, stdout=stdout_target)
            except subprocess.CalledProcessError:
                return {}

            # 최상위 모듈 탐지
            modules = self._detect_top_level_modules(python_bin, pip_name)

            # API 추출
            return self._extract_apis_from_modules(python_bin, modules)

        finally:
            # 임시 디렉토리 정리
            shutil.rmtree(workdir, ignore_errors=True)

    def _detect_top_level_modules(self, python_bin: str, pip_name: str) -> List[str]:
        """최상위 모듈을 탐지합니다."""
        try:
            out = subprocess.check_output([python_bin, self.config.detect_script_path, pip_name], text=True)
            return json.loads(out).get('modules', [])
        except Exception:
            return []

    def _extract_apis_from_modules(self, python_bin: str, modules: List[str]) -> Dict[str, List[str]]:
        """모듈들로부터 API를 추출합니다."""
        results: Dict[str, List[str]] = {}

        for mod in modules:
            try:
                # 모듈별 API 추출
                out = subprocess.check_output([python_bin, self.config.extract_script_path, mod],
                                            text=True, stderr=subprocess.DEVNULL)
                data = json.loads(out)
                funcs = data.get('functions', [])
                if funcs:
                    results[mod] = funcs
            except Exception:
                # 알려진 문제 패키지가 아닌 경우에만 오류 메시지 출력
                if not self.config.is_problematic_package(mod):
                    print(f"  {mod} 모듈에서 API 추출 실패")
                continue

        return results