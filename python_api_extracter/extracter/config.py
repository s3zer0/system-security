"""
설정 관리 모듈
"""
import os
import warnings
from typing import Set

# 경고 메시지 억제 설정
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=Warning, module="urllib3.contrib.socks")


class Config:
    """애플리케이션 설정을 관리하는 클래스"""

    def __init__(self):
        # 스크립트 디렉토리 경로
        self.script_dir = os.path.join(os.path.dirname(__file__), '..', 'scripts')
        self.extract_script_path = os.path.join(self.script_dir, 'extract_apis.py')
        self.detect_script_path = os.path.join(self.script_dir, 'detect_modules.py')

        # API 추출이 문제가 되는 패키지들 (무시할 패키지 목록)
        self.problematic_packages: Set[str] = {
            'pip',
            '_distutils_hack',
            'pkg_resources',
            'setuptools',
            'wheel',
            'distutils'
        }

        # 임시 디렉토리 접두사
        self.temp_dir_prefix = "api_ext_"

        # 가상 환경 설정
        self.venv_name = "venv"
        self.python_executable = "python"

        # pip 설정
        self.pip_upgrade_on_install = True
        self.pip_quiet_install = True

    def add_problematic_package(self, package_name: str):
        """문제 패키지 목록에 패키지를 추가합니다."""
        self.problematic_packages.add(package_name)

    def remove_problematic_package(self, package_name: str):
        """문제 패키지 목록에서 패키지를 제거합니다."""
        self.problematic_packages.discard(package_name)

    def is_problematic_package(self, package_name: str) -> bool:
        """패키지가 문제 패키지인지 확인합니다."""
        return package_name in self.problematic_packages


# 전역 설정 인스턴스
config = Config()