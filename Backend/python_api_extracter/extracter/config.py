"""
설정 관리 모듈

API 추출 시스템의 전체 설정을 관리합니다.
"""
import os
import warnings
from typing import Set

# 불필요한 경고 메시지 억제 설정
# DeprecationWarning과 urllib3 관련 경고 무시
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=Warning, module="urllib3.contrib.socks")


class Config:
    """
    애플리케이션 설정을 관리하는 클래스

    API 추출 시스템의 경로, 패키지, pip 설정 등을 관리합니다.
    """

    def __init__(self):
        """
        Config 초기화 - 기본 설정값 지정
        """
        # 스크립트 디렉토리 및 경로 설정
        self.script_dir = os.path.join(os.path.dirname(__file__), '..', 'scripts')
        self.extract_script_path = os.path.join(self.script_dir, 'extract_apis.py')  # API 추출 스크립트
        self.detect_script_path = os.path.join(self.script_dir, 'detect_modules.py')  # 모듈 탐지 스크립트

        # API 추출 시 문제가 발생하는 패키지 목록
        # 이 패키지들은 API 추출 시 무시됩니다
        self.problematic_packages: Set[str] = {
            'pip',  # pip 패키지 관리자
            '_distutils_hack',  # distutils 호환성 해킹
            'pkg_resources',  # setuptools의 일부
            'setuptools',  # Python 패키지 빌드 도구
            'wheel',  # Python wheel 패키지 포맷
            'distutils'  # Python 배포 유틸리티
        }

        # 임시 디렉토리 접두사 (고유한 임시 폴더 생성용)
        self.temp_dir_prefix = "api_ext_"

        # 가상 환경 설정
        self.venv_name = "venv"  # 가상 환경 디렉토리명
        self.python_executable = "python"  # Python 실행 파일명

        # pip 설정
        self.pip_upgrade_on_install = True  # 설치 시 pip 업그레이드 여부
        self.pip_quiet_install = True  # 조용한 설치 모드 사용 여부

    def add_problematic_package(self, package_name: str):
        """
        문제 패키지 목록에 패키지를 추가합니다.

        Args:
            package_name: 추가할 패키지 이름
        """
        self.problematic_packages.add(package_name)

    def remove_problematic_package(self, package_name: str):
        """
        문제 패키지 목록에서 패키지를 제거합니다.

        Args:
            package_name: 제거할 패키지 이름
        """
        self.problematic_packages.discard(package_name)

    def is_problematic_package(self, package_name: str) -> bool:
        """
        패키지가 문제 패키지인지 확인합니다.

        Args:
            package_name: 확인할 패키지 이름

        Returns:
            문제 패키지인 경우 True, 아니면 False
        """
        return package_name in self.problematic_packages


# 전역 설정 인스턴스 생성
# 모든 모듈에서 이 인스턴스를 공유하여 사용
config = Config()