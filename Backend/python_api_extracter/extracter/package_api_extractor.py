"""
패키지 API 추출 모듈 (Security-Hardened Version)
"""
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List

from .config import config


# ============================================================================
# Custom Exceptions
# ============================================================================

class PackageExtractionError(Exception):
    """패키지 API 추출 관련 기본 예외"""
    pass


class SecurityException(PackageExtractionError):
    """패키지 보안 검증 실패 예외"""
    pass


class InstallError(PackageExtractionError):
    """패키지 설치 실패 예외"""
    pass


class ExtractionError(PackageExtractionError):
    """API 추출 실패 예외"""
    pass


# ============================================================================
# Package Security Validator
# ============================================================================

class PackageSecurityValidator:
    """
    패키지 이름과 버전을 검증하여 RCE 공격을 방지하는 보안 검증 클래스
    """

    # 안전한 패키지 이름 패턴: 알파벳, 숫자, 하이픈, 언더스코어, 점만 허용
    SAFE_PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')

    # 안전한 버전 패턴: PEP 440 표준 지원 (Epoch, Local version segments 포함)
    # 예: 1.0.0, 2.3.4a1, 1.0.0rc1, 1.2.3.post1, 1!2.0, 1.9.0+cu111
    SAFE_VERSION_PATTERN = re.compile(r'^[a-zA-Z0-9\.\-\_\+\!]+$')

    # 위험한 문자 패턴 (명령어 인젝션 방지)
    DANGEROUS_CHARS_PATTERN = re.compile(r'[;&|`$\(\)<>\'\"\\\n\r]')

    # 최대 길이 제한
    MAX_PACKAGE_NAME_LENGTH = 128
    MAX_VERSION_LENGTH = 64

    def __init__(self, logger: logging.Logger = None):
        """
        PackageSecurityValidator 생성자

        Args:
            logger: 로깅에 사용할 Logger 인스턴스
        """
        self.logger = logger or logging.getLogger(__name__)

    def validate_package_name(self, package_name: str) -> None:
        """
        패키지 이름의 보안성을 검증

        Args:
            package_name: 검증할 패키지 이름

        Raises:
            SecurityException: 검증 실패 시
        """
        if not package_name:
            raise SecurityException("패키지 이름이 비어있습니다")

        if len(package_name) > self.MAX_PACKAGE_NAME_LENGTH:
            raise SecurityException(
                f"패키지 이름이 너무 깁니다 (최대 {self.MAX_PACKAGE_NAME_LENGTH}자)"
            )

        # 위험한 문자 검사
        if self.DANGEROUS_CHARS_PATTERN.search(package_name):
            self.logger.error(f"위험한 문자가 포함된 패키지 이름: {package_name}")
            raise SecurityException(
                f"패키지 이름에 위험한 문자가 포함되어 있습니다: {package_name}"
            )

        # 안전한 패턴 검사
        if not self.SAFE_PACKAGE_NAME_PATTERN.match(package_name):
            self.logger.error(f"잘못된 형식의 패키지 이름: {package_name}")
            raise SecurityException(
                f"패키지 이름이 허용된 형식이 아닙니다: {package_name}"
            )

        self.logger.debug(f"패키지 이름 검증 성공: {package_name}")

    def validate_version(self, version: str) -> None:
        """
        패키지 버전의 보안성을 검증

        PEP 440 표준을 지원하며 Epoch(!)와 Local version segments(+)를 허용합니다.
        예: 1.0.0, 2.3.4a1, 1!2.0.0, 1.9.0+cu111

        Args:
            version: 검증할 버전 문자열

        Raises:
            SecurityException: 검증 실패 시
        """
        if not version:
            raise SecurityException("버전 정보가 비어있습니다")

        if len(version) > self.MAX_VERSION_LENGTH:
            raise SecurityException(
                f"버전 문자열이 너무 깁니다 (최대 {self.MAX_VERSION_LENGTH}자)"
            )

        # 위험한 문자 검사
        if self.DANGEROUS_CHARS_PATTERN.search(version):
            self.logger.error(f"위험한 문자가 포함된 버전: {version}")
            raise SecurityException(
                f"버전에 위험한 문자가 포함되어 있습니다: {version}"
            )

        # 안전한 패턴 검사
        if not self.SAFE_VERSION_PATTERN.match(version):
            self.logger.error(f"잘못된 형식의 버전: {version}")
            raise SecurityException(
                f"버전이 허용된 형식이 아닙니다: {version}"
            )

        self.logger.debug(f"버전 검증 성공: {version}")

    def validate(self, package_name: str, version: str) -> None:
        """
        패키지 이름과 버전을 모두 검증

        Args:
            package_name: 검증할 패키지 이름
            version: 검증할 버전

        Raises:
            SecurityException: 검증 실패 시
        """
        self.validate_package_name(package_name)
        self.validate_version(version)
        self.logger.info(f"보안 검증 완료: {package_name}=={version}")


# ============================================================================
# Package API Extractor
# ============================================================================

class PackageAPIExtractor:
    """패키지 API 추출을 담당하는 클래스 (보안 강화 버전)"""

    def __init__(self, use_config=None, logger: logging.Logger = None):
        """
        PackageAPIExtractor 클래스 생성자

        Args:
            use_config: 사용할 설정 객체 (기본값: 전역 설정)
            logger: 로깅에 사용할 Logger 인스턴스
        """
        # 설정 객체 초기화
        self.config = use_config or config

        # 로거 초기화
        self.logger = logger or self._setup_default_logger()

        # 보안 검증기 초기화
        self.validator = PackageSecurityValidator(logger=self.logger)

    def _setup_default_logger(self) -> logging.Logger:
        """
        기본 로거 설정

        Returns:
            설정된 Logger 인스턴스
        """
        logger = logging.getLogger(__name__)

        # 로거가 아직 핸들러가 없으면 기본 설정
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)

        return logger

    def extract_api_list(self, pip_name: str, version: str) -> Dict[str, List[str]]:
        """
        임시 가상 환경을 생성하고, 지정된 패키지 버전을 설치한 뒤,
        최상위 모듈을 탐지하고 호출 가능한 API 목록을 추출합니다.

        Args:
            pip_name (str): 설치할 패키지 이름
            version (str): 패키지 버전

        Returns:
            Dict[str, List[str]]: 모듈별 API 목록

        Raises:
            SecurityException: 패키지 이름 또는 버전이 보안 검증을 통과하지 못한 경우
            InstallError: 패키지 설치 실패 시
            ExtractionError: API 추출 실패 시
        """
        # 보안 검증 수행 (RCE 공격 방지)
        self.logger.info(f"패키지 추출 시작: {pip_name}=={version}")
        try:
            self.validator.validate(pip_name, version)
        except SecurityException as e:
            self.logger.error(f"보안 검증 실패: {e}")
            raise

        # 패키지 설치 명세 생성
        spec = f"{pip_name}=={version}"

        # 임시 작업 디렉토리 생성
        workdir = tempfile.mkdtemp(prefix=self.config.temp_dir_prefix)
        self.logger.debug(f"임시 디렉토리 생성: {workdir}")

        # 가상 환경 디렉토리 경로 설정
        venv_dir = os.path.join(workdir, self.config.venv_name)

        try:
            # Python 가상 환경 생성
            self.logger.info(f"가상 환경 생성 중: {venv_dir}")
            try:
                subprocess.run(
                    [sys.executable, "-m", "venv", venv_dir],
                    check=True,
                    capture_output=True,
                    text=True
                )
            except subprocess.CalledProcessError as e:
                self.logger.error(f"가상 환경 생성 실패: {e.stderr}")
                raise InstallError(f"가상 환경 생성 실패: {e.stderr}")

            # OS에 따른 Python 실행 파일 경로 설정
            python_bin = os.path.join(
                venv_dir,
                'Scripts' if os.name == 'nt' else 'bin',
                self.config.python_executable
            )

            # 설정에 따라 pip 업그레이드 수행
            if self.config.pip_upgrade_on_install:
                self.logger.debug("pip 업그레이드 수행 중")
                stdout_target = subprocess.DEVNULL if self.config.pip_quiet_install else None
                try:
                    subprocess.run(
                        [python_bin, '-m', 'pip', 'install', '--upgrade', 'pip'],
                        check=True,
                        stdout=stdout_target,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                except subprocess.CalledProcessError as e:
                    self.logger.warning(f"pip 업그레이드 실패 (계속 진행): {e.stderr}")

            # 지정된 버전의 패키지 설치
            self.logger.info(f"패키지 설치 중: {spec}")
            try:
                stdout_target = subprocess.DEVNULL if self.config.pip_quiet_install else None
                result = subprocess.run(
                    [python_bin, '-m', 'pip', 'install', spec],
                    check=True,
                    stdout=stdout_target,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.logger.info(f"패키지 설치 완료: {spec}")
            except subprocess.CalledProcessError as e:
                # 명확한 에러 메시지와 함께 예외 발생
                error_msg = f"패키지 설치 실패 ({spec}): {e.stderr}"
                self.logger.error(error_msg)
                raise InstallError(error_msg)

            # 설치된 패키지의 최상위 모듈 탐지
            self.logger.info(f"최상위 모듈 탐지 중: {pip_name}")
            modules = self._detect_top_level_modules(python_bin, pip_name)
            self.logger.info(f"탐지된 모듈 수: {len(modules)}")

            # 감지된 모듈에서 API 목록 추출
            self.logger.info("API 추출 시작")
            api_dict = self._extract_apis_from_modules(python_bin, modules)
            self.logger.info(f"API 추출 완료: {len(api_dict)}개 모듈")

            return api_dict

        finally:
            # 작업 완료 후 임시 디렉토리 정리
            self.logger.debug(f"임시 디렉토리 정리 중: {workdir}")
            shutil.rmtree(workdir, ignore_errors=True)

    def _detect_top_level_modules(self, python_bin: str, pip_name: str) -> List[str]:
        """
        패키지의 최상위 모듈을 탐지합니다.

        Args:
            python_bin: Python 실행 파일 경로
            pip_name: 패키지 이름

        Returns:
            최상위 모듈 이름 리스트

        Raises:
            ExtractionError: 모듈 탐지 실패 시
        """
        try:
            # 모듈 탐지 스크립트 실행
            self.logger.debug(f"모듈 탐지 스크립트 실행: {self.config.detect_script_path}")
            out = subprocess.check_output(
                [python_bin, self.config.detect_script_path, pip_name],
                text=True,
                stderr=subprocess.PIPE
            )

            # JSON 결과 파싱 및 모듈 목록 추출
            modules = json.loads(out).get('modules', [])
            self.logger.debug(f"탐지된 모듈: {modules}")
            return modules

        except subprocess.CalledProcessError as e:
            error_msg = f"모듈 탐지 프로세스 실패 ({pip_name}): {e.stderr}"
            self.logger.error(error_msg)
            raise ExtractionError(error_msg)
        except json.JSONDecodeError as e:
            error_msg = f"모듈 탐지 결과 파싱 실패 ({pip_name}): {e}"
            self.logger.error(error_msg)
            raise ExtractionError(error_msg)
        except Exception as e:
            error_msg = f"모듈 탐지 중 예상치 못한 오류 ({pip_name}): {e}"
            self.logger.error(error_msg)
            raise ExtractionError(error_msg)

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
        failed_modules: List[str] = []

        # 각 모듈에 대해 처리
        for mod in modules:
            try:
                self.logger.debug(f"API 추출 중: {mod}")

                # API 추출 스크립트 실행
                out = subprocess.check_output(
                    [python_bin, self.config.extract_script_path, mod],
                    text=True,
                    stderr=subprocess.PIPE
                )

                # JSON 결과 파싱
                data = json.loads(out)
                funcs = data.get('functions', [])

                # 함수가 있으면 결과에 추가
                if funcs:
                    results[mod] = funcs
                    self.logger.debug(f"{mod}: {len(funcs)}개 함수 추출")

            except subprocess.CalledProcessError as e:
                # 알려진 문제 패키지가 아닌 경우에만 로깅
                if not self.config.is_problematic_package(mod):
                    self.logger.warning(f"{mod} 모듈 API 추출 실패 (프로세스 오류): {e.stderr}")
                    failed_modules.append(mod)
                else:
                    self.logger.debug(f"{mod} 모듈 스킵 (알려진 문제 패키지)")
                continue

            except json.JSONDecodeError as e:
                if not self.config.is_problematic_package(mod):
                    self.logger.warning(f"{mod} 모듈 API 추출 실패 (JSON 파싱 오류): {e}")
                    failed_modules.append(mod)
                continue

            except Exception as e:
                if not self.config.is_problematic_package(mod):
                    self.logger.warning(f"{mod} 모듈 API 추출 실패 (알 수 없는 오류): {e}")
                    failed_modules.append(mod)
                continue

        # 실패한 모듈이 있으면 요약 로그 출력
        if failed_modules:
            self.logger.info(f"API 추출 실패 모듈 ({len(failed_modules)}개): {', '.join(failed_modules)}")

        return results
