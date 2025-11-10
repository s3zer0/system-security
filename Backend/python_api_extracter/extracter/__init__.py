"""
Python API 추출기 패키지입니다.

CVE와 API 매핑을 생성하는 기능을 제공합니다.
"""

from .api_extracter import build_cve_api_mapping
from .trivy_parser import map_cves_by_package
from .package_api_extractor import PackageAPIExtractor
from .config import config, Config

__all__ = [
    'build_cve_api_mapping',
    'map_cves_by_package',
    'PackageAPIExtractor',
    'config',
    'Config'
]
