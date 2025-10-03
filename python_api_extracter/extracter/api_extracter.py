"""
API 추출 모듈 - Trivy 보고서에서 CVE와 API를 매핑하는 기능 제공
"""

from typing import Dict, List
from .trivy_parser import map_cves_by_package
from .package_api_extractor import PackageAPIExtractor



def build_cve_api_mapping(report_data: dict) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    """
    Trivy 보고서에서 패키지 및 버전별 CVE와 API의 통합 매핑을 생성합니다.

    Args:
        report_data (dict): Trivy JSON 보고서 데이터

    Returns:
        Dict[str, Dict[str, Dict[str, List[str]]]]: 패키지와 버전별 CVE 및 API 매핑
            {패키지: {버전: {'cves': [...], 'apis': {...}}, ...}, ...}
    """
    # Trivy 보고서에서 패키지별 CVE 매핑 생성
    mapping = map_cves_by_package(report_data)

    # API 추출기 객체 생성
    api_extractor = PackageAPIExtractor()

    # 결과를 저장할 디셉셔너리 초기화
    combined: Dict[str, Dict[str, Dict[str, List[str]]]] = {}

    # 각 패키지와 버전에 대해 처리
    for pkg, versions in mapping.items():
        combined[pkg] = {}
        for ver, cves in versions.items():
            # 현재 처리 중인 패키지 정보 출력
            print(f"{pkg}@{ver}의 API 추출 중...")

            # 해당 패키지의 API 목록 추출
            apis = api_extractor.extract_api_list(pkg.lower(), ver)

            # CVE와 API 정보를 함께 저장
            combined[pkg][ver] = {
                'cves': cves,
                'apis': apis
            }

    return combined