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
    mapping = map_cves_by_package(report_data)
    api_extractor = PackageAPIExtractor()
    combined: Dict[str, Dict[str, Dict[str, List[str]]]] = {}

    for pkg, versions in mapping.items():
        combined[pkg] = {}
        for ver, cves in versions.items():
            print(f"{pkg}@{ver}의 API 추출 중...")
            apis = api_extractor.extract_api_list(pkg.lower(), ver)
            combined[pkg][ver] = {
                'cves': cves,
                'apis': apis
            }
    return combined