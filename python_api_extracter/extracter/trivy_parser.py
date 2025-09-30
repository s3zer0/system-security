"""
Trivy JSON 보고서 파싱 모듈
"""
from typing import Dict, List


def map_cves_by_package(report_data: dict) -> Dict[str, Dict[str, List[str]]]:
    """
    Trivy JSON 보고서에서 Python 패키지 및 버전별 CVE 매핑을 생성합니다.

    Args:
        report_data (dict): Trivy JSON 보고서 데이터

    Returns:
        Dict[str, Dict[str, List[str]]]: 패키지 이름과 버전별 CVE 목록
    """
    mapping: Dict[str, Dict[str, List[str]]] = {}

    # 표준 Trivy 형식 처리
    if "Results" in report_data:
        for result in report_data.get("Results", []):
            target = result.get("Target", "").lower()
            if "python" in target:
                for vuln in result.get("Vulnerabilities", []):
                    pkg = vuln.get("PkgName")
                    ver = vuln.get("InstalledVersion")
                    cve = vuln.get("VulnerabilityID")
                    if pkg and ver and cve:
                        mapping.setdefault(pkg, {}).setdefault(ver, []).append(cve)

    # 사용자 정의 형식 처리 (vulnerabilities 배열이 직접 있는 경우)
    elif "vulnerabilities" in report_data:
        for vuln in report_data.get("vulnerabilities", []):
            pkg = vuln.get("package_name")
            ver = vuln.get("installed_version")
            cve = vuln.get("id")
            pkg_type = vuln.get("package_type", "")
            if pkg and ver and cve and "python" in pkg_type:
                mapping.setdefault(pkg, {}).setdefault(ver, []).append(cve)

    return mapping