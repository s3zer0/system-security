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
    # 결과를 저장할 매핑 디셉셔너리 초기화
    mapping: Dict[str, Dict[str, List[str]]] = {}

    # Trivy 표준 형식 처리 (Results 필드가 있는 경우)
    if "Results" in report_data:
        # 각 결과 항목을 순회
        for result in report_data.get("Results", []):
            # 대상 파일/패키지 이름 확인
            target = result.get("Target", "").lower()

            # Python 관련 취약점만 처리
            if "python" in target:
                # 취약점 목록 순회
                for vuln in result.get("Vulnerabilities", []):
                    # 필요한 정보 추출
                    pkg = vuln.get("PkgName")  # 패키지 이름
                    ver = vuln.get("InstalledVersion")  # 설치된 버전
                    cve = vuln.get("VulnerabilityID")  # CVE ID

                    # 모든 필수 정보가 있으면 매핑에 추가
                    if pkg and ver and cve:
                        mapping.setdefault(pkg, {}).setdefault(ver, []).append(cve)

    # 사용자 정의 형식 처리 (vulnerabilities 배열이 직접 있는 경우)
    elif "vulnerabilities" in report_data:
        # 취약점 배열을 순회
        for vuln in report_data.get("vulnerabilities", []):
            # 사용자 정의 형식에서 필드 추출
            pkg = vuln.get("package_name")  # 패키지 이름
            ver = vuln.get("installed_version")  # 설치 버전
            cve = vuln.get("id")  # CVE ID
            pkg_type = vuln.get("package_type", "")  # 패키지 타입

            # Python 패키지에 대해서만 처리
            if pkg and ver and cve and "python" in pkg_type:
                mapping.setdefault(pkg, {}).setdefault(ver, []).append(cve)

    return mapping