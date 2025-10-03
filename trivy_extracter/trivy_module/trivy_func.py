"""
Trivy 취약점 스캐닝 기능 모듈
"""

import subprocess
import json
from typing import Dict, List, Any

def scan_vulnerabilities(input_archive: str, output_file: str, full_scan: bool = True):
    """
    Scan container image (in tar/zip format) for CVE vulnerabilities using Trivy
    and save the result as JSON to the specified output file.

    Args:
        input_archive: Path to the container image tar/zip file to scan
        output_file: Path to save the JSON report
        full_scan: If True, includes all severity levels, otherwise only critical/high
    """
    # Trivy 명령어 구성
    cmd = [
        "trivy", "image",  # 이미지 스캔 모드
        "--input", input_archive,  # 입력 tar/zip 파일
        "--format", "json",  # 출력 형식
        "--output", output_file,  # 출력 파일 경로
        "--scanners", "vuln",  # 취약점 스캐너만 사용
        "--vuln-type", "library",  # 라이브러리 취약점만 검사
        "--no-progress",  # 진행 표시줄 비활성화
    ]

    # 스캔 범위 설정 (심각도 레벨)
    if full_scan:
        # 전체 스캔: 모든 심각도 포함
        cmd += ["--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"]
    else:
        # 부분 스캔: 높음/심각함만 포함
        cmd += ["--severity", "HIGH,CRITICAL"]

    # Trivy 명령 실행
    subprocess.run(cmd, check=True)

    # 스캔 결과 정제
    clean_scan_results(output_file)


def clean_scan_results(output_file: str):
    """
    Trivy 스캔 결과에서 불필요한 정보를 제거하고 필수 정보만 남김

    Args:
        output_file: 정제할 JSON 파일 경로
    """
    # 기존 스캔 결과 파일 읽기
    with open(output_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 정제된 데이터 구조 초기화
    cleaned_data = {
        # 스캔 기본 정보
        "scan_info": {
            "target": data.get("ArtifactName", ""),  # 스캔 대상
            "scan_date": data.get("CreatedAt", ""),  # 스캔 날짜
            "os_info": data.get("Metadata", {}).get("OS", {})  # OS 정보
        },
        # 취약점 통계 정보
        "vulnerability_summary": {
            "total_vulnerabilities": 0,  # 총 취약점 수
            "by_severity": {},  # 심각도별 통계
            "by_package_type": {}  # 패키지 타입별 통계
        },
        "vulnerabilities": []  # 취약점 목록
    }

    # 취약점 정보 처리 (Python 패키지만 포함)
    for result in data.get("Results", []):
        # 패키지 타입 확인
        package_type = result.get("Type", "unknown")

        # Python 패키지가 아니면 건너뛰기
        if package_type != "python-pkg":
            continue

        # 해당 패키지의 모든 취약점 처리
        vulnerabilities = result.get("Vulnerabilities", [])

        for vuln in vulnerabilities:
            # 필수 정보만 추출하여 정제된 취약점 객체 생성
            cleaned_vuln = {
                "id": vuln.get("VulnerabilityID", ""),  # CVE ID
                "package_name": vuln.get("PkgName", ""),  # 패키지명
                "installed_version": vuln.get("InstalledVersion", ""),  # 설치 버전
                "package_type": package_type,  # 패키지 타입
                "severity": vuln.get("Severity", "UNKNOWN"),  # 심각도
                "title": vuln.get("Title", ""),  # 취약점 제목
                "description": vuln.get("Description", ""),  # 설명
                "fixed_version": vuln.get("FixedVersion", ""),  # 수정 버전
                "cvss": vuln.get("CVSS", {}),  # CVSS 점수
                "references": vuln.get("References", []),  # 참조 링크
                "primary_url": vuln.get("PrimaryURL", ""),  # 주 URL
                "data_source": vuln.get("DataSource", {})  # 데이터 소스
            }

            # 정제된 취약점을 목록에 추가
            cleaned_data["vulnerabilities"].append(cleaned_vuln)

            # 통계 정보 업데이트
            # 총 취약점 수 증가
            cleaned_data["vulnerability_summary"]["total_vulnerabilities"] += 1

            # 심각도별 통계 업데이트
            severity = cleaned_vuln["severity"]
            cleaned_data["vulnerability_summary"]["by_severity"][severity] = \
                cleaned_data["vulnerability_summary"]["by_severity"].get(severity, 0) + 1

            # 패키지 타입별 통계 업데이트
            cleaned_data["vulnerability_summary"]["by_package_type"][package_type] = \
                cleaned_data["vulnerability_summary"]["by_package_type"].get(package_type, 0) + 1

    # 정제된 결과를 동일한 파일에 덮어쓰기
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(cleaned_data, f, indent=2, ensure_ascii=False)


