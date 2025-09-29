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
    cmd = [
        "trivy", "image",
        "--input", input_archive,
        "--format", "json",
        "--output", output_file,
        "--scanners", "vuln",
        "--vuln-type", "library",
        "--no-progress",
    ]

    if full_scan:
        cmd += ["--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"]
    else:
        cmd += ["--severity", "HIGH,CRITICAL"]

    subprocess.run(cmd, check=True)

    clean_scan_results(output_file)


def clean_scan_results(output_file: str):
    """
    Trivy 스캔 결과에서 불필요한 정보를 제거하고 필수 정보만 남김
    """
    with open(output_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 정제된 결과 생성
    cleaned_data = {
        "scan_info": {
            "target": data.get("ArtifactName", ""),
            "scan_date": data.get("CreatedAt", ""),
            "os_info": data.get("Metadata", {}).get("OS", {})
        },
        "vulnerability_summary": {
            "total_vulnerabilities": 0,
            "by_severity": {},
            "by_package_type": {}
        },
        "vulnerabilities": []
    }

    # 취약점 정보 정제 (python-pkg만)
    for result in data.get("Results", []):
        package_type = result.get("Type", "unknown")

        # python-pkg가 아닌 경우 건너뛰기
        if package_type != "python-pkg":
            continue

        vulnerabilities = result.get("Vulnerabilities", [])

        for vuln in vulnerabilities:
            cleaned_vuln = {
                "id": vuln.get("VulnerabilityID", ""),
                "package": {
                    "name": vuln.get("PkgName", ""),
                    "version": vuln.get("InstalledVersion", ""),
                    "type": package_type
                },
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "published_date": vuln.get("PublishedDate", ""),
                "cvss": vuln.get("CVSS", {})
            }

            cleaned_data["vulnerabilities"].append(cleaned_vuln)

            # 통계 업데이트
            cleaned_data["vulnerability_summary"]["total_vulnerabilities"] += 1

            severity = cleaned_vuln["severity"]
            cleaned_data["vulnerability_summary"]["by_severity"][severity] = \
                cleaned_data["vulnerability_summary"]["by_severity"].get(severity, 0) + 1

            cleaned_data["vulnerability_summary"]["by_package_type"][package_type] = \
                cleaned_data["vulnerability_summary"]["by_package_type"].get(package_type, 0) + 1

    # 정제된 결과 저장
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(cleaned_data, f, indent=2, ensure_ascii=False)


