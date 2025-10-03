"""
Trivy 취약점 스캐너 메인 스크립트
컨테이너 이미지의 취약점을 스캔하고 JSON 보고서를 생성합니다.
"""

import argparse

from trivy_module import trivy_func

if __name__ == "__main__":
    # 명령줄 인자 파서 생성
    parser = argparse.ArgumentParser(description="Tool to scan container vulnerabilities using Trivy")

    # 필수 인자 정의
    parser.add_argument("input", help="Path to image tar/zip file")  # 입력 파일 경로
    parser.add_argument("output", help="Path to save JSON report")  # 출력 JSON 파일 경로

    # 선택적 인자 정의
    parser.add_argument("--no-full-scan", action="store_true", help="Disable full scan")  # 전체 스캔 비활성화 옵션

    # 명령줄 인자 파싱
    args = parser.parse_args()

    # Trivy 취약점 스캔 실행
    # full_scan 파라미터는 --no-full-scan 플래그의 반대값
    trivy_func.scan_vulnerabilities(args.input, args.output, full_scan=not args.no_full_scan)

# python3 main.py ../test_target/pyyaml-vuln.tar ../DB/trivy_analysis_result.json