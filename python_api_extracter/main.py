#!/usr/bin/env python3
"""Trivy JSON 보고서에서 CVE와 API 매핑을 생성하는 메인 스크립트"""

import argparse
import json
from typing import Dict, List

from extracter import api_extracter

def main():
    """프로그램의 메인 진입점"""
    # 명령줄 인자 파서 생성
    parser = argparse.ArgumentParser(
        description="Generate combined CVE and API mapping from Trivy JSON report."
    )
    parser.add_argument(
        "report",
        help="Path to the Trivy JSON report file"
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to save the generated mapping file (JSON format)",
        metavar="FILE"
    )
    args = parser.parse_args()

    # Trivy JSON 보고서 파일 읽기
    with open(args.report, encoding="utf-8") as f:
        data = json.load(f)

    # CVE와 API 매핑 생성 (라이브러리 -> CVE -> 패키지 -> API 리스트)
    combined: Dict[str, Dict[str, Dict[str, List[str]]]] = api_extracter.build_cve_api_mapping(data)

    # 결과를 JSON 문자열로 변환
    output_str = json.dumps(combined, indent=2, ensure_ascii=False)

    # 출력 옵션에 따라 파일 저장 또는 콘솔 출력
    if args.output:
        # 파일로 저장
        with open(args.output, 'w', encoding='utf-8') as out_f:
            out_f.write(output_str)
    else:
        # 콘솔에 출력
        print(output_str)

if __name__ == "__main__":
    main()

# Usage:
# python3 main.py ../DB/trivy_analysis_result.json -o ../DB/lib2cve2api.json