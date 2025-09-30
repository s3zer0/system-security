#!/usr/bin/env python3
import argparse
import json
from typing import Dict, List

from extracter import api_extracter

def main():
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

    with open(args.report, encoding="utf-8") as f:
        data = json.load(f)

    # 단일 호출로 매핑 생성
    combined: Dict[str, Dict[str, Dict[str, List[str]]]] = api_extracter.build_cve_api_mapping(data)

    output_str = json.dumps(combined, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as out_f:
            out_f.write(output_str)
    else:
        print(output_str)

if __name__ == "__main__":
    main()

# Usage:
# python3 main.py ../DB/trivy_analysis_result.json -o ../DB/lib2cve2api.json