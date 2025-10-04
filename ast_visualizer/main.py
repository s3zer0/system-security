#!/usr/bin/env python3
"""
Python AST 시각화 도구 - 모듈화 버전

Python 코드를 분석하고, call-graph 다이어그램을 생성하며,
API 사용에 대해 보고하는 명령행 도구입니다. gpt5_results.json에서 CVE 결과도 처리할 수 있습니다.

요구사항:
- Python 3.6+
- Graphviz (명령행): https://graphviz.org/
- pip install graphviz

사용법:
    python main.py <경로> [옵션]
    python main.py --gpt5-results <gpt5_results.json> [옵션]

옵션:
    -o, --output <접두사>    출력 파일명 접두사 (기본값: callflow)
    -t, --target <api>       강조할 대상 API (예: yaml.load)
    --no-graph               그래프 생성 건너뛰기 (API 분석만 출력)
    -j, --json               결과를 JSON 파일로 저장
    --gpt5-results <파일>    gpt5_results.json에서 CVE 결과 처리

예시:
    python main.py ./src -t yaml.load -t requests.get -o api_graph
    python main.py ./src -t yaml.load -o output --json
    python main.py ./src -t yaml.load --no-graph --json
    python main.py --gpt5-results DB/gpt5_results.json -o cve_analysis --json
"""

import argparse
import logging

from modules.analyzer import analyze_code
from modules.cve_processor import process_gpt5_results

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def main():
    """AST 시각화 도구의 메인 진입점"""
    parser = argparse.ArgumentParser(
        description='Python 코드를 분석하고 call-graph 다이어그램 생성, 또는 CVE 결과 처리'
    )
    parser.add_argument('path', nargs='?', help='Python 파일 또는 폴더 경로')
    parser.add_argument('-o', '--output', default='callflow',
                       help='출력 접두사 (기본값: callflow)')
    parser.add_argument('-t', '--target', action='append', default=[],
                       help='강조할 대상 함수 (예: yaml.load)')
    parser.add_argument('--no-graph', action='store_true',
                       help='그래프 생성 건너뛰기 (API 분석만 출력)')
    parser.add_argument('-j', '--json', action='store_true',
                       help='결과를 JSON 파일로 저장')
    parser.add_argument('--gpt5-results', metavar='FILE',
                       help='gpt5_results.json 파일에서 CVE 결과 처리')
    args = parser.parse_args()

    # GPT5 결과 처리
    if args.gpt5_results:
        return process_gpt5_results(args.gpt5_results, args.output, args.json, args.no_graph)

    # 일반 모드에서 path 인수 유효성 검사
    if not args.path:
        parser.error("--gpt5-results를 사용하지 않을 때는 path 인수가 필요합니다")

    # Python 코드 분석
    return analyze_code(args.path, args.output, args.target, args.json, args.no_graph)


if __name__ == '__main__':
    main()