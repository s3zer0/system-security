#!/usr/bin/env python3
"""
Python AST 시각화 도구 - 메인 진입점

사용법:
    python main.py <path> [옵션]

옵션:
    -o, --output <prefix>    출력 파일 이름 접두사 (기본값: callflow)
    -t, --target <api>       강조할 대상 API (예: yaml.load)
    --no-graph               그래프 생성을 건너뛰고 API 분석만 수행
    -j, --json               결과를 JSON 파일로 저장
    --security-analysis      LLM 기반 보안 분석을 활성화합니다.  # ← 추가
    --trivy-data <file>      Trivy 분석 결과 JSON 경로입니다.  # ← 추가

예시:
    python3 main.py ../DB/output/ -o ../DB/test_output --json --security-analysis --trivy-data ../DB/trivy_analysis_result.json
"""

import os
import argparse
import logging

from common import ASTResult, read_json, setup_logging, write_json

from utils import ast_to_png
from utils.security_analyzer import SecurityAnalyzer  # ← 추가

setup_logging(fmt='[%(levelname)s] %(message)s')


def load_trivy_data(trivy_file: str):
    """Trivy 분석 결과 로드"""
    try:
        return read_json(trivy_file)
    except Exception as e:
        logging.warning(f"Trivy 데이터 로드 실패: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Python code and generate call-graph diagram'
    )
    parser.add_argument('path', help='Path to Python file or folder')
    parser.add_argument('-o', '--output', default='callflow', 
                       help='Output prefix (default: callflow)')
    parser.add_argument('-t', '--target', action='append', default=[], 
                       help='Highlight target functions (e.g. yaml.load)')
    parser.add_argument('--no-graph', action='store_true',
                       help='Skip graph generation (only output API analysis)')
    parser.add_argument('-j', '--json', action='store_true',
                       help='Save results to JSON file')
    
    # ← 새로운 보안 분석 옵션 추가
    parser.add_argument('--security-analysis', action='store_true',
                       help='Enable LLM-based security analysis')
    parser.add_argument('--trivy-data', type=str,
                       help='Path to Trivy analysis result JSON')
    
    args = parser.parse_args()

    target_list = args.target
    force = len(target_list) == 0
    targets = ast_to_png.parse_target_calls(target_list)
    
    input_path = args.path
    if os.path.isdir(input_path):
        base = input_path.rstrip(os.sep)
        files = []
        for r, _, fns in os.walk(input_path):
            for fn in fns:
                if fn.endswith('.py'):
                    files.append(os.path.join(r, fn))
        logging.info(f"Collected {len(files)} Python files for analysis")
    else:
        base = os.path.dirname(input_path) or '.'
        files = [input_path]
        logging.info(f"Single file mode: {input_path}")

    external_apis, internal_only_apis, unused_apis = ast_to_png.visualize_call_flow(
        files, base, args.output, targets, force, args.no_graph
    )
    
    # 콘솔에 결과를 출력합니다.
    print("\nExternally exposed APIs:")
    for api in external_apis:
        print(f"  {api}")
    print("\nInternally only APIs:")
    for api in internal_only_apis:
        print(f"  {api}")
    print("\nUnused APIs:")
    for api in unused_apis:
        print(f"  {api}")
    
    # 요청 시 결과를 JSON으로 저장합니다.
    if args.json:
        result = ASTResult(
            external=external_apis,
            internal=internal_only_apis,
            unused=unused_apis,
        )
        json_filename = f"{args.output}_result.json"
        write_json(json_filename, result.to_dict())
        logging.info(f"Results saved to {json_filename}")
    
    # ← 새로운 보안 분석 실행
    if args.security_analysis:
        print("\n" + "=" * 80)
        print("🔐 보안 분석 시작 (LLM 기반)")
        print("=" * 80)
        
        try:
            # Trivy 데이터 로드 (있으면)
            trivy_data = None
            if args.trivy_data:
                trivy_data = load_trivy_data(args.trivy_data)
                if trivy_data:
                    logging.info(f"Trivy 데이터 로드 완료: {args.trivy_data}")
            
            # 보안 분석 실행
            analyzer = SecurityAnalyzer()
            analysis = analyzer.analyze_security_posture(
                external_apis=external_apis,
                internal_apis=internal_only_apis,
                unused_apis=unused_apis,
                vulnerability_data=trivy_data
            )
            
            # 리포트 생성 및 출력
            report = analyzer.generate_report(
                analysis,
                output_file=f"{args.output}_security_report.txt"
            )
            print(report)
            
            # JSON 저장
            security_json = f"{args.output}_security_analysis.json"
            write_json(security_json, analysis)
            logging.info(f"보안 분석 JSON 저장: {security_json}")
            
        except ValueError as e:
            logging.error(f"보안 분석 실패: {e}")
            logging.info("ANTHROPIC_API_KEY 환경변수를 설정하세요.")
        except Exception as e:
            logging.error(f"보안 분석 중 오류: {e}", exc_info=True)


if __name__ == '__main__':
    main()
