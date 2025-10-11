"""
Trivy 취약점 스캐너 메인 스크립트
컨테이너 이미지의 취약점을 스캔하고 JSON 보고서를 생성합니다.
"""

import argparse
import json

from trivy_module import trivy_func
from trivy_module.description_enhancer import DescriptionEnhancer  # ← 추가


def enhance_descriptions(input_file: str, output_file: str):
    """
    Trivy 결과에 향상된 설명 추가
    
    Args:
        input_file: 원본 Trivy JSON
        output_file: 향상된 결과를 저장할 파일
    """
    print(f"\n[+] 취약점 설명 향상 시작: {input_file}")
    
    # 원본 데이터 로드
    with open(input_file, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)
    
    # 설명 향상
    enhancer = DescriptionEnhancer()
    enhanced_data = enhancer.enhance_all_vulnerabilities(trivy_data)
    
    # 향상된 데이터 저장
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
    
    print(f"[✓] 향상된 데이터 저장: {output_file}")
    
    # 읽기 쉬운 리포트 생성
    report_file = output_file.replace('.json', '_report.txt')
    enhancer.generate_readable_report(enhanced_data, report_file)
    
    print(f"[✓] 리포트 생성 완료!")
    print(f"    JSON: {output_file}")
    print(f"    TXT:  {report_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trivy를 사용해 컨테이너 취약점을 스캔하고 보고서를 생성합니다.")

    parser.add_argument("input", help="이미지 tar/zip 파일 경로")
    parser.add_argument("output", help="JSON 보고서를 저장할 경로")
    parser.add_argument("--no-full-scan", action="store_true", help="전체 스캔을 비활성화합니다.")
    parser.add_argument("--enhance", action="store_true",  # ← 추가
                       help="LLM을 사용해 취약점 설명을 향상합니다.")

    args = parser.parse_args()

    # Trivy 취약점 스캔 실행
    trivy_func.scan_vulnerabilities(args.input, args.output, full_scan=not args.no_full_scan)
    
    # ← 향상된 설명 생성 (옵션)
    if args.enhance:
        enhanced_output = args.output.replace('.json', '_enhanced.json')
        try:
            enhance_descriptions(args.output, enhanced_output)
        except ValueError as e:
            print(f"[!] 설명 향상 실패: {e}")
            print("[!] ANTHROPIC_API_KEY 환경변수를 설정하세요.")
        except Exception as e:
            print(f"[!] 오류: {e}")

# 사용 예시:
# python3 main.py ../test_target/pyyaml-vuln.tar ../DB/trivy_analysis_result.json --enhance
