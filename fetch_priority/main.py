#!/usr/bin/env python3
"""패치 우선순위 평가기의 CLI 진입점입니다."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Dict

try:
    from .module.evaluator import PatchPriorityEvaluator
except ImportError:  # pragma: no cover - 스크립트 직접 실행 대비 폴백
    from module.evaluator import PatchPriorityEvaluator  # type: ignore

REQUIRED_FILES: Dict[str, str] = {
    "ast_file": "ast_visualize_result.json",
    "gpt5_results_file": "gpt5_results.json",
    "lib2cve2api_file": "lib2cve2api.json",
    "trivy_file": "trivy_analysis_result.json",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AST, Trivy, CVE-API 데이터를 통합하여 패치 우선순위를 계산합니다.",
    )
    parser.add_argument(
        "data_dir",
        nargs="?",
        default="../DB",
        help="분석 산출물이 있는 디렉터리 (기본값: ../DB)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="생성된 patch_priorities.json을 저장할 경로",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-5-20250929",
        help="사용할 Anthropic 모델 식별자 (기본값: claude-sonnet-4-5-20250929)",
    )
    parser.add_argument(
        "--enable-perplexity",
        action="store_true",
        default=False,
        help="Perplexity API를 사용해 실제 사례 검색을 활성화합니다 (PERPLEXITY_API_KEY 필요)",
    )
    parser.add_argument(
        "--perplexity-api-key",
        help="Perplexity API 키 (환경 변수 PERPLEXITY_API_KEY 대체 입력)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir).resolve()
    missing = []
    file_paths = {}
    for key, filename in REQUIRED_FILES.items():
        path = data_dir / filename
        file_paths[key] = path
        if not path.exists():
            missing.append(path)

    if missing:
        print("오류: 필수 파일을 찾을 수 없습니다:")
        for path in missing:
            print(f"  - {path}")
        print("\n사용법: python3 -m fetch_priority [데이터_디렉토리]")
        print(f"현재 디렉토리: {data_dir}")
        return 1

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("오류: 환경 변수 ANTHROPIC_API_KEY가 설정되어 있지 않습니다")
        print(".env 파일에 ANTHROPIC_API_KEY=... 값을 설정하거나 환경 변수로 지정하세요.")
        return 1

    # Perplexity 설정 확인
    perplexity_key = args.perplexity_api_key or os.getenv("PERPLEXITY_API_KEY")
    if args.enable_perplexity and not perplexity_key:
        print("경고: --enable-perplexity가 지정되었지만 PERPLEXITY_API_KEY가 설정되지 않았습니다")
        print("실제 사례 검색이 비활성화됩니다.")
        print(".env 파일에 PERPLEXITY_API_KEY=... 값을 설정하거나 --perplexity-api-key 옵션을 사용하세요.")

    output_path = args.output.resolve() if args.output else data_dir / "patch_priorities.json"

    print(f"설정:")
    print(f"  - Claude 모델: {args.model}")
    print(f"  - Perplexity 검색: {'활성화' if args.enable_perplexity and perplexity_key else '비활성화'}")
    print(f"  - 출력 파일: {output_path}")
    print()

    evaluator = PatchPriorityEvaluator(
        api_key=api_key, 
        model=args.model,
        perplexity_api_key=perplexity_key,
        enable_perplexity=args.enable_perplexity
    )
    
    evaluator.run_analysis(
        ast_file=str(file_paths["ast_file"]),
        gpt5_results_file=str(file_paths["gpt5_results_file"]),
        lib2cve2api_file=str(file_paths["lib2cve2api_file"]),
        trivy_file=str(file_paths["trivy_file"]),
        output_file=str(output_path),
    )

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
