#!/usr/bin/env python3
"""엔드투엔드 보안 파이프라인 오케스트레이터.

이 스크립트는 보안 분석 워크플로를 구성하는 각 모듈을 다음 순서로
연결합니다:

1. 컨테이너 이미지 타르볼에서 애플리케이션 소스를 추출합니다.
2. Trivy 취약점 스캔을 실행합니다.
3. 라이브러리  ->  CVE  ->  API 매핑을 생성합니다.
4. 추출된 소스에 대해 AST 분석을 수행합니다.
5. GPT-5 모델로 CVE와 API를 연결합니다.
6. 패치 우선순위를 계산하고 ``fetch_priority.json`` 을 생성합니다.

각 단계는 예상 산출물이 이미 존재하고 ``--force`` 가 제공되지 않는 한
자동으로 건너뜁니다. 경로는 프로젝트 README에 설명된 기본 레이아웃을
기본값으로 사용하지만 CLI 플래그로 재정의할 수 있습니다.
"""

from __future__ import annotations

from dataclasses import dataclass

import argparse
import logging
import os
import shutil
import sys
from dotenv import load_dotenv
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from common import ASTResult, ensure_dir, read_json, setup_logging, write_json
from search_source.modules.extractor import extract_app_layer
from trivy_extracter.trivy_module import trivy_func
from python_api_extracter.extracter import api_extracter
from ast_visualizer.utils import ast_to_png

setup_logging(level=logging.INFO, fmt="[%(levelname)s] %(message)s")
logger = logging.getLogger("pipeline")


@dataclass
class PipelineContext:
    image_tar: Path
    sources_dir: Path
    app_path: Optional[str]
    include_filter: Optional[str]
    auto_detect: bool
    force: bool


# --------------------------------------------------------------------------- #
# 유틸리티 도우미
# --------------------------------------------------------------------------- #


def path_exists_and_non_empty(path: Path) -> bool:
    """경로가 존재하고 (디렉터리의 경우) 비어 있지 않거나 파일이 존재하면 True를 반환합니다."""
    # 디렉터리는 최소 하나 이상의 항목을 포함해야 실질적인 산출물이 있다고 판단한다.
    if path.is_dir():
        return any(path.iterdir())
    # 일반 파일은 존재 여부만 확인해도 충분하다.
    return path.exists()


def collect_python_files(root: Path) -> List[Path]:
    """``root`` 경로 아래의 모든 Python 파일을 재귀적으로 수집합니다."""
    # rglob를 사용해 하위 디렉터리까지 모두 훑어서 분석 대상 목록을 구성한다.
    return [path for path in root.rglob("*.py") if path.is_file()]


# --------------------------------------------------------------------------- #
# 파이프라인 단계
# --------------------------------------------------------------------------- #


def step_source_extraction(ctx: PipelineContext) -> None:
    """컨테이너 이미지에서 애플리케이션 소스를 추출합니다."""
    # 이미 추출된 산출물이 있고 강제 재실행 옵션이 없으면 시간을 절약하기 위해 건너뛴다.
    if ctx.sources_dir.exists() and not ctx.force:
        logger.info(f"Skipping: {ctx.sources_dir} exists")
        return

    # 추출기는 tarball 구조와 필터를 참고해 애플리케이션 레이어만 복사한다.
    extract_app_layer(
        image_tar_path=str(ctx.image_tar),
        output_dir=str(ctx.sources_dir),
        app_path=ctx.app_path,
        auto_detect=ctx.auto_detect,
        include_filter=ctx.include_filter,
    )


def step_trivy_scan(
    image_tar: Path,
    trivy_output: Path,
    full_scan: bool,
    enhance: bool,
    force: bool,
) -> None:
    """컨테이너 이미지 타르볼을 대상으로 Trivy 스캔을 실행합니다."""
    # 기존 스캔 결과가 있고 --force가 없으면 비용이 큰 스캔을 반복하지 않는다.
    if trivy_output.exists() and not force:
        logger.info("Skipping Trivy scan: %s already exists", trivy_output)
        return

    # 결과 파일을 안전하게 쓰기 위해 출력 디렉터리를 보장한다.
    ensure_dir(trivy_output.parent)
    logger.info("Running Trivy scan (full_scan=%s)  ->  %s", full_scan, trivy_output)
    # Trivy CLI 래퍼를 호출해 취약점 보고서를 JSON 형태로 수집한다.
    trivy_func.scan_vulnerabilities(
        input_archive=str(image_tar),
        output_file=str(trivy_output),
        full_scan=full_scan,
    )

    if enhance:
        # 선택적 의존성을 필요로 하므로 지연 임포트를 사용한다.
        try:
            from trivy_extracter.main import enhance_descriptions
        except ImportError as exc:  # pragma: no cover - 선택적 의존성
            logger.warning("Unable to import enhance_descriptions: %s", exc)
            return

        enhanced_output = trivy_output.with_name(
            trivy_output.stem + "_enhanced.json"
        )
        logger.info("Enhancing Trivy descriptions  ->  %s", enhanced_output)
        # LLM을 활용해 취약점 설명을 보강하고 별도 산출물로 저장한다.
        enhance_descriptions(str(trivy_output), str(enhanced_output))


def step_python_api_mapping(
    trivy_output: Path,
    mapping_output: Path,
    force: bool,
) -> None:
    """Trivy 보고서를 기반으로 라이브러리 -> CVE -> API 매핑을 생성합니다."""
    # 기존 매핑이 있으면 불필요한 재계산을 방지한다.
    if mapping_output.exists() and not force:
        logger.info("Skipping API mapping: %s already exists", mapping_output)
        return

    logger.info("Building library -> CVE -> API mapping  ->  %s", mapping_output)
    # 취약점 데이터를 파싱해 라이브러리 단위 분석 결과를 구성한다.
    trivy_data = read_json(trivy_output)
    combined = api_extracter.build_cve_api_mapping(trivy_data)
    write_json(mapping_output, combined)


def step_ast_analysis(
    source_dir: Path,
    output_prefix: Path,
    trivy_output: Optional[Path],
    skip_graph: bool,
    run_security: bool,
    force: bool,
) -> Tuple[Path, Optional[Path]]:
    """추출된 소스 트리에 대해 AST 분석을 실행합니다."""
    json_output = output_prefix.with_name(output_prefix.name + "_result.json")
    security_json: Optional[Path] = output_prefix.with_name(
        output_prefix.name + "_security_analysis.json"
    )

    security_exists = security_json.exists()
    needs_security_rerun = run_security and not security_exists

    # 이전 결과가 남아 있고 강제 실행이나 보안 분석 요구가 없으면 그대로 재사용한다.
    if json_output.exists() and not force and not needs_security_rerun:
        logger.info("Skipping AST analysis: %s already exists", json_output)
        return json_output, security_json if security_exists else None

    if needs_security_rerun:
        logger.info(
            "Security analysis requested but missing; rerunning AST/security analysis."
        )

    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    # 분석 대상 Python 파일을 수집해 AST 시각화와 보안 평가 범위를 확정한다.
    py_files = collect_python_files(source_dir)
    if not py_files:
        raise RuntimeError(f"No Python files found under {source_dir}")

    logger.info(
        "Running AST analysis on %d files  ->  %s", len(py_files), json_output
    )

    base_dir = source_dir.resolve()
    targets = ast_to_png.parse_target_calls([])
    # AST 호출 흐름을 그려 외부/내부 API 그래프와 미사용 API 목록을 도출한다.
    external, internal, unused = ast_to_png.visualize_call_flow(
        [str(p) for p in py_files],
        str(base_dir),
        str(output_prefix),
        targets,
        force_detection=True,
        no_graph=skip_graph,
    )

    result = ASTResult(external=external, internal=internal, unused=unused)
    write_json(json_output, result.to_dict())

    security_output_path = None
    if run_security:
        # 보안 분석 컴포넌트는 선택적 의존성을 요구하므로 실패 시 경고만 남긴다.
        try:
            from ast_visualizer.utils.security_analyzer import SecurityAnalyzer
        except ImportError as exc:  # pragma: no cover - 선택적 의존성
            logger.warning("Security analysis disabled (missing dependency): %s", exc)
        else:
            trivy_data = read_json(trivy_output) if trivy_output else None
            analyzer = SecurityAnalyzer()
            analysis = analyzer.analyze_security_posture(
                external_apis=external,
                internal_apis=internal,
                unused_apis=unused,
                vulnerability_data=trivy_data,
            )
            write_json(security_json, analysis)
            security_output_path = security_json

    return json_output, security_output_path


def step_cve_api_mapper(
    trivy_output: Path,
    mapping_output: Path,
    results_dir: Path,
    raw_dir: Path,
    gpt5_output: Path,
    force: bool,
) -> None:
    """GPT-5 모델을 사용하여 CVE -> API 매퍼를 실행합니다."""
    # GPT-5 결과가 이미 준비되어 있으면 재호출을 피한다.
    if gpt5_output.exists() and not force:
        logger.info("Skipping CVE -> API mapping: %s already exists", gpt5_output)
        return

    results_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    try:
        from cve_api_mapper.mapper.cve_api_mapper import CveApiMapper
    except ImportError as exc:
        raise RuntimeError(
            "Failed to import CveApiMapper. Ensure all optional dependencies "
            "for cve_api_mapper are installed."
        ) from exc

    logger.info("Running CVE -> API mapper (GPT-5)  ->  %s", gpt5_output)
    mapper = CveApiMapper(models_to_test=["gpt-5"])
    mapper.run_analysis(
        trivy_input_file=str(trivy_output),
        api_input_file=str(mapping_output),
        output_dir=str(results_dir),
        llm_raw_output_dir=str(raw_dir),
    )

    source_file = results_dir / "gpt-5_results.json"
    if not source_file.exists():
        raise FileNotFoundError(
            f"Expected GPT-5 results at {source_file}, but the mapper did not produce it."
        )

    shutil.copyfile(source_file, gpt5_output)


def step_fetch_priority(
    ast_json: Path,
    gpt5_json: Path,
    mapping_json: Path,
    trivy_json: Path,
    output_json: Path,
    force: bool,
    enable_perplexity: bool,
    perplexity_api_key: Optional[str],
) -> None:
    """패치 우선순위를 평가하고 ``fetch_priority.json`` 을 생성합니다."""
    # 산출물이 있으면 반복적인 비용을 줄이기 위해 건너뛴다.
    if output_json.exists() and not force:
        logger.info("Skipping fetch priority: %s already exists", output_json)
        return

    try:
        from fetch_priority.module import PatchPriorityEvaluator
    except ImportError as exc:
        raise RuntimeError("Failed to import PatchPriorityEvaluator.") from exc

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY is required for fetch_priority. Set it in the environment."
        )

    if enable_perplexity and not perplexity_api_key:
        logger.warning(
            "Perplexity search requested but no API key supplied; set PERPLEXITY_API_KEY before running."
        )

    ensure_dir(output_json.parent)
    logger.info("Evaluating patch priorities  ->  %s", output_json)
    evaluator = PatchPriorityEvaluator(
        api_key=api_key,
        perplexity_api_key=perplexity_api_key,
        enable_perplexity=enable_perplexity,
    )
    # 여러 분석 산출물을 통합하여 취약점 대응 순위를 계산한다.
    evaluator.run_analysis(
        ast_file=str(ast_json),
        gpt5_results_file=str(gpt5_json),
        lib2cve2api_file=str(mapping_json),
        trivy_file=str(trivy_json),
        output_file=str(output_json),
    )


# --------------------------------------------------------------------------- #
# CLI 명령행
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    """파이프라인 전체를 제어하는 CLI 파서를 구성합니다."""
    parser = argparse.ArgumentParser(
        description="Run the full system-security analysis pipeline."
    )
    parser.add_argument(
        "--image",
        required=True,
        type=Path,
        help="Container image tarball to analyse (e.g. test_target/pyyaml-vuln.tar).",
    )
    parser.add_argument(
        "--db-dir",
        type=Path,
        default=Path("DB"),
        help="Directory used to store intermediate and final artefacts (default: ./DB).",
    )
    parser.add_argument(
        "--sources-dir",
        type=Path,
        help="Directory to place extracted sources (default: <db-dir>/output).",
    )
    parser.add_argument(
        "--app-path",
        help="Explicit application path inside the image (disables auto-detection).",
    )
    parser.add_argument(
        "--include-filter",
        help="Copy only files matching the given extension during extraction (e.g. .py).",
    )
    parser.add_argument(
        "--no-full-scan",
        action="store_true",
        help="Limit Trivy scan severity to HIGH/CRITICAL instead of all severities.",
    )
    parser.add_argument(
        "--enhance-trivy",
        action="store_true",
        help="Use the LLM-based enhancer to enrich Trivy findings (requires Anthropic).",
    )
    parser.add_argument(
        "--run-security-analysis",
        action="store_true",
        help="Run the AST security analysis step (requires Anthropic).",
    )
    parser.add_argument(
        "--emit-graph",
        action="store_true",
        help="Generate Graphviz diagrams during AST analysis (requires graphviz).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run all steps even if artefacts already exist.",
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI 진입점: 각 하위 모듈을 순차적으로 호출해 파이프라인을 실행합니다."""
    parser = build_parser()
    args = parser.parse_args(argv)

    load_dotenv()

    # 데이터베이스 디렉터리와 산출물 경로를 절대 경로로 정규화한다.
    db_dir: Path = args.db_dir.resolve()
    sources_dir: Path = (
        args.sources_dir.resolve()
        if args.sources_dir
        else (db_dir / "output").resolve()
    )

    trivy_output = (db_dir / "trivy_analysis_result.json").resolve()
    mapping_output = (db_dir / "lib2cve2api.json").resolve()
    ast_output_prefix = (db_dir / "ast_visualize").resolve()
    gpt5_output = (db_dir / "gpt5_results.json").resolve()
    fetch_priority_output = (db_dir / "fetch_priority.json").resolve()

    results_dir = (db_dir / "cve_api_mapper_results").resolve()
    raw_dir = (db_dir / "cve_api_mapper_raw").resolve()

    perplexity_api_key = os.getenv("PERPLEXITY_API_KEY")
    enable_perplexity = bool(perplexity_api_key)
    if enable_perplexity:
        logger.info("Perplexity case search enabled using PERPLEXITY_API_KEY.")
    else:
        logger.info("Perplexity case search disabled (set PERPLEXITY_API_KEY to enable).")

    ctx = PipelineContext(
        image_tar=args.image.resolve(),
        sources_dir=sources_dir,
        app_path=args.app_path,
        include_filter=args.include_filter,
        auto_detect=args.app_path is None,
        force=args.force,
    )

    try:
        # 컨테이너에서 소스를 꺼낸 뒤 이하 단계에서 해당 산출물을 공유한다.
        step_source_extraction(ctx)

        step_trivy_scan(
            image_tar=args.image.resolve(),
            trivy_output=trivy_output,
            full_scan=not args.no_full_scan,
            enhance=args.enhance_trivy,
            force=args.force,
        )

        step_python_api_mapping(
            trivy_output=trivy_output,
            mapping_output=mapping_output,
            force=args.force,
        )

        step_ast_analysis(
            source_dir=sources_dir,
            output_prefix=ast_output_prefix,
            trivy_output=trivy_output if args.run_security_analysis else None,
            skip_graph=not args.emit_graph,
            run_security=args.run_security_analysis,
            force=args.force,
        )

        step_cve_api_mapper(
            trivy_output=trivy_output,
            mapping_output=mapping_output,
            results_dir=results_dir,
            raw_dir=raw_dir,
            gpt5_output=gpt5_output,
            force=args.force,
        )

        step_fetch_priority(
            ast_json=ast_output_prefix.with_name(
                ast_output_prefix.name + "_result.json"
            ),
            gpt5_json=gpt5_output,
            mapping_json=mapping_output,
            trivy_json=trivy_output,
            output_json=fetch_priority_output,
            force=args.force,
            enable_perplexity=enable_perplexity,
            perplexity_api_key=perplexity_api_key,
        )

    except Exception as exc:  # pragma: no cover - 최상위 가드
        logger.error("Pipeline failed: %s", exc)
        return 1

    logger.info(
        "Pipeline completed successfully; final report at %s",
        fetch_priority_output,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
