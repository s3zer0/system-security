#!/usr/bin/env python3
"""End-to-end security pipeline orchestrator.

This script stitches together the individual modules that make up the security
analysis workflow:

1. Extract application sources from a container image tarball.
2. Run a Trivy vulnerability scan.
3. Build a library  ->  CVE  ->  API mapping.
4. Perform AST analysis of the extracted sources.
5. Map CVEs to APIs with the GPT-5 model.
6. Compute patch priorities and emit ``fetch_priority.json``.

Each step is skipped automatically when its expected output already exists
unless ``--force`` is supplied. Paths default to the layout described in the
project README, but can be overridden via CLI flags.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from search_source.modules.extractor import extract_app_layer
from trivy_extracter.trivy_module import trivy_func
from python_api_extracter.extracter import api_extracter
from ast_visualizer.utils import ast_to_png

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("pipeline")


# --------------------------------------------------------------------------- #
# Utility helpers
# --------------------------------------------------------------------------- #

def path_exists_and_non_empty(path: Path) -> bool:
    """Return True if the path exists and is not empty (for dirs) or file exists."""
    if path.is_dir():
        return any(path.iterdir())
    return path.exists()


def ensure_parent_dir(path: Path) -> None:
    """Ensure that the parent directory for ``path`` exists."""
    path.parent.mkdir(parents=True, exist_ok=True)


def collect_python_files(root: Path) -> List[Path]:
    """Recursively collect Python files under ``root``."""
    return [path for path in root.rglob("*.py") if path.is_file()]


def read_json(path: Path) -> dict:
    """Read a JSON document from ``path``."""
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: dict) -> None:
    """Write ``data`` as JSON to ``path``."""
    ensure_parent_dir(path)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Pipeline steps
# --------------------------------------------------------------------------- #

def step_source_extraction(
    image_tar: Path,
    output_dir: Path,
    app_path: Optional[str],
    include_filter: Optional[str],
    force: bool,
) -> None:
    """Extract application sources from the container image tarball."""
    if path_exists_and_non_empty(output_dir) and not force:
        logger.info("Skipping source extraction: %s already populated", output_dir)
        return

    if output_dir.exists() and force:
        logger.info("Clearing existing source output: %s", output_dir)
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    auto_detect = app_path is None
    logger.info("Extracting sources (auto_detect=%s)  ->  %s", auto_detect, output_dir)
    extract_app_layer(
        image_tar_path=str(image_tar),
        output_dir=str(output_dir),
        app_path=app_path,
        auto_detect=auto_detect,
        include_filter=include_filter,
    )


def step_trivy_scan(
    image_tar: Path,
    trivy_output: Path,
    full_scan: bool,
    enhance: bool,
    force: bool,
) -> None:
    """Run Trivy against the container image tarball."""
    if trivy_output.exists() and not force:
        logger.info("Skipping Trivy scan: %s already exists", trivy_output)
        return

    ensure_parent_dir(trivy_output)
    logger.info("Running Trivy scan (full_scan=%s)  ->  %s", full_scan, trivy_output)
    trivy_func.scan_vulnerabilities(
        input_archive=str(image_tar),
        output_file=str(trivy_output),
        full_scan=full_scan,
    )

    if enhance:
        try:
            from trivy_extracter.main import enhance_descriptions  # lazy import
        except ImportError as exc:  # pragma: no cover - optional dependency
            logger.warning("Unable to import enhance_descriptions: %s", exc)
            return

        enhanced_output = trivy_output.with_name(
            trivy_output.stem + "_enhanced.json"
        )
        logger.info("Enhancing Trivy descriptions  ->  %s", enhanced_output)
        enhance_descriptions(str(trivy_output), str(enhanced_output))


def step_python_api_mapping(
    trivy_output: Path,
    mapping_output: Path,
    force: bool,
) -> None:
    """Generate the library -> CVE -> API mapping from the Trivy report."""
    if mapping_output.exists() and not force:
        logger.info("Skipping API mapping: %s already exists", mapping_output)
        return

    logger.info("Building library -> CVE -> API mapping  ->  %s", mapping_output)
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
    """Run AST analysis against the extracted source tree."""
    json_output = output_prefix.with_name(output_prefix.name + "_result.json")
    security_json: Optional[Path] = output_prefix.with_name(
        output_prefix.name + "_security_analysis.json"
    )

    if json_output.exists() and not force:
        logger.info("Skipping AST analysis: %s already exists", json_output)
        if run_security and security_json and not security_json.exists():
            logger.info("Security analysis requested but missing; rerunning analysis.")
        else:
            return json_output, security_json if security_json.exists() else None

    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    py_files = collect_python_files(source_dir)
    if not py_files:
        raise RuntimeError(f"No Python files found under {source_dir}")

    logger.info(
        "Running AST analysis on %d files  ->  %s", len(py_files), json_output
    )

    base_dir = source_dir.resolve()
    targets = ast_to_png.parse_target_calls([])
    external, internal, unused = ast_to_png.visualize_call_flow(
        [str(p) for p in py_files],
        str(base_dir),
        str(output_prefix),
        targets,
        force_detection=True,
        no_graph=skip_graph,
    )

    result = {
        "external": external,
        "internal": internal,
        "unused": unused,
    }
    write_json(json_output, result)

    security_output_path = None
    if run_security:
        try:
            from ast_visualizer.utils.security_analyzer import SecurityAnalyzer
        except ImportError as exc:  # pragma: no cover - optional dependency
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
    """Run the CVE -> API mapper using the GPT-5 model."""
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
) -> None:
    """Evaluate patch priorities and emit fetch_priority.json."""
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

    ensure_parent_dir(output_json)
    logger.info("Evaluating patch priorities  ->  %s", output_json)
    evaluator = PatchPriorityEvaluator(api_key=api_key)
    evaluator.run_analysis(
        ast_file=str(ast_json),
        gpt5_results_file=str(gpt5_json),
        lib2cve2api_file=str(mapping_json),
        trivy_file=str(trivy_json),
        output_file=str(output_json),
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
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
    parser = build_parser()
    args = parser.parse_args(argv)

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

    try:
        step_source_extraction(
            image_tar=args.image.resolve(),
            output_dir=sources_dir,
            app_path=args.app_path,
            include_filter=args.include_filter,
            force=args.force,
        )

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
            ast_json=ast_output_prefix.with_name(ast_output_prefix.name + "_result.json"),
            gpt5_json=gpt5_output,
            mapping_json=mapping_output,
            trivy_json=trivy_output,
            output_json=fetch_priority_output,
            force=args.force,
        )

    except Exception as exc:  # pragma: no cover - top-level guard
        logger.error("Pipeline failed: %s", exc)
        return 1

    logger.info("Pipeline completed successfully; final report at %s", fetch_priority_output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
