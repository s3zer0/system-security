#!/usr/bin/env python3
"""CLI entrypoint that delegates to the shared pipeline engine."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Iterable, Optional

from dotenv import load_dotenv

from app.core.analysis_engine import PipelineConfig, run_pipeline

logger = logging.getLogger("pipeline.cli")


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser used to orchestrate the pipeline."""

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
    """CLI entrypoint: parse arguments and run the shared pipeline."""

    parser = build_parser()
    args = parser.parse_args(argv)

    load_dotenv()

    db_dir: Path = args.db_dir.resolve()
    sources_dir: Optional[Path] = args.sources_dir.resolve() if args.sources_dir else None

    perplexity_api_key = os.getenv("PERPLEXITY_API_KEY")
    enable_perplexity = bool(perplexity_api_key)

    config = PipelineConfig(
        image_path=args.image.resolve(),
        db_dir=db_dir,
        sources_dir=sources_dir,
        app_path=args.app_path,
        include_filter=args.include_filter,
        full_scan=not args.no_full_scan,
        enhance_trivy=args.enhance_trivy,
        run_security_analysis=args.run_security_analysis,
        emit_graph=args.emit_graph,
        force=args.force,
        enable_perplexity=enable_perplexity,
        perplexity_api_key=perplexity_api_key,
    )

    try:
        result = run_pipeline(config)
    except Exception as exc:  # pragma: no cover - defensive guard for CLI usage
        logger.error("Pipeline failed: %s", exc)
        return 1

    fetch_priority_path = result["artifacts"].get("fetch_priority")
    logger.info(
        "Pipeline completed successfully; final report at %s",
        fetch_priority_path,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
