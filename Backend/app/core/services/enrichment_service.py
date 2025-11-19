"""Service for enriching analysis results with priority evaluation."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from common import ensure_dir, read_json, write_json

from ..exceptions import EnrichmentError, wrap_exception

logger = logging.getLogger("pipeline.enrichment")


class EnrichmentService:
    """Handles priority evaluation and enrichment of analysis results."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        perplexity_api_key: Optional[str] = None,
        enable_perplexity: bool = False,
    ):
        """
        Initialize enrichment service.

        Args:
            api_key: Anthropic API key for AI analysis
            perplexity_api_key: Perplexity API key for case search
            enable_perplexity: Whether to enable Perplexity search
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.perplexity_api_key = perplexity_api_key or os.getenv("PERPLEXITY_API_KEY")
        self.enable_perplexity = enable_perplexity or bool(self.perplexity_api_key)

    def evaluate_patch_priorities(
        self,
        *,
        ast_json: Path,
        gpt5_json: Path,
        mapping_json: Path,
        trivy_json: Path,
        output_json: Path,
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate patch priorities and emit fetch_priority.json.

        This is a NON-CRITICAL operation. Failures are logged and None is returned,
        allowing the pipeline to continue gracefully.

        Args:
            ast_json: Path to AST analysis results
            gpt5_json: Path to GPT-5 CVE-API mapping results
            mapping_json: Path to library CVE API mapping
            trivy_json: Path to Trivy scan results
            output_json: Path to write priority evaluation results
            force: Force re-evaluation even if results exist

        Returns:
            Dict containing priority data on success, None if enrichment is skipped or fails.

        Raises:
            EnrichmentError: Only raised if explicitly requested via force parameter,
                           otherwise errors are caught and logged.
        """
        # If output exists and we're not forcing, try to load it
        if output_json.exists() and not force:
            logger.info("Skipping fetch priority: %s already exists", output_json)
            existing_data = self._read_json_if_exists(output_json)
            return existing_data if existing_data else {}

        # Check for API key early - soft dependency
        if not self.api_key:
            logger.warning(
                "Skipping AI priority analysis: ANTHROPIC_API_KEY not set. "
                "Pipeline will continue with scanner and AST data only."
            )
            self._write_skipped_priority_file(
                output_json, "ANTHROPIC_API_KEY not set - AI analysis disabled"
            )
            return None

        # Wrap entire logic in try/except to handle API failures gracefully
        try:
            # Validate input files exist
            missing_files = []
            for name, path in [
                ("AST", ast_json),
                ("GPT-5 results", gpt5_json),
                ("Library mapping", mapping_json),
                ("Trivy results", trivy_json),
            ]:
                if not path.exists():
                    missing_files.append(f"{name}: {path}")

            if missing_files:
                error_msg = f"Required input files missing: {', '.join(missing_files)}"
                logger.warning("%s. Skipping enrichment.", error_msg)
                self._write_skipped_priority_file(output_json, error_msg)
                return None

            try:
                from fetch_priority.module import PatchPriorityEvaluator
            except ImportError as exc:
                logger.warning(
                    "Skipping AI priority analysis: Failed to import PatchPriorityEvaluator (%s). "
                    "Pipeline will continue with scanner and AST data only.",
                    exc,
                )
                self._write_skipped_priority_file(
                    output_json, f"Failed to import PatchPriorityEvaluator: {exc}"
                )
                return None

            if self.enable_perplexity and not self.perplexity_api_key:
                logger.warning(
                    "Perplexity search requested but no API key supplied; "
                    "set PERPLEXITY_API_KEY before running."
                )

            ensure_dir(output_json.parent)
            logger.info("Evaluating patch priorities -> %s", output_json)

            evaluator = PatchPriorityEvaluator(
                api_key=self.api_key,
                perplexity_api_key=self.perplexity_api_key,
                enable_perplexity=self.enable_perplexity,
            )
            evaluator.run_analysis(
                ast_file=str(ast_json),
                gpt5_results_file=str(gpt5_json),
                lib2cve2api_file=str(mapping_json),
                trivy_file=str(trivy_json),
                output_file=str(output_json),
            )

            # Verify output was created
            if not output_json.exists():
                logger.warning(
                    "Priority evaluation completed but output file was not created: %s",
                    output_json
                )
                self._write_skipped_priority_file(
                    output_json, "Evaluation completed but no output produced"
                )
                return None

            # Load and return the result
            result_data = self._read_json_if_exists(output_json)
            if result_data:
                logger.info("Successfully completed priority evaluation")
                return result_data

            logger.warning("Priority evaluation file exists but is empty")
            return {}

        except Exception as exc:
            # EnrichmentError is NON-CRITICAL - log and continue
            logger.error(
                "AI priority analysis failed: %s: %s. "
                "Pipeline will continue with scanner and AST data only.",
                type(exc).__name__,
                str(exc),
            )
            self._write_skipped_priority_file(
                output_json, f"AI analysis failed: {type(exc).__name__}: {str(exc)}"
            )
            return None

    def _write_skipped_priority_file(self, output_json: Path, reason: str) -> None:
        """Write a placeholder JSON file when AI priority analysis is skipped."""
        ensure_dir(output_json.parent)
        skipped_data = {
            "skipped": True,
            "reason": reason,
            "modules_by_priority": [],
        }
        write_json(output_json, skipped_data)
        logger.info("Written skipped priority file: %s", output_json)

    def _read_json_if_exists(self, path: Path) -> Optional[Any]:
        """Read JSON file if it exists."""
        if not path.exists():
            return None

        try:
            return read_json(path)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.warning("Failed to read %s: %s", path, exc)
            return None
