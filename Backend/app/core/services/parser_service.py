"""Service for parsing and mapping CVE/API data."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from common import ensure_dir, read_json, write_json
from python_api_extracter.extracter import api_extracter

logger = logging.getLogger("pipeline.parser")


class ParserService:
    """Handles parsing of Trivy output and CVE/API mapping."""

    def build_library_cve_api_mapping(
        self,
        *,
        trivy_output: Path,
        mapping_output: Path,
        force: bool = False,
    ) -> None:
        """
        Build the library -> CVE -> API mapping from Trivy output.

        Args:
            trivy_output: Path to Trivy scan results
            mapping_output: Path to write mapping results
            force: Force regeneration even if mapping exists
        """
        if mapping_output.exists() and not force:
            logger.info("Skipping API mapping: %s already exists", mapping_output)
            return

        logger.info("Building library -> CVE -> API mapping -> %s", mapping_output)
        trivy_data = read_json(trivy_output)
        combined = api_extracter.build_cve_api_mapping(trivy_data)
        write_json(mapping_output, combined)

    def run_cve_api_mapper(
        self,
        *,
        trivy_output: Path,
        mapping_output: Path,
        results_dir: Path,
        raw_dir: Path,
        gpt5_output: Path,
        force: bool = False,
    ) -> None:
        """
        Run the GPT-5 powered CVE -> API mapping job.

        Args:
            trivy_output: Path to Trivy scan results
            mapping_output: Path to library CVE API mapping
            results_dir: Directory to store mapper results
            raw_dir: Directory to store raw LLM outputs
            gpt5_output: Path to write final GPT-5 results
            force: Force regeneration even if results exist
        """
        if gpt5_output.exists() and not force:
            logger.info("Skipping CVE -> API mapping: %s already exists", gpt5_output)
            return

        results_dir.mkdir(parents=True, exist_ok=True)
        raw_dir.mkdir(parents=True, exist_ok=True)

        try:
            from cve_api_mapper.mapper.cve_api_mapper import CveApiMapper
        except ImportError as exc:
            raise RuntimeError(
                "Failed to import CveApiMapper. Ensure optional dependencies are installed."
            ) from exc

        logger.info("Running CVE -> API mapper (GPT-5) -> %s", gpt5_output)
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
