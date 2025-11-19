"""Service for parsing and mapping CVE/API data."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

from common import ensure_dir, read_json, write_json

from ..exceptions import ParserError, wrap_exception

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

        Raises:
            ParserError: If parsing or mapping fails
        """
        try:
            if mapping_output.exists() and not force:
                logger.info("Skipping API mapping: %s already exists", mapping_output)
                return

            # Validate input file exists
            if not trivy_output.exists():
                raise ParserError(
                    f"Trivy output file not found: {trivy_output}"
                )

            logger.info("Building library -> CVE -> API mapping -> %s", mapping_output)

            # Read and validate Trivy data
            try:
                trivy_data = read_json(trivy_output)
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON in Trivy output: %s", e)
                raise wrap_exception(
                    ParserError,
                    f"Trivy output file contains invalid JSON: {trivy_output}",
                    e
                )

            if not trivy_data:
                raise ParserError(
                    f"Trivy output file is empty or null: {trivy_output}"
                )

            # Import and run API extractor
            try:
                from python_api_extracter.extracter import api_extracter
            except ImportError as e:
                logger.error("Failed to import API extractor: %s", e)
                raise wrap_exception(
                    ParserError,
                    "API extractor module not available - ensure dependencies are installed",
                    e
                )

            combined = api_extracter.build_cve_api_mapping(trivy_data)

            # Write output
            write_json(mapping_output, combined)

            # Verify output was created
            if not mapping_output.exists():
                raise ParserError(
                    f"Mapping operation completed but output file was not created: {mapping_output}"
                )

            logger.info("Successfully built CVE API mapping: %s", mapping_output)

        except ParserError:
            # Re-raise our custom exceptions as-is
            raise

        except FileNotFoundError as e:
            logger.error("File not found during mapping: %s", e)
            raise wrap_exception(
                ParserError,
                f"Required file not found during CVE/API mapping: {e}",
                e
            )

        except Exception as e:
            # Catch-all for unexpected errors
            logger.error(
                "Unexpected error during CVE/API mapping: %s: %s",
                type(e).__name__, str(e)
            )
            raise wrap_exception(
                ParserError,
                f"Unexpected error during parsing: {type(e).__name__}",
                e
            )

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

        Raises:
            ParserError: If CVE API mapping fails
        """
        try:
            if gpt5_output.exists() and not force:
                logger.info("Skipping CVE -> API mapping: %s already exists", gpt5_output)
                return

            # Validate input files exist
            if not trivy_output.exists():
                raise ParserError(
                    f"Trivy output file not found: {trivy_output}"
                )

            if not mapping_output.exists():
                raise ParserError(
                    f"Library CVE API mapping file not found: {mapping_output}"
                )

            results_dir.mkdir(parents=True, exist_ok=True)
            raw_dir.mkdir(parents=True, exist_ok=True)

            # Import CVE API mapper
            try:
                from cve_api_mapper.mapper.cve_api_mapper import CveApiMapper
            except ImportError as exc:
                logger.error("Failed to import CveApiMapper: %s", exc)
                raise wrap_exception(
                    ParserError,
                    "CveApiMapper module not available - ensure optional dependencies are installed",
                    exc
                )

            logger.info("Running CVE -> API mapper (GPT-5) -> %s", gpt5_output)

            mapper = CveApiMapper(models_to_test=["gpt-5"])
            mapper.run_analysis(
                trivy_input_file=str(trivy_output),
                api_input_file=str(mapping_output),
                output_dir=str(results_dir),
                llm_raw_output_dir=str(raw_dir),
            )

            # Verify mapper produced expected output
            source_file = results_dir / "gpt-5_results.json"
            if not source_file.exists():
                raise ParserError(
                    f"CVE API mapper did not produce expected output file: {source_file}"
                )

            # Copy to final location
            shutil.copyfile(source_file, gpt5_output)

            logger.info("Successfully completed CVE -> API mapping: %s", gpt5_output)

        except ParserError:
            # Re-raise our custom exceptions as-is
            raise

        except FileNotFoundError as e:
            logger.error("File not found during CVE API mapping: %s", e)
            raise wrap_exception(
                ParserError,
                f"Required file not found during CVE API mapping: {e}",
                e
            )

        except PermissionError as e:
            logger.error("Permission denied during CVE API mapping: %s", e)
            raise wrap_exception(
                ParserError,
                f"Permission denied: {e}",
                e
            )

        except Exception as e:
            # Catch-all for unexpected errors
            logger.error(
                "Unexpected error during CVE API mapping: %s: %s",
                type(e).__name__, str(e)
            )
            raise wrap_exception(
                ParserError,
                f"Unexpected error during CVE API mapping: {type(e).__name__}",
                e
            )
