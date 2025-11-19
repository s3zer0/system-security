"""Service for running Trivy vulnerability scans."""

from __future__ import annotations

import logging
from pathlib import Path

from common import ensure_dir
from trivy_extracter.trivy_module import trivy_func

logger = logging.getLogger("pipeline.scanner")


class ScannerService:
    """Handles Trivy vulnerability scanning."""

    def scan_vulnerabilities(
        self,
        *,
        image_tar: Path,
        trivy_output: Path,
        full_scan: bool = True,
        enhance: bool = False,
        force: bool = False,
    ) -> None:
        """
        Invoke Trivy against the supplied container image.

        Args:
            image_tar: Path to the container image tar file
            trivy_output: Path to write Trivy scan results
            full_scan: Whether to perform a full scan
            enhance: Whether to enhance Trivy descriptions
            force: Force re-scan even if results exist
        """
        if trivy_output.exists() and not force:
            logger.info("Skipping Trivy scan: %s already exists", trivy_output)
            return

        ensure_dir(trivy_output.parent)
        logger.info("Running Trivy scan (full_scan=%s) -> %s", full_scan, trivy_output)

        trivy_func.scan_vulnerabilities(
            input_archive=str(image_tar),
            output_file=str(trivy_output),
            full_scan=full_scan,
        )

        if enhance:
            self._enhance_descriptions(trivy_output)

    def _enhance_descriptions(self, trivy_output: Path) -> None:
        """Enhance Trivy vulnerability descriptions."""
        try:
            from trivy_extracter.main import enhance_descriptions
        except ImportError as exc:  # pragma: no cover - optional dependency
            logger.warning("Unable to import enhance_descriptions: %s", exc)
            return

        enhanced_output = trivy_output.with_name(trivy_output.stem + "_enhanced.json")
        logger.info("Enhancing Trivy descriptions -> %s", enhanced_output)
        enhance_descriptions(str(trivy_output), str(enhanced_output))
