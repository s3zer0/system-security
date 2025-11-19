"""Service for running Trivy vulnerability scans."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from common import ensure_dir

from ..exceptions import ScannerError, wrap_exception

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

        Raises:
            ScannerError: If Trivy scanning fails for any reason
        """
        try:
            if trivy_output.exists() and not force:
                logger.info("Skipping Trivy scan: %s already exists", trivy_output)
                return

            # Validate inputs
            if not image_tar.exists():
                raise ScannerError(
                    f"Container image file not found for scanning: {image_tar}"
                )

            ensure_dir(trivy_output.parent)
            logger.info("Running Trivy scan (full_scan=%s) -> %s", full_scan, trivy_output)

            # Import and run Trivy
            try:
                from trivy_extracter.trivy_module import trivy_func
            except ImportError as e:
                logger.error("Failed to import Trivy module: %s", e)
                raise wrap_exception(
                    ScannerError,
                    "Trivy module not available - ensure dependencies are installed",
                    e
                )

            trivy_func.scan_vulnerabilities(
                input_archive=str(image_tar),
                output_file=str(trivy_output),
                full_scan=full_scan,
            )

            # Verify scan output was created
            if not trivy_output.exists():
                raise ScannerError(
                    f"Trivy scan completed but output file was not created: {trivy_output}"
                )

            # Check if output is not empty
            if trivy_output.stat().st_size == 0:
                raise ScannerError(
                    f"Trivy scan produced empty output file: {trivy_output}"
                )

            logger.info("Trivy scan completed successfully: %s", trivy_output)

            if enhance:
                self._enhance_descriptions(trivy_output)

        except ScannerError:
            # Re-raise our custom exceptions as-is
            raise

        except subprocess.CalledProcessError as e:
            logger.error(
                "Trivy subprocess failed: %s (exit code: %d)",
                e.cmd, e.returncode
            )
            raise wrap_exception(
                ScannerError,
                f"Trivy command failed with exit code {e.returncode}",
                e
            )

        except FileNotFoundError as e:
            logger.error("File not found during Trivy scan: %s", e)
            raise wrap_exception(
                ScannerError,
                f"Required file not found during scanning: {e}",
                e
            )

        except PermissionError as e:
            logger.error("Permission denied during Trivy scan: %s", e)
            raise wrap_exception(
                ScannerError,
                f"Permission denied: {e}",
                e
            )

        except Exception as e:
            # Catch-all for unexpected errors
            logger.error(
                "Unexpected error during Trivy scan: %s: %s",
                type(e).__name__, str(e)
            )
            raise wrap_exception(
                ScannerError,
                f"Unexpected error during vulnerability scanning: {type(e).__name__}",
                e
            )

    def _enhance_descriptions(self, trivy_output: Path) -> None:
        """
        Enhance Trivy vulnerability descriptions.

        Note: Enhancement failures are logged but do not raise exceptions,
        as this is an optional feature.
        """
        try:
            from trivy_extracter.main import enhance_descriptions
        except ImportError as exc:
            logger.warning("Unable to import enhance_descriptions: %s", exc)
            return

        try:
            enhanced_output = trivy_output.with_name(trivy_output.stem + "_enhanced.json")
            logger.info("Enhancing Trivy descriptions -> %s", enhanced_output)
            enhance_descriptions(str(trivy_output), str(enhanced_output))
            logger.info("Successfully enhanced Trivy descriptions")

        except Exception as e:
            # Enhancement is optional - log but don't fail
            logger.warning(
                "Failed to enhance Trivy descriptions (continuing anyway): %s: %s",
                type(e).__name__, str(e)
            )
