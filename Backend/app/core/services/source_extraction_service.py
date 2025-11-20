"""Service for extracting application sources from container images."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from search_source.modules.extractor import extract_app_layer

from ..exceptions import SourceExtractionError, wrap_exception

logger = logging.getLogger("pipeline.source_extraction")


class SourceExtractionService:
    """Handles extraction of application sources from container images."""

    def extract_sources(
        self,
        *,
        image_tar: Path,
        sources_dir: Path,
        app_path: Optional[str] = None,
        include_filter: Optional[str] = None,
        auto_detect: bool = True,
        force: bool = False,
    ) -> None:
        """
        Extract application sources from the container image.

        Args:
            image_tar: Path to the container image tar file
            sources_dir: Directory to extract sources to
            app_path: Specific application path to extract
            include_filter: Filter for files to include
            auto_detect: Whether to auto-detect application path
            force: Force re-extraction even if sources exist

        Raises:
            SourceExtractionError: If extraction fails for any reason
        """
        try:
            if sources_dir.exists() and not force:
                logger.info("Skipping: %s exists", sources_dir)
                return

            # Validate inputs
            if not image_tar.exists():
                raise SourceExtractionError(
                    f"Container image file not found: {image_tar}"
                )

            logger.info("Extracting sources from %s to %s", image_tar, sources_dir)
            extract_app_layer(
                image_tar_path=str(image_tar),
                output_dir=str(sources_dir),
                app_path=app_path,
                auto_detect=auto_detect,
                include_filter=include_filter,
            )

            # Verify extraction succeeded
            if not sources_dir.exists() or not any(sources_dir.iterdir()):
                raise SourceExtractionError(
                    f"Source extraction completed but output directory is empty: {sources_dir}"
                )

            logger.info("Successfully extracted sources to %s", sources_dir)

        except SourceExtractionError:
            # Re-raise our custom exceptions as-is
            raise

        except FileNotFoundError as e:
            logger.error("File not found during source extraction: %s", e)
            raise wrap_exception(
                SourceExtractionError,
                f"Required file not found during extraction: {e}",
                e
            )

        except subprocess.CalledProcessError as e:
            logger.error(
                "Subprocess failed during source extraction: %s (exit code: %d)",
                e.cmd, e.returncode
            )
            raise wrap_exception(
                SourceExtractionError,
                f"External command failed during extraction: {e.cmd}",
                e
            )

        except PermissionError as e:
            logger.error("Permission denied during source extraction: %s", e)
            raise wrap_exception(
                SourceExtractionError,
                f"Permission denied: {e}",
                e
            )

        except Exception as e:
            # Catch-all for unexpected errors
            logger.error(
                "Unexpected error during source extraction: %s: %s",
                type(e).__name__, str(e)
            )
            raise wrap_exception(
                SourceExtractionError,
                f"Unexpected error during source extraction: {type(e).__name__}",
                e
            )
