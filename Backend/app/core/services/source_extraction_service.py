"""Service for extracting application sources from container images."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from search_source.modules.extractor import extract_app_layer

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
        """
        if sources_dir.exists() and not force:
            logger.info("Skipping: %s exists", sources_dir)
            return

        logger.info("Extracting sources from %s to %s", image_tar, sources_dir)
        extract_app_layer(
            image_tar_path=str(image_tar),
            output_dir=str(sources_dir),
            app_path=app_path,
            auto_detect=auto_detect,
            include_filter=include_filter,
        )
