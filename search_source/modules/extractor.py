"""Core extraction logic for container images."""

import tarfile
import json
import os
import shutil
import tempfile
from typing import Optional, List, Set

from .config import CANDIDATE_APP_PATHS, MESSAGES, ERROR_MESSAGES
from .utils import copy_directory, find_app_path


class ImageExtractor:
    """Container image extraction handler."""

    def __init__(self, image_tar_path: str, output_dir: str):
        """
        Initialize the ImageExtractor.

        Args:
            image_tar_path: Path to the container image tar file
            output_dir: Directory where the extracted source will be saved
        """
        self.image_tar_path = image_tar_path
        self.output_dir = output_dir
        self.temp_dir = None
        self.merged_fs = None

    def extract_image(self) -> str:
        """
        Extract the container image tar file to a temporary directory.

        Returns:
            Path to the temporary directory containing extracted content
        """
        self.temp_dir = tempfile.mkdtemp()
        print(MESSAGES["extract_start"].format(path=self.image_tar_path))

        with tarfile.open(self.image_tar_path, "r") as tar:
            tar.extractall(path=self.temp_dir)

        return self.temp_dir

    def get_layers(self) -> List[str]:
        """
        Read the manifest.json and get the list of layers.

        Returns:
            List of layer tar file paths

        Raises:
            FileNotFoundError: If manifest.json is not found
        """
        manifest_path = os.path.join(self.temp_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(ERROR_MESSAGES["manifest_not_found"])

        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        return manifest[0]["Layers"]

    def merge_layers(self, layers: List[str]) -> str:
        """
        Merge all layers to create a complete filesystem.
        Handles Docker whiteout files (.wh.*) properly.

        Args:
            layers: List of layer tar file paths

        Returns:
            Path to the merged filesystem directory
        """
        self.merged_fs = os.path.join(self.temp_dir, "merged_fs")
        os.makedirs(self.merged_fs, exist_ok=True)

        for layer_tar in layers:
            layer_tar_path = os.path.join(self.temp_dir, layer_tar)
            self._apply_layer_with_whiteouts(layer_tar_path, self.merged_fs)
            print(MESSAGES["layer_applied"].format(layer=layer_tar))

        return self.merged_fs

    def _apply_layer_with_whiteouts(self, layer_tar_path: str, target_dir: str) -> None:
        """
        Apply a single layer to the target directory, handling whiteout files.

        Args:
            layer_tar_path: Path to the layer tar file
            target_dir: Directory where the layer should be applied
        """
        with tarfile.open(layer_tar_path, "r") as layer_tarfile:
            # First pass: collect whiteout information
            whiteout_files: Set[str] = set()
            opaque_dirs: Set[str] = set()

            for member in layer_tarfile.getmembers():
                # Check for opaque directory marker
                if member.name.endswith(".wh..wh..opq"):
                    dir_path = os.path.dirname(member.name)
                    opaque_dirs.add(dir_path)
                # Check for regular whiteout files
                elif "/.wh." in member.name or member.name.startswith(".wh."):
                    whiteout_files.add(member.name)

            # Process opaque directories (clear them first)
            for opaque_dir in opaque_dirs:
                real_dir = os.path.join(target_dir, opaque_dir)
                if os.path.exists(real_dir):
                    shutil.rmtree(real_dir)
                os.makedirs(real_dir, exist_ok=True)

            # Second pass: extract files, skipping whiteout markers
            for member in layer_tarfile.getmembers():
                # Skip whiteout marker files themselves
                if member.name.endswith(".wh..wh..opq"):
                    continue

                # Handle regular whiteout files
                if "/.wh." in member.name or member.name.startswith(".wh."):
                    # Extract the actual filename that should be deleted
                    parts = member.name.rsplit("/.wh.", 1)
                    if len(parts) == 2:
                        deleted_file = os.path.join(parts[0], parts[1])
                    else:
                        # Handle case where .wh. is at the beginning
                        deleted_file = member.name[4:]  # Remove ".wh." prefix

                    # Delete the corresponding file/directory
                    target_path = os.path.join(target_dir, deleted_file)
                    if os.path.exists(target_path):
                        if os.path.isdir(target_path):
                            shutil.rmtree(target_path)
                        else:
                            os.remove(target_path)
                    continue

                # Extract normal files
                layer_tarfile.extract(member, path=target_dir)

    def extract_app_auto(self, include_filter: Optional[str] = None) -> bool:
        """
        Automatically detect and extract application source.

        Args:
            include_filter: Optional file extension filter

        Returns:
            True if extraction was successful, False otherwise

        Raises:
            FileNotFoundError: If no application source is found
        """
        found = False

        for candidate in CANDIDATE_APP_PATHS:
            test_path = os.path.join(self.merged_fs, candidate.lstrip('/'))
            if not os.path.exists(test_path):
                continue

            print(MESSAGES["app_found"].format(path=candidate))
            dest_path = os.path.join(self.output_dir, os.path.basename(candidate.rstrip('/')))
            copy_directory(test_path, dest_path, include_filter)
            print(MESSAGES["copy_complete"].format(src=candidate, dest=dest_path))
            found = True

        if not found:
            raise FileNotFoundError(ERROR_MESSAGES["auto_detect_failed"])

        return found

    def extract_app_manual(self, app_path: str, include_filter: Optional[str] = None) -> None:
        """
        Extract application source from a manually specified path.

        Args:
            app_path: Path to the application source in the container
            include_filter: Optional file extension filter

        Raises:
            FileNotFoundError: If the specified path doesn't exist
        """
        app_src = os.path.join(self.merged_fs, app_path.lstrip('/'))
        if not os.path.exists(app_src):
            raise FileNotFoundError(ERROR_MESSAGES["app_path_not_found"].format(path=app_path))

        print(MESSAGES["manual_copy_start"].format(path=app_path))

        # Remove existing output directory if it exists
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

        copy_directory(app_src, self.output_dir, include_filter)
        print(MESSAGES["copy_success"].format(path=self.output_dir))

    def cleanup(self) -> None:
        """Clean up temporary directories."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)


def extract_app_layer(
    image_tar_path: str,
    output_dir: str,
    app_path: Optional[str] = None,
    auto_detect: bool = False,
    include_filter: Optional[str] = None
) -> None:
    """
    Extract application layer from a container image tar file.

    Args:
        image_tar_path: Path to the container image tar file
        output_dir: Directory where the extracted source will be saved
        app_path: Manual path to the application source (if not auto-detecting)
        auto_detect: Whether to automatically detect the application source path
        include_filter: Optional file extension filter

    Raises:
        FileNotFoundError: If required files or paths are not found
        ValueError: If invalid arguments are provided
    """
    extractor = ImageExtractor(image_tar_path, output_dir)

    try:
        # Extract image to temporary directory
        extractor.extract_image()

        # Get layers from manifest
        layers = extractor.get_layers()

        # Merge all layers
        extractor.merge_layers(layers)

        # Extract application source
        if auto_detect:
            extractor.extract_app_auto(include_filter)
        else:
            if not app_path:
                raise ValueError(ERROR_MESSAGES["app_path_required"])
            extractor.extract_app_manual(app_path, include_filter)

    finally:
        # Always cleanup temporary directories
        extractor.cleanup()