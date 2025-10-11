"""Utility functions for the container image source extractor."""

import os
import shutil
from typing import Optional

from common import ensure_dir


def copy_directory(src: str, dest: str, include_filter: Optional[str] = None) -> None:
    """
    Copy a directory from source to destination with optional filtering.

    Args:
        src: Source directory path
        dest: Destination directory path
        include_filter: Optional file extension filter (e.g., '.py')
    """
    if include_filter:
        # If filter is specified, copy only matching files
        os.makedirs(dest, exist_ok=True)
        for root, dirs, files in os.walk(src):
            # Calculate relative path from source
            rel_path = os.path.relpath(root, src)
            dest_dir = os.path.join(dest, rel_path) if rel_path != '.' else dest

            # Create directory structure
            os.makedirs(dest_dir, exist_ok=True)

            # Copy only files matching the filter
            for file in files:
                if file.endswith(include_filter):
                    src_file = os.path.join(root, file)
                    dest_file = os.path.join(dest_dir, file)
                    shutil.copy2(src_file, dest_file)
    else:
        # No filter, copy everything
        shutil.copytree(src, dest, dirs_exist_ok=True)


def find_app_path(merged_fs: str, candidate_paths: list) -> Optional[str]:
    """
    Find the application path from a list of candidates.

    Args:
        merged_fs: Path to the merged filesystem
        candidate_paths: List of candidate paths to check

    Returns:
        The first valid path found, or None if no path is found
    """
    for candidate in candidate_paths:
        test_path = os.path.join(merged_fs, candidate.lstrip('/'))
        if os.path.exists(test_path):
            return test_path
    return None


def validate_tar_file(file_path: str) -> bool:
    """
    Validate if the given file is a valid tar file.

    Args:
        file_path: Path to the file to validate

    Returns:
        True if the file is a valid tar file, False otherwise
    """
    if not os.path.exists(file_path):
        return False

    if not file_path.endswith(('.tar', '.tar.gz', '.tgz')):
        return False

    return os.path.isfile(file_path)


def ensure_directory(path: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path to ensure exists
    """
    ensure_dir(path)


def safe_remove_directory(path: str) -> None:
    """
    Safely remove a directory if it exists.

    Args:
        path: Directory path to remove
    """
    if os.path.exists(path) and os.path.isdir(path):
        shutil.rmtree(path)