"""Centralised logging configuration helpers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Union

from .file_utils import ensure_dir

PathLike = Union[str, Path]


def setup_logging(
    *,
    level: int = logging.INFO,
    log_file: Optional[PathLike] = None,
    fmt: str = "[%(levelname)s] %(message)s",
    datefmt: Optional[str] = None,
    stream: bool = True,
    force: bool = True,
) -> None:
    """Configure root logging with consistent handlers.

    Args:
        level: Logging level to apply.
        log_file: Optional file path for log output. File is truncated on setup.
        fmt: Log message format string.
        datefmt: Optional date format string.
        stream: Whether to emit logs to stderr via ``StreamHandler``.
        force: Whether to override existing logging configuration.
    """
    handlers = []
    if stream:
        handlers.append(logging.StreamHandler())
    if log_file:
        log_path = Path(log_file)
        ensure_dir(log_path.parent)
        handlers.append(logging.FileHandler(log_path, mode="w", encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt=datefmt,
        handlers=handlers or None,
        force=force,
    )
