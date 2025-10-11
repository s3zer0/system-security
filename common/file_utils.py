"""Reusable filesystem helpers for JSON IO and directory management."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

JsonLike = Union[dict, list]
PathLike = Union[str, Path]


def _to_path(path: PathLike) -> Path:
    """Convert ``path`` to :class:`Path` without resolving it."""
    return path if isinstance(path, Path) else Path(path)


def ensure_dir(directory: PathLike) -> Path:
    """Create ``directory`` (and parents) if it does not already exist."""
    path = _to_path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: PathLike) -> JsonLike:
    """Read a UTF-8 encoded JSON document from ``path``."""
    file_path = _to_path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: PathLike, data: JsonLike, *, ensure_ascii: bool = False) -> None:
    """Serialise ``data`` as JSON to ``path`` using UTF-8 encoding."""
    file_path = _to_path(path)
    ensure_dir(file_path.parent)
    with file_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=ensure_ascii)
