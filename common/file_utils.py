"""JSON 입출력과 디렉터리 관리를 위한 재사용 가능한 파일 시스템 도우미입니다."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

JsonLike = Union[dict, list]
PathLike = Union[str, Path]


def _to_path(path: PathLike) -> Path:
    """``path`` 값을 해석하지 않고 :class:`Path` 로 변환합니다."""
    return path if isinstance(path, Path) else Path(path)


def ensure_dir(directory: PathLike) -> Path:
    """``directory`` 가 존재하지 않으면 부모 디렉터리를 포함해 생성합니다."""
    path = _to_path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: PathLike) -> JsonLike:
    """UTF-8로 인코딩된 JSON 문서를 ``path`` 에서 읽어옵니다."""
    file_path = _to_path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: PathLike, data: JsonLike, *, ensure_ascii: bool = False) -> None:
    """``data`` 를 UTF-8로 인코딩된 JSON 형태로 ``path`` 에 기록합니다."""
    file_path = _to_path(path)
    ensure_dir(file_path.parent)
    with file_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=ensure_ascii)
