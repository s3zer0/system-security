"""중앙 집중식 로깅 구성 도우미 모음입니다."""

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
    """일관된 핸들러를 사용하도록 루트 로깅을 구성합니다.

    Args:
        level: 적용할 로깅 레벨입니다.
        log_file: 로그를 기록할 선택적 파일 경로입니다. 설정 시 기존 파일은 비워집니다.
        fmt: 로그 메시지 형식 문자열입니다.
        datefmt: 선택적인 날짜 형식 문자열입니다.
        stream: ``StreamHandler`` 를 통해 stderr에 로그를 출력할지 여부입니다.
        force: 기존 로깅 구성을 덮어쓸지 여부입니다.
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
