"""Read-only endpoints that enumerate stored analyses."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List

from fastapi import APIRouter

from app.core.analysis_engine import DEFAULT_DB_DIR
from app.models import AnalysisMeta


logger = logging.getLogger("analyses.router")
router = APIRouter()
EXCLUDED_DIRS = {"uploads", "legacy_root"}


@router.get("/analyses", response_model=List[AnalysisMeta])
async def list_analyses() -> List[AnalysisMeta]:
    """Return stored analysis metadata ordered by creation time (desc)."""

    entries: List[AnalysisMeta] = []
    if not DEFAULT_DB_DIR.exists():
        return entries

    for candidate in DEFAULT_DB_DIR.iterdir():
        if not candidate.is_dir() or candidate.name in EXCLUDED_DIRS:
            continue

        meta_path = candidate / "meta.json"
        if not meta_path.is_file():
            logger.warning("Skipping %s: meta.json missing", candidate.name)
            continue

        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            meta = AnalysisMeta(**data)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping %s: invalid meta.json (%s)", candidate.name, exc)
            continue
        except OSError as exc:
            logger.warning("Skipping %s: unable to read meta.json (%s)", candidate.name, exc)
            continue

        entries.append(meta)

    entries.sort(key=lambda item: item.created_at or datetime.min, reverse=True)
    return entries
