"""Analysis-related FastAPI routes."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core import run_security_analysis
from app.models import AnalysisResponse


logger = logging.getLogger("analysis.router")
BASE_DIR = Path(__file__).resolve().parents[2]
UPLOADS_DIR = BASE_DIR / "DB" / "uploads"
ALLOWED_CONTENT_TYPES = {
    "application/x-tar",
    "application/gzip",
    "application/zip",
    "application/octet-stream",
}


router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/ping")
async def ping() -> Dict[str, str]:
    """Simple readiness probe for the analysis router."""
    return {"message": "pong"}


async def _save_upload(upload: UploadFile, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("wb") as buffer:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                buffer.write(chunk)
    finally:
        await upload.close()


@router.post("", response_model=AnalysisResponse)
async def run_analysis(file: UploadFile = File(...)) -> AnalysisResponse:
    """Accepts an image archive, runs the pipeline, and returns structured results."""

    if file is None or not file.filename:
        raise HTTPException(status_code=400, detail="file upload is required")

    content_type = (file.content_type or "").lower()
    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="unsupported content type")

    safe_name = Path(file.filename).name
    saved_path = UPLOADS_DIR / safe_name

    try:
        await _save_upload(file, saved_path)
    except Exception as exc:
        logger.exception("Failed to persist upload: %s", exc)
        raise HTTPException(status_code=500, detail="failed to store upload") from exc

    try:
        payload = run_security_analysis(str(saved_path))
    except Exception as exc:
        logger.exception("Analysis pipeline failed: %s", exc)
        raise HTTPException(status_code=500, detail="analysis failed") from exc

    result = payload.get("result")
    meta = payload.get("meta")
    if not result or not meta:
        raise HTTPException(status_code=500, detail="analysis returned unexpected payload")

    return AnalysisResponse(result=result, meta=meta)
