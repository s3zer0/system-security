"""Analysis-related FastAPI routes."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import ValidationError

from app.core import run_security_analysis
from app.core.analysis_engine import DEFAULT_DB_DIR
from app.models import (
    AnalysisMeta,
    AnalysisQARequest,
    AnalysisQAResponse,
    AnalysisResponse,
    AnalysisResult,
)
from app.services.qa_service import run_qa


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


def _load_analysis_from_disk(analysis_id: str) -> AnalysisResponse:
    """Load stored artefacts and convert them into the structured response."""

    analysis_dir = DEFAULT_DB_DIR / analysis_id
    if not analysis_dir.is_dir():
        raise HTTPException(status_code=404, detail="analysis not found")

    meta_path = analysis_dir / "meta.json"
    result_path = analysis_dir / "Result.json"
    missing = [path.name for path in (meta_path, result_path) if not path.is_file()]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"missing artefacts for {analysis_id}: {', '.join(missing)}",
        )

    try:
        meta_data = json.loads(meta_path.read_text(encoding="utf-8"))
        result_data = json.loads(result_path.read_text(encoding="utf-8"))
        meta = AnalysisMeta(**meta_data)
        result = AnalysisResult(**result_data)
    except json.JSONDecodeError as exc:
        logger.exception("Failed to parse JSON for analysis %s", analysis_id)
        raise HTTPException(
            status_code=500,
            detail=f"corrupted artefact for {analysis_id}: {exc}",
        ) from exc
    except OSError as exc:
        logger.exception("Failed to read artefacts for analysis %s", analysis_id)
        raise HTTPException(
            status_code=500,
            detail=f"unable to read artefacts for {analysis_id}: {exc}",
        ) from exc
    except ValidationError as exc:
        logger.exception("Invalid artefact schema for analysis %s", analysis_id)
        raise HTTPException(
            status_code=500,
            detail=f"corrupted artefact for {analysis_id}: {exc}",
        ) from exc

    return AnalysisResponse(result=result, meta=meta)


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


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis_detail(analysis_id: str) -> AnalysisResponse:
    """Return the stored result/meta for a completed analysis run."""

    return _load_analysis_from_disk(analysis_id)


@router.post("/{analysis_id}/qa", response_model=AnalysisQAResponse)
async def qa_analysis(analysis_id: str, payload: AnalysisQARequest) -> AnalysisQAResponse:
    """Answer Korean security questions using the stored analysis result.

    Example:
        curl -X POST "http://localhost:8000/analysis/ae36e75a0eb147838c4db562df173933/qa" \
             -H "Content-Type: application/json" \
             -d '{"question": "이 이미지에서 가장 위험한 취약점과 우선적으로 패치해야 할 라이브러리를 알려줘."}'

    Expected response:
        {
          "analysis_id": "ae36e75a0eb147838c4db562df173933",
          "question": "이 이미지에서 가장 위험한 취약점과 우선적으로 패치해야 할 라이브러리를 알려줘.",
          "answer": "이 이미지에서 가장 위험한 취약점은 CVE-2020-14343(PyYAML)이며, ...",
          "used_cves": ["CVE-2020-14343", "CVE-2023-30861"],
          "risk_level": "CRITICAL"
        }
    """

    analysis = _load_analysis_from_disk(analysis_id)
    meta = analysis.meta
    result = analysis.result

    try:
        answer_text, used_cves, inferred_risk = await run_qa(meta, result, payload.question)
    except Exception as exc:  # pragma: no cover - network failures
        logger.exception("LLM Q&A failed for analysis %s", analysis_id)
        raise HTTPException(status_code=502, detail="LLM Q&A failed") from exc

    return AnalysisQAResponse(
        analysis_id=analysis_id,
        question=payload.question,
        answer=answer_text,
        used_cves=used_cves,
        risk_level=inferred_risk,
    )
