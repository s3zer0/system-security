"""Analysis-related FastAPI routes."""

from __future__ import annotations

from typing import Dict

from fastapi import APIRouter


router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/ping")
async def ping() -> Dict[str, str]:
    """Simple readiness probe for the analysis router."""
    return {"message": "pong"}
