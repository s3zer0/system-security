"""FastAPI application entrypoint for the security analysis backend."""

from __future__ import annotations

from typing import Dict

from fastapi import FastAPI

from app.routers import analysis_router, analyses_router


app = FastAPI(title="System Security API", version="0.1.0")


@app.get("/health")
async def health() -> Dict[str, str]:
    """Simple health check endpoint for orchestration environments."""
    return {"status": "ok"}


app.include_router(analyses_router)
app.include_router(analysis_router)
