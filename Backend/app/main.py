"""FastAPI application entrypoint for the security analysis backend."""

from __future__ import annotations

from typing import Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import analysis_router, analyses_router


app = FastAPI(title="System Security API", version="0.1.0")

allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> Dict[str, str]:
    """Simple health check endpoint for orchestration environments."""
    return {"status": "ok"}


app.include_router(analyses_router, prefix="/api")
app.include_router(analysis_router)
