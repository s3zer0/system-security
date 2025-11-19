"""Pydantic schemas aligned with the unified analysis result/meta."""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, model_validator


class AnalysisStatus(BaseModel):
    """Status tracking for async analysis jobs."""
    analysis_id: str
    status: Literal["PENDING", "PROCESSING", "COMPLETED", "FAILED"]
    created_at: datetime
    updated_at: datetime
    error_message: Optional[str] = None


class AnalysisStartResponse(BaseModel):
    """Response when analysis is queued (HTTP 202)."""
    analysis_id: str
    status: Literal["PENDING", "PROCESSING"] = "PENDING"
    message: str = "Analysis has been queued and will be processed in the background"


class VulnerabilitySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    overall_risk: str = "LOW"


class Vulnerability(BaseModel):
    cve_id: str
    package: str
    version: str
    severity: str
    description: Optional[str] = None
    direct_call: bool = False
    call_example: Optional[str] = None


class LibraryApiMapping(BaseModel):
    package: str
    version: str
    module: str
    api: str
    related_cves: List[str] = Field(default_factory=list)


class PatchPriorityItem(BaseModel):
    set_no: int
    package: str
    current_version: str
    recommended_version: Optional[str] = None
    score: int = 0
    urgency: Literal["IMMEDIATE", "PLANNED"] = "PLANNED"
    note: str


class AnalysisResult(BaseModel):
    language: str
    overview: str
    vulnerabilities_summary: VulnerabilitySummary
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    libraries_and_apis: List[LibraryApiMapping] = Field(default_factory=list)
    patch_priority: List[PatchPriorityItem] = Field(default_factory=list)
    logs: List[str] = Field(default_factory=list)


class AnalysisMeta(BaseModel):
    analysis_id: str
    file_name: str
    original_filename: Optional[str] = None
    created_at: datetime
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    image_path: Optional[str] = None

    @model_validator(mode="after")
    def set_default_original_filename(self) -> "AnalysisMeta":
        """Fallback to file_name if original_filename is missing (backward compatibility)."""
        if self.original_filename is None:
            self.original_filename = self.file_name
        return self


class AnalysisResponse(BaseModel):
    result: AnalysisResult
    meta: AnalysisMeta


class AnalysisQARequest(BaseModel):
    question: str


class AnalysisQAResponse(BaseModel):
    analysis_id: str
    question: str
    answer: str
    used_cves: List[str] = Field(default_factory=list)
    risk_level: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]] = None


__all__ = [
    "VulnerabilitySummary",
    "Vulnerability",
    "LibraryApiMapping",
    "PatchPriorityItem",
    "AnalysisResult",
    "AnalysisMeta",
    "AnalysisResponse",
    "AnalysisQARequest",
    "AnalysisQAResponse",
    "AnalysisStatus",
    "AnalysisStartResponse",
]
