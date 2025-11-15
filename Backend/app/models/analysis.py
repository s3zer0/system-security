"""Pydantic schemas for analysis results and metadata."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AnalysisOverview(BaseModel):
    summary: str
    risk_level: str


class VulnerabilitySummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class Vulnerability(BaseModel):
    cve_id: str
    package_name: str
    installed_version: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    fixed_version: Optional[str] = None
    cvss: Optional[Dict[str, Any]] = None
    references: List[str] = Field(default_factory=list)
    primary_url: Optional[str] = None
    package_type: Optional[str] = None


class LibraryApiMapping(BaseModel):
    library: str
    version: str
    cves: List[str] = Field(default_factory=list)
    apis: Dict[str, List[str]] = Field(default_factory=dict)


class PatchModuleVulnerability(BaseModel):
    cve_id: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    vulnerable_functions: List[str] = Field(default_factory=list)
    functions_used_in_code: Optional[bool] = None
    external_api_exposed: Optional[bool] = None
    exploit_scenario: Optional[str] = None
    potential_impact: Optional[str] = None


class PatchModulePatching(BaseModel):
    target_version: Optional[str] = None
    upgrade_command: Optional[str] = None
    breaking_changes: List[str] = Field(default_factory=list)
    compatibility_notes: Optional[str] = None
    testing_steps: List[str] = Field(default_factory=list)


class PatchModule(BaseModel):
    package_name: str
    current_version: Optional[str] = None
    priority_level: Optional[str] = None
    risk_score: Optional[float] = None
    docker_external_exposure: Optional[bool] = None
    vulnerabilities: List[PatchModuleVulnerability] = Field(default_factory=list)
    patching: Optional[PatchModulePatching] = None
    real_world_cases: List[Dict[str, Any]] = Field(default_factory=list)
    overall_recommendation: Optional[str] = None


class PatchPrioritySummary(BaseModel):
    total_modules: int = 0
    total_vulnerabilities: int = 0
    critical_modules: int = 0
    high_priority_modules: int = 0
    medium_priority_modules: int = 0
    low_priority_modules: int = 0
    external_exposed_modules: Optional[int] = None


class PatchPriorityBlock(BaseModel):
    modules_by_priority: List[PatchModule] = Field(default_factory=list)
    summary: PatchPrioritySummary
    patching_roadmap: Dict[str, List[str]] = Field(default_factory=dict)
    overall_assessment: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ASTCallGraph(BaseModel):
    external: List[str] = Field(default_factory=list)
    internal: List[str] = Field(default_factory=list)
    unused: List[str] = Field(default_factory=list)


class AnalysisArtifacts(BaseModel):
    db_dir: str
    sources_dir: str
    trivy_report: str
    lib_cve_api_mapping: str
    ast_result: str
    ast_security: Optional[str] = None
    gpt5_results: str
    fetch_priority: str
    ast_graph_prefix: str
    cve_mapper_results_dir: str
    cve_mapper_raw_dir: str


class AnalysisResult(BaseModel):
    language: str
    overview: AnalysisOverview
    vulnerabilities_summary: VulnerabilitySummary
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    libraries_and_apis: List[LibraryApiMapping] = Field(default_factory=list)
    patch_priority: PatchPriorityBlock
    ast_analysis: Optional[ASTCallGraph] = None
    artifacts: Optional[AnalysisArtifacts] = None


class AnalysisStats(BaseModel):
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    modules_analyzed: Optional[int] = None
    external_apis: Optional[int] = None
    internal_apis: Optional[int] = None


class AnalysisMeta(BaseModel):
    analysis_id: str
    image_name: Optional[str] = None
    image_path: str
    created_at: datetime
    language: str
    risk_level: str
    stats: AnalysisStats


class AnalysisResponse(BaseModel):
    result: AnalysisResult
    meta: AnalysisMeta


__all__ = [
    "AnalysisOverview",
    "VulnerabilitySummary",
    "Vulnerability",
    "LibraryApiMapping",
    "PatchModuleVulnerability",
    "PatchModulePatching",
    "PatchModule",
    "PatchPrioritySummary",
    "PatchPriorityBlock",
    "ASTCallGraph",
    "AnalysisArtifacts",
    "AnalysisResult",
    "AnalysisStats",
    "AnalysisMeta",
    "AnalysisResponse",
]
