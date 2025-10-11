"""Shared dataclass models for system-security components."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class Vulnerability:
    """Normalised vulnerability record produced from Trivy results."""

    id: str
    package_name: str
    installed_version: str
    severity: str
    title: str
    description: str
    fixed_version: str
    cvss: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    primary_url: str = ""
    data_source: Dict[str, Any] = field(default_factory=dict)
    package_type: str = "python-pkg"

    def to_dict(self) -> Dict[str, Any]:
        """Return the vulnerability as a plain dictionary for JSON serialisation."""
        return asdict(self)


@dataclass(slots=True)
class ASTResult:
    """Summary of AST call graph classification."""

    external: List[str] = field(default_factory=list)
    internal: List[str] = field(default_factory=list)
    unused: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, List[str]]:
        return {
            "external": list(self.external),
            "internal": list(self.internal),
            "unused": list(self.unused),
        }


@dataclass(slots=True)
class RealWorldCase:
    """Structured information about a real-world vulnerability incident."""

    title: str
    description: str
    source_url: str
    date: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class VulnerabilityContext:
    """Aggregated context used for patch priority evaluation."""

    cve_id: str
    package_name: str
    version: str
    severity: str
    cvss_score: float
    epss_score: float
    description: str
    vulnerable_apis: List[str]
    used_apis: List[str]
    is_api_used: bool
    is_external_api_used: bool
    external_apis: List[str]
    fix_version: str
    real_world_cases: Optional[List[RealWorldCase]] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        if self.real_world_cases is not None:
            payload["real_world_cases"] = [case.to_dict() for case in self.real_world_cases]
        return payload
