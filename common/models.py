"""system-security 구성 요소에서 공유하는 데이터클래스 모델 모음입니다."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class Vulnerability:
    """Trivy 결과로부터 생성된 정규화된 취약점 레코드입니다."""

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
        """JSON 직렬화를 위해 취약점 정보를 일반 딕셔너리로 반환합니다."""
        return asdict(self)


@dataclass(slots=True)
class ASTResult:
    """AST 호출 그래프 분류에 대한 요약입니다."""

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
    """실제 취약점 사고에 대한 구조화된 정보를 나타냅니다."""

    title: str
    description: str
    source_url: str
    date: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class VulnerabilityContext:
    """패치 우선순위 평가에 사용되는 통합 컨텍스트입니다."""

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
