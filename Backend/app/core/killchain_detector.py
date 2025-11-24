"""Lightweight rule-based killchain detector for container images.

This module inspects extracted build artefacts (Dockerfile) alongside
vulnerability metadata to flag common end-to-end attack paths such as
network-triggered RCE leading to container takeover and lateral movement.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

# Secret-like keywords to flag from environment variable names
_SECRET_KEYWORDS = (
    "KEY",
    "TOKEN",
    "PASSWORD",
    "SECRET",
    "ACCESS_KEY",
    "PRIVATE",
)

# Sensitive mount markers that often grant host escape or orchestration control
_SENSITIVE_MOUNT_MARKERS = (
    "/var/run/docker.sock",
    "kube/config",
    "/var/lib/mysql",
)


def _looks_like_secret(var_name: str) -> bool:
    upper_name = var_name.upper()
    return any(keyword in upper_name for keyword in _SECRET_KEYWORDS)


def _extract_env_keys(assignments: Iterable[str]) -> Set[str]:
    keys: Set[str] = set()
    for assignment in assignments:
        if not assignment:
            continue
        if "=" in assignment:
            key, _ = assignment.split("=", 1)
        else:
            key = assignment
        if key:
            keys.add(key.strip())
    return keys


def _parse_dockerfile(path: Path) -> Dict[str, Any]:
    exposed_ports: Set[int] = set()
    env_keys: Set[str] = set()
    sensitive_mounts: Set[str] = set()
    run_user: str | None = None

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {
            "exposed_ports": exposed_ports,
            "env_keys": env_keys,
            "sensitive_mounts": sensitive_mounts,
            "run_user": run_user,
        }

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        tokens = line.split()
        if not tokens:
            continue

        directive = tokens[0].upper()
        args = tokens[1:]

        if directive == "EXPOSE":
            for arg in args:
                match = re.match(r"(\d+)", arg)
                if match:
                    try:
                        exposed_ports.add(int(match.group(1)))
                    except ValueError:
                        continue
        elif directive == "USER" and args:
            run_user = args[0]
        elif directive == "ENV" and args:
            env_keys.update(_extract_env_keys(args))
        elif directive == "VOLUME" and args:
            volume_spec = " ".join(args)
            for marker in _SENSITIVE_MOUNT_MARKERS:
                if marker in volume_spec:
                    sensitive_mounts.add(marker)
    return {
        "exposed_ports": exposed_ports,
        "env_keys": env_keys,
        "sensitive_mounts": sensitive_mounts,
        "run_user": run_user,
    }


def _collect_container_facts(sources_dir: Path) -> Dict[str, Any]:
    exposed_ports: Set[int] = set()
    env_keys: Set[str] = set()
    sensitive_mounts: Set[str] = set()
    run_user: str | None = None
    dockerfile_paths: List[str] = []

    if not sources_dir.exists():
        return {
            "exposed_ports": [],
            "env_keys": [],
            "secret_env_keys": [],
            "sensitive_mounts": [],
            "run_user": None,
            "runs_as_root": True,
            "dockerfiles": dockerfile_paths,
        }

    for dockerfile in sources_dir.rglob("Dockerfile"):
        dockerfile_paths.append(str(dockerfile))
        parsed = _parse_dockerfile(dockerfile)
        exposed_ports.update(parsed["exposed_ports"])
        env_keys.update(parsed["env_keys"])
        sensitive_mounts.update(parsed["sensitive_mounts"])
        # Last USER directive wins
        if parsed["run_user"] is not None:
            run_user = parsed["run_user"]

    secret_env_keys = sorted(key for key in env_keys if _looks_like_secret(key))

    return {
        "exposed_ports": sorted(exposed_ports),
        "env_keys": sorted(env_keys),
        "secret_env_keys": secret_env_keys,
        "sensitive_mounts": sorted(sensitive_mounts),
        "run_user": run_user,
        "runs_as_root": run_user is None or run_user.lower() == "root",
        "dockerfiles": dockerfile_paths,
    }


def _is_network_rce(vuln: Dict[str, Any]) -> bool:
    """Return True if a vulnerability is a likely network-triggered RCE."""

    cvss_block = vuln.get("cvss") or {}
    vectors: List[str] = []
    for entry in cvss_block.values():
        if isinstance(entry, dict):
            vector = (
                entry.get("V3Vector")
                or entry.get("vector")
                or entry.get("vectorString")
                or entry.get("V31Vector")
                or entry.get("Vector")
            )
            if isinstance(vector, str):
                vectors.append(vector)

    has_network_vector = any("AV:N" in vector for vector in vectors)

    text_blob = " ".join(
        str(part)
        for part in [
            vuln.get("title"),
            vuln.get("description"),
            vuln.get("id"),
            vuln.get("VulnerabilityID"),
        ]
        if part
    ).lower()
    rce_hint = any(keyword in text_blob for keyword in ("remote code execution", " rce", "code execution"))
    severity = (vuln.get("severity") or vuln.get("Severity") or "").upper()

    return bool(has_network_vector and (rce_hint or severity in {"CRITICAL", "HIGH"}))


def _format_ports(ports: Iterable[int]) -> str:
    port_list = sorted(set(int(p) for p in ports))
    return ", ".join(str(port) for port in port_list) if port_list else "(none)"


def detect_killchains(sources_dir: Path, trivy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate simple rule-based killchains using Dockerfile facts and CVEs."""

    facts = _collect_container_facts(sources_dir)
    vulnerabilities = trivy_data.get("vulnerabilities") or []
    network_rces = [v for v in vulnerabilities if _is_network_rce(v)]

    findings: List[Dict[str, Any]] = []

    if network_rces and facts["exposed_ports"] and facts["runs_as_root"]:
        cve_list = sorted(
            {v.get("id") or v.get("VulnerabilityID") for v in network_rces if v.get("id") or v.get("VulnerabilityID")}
        )
        evidences = [
            f"Network-exploitable CVEs: {', '.join(cve_list)}",
            f"Exposed ports in Dockerfile: {_format_ports(facts['exposed_ports'])}",
            "Container runs as root (USER not set)" if facts["run_user"] is None else f"Container runs as user '{facts['run_user']}'",
        ]
        findings.append(
            {
                "rule_id": "KILLCHAIN_REMOTE_RCE_ROOT",
                "title": "원격 RCE → 컨테이너 탈취",
                "severity": "HIGH",
                "description": "네트워크에서 악용 가능한 RCE와 외부 노출 포트, root 권한이 결합되어 즉시 컨테이너 장악이 가능합니다.",
                "evidences": evidences,
            }
        )

        if facts["secret_env_keys"] or facts["sensitive_mounts"]:
            lateral_evidence = []
            if facts["secret_env_keys"]:
                lateral_evidence.append(
                    "Environment keys with secret patterns detected: "
                    + ", ".join(facts["secret_env_keys"])
                )
            if facts["sensitive_mounts"]:
                lateral_evidence.append(
                    "Sensitive mounts present: " + ", ".join(facts["sensitive_mounts"])
                )
            findings.append(
                {
                    "rule_id": "KILLCHAIN_POST_RCE_SECRETS",
                    "title": "컨테이너 탈취 후 시크릿/호스트 확장",
                    "severity": "CRITICAL",
                    "description": "컨테이너 탈취 시 시크릿 또는 민감 마운트를 이용해 내부 자산이나 호스트로 이동이 가능합니다.",
                    "evidences": lateral_evidence,
                }
            )

    return findings


__all__ = ["detect_killchains"]