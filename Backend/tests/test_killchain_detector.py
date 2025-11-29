import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.killchain_detector import detect_killchains


def _write_dockerfile(tmp_path: Path) -> Path:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "\n".join(
            [
                "FROM python:3.9-slim",
                "USER root",
                "EXPOSE 80",
                "ENV AWS_ACCESS_KEY_ID=abc TOKEN=xyz",
                "VOLUME [\"/var/run/docker.sock\"]",
            ]
        ),
        encoding="utf-8",
    )
    return dockerfile


def _write_runtime(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(exist_ok=True)
    (runtime_dir / "netstat.txt").write_text(
        "tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      123/python\n",
        encoding="utf-8",
    )
    (runtime_dir / "ps.txt").write_text(
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.1  12345  2345 ?        Ss   10:00   0:01 python app.py\n",
        encoding="utf-8",
    )

    
def test_detects_rce_killchain(tmp_path: Path):
    _write_dockerfile(tmp_path)
    trivy_data = {
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "severity": "CRITICAL",
                "title": "Remote code execution bug",
                "description": "Allows remote code execution over the network",
                "cvss": {
                    "nvd": {
                        "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                },
            }
        ]
    }

    findings = detect_killchains(tmp_path, trivy_data)
    rule_ids = {finding["rule_id"] for finding in findings}

    assert "KILLCHAIN_REMOTE_RCE_ROOT" in rule_ids
    assert "KILLCHAIN_POST_RCE_SECRETS" in rule_ids

    remote_rule = next(f for f in findings if f["rule_id"] == "KILLCHAIN_REMOTE_RCE_ROOT")
    assert "T1190" in remote_rule.get("attack_mappings", [])


@pytest.mark.parametrize(
    "vector, expected",
    [
        ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N", True),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", False),
    ],
)
def test_rce_rule_requires_network_and_risk(tmp_path: Path, vector: str, expected: bool):
    _write_dockerfile(tmp_path)
    trivy_data = {
        "vulnerabilities": [
            {
                "id": "CVE-2024-0002",
                "severity": "HIGH",
                "title": "Code execution",
                "description": "Arbitrary code execution",
                "cvss": {"nvd": {"V3Vector": vector}},
            }
        ]
    }

    findings = detect_killchains(tmp_path, trivy_data)
    rule_ids = {finding["rule_id"] for finding in findings}
    assert ("KILLCHAIN_REMOTE_RCE_ROOT" in rule_ids) == expected


def test_runtime_ports_enable_rule(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:3.18\nUSER root", encoding="utf-8")
    _write_runtime(tmp_path)

    trivy_data = {
        "vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2024-1111",
                "severity": "CRITICAL",
                "title": "Network RCE vuln",
                "description": "Remote code execution over network",
                "cvss": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
            }
        ]
    }

    findings = detect_killchains(tmp_path, trivy_data)

    assert any(f["rule_id"] == "KILLCHAIN_REMOTE_RCE_ROOT" for f in findings)
    # Runtime evidence should be present
    remote_rule = next(f for f in findings if f["rule_id"] == "KILLCHAIN_REMOTE_RCE_ROOT")
    assert any("Observed listening ports" in ev for ev in remote_rule["evidences"])
    assert "T1190" in remote_rule.get("attack_mappings", [])