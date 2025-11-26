import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

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