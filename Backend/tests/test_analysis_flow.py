import json
import os
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from pathlib import Path
import sys
from unittest.mock import patch

# Add app directory to sys.path to allow imports
sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.core.analysis_engine import DEFAULT_DB_DIR, create_analysis_status

client = TestClient(app)

TEST_TARGET_PATH = Path(__file__).resolve().parents[1] / "test_target" / "test_target.tar"


def mock_process_analysis_background(
    analysis_id: str,
    file_path: str,
    original_filename: str = None,
) -> None:
    """
    Mock implementation that simulates successful analysis completion
    without running the heavy security pipeline.

    This mock:
    1. Updates the database status to "COMPLETED"
    2. Writes minimal dummy meta.json and Result.json files
    """
    analysis_dir = DEFAULT_DB_DIR / analysis_id

    # Update status to COMPLETED
    create_analysis_status(analysis_id, analysis_dir, status="COMPLETED")

    # Write minimal dummy meta.json
    meta_data = {
        "analysis_id": analysis_id,
        "file_name": Path(file_path).name,
        "original_filename": original_filename or Path(file_path).name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "risk_level": "LOW",
        "image_path": file_path,
    }
    meta_path = analysis_dir / "meta.json"
    meta_path.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")

    # Write minimal dummy Result.json
    result_data = {
        "language": "Python",
        "overview": "Test analysis completed",
        "vulnerabilities_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk": "LOW"
        },
        "vulnerabilities": [],
        "libraries_and_apis": [],
        "patch_priority": [],
        "logs": []
    }
    result_path = analysis_dir / "Result.json"
    result_path.write_text(json.dumps(result_data, indent=2), encoding="utf-8")


@patch("app.routers.analysis.process_analysis_background", side_effect=mock_process_analysis_background)
def test_run_analysis_flow(mock_process):
    """
    Test the full analysis flow:
    1. Upload a file to /analysis
    2. Verify the background task was queued (mocked)
    3. Check status at /analysis/{id}/status
    4. Verify status is COMPLETED (thanks to mock)
    """
    assert TEST_TARGET_PATH.exists(), f"Test file not found at {TEST_TARGET_PATH}"

    with open(TEST_TARGET_PATH, "rb") as f:
        response = client.post(
            "/analysis",
            files={"file": ("test_target.tar", f, "application/x-tar")}
        )

    assert response.status_code == 202
    data = response.json()
    assert "analysis_id" in data
    analysis_id = data["analysis_id"]
    assert data["status"] == "PENDING"

    # Verify that process_analysis_background was called once
    mock_process.assert_called_once()
    call_args = mock_process.call_args
    assert call_args[0][0] == analysis_id  # First arg is analysis_id
    assert "test_target.tar" in call_args[0][2]  # Third arg is original_filename

    # Check status - should be COMPLETED now thanks to our mock
    response = client.get(f"/analysis/{analysis_id}/status")
    assert response.status_code == 200
    status_data = response.json()
    assert status_data["analysis_id"] == analysis_id
    assert status_data["status"] == "COMPLETED"

    # Verify we can also fetch the full analysis result
    response = client.get(f"/analysis/{analysis_id}")
    assert response.status_code == 200
    result = response.json()
    assert result["meta"]["analysis_id"] == analysis_id
    assert result["result"]["language"] == "Python"
