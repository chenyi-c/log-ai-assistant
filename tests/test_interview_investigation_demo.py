"""Regression coverage for the no-key interview investigation replay."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import app
from src.detection.interview_demo import (
    render_interview_investigation_demo_markdown,
    run_interview_investigation_demo,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
JSON_GOLDEN = REPOSITORY_ROOT / "docs" / "evidence" / "interview-investigation-demo.json"
MARKDOWN_GOLDEN = REPOSITORY_ROOT / "docs" / "evidence" / "interview-investigation-demo.md"


def test_interview_demo_replays_detection_then_api_review_without_raw_logs() -> None:
    report = run_interview_investigation_demo()

    assert report["version"] == "v1"
    assert report["requiresExternalApiKey"] is False
    assert report["summary"]["selectedCaseCount"] == 5

    failed_login = next(item for item in report["cases"] if item["scenarioName"] == "failed-login-user-spike")
    assert failed_login["anomalyId"].startswith("anom-")
    assert failed_login["reasonCodes"] == ["failed_login_spike"]
    assert failed_login["deduplicated"] is True
    assert failed_login["apiReplay"]["beforeReviewStatus"] == "pending"
    assert failed_login["apiReplay"]["afterReviewStatus"] == "confirmed"
    assert failed_login["apiReplay"]["investigation"]["attackTechniques"][0]["techniqueId"] == "T1110"
    assert "raw_log" not in str(failed_login)

    credential_stuffing = next(item for item in report["cases"] if item["scenarioName"] == "credential-stuffing")
    assert credential_stuffing["sanitizedEvidence"]["distinct_users_5m"] == ["d***a", "d***b", "d***c", "d***d"]
    assert "demo.user.a" not in str(credential_stuffing)

    normal = next(item for item in report["cases"] if item["scenarioName"] == "normal-known-source-login")
    assert normal["anomalyId"] is None
    assert normal["normalControl"] is True
    assert normal["apiReplay"] is None


def test_demo_api_returns_the_repeatable_investigation_replay() -> None:
    response = TestClient(app).get("/api/v1/demo/investigation-replay")

    assert response.status_code == 200
    assert response.json()["summary"] == {"selectedCaseCount": 5, "apiReviewReplayCount": 1}


def test_committed_json_and_markdown_evidence_match_the_redacted_replay() -> None:
    report = run_interview_investigation_demo()
    markdown = render_interview_investigation_demo_markdown(report)
    json_golden = JSON_GOLDEN.read_text(encoding="utf-8")
    markdown_golden = MARKDOWN_GOLDEN.read_text(encoding="utf-8")

    anomaly_ids = [item["anomalyId"] for item in report["cases"] if item["anomalyId"]]
    assert anomaly_ids
    assert json.loads(json_golden) == report
    assert markdown_golden == markdown
    assert all(anomaly_id in markdown_golden for anomaly_id in anomaly_ids)
    assert json_golden.endswith("\n") and not json_golden.endswith("\n\n")
    assert markdown_golden.endswith("\n") and not markdown_golden.endswith("\n\n")

    combined = f"{json_golden}\n{markdown_golden}"
    for sensitive_value in ("demo.user.a", "demo.user.b", "demo.user.c", "demo.user.d", "203.0.113.42"):
        assert sensitive_value not in combined
    assert "raw_log" not in combined


def test_tester_container_includes_committed_evidence_goldens() -> None:
    root = Path(__file__).parents[1]
    dockerfile = (root / "docker" / "tester.Dockerfile").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")

    assert "COPY docs/evidence docs/evidence" in dockerfile
    assert "./docs/evidence:/app/docs/evidence:ro" in compose
