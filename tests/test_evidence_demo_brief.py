"""Contract coverage for a concise, no-key anomaly evidence briefing."""

from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import app
from src.detection.evidence_demo_brief import (
    build_evidence_demo_brief,
    render_evidence_demo_brief_markdown,
)


def test_brief_reports_synthetic_coverage_and_limitations_without_raw_logs() -> None:
    report = build_evidence_demo_brief()

    assert report["version"] == "v1"
    assert report["requires_external_api_key"] is False
    assert report["is_accuracy_metric"] is False
    assert report["summary"] == {
        "scenario_count": 10,
        "passed_scenario_count": 10,
        "normal_control_count": 2,
        "api_review_replay_count": 1,
    }
    assert "raw_log" not in str(report)
    assert "synthetic" in report["limitations"][0].lower()


def test_brief_markdown_and_api_expose_the_same_safe_demo_scope() -> None:
    markdown = render_evidence_demo_brief_markdown(build_evidence_demo_brief())
    response = TestClient(app).get("/api/v1/demo/evidence-brief")

    assert "# Local Anomaly Evidence Demo Brief" in markdown
    assert "not an accuracy measurement" in markdown
    assert response.status_code == 200
    assert response.json()["requires_external_api_key"] is False
