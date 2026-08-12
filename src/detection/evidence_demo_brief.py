"""A compact, deterministic briefing over the existing synthetic demo artifacts."""

from __future__ import annotations

from typing import Any

from src.detection.evaluation import run_detection_evaluation
from src.detection.interview_demo import run_interview_investigation_demo


def build_evidence_demo_brief() -> dict[str, Any]:
    """Summarize fixed synthetic coverage without reading real logs or calling a model."""
    evaluation = run_detection_evaluation()
    interview = run_interview_investigation_demo()
    cases = evaluation["cases"]
    return {
        "version": "v1",
        "requires_external_api_key": False,
        "is_accuracy_metric": False,
        "source_scope": "fixed_synthetic_fixtures_and_local_api_replay",
        "summary": {
            "scenario_count": len(cases),
            "passed_scenario_count": sum(case["passed"] for case in cases),
            "normal_control_count": sum(case["anomaly_id"] is None for case in cases),
            "api_review_replay_count": interview["summary"]["apiReviewReplayCount"],
        },
        "rule_coverage": sorted(
            {rule for case in cases for rule in case["actual_rules"]}
        ),
        "limitations": [
            "This briefing replays fixed synthetic fixtures; it does not measure production detection accuracy.",
            "It does not read real logs, call a model, or replace analyst investigation.",
            "Only one selected synthetic anomaly is replayed through the API review flow.",
        ],
    }


def render_evidence_demo_brief_markdown(report: dict[str, Any]) -> str:
    """Render a compact interview artifact without raw event bodies or identifiers."""
    summary = report["summary"]
    lines = [
        "# Local Anomaly Evidence Demo Brief",
        "",
        "Fixed synthetic replay only; not an accuracy measurement, SOC/SIEM result, or production-data claim.",
        "",
        "## Coverage",
        f"- Synthetic scenarios: {summary['scenario_count']}",
        f"- Passing regression scenarios: {summary['passed_scenario_count']}",
        f"- Normal controls: {summary['normal_control_count']}",
        f"- API review replays: {summary['api_review_replay_count']}",
        f"- Rule hits covered: {', '.join(report['rule_coverage'])}",
        "",
        "## Limitations",
    ]
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"
