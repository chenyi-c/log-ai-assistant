"""Unified synthetic replay report for the anomaly-detection portfolio module."""

from __future__ import annotations

from typing import Any

from src.detection.demo import _detect, _load_scenarios
from src.detection.regression import run_rule_regression
from src.detection.worker import _dedupe_anomalies


def run_detection_evaluation() -> dict[str, Any]:
    """Replay fixed synthetic scenarios and combine expected rules, evidence, and deduplication checks."""
    regression_cases = {case["scenario_id"]: case for case in run_rule_regression()["cases"]}
    cases = [_evaluation_case(scenario, regression_cases[scenario["id"]]) for scenario in _load_scenarios()]
    return {
        "version": "v1",
        "metric": "synthetic_detection_regression",
        "is_accuracy_metric": False,
        "sanitization": "Synthetic fixture only; no live logs, credentials, or raw log bodies are read.",
        "summary": {
            "case_count": len(cases),
            "passed_case_count": sum(case["passed"] for case in cases),
            "failed_case_count": sum(not case["passed"] for case in cases),
        },
        "cases": cases,
    }


def _evaluation_case(scenario: dict[str, Any], regression_case: dict[str, Any]) -> dict[str, Any]:
    anomalies = _detect(scenario)
    unique = _dedupe_anomalies([*anomalies, *anomalies], set())
    actual = regression_case["actual"]
    return {
        "trace_id": f"detection-eval-v1-{scenario['id']}",
        "scenario_name": scenario["id"],
        "input_event_count": regression_case["input_summary"]["event_count"],
        "expected_rules": regression_case["expected"]["reason_codes"],
        "actual_rules": actual["reason_codes"],
        "risk_level": actual["risk_level"],
        "anomaly_id": actual["anomaly_ids"][0] if actual["anomaly_ids"] else None,
        "reason_codes": actual["reason_codes"],
        "evidence": actual["evidence"],
        "deduplicated": len(unique) < len(anomalies) * 2 if anomalies else True,
        "passed": regression_case["passed"],
    }
