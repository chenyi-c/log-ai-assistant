"""Structured regression report derived from the synthetic anomaly scenarios."""

from __future__ import annotations

from typing import Any

from src.detection.demo import _detect, _load_scenarios, _materialize_logs
from src.schemas import AnomalyEvent


def run_rule_regression() -> dict[str, Any]:
    """Compare fixed scenario expectations with the current RuleEngine output."""
    cases = [_run_case(scenario) for scenario in _load_scenarios()]
    return {
        "version": "v1",
        "metric": "synthetic_rule_regression",
        "is_accuracy_metric": False,
        "sanitization": "Synthetic fixture only; summaries exclude account IDs, source IPs, and raw log text.",
        "cases": cases,
        "passed_case_count": sum(case["passed"] for case in cases),
        "failed_case_count": sum(not case["passed"] for case in cases),
    }


def _run_case(scenario: dict[str, Any]) -> dict[str, Any]:
    logs = _materialize_logs(scenario)
    anomalies = _detect(scenario, logs)
    expected = scenario["expected"]
    matched = _matching_anomalies(anomalies, expected)
    expected_count = expected["target_anomaly_count"]
    # A scenario can intentionally emit supporting events in addition to its named target.
    # The fixture's count is therefore the number of expected matches, matching its existing test contract.
    passed = (not anomalies if expected_count == 0 else len(matched) == expected_count)
    actual = _actual_summary(anomalies, matched)
    return {
        "scenario_id": scenario["id"],
        "rule_category": scenario["category"],
        "input_summary": _input_summary(logs),
        "expected": {
            "anomaly_count": expected_count,
            "risk_level": expected["risk_level"],
            "reason_codes": expected["reason_codes"],
            "evidence": expected["evidence"],
        },
        "actual": actual,
        "passed": passed,
    }


def _matching_anomalies(anomalies: list[AnomalyEvent], expected: dict[str, Any]) -> list[AnomalyEvent]:
    if expected["target_anomaly_count"] == 0:
        return []
    return [
        anomaly
        for anomaly in anomalies
        if anomaly.risk_level == expected["risk_level"]
        and set(expected["reason_codes"]).issubset(anomaly.reason_codes)
        and all(anomaly.evidence.get(key) == value for key, value in expected["evidence"].items())
        and set(expected["related_event_ids"]).issubset(anomaly.related_event_ids)
    ]


def _actual_summary(anomalies: list[AnomalyEvent], matched: list[AnomalyEvent]) -> dict[str, Any]:
    selected = matched[0] if matched else (anomalies[0] if anomalies else None)
    if selected is None:
        return {"anomaly_count": 0, "anomaly_ids": [], "risk_level": "low", "reason_codes": [], "evidence": {}}
    return {
        "anomaly_count": len(anomalies),
        "expected_match_count": len(matched),
        "anomaly_ids": [anomaly.event_id for anomaly in anomalies],
        "risk_level": selected.risk_level,
        "reason_codes": selected.reason_codes,
        "evidence": selected.evidence,
    }


def _input_summary(logs: list[Any]) -> dict[str, Any]:
    """Expose rule-relevant input shape without echoing synthetic identifiers or raw text."""
    return {
        "event_count": len(logs),
        "source_types": sorted({str(log.source_type) for log in logs}),
        "log_types": sorted({log.log_type for log in logs}),
        "actions": sorted({log.action for log in logs}),
        "resources": sorted({log.resource for log in logs if log.resource}),
        "results": sorted({str(log.result) for log in logs}),
    }
