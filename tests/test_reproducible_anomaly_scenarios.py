"""Regression coverage for the sanitized anomaly-detection demo scenarios."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, get_storage, list_alerts
from src.detection.anomaly_builder import AnomalyEventBuilder
from src.detection.rules import DetectionContext, RuleEngine
from src.schemas import NormalizedLog


SCENARIO_PATH = Path(__file__).parent / "fixtures" / "reproducible_anomaly_scenarios_v1.json"
REQUIRED_CATEGORIES = {
    "failed_login_spike",
    "credential_stuffing",
    "high_api_rate",
    "sensitive_resource_access",
    "new_source_then_sensitive_access",
    "normal_behavior",
}


class ScenarioStorage:
    """Minimal storage adapter so the test covers the existing FastAPI response contract."""

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items

    def list_anomalies(self, **_kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        return self.items, len(self.items)


def _load_scenarios() -> list[dict[str, Any]]:
    with SCENARIO_PATH.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    assert payload["version"] == "v1"
    return payload["scenarios"]


def _materialize_logs(scenario: dict[str, Any]) -> list[NormalizedLog]:
    input_spec = scenario["input"]
    defaults = input_spec["defaults"]
    logs: list[NormalizedLog] = []
    for sequence in input_spec["sequences"]:
        start = datetime.fromisoformat(sequence["start_time"].replace("Z", "+00:00"))
        for index in range(sequence["count"]):
            event_time = start.timestamp() + index * sequence.get("interval_seconds", 1)
            payload = {
                **defaults,
                **sequence.get("overrides", {}),
                "event_id": f"{sequence['event_id_prefix']}-{index + 1:03d}",
                "event_time": datetime.fromtimestamp(event_time, tz=timezone.utc),
                "ingest_time": datetime.fromtimestamp(event_time, tz=timezone.utc),
            }
            logs.append(NormalizedLog.model_validate(payload))
    return logs


def _detect_scenario(scenario: dict[str, Any]):
    builder = AnomalyEventBuilder(clock=lambda: datetime(2026, 7, 1, tzinfo=timezone.utc))
    engine = RuleEngine(builder=builder)
    context = DetectionContext(**scenario.get("context", {}))
    anomalies = []
    for log in _materialize_logs(scenario):
        anomalies.extend(engine.evaluate_log(log, context))
    return anomalies


def _contains_expected_values(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def test_sanitized_scenario_catalog_has_required_coverage() -> None:
    scenarios = _load_scenarios()

    assert len(scenarios) >= 10
    assert REQUIRED_CATEGORIES <= {scenario["category"] for scenario in scenarios}
    assert len({scenario["id"] for scenario in scenarios}) == len(scenarios)
    for scenario in scenarios:
        assert scenario["input"]["sequences"]
        assert scenario["expected"]["target_anomaly_count"] >= 0
        assert scenario["expected"]["risk_level"] in {"low", "medium", "high", "critical"}
        assert "reason_codes" in scenario["expected"]
        assert "evidence" in scenario["expected"]
        assert "related_event_ids" in scenario["expected"]


@pytest.mark.parametrize("scenario", _load_scenarios(), ids=lambda item: item["id"])
def test_scenarios_flow_from_logs_to_rule_events_and_fastapi_results(scenario: dict[str, Any]) -> None:
    anomalies = _detect_scenario(scenario)
    expected = scenario["expected"]

    if expected["target_anomaly_count"] == 0:
        assert anomalies == []
    else:
        matching = [
            anomaly
            for anomaly in anomalies
            if set(expected["reason_codes"]).issubset(anomaly.reason_codes)
            and anomaly.risk_level == expected["risk_level"]
            and _contains_expected_values(anomaly.evidence, expected["evidence"])
            and set(expected["related_event_ids"]).issubset(anomaly.related_event_ids)
        ]
        assert matching, f"scenario {scenario['id']} did not produce its expected anomaly"
        assert len(matching) == expected["target_anomaly_count"]

    response = list_alerts(
        tenant_id=None,
        risk_level=None,
        user_id=None,
        src_ip=None,
        reason_code=None,
        ai_status=None,
        status=None,
        start_time=None,
        end_time=None,
        limit=200,
        offset=0,
        storage=ScenarioStorage([anomaly.model_dump(mode="json") for anomaly in anomalies]),
    )
    assert response.total == len(anomalies)
    assert [item.event_id for item in response.items] == [anomaly.event_id for anomaly in anomalies]

    app.dependency_overrides[get_storage] = lambda: ScenarioStorage(
        [anomaly.model_dump(mode="json") for anomaly in anomalies]
    )
    try:
        http_response = TestClient(app).get("/api/v1/anomalies", params={"limit": 200})
    finally:
        app.dependency_overrides.pop(get_storage, None)

    assert http_response.status_code == 200
    assert http_response.json()["total"] == len(anomalies)
