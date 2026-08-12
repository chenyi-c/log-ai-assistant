"""Reproducible, synthetic acceptance report for the anomaly-detection module."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.api.app import list_alerts
from src.detection.anomaly_builder import AnomalyEventBuilder
from src.detection.rules import DetectionContext, RuleEngine
from src.detection.worker import _dedupe_anomalies
from src.schemas import AnomalyEvent, NormalizedLog


SCENARIO_PATH = Path(__file__).parents[2] / "tests" / "fixtures" / "reproducible_anomaly_scenarios_v1.json"


class _ScenarioStorage:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items

    def list_anomalies(self, **_kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        return self.items, len(self.items)


def run_demo() -> dict[str, Any]:
    """Run every synthetic scenario and return only structured acceptance evidence."""
    scenarios = _load_scenarios()
    results = [_run_scenario(scenario) for scenario in scenarios]
    replayed = [anomaly for scenario in scenarios for anomaly in _detect(scenario)]
    unique = _dedupe_anomalies([*replayed, *replayed], set())
    return {
        "version": "v1",
        "sanitization": "Synthetic fixture only; no live logs, credentials, or external API calls.",
        "scenarios": results,
        "deduplication": {
            "replayed_anomaly_count": len(replayed) * 2,
            "unique_anomaly_count": len(unique),
            "deduplicated": len(unique) < len(replayed) * 2,
        },
    }


def _run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    logs = _materialize_logs(scenario)
    anomalies = _detect(scenario, logs)
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
        storage=_ScenarioStorage([anomaly.model_dump(mode="json") for anomaly in anomalies]),
    )
    return {
        "scenario_id": scenario["id"],
        "category": scenario["category"],
        "input_count": len(logs),
        "anomaly_ids": [anomaly.event_id for anomaly in anomalies],
        "reason_codes": [anomaly.reason_codes for anomaly in anomalies],
        "risk_levels": [anomaly.risk_level for anomaly in anomalies],
        "evidence": [anomaly.evidence for anomaly in anomalies],
        "api_evidence": [item.evidence for item in response.items],
    }


def _load_scenarios() -> list[dict[str, Any]]:
    with SCENARIO_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)["scenarios"]


def _detect(scenario: dict[str, Any], logs: list[NormalizedLog] | None = None) -> list[AnomalyEvent]:
    builder = AnomalyEventBuilder(clock=lambda: datetime(2026, 7, 1, tzinfo=timezone.utc))
    engine = RuleEngine(builder=builder)
    context = DetectionContext(**scenario.get("context", {}))
    anomalies: list[AnomalyEvent] = []
    for log in logs or _materialize_logs(scenario):
        anomalies.extend(engine.evaluate_log(log, context))
    return anomalies


def _materialize_logs(scenario: dict[str, Any]) -> list[NormalizedLog]:
    defaults = scenario["input"]["defaults"]
    logs: list[NormalizedLog] = []
    for sequence in scenario["input"]["sequences"]:
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

