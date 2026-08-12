from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.operations import acceptance
from src.operations.config import OperationsConfig


NOW = datetime(2026, 6, 15, 8, 0, tzinfo=timezone.utc)


class AcceptanceStorage:
    def __init__(self) -> None:
        self.saved = None

    def acceptance_scenario_rows(self, *, tenant_id, start_time=None, end_time=None):
        normal = [
            {
                "event_id": f"normal-{source}",
                "event_time": NOW,
                "source_type": source,
                "injected_label": "normal",
                "attack_chain_id": "",
            }
            for source in ("vpn", "api", "oa")
        ]
        attacks = [
            {
                "event_id": f"attack-{index}",
                "event_time": NOW + timedelta(seconds=index),
                "source_type": "api",
                "injected_label": label,
                "attack_chain_id": f"chain-{index}",
            }
            for index, label in enumerate(
                ("attack_credential_stuffing", "attack_account_takeover", "attack_data_exfiltration"),
                start=1,
            )
        ]
        anomalies = [
            {
                "event_id": f"alert-{index}",
                "event_time": NOW + timedelta(seconds=index),
                "detect_time": NOW + timedelta(seconds=index + 10),
                "risk_level": "high",
                "risk_score": 80,
                "attack_type": ("credential_stuffing", "account_takeover", "data_exfiltration")[index - 1],
                "attack_chain_id": f"chain-{index}",
                "related_event_ids": [f"attack-{index}"],
            }
            for index in range(1, 4)
        ]
        deliveries = [
            {"event_id": f"alert-{index}", "delivered_at": NOW + timedelta(seconds=index + 20)} for index in range(1, 4)
        ]
        judgements = [
            {
                "event_id": "alert-1",
                "model_name": "qwen-plus",
                "model_version": "real-v1",
                "is_mock": 0,
                "created_at": NOW,
            },
            {"event_id": "alert-2", "model_name": "mock", "model_version": "mock-v1", "is_mock": 1, "created_at": NOW},
        ]
        return {"logs": [*normal, *attacks], "anomalies": anomalies, "deliveries": deliveries, "judgements": judgements}

    def latest_baseline_model_version(self, _tenant_id):
        return "baseline-v2"

    def insert_acceptance_report(self, report, metrics):
        self.saved = (report, metrics)


def test_acceptance_reports_separate_rates_latency_and_real_mock_ai(tmp_path: Path, monkeypatch) -> None:
    thresholds = {
        "version": "acceptance-test",
        "normal_false_positive_rate_max": 0.05,
        "attack_detection_rate_min": 0.8,
        "high_risk_detection_rate_min": 0.8,
        "traceability_rate_min": 0.95,
        "precision_high_risk_min": 0.8,
        "attack_event_recall_min": 0.8,
        "risk_level_accuracy_min": 0.8,
        "detection_latency_p95_seconds_max": 120,
        "notification_latency_p95_seconds_max": 300,
    }
    threshold_path = tmp_path / "thresholds.json"
    threshold_path.write_text(json.dumps(thresholds), encoding="utf-8")
    cfg = OperationsConfig(
        timezone_name="UTC",
        lock_dir=tmp_path,
        manifest_path=tmp_path / "manifest.jsonl",
        threshold_path=threshold_path,
        scheduler_interval_seconds=60,
        max_attempts=3,
        retry_base_seconds=1,
        watermark_grace_minutes=0,
        notification_webhook_url="",
        notification_max_attempts=3,
        frontend_base_url="http://frontend",
    )
    monkeypatch.setattr(acceptance, "load_operations_config", lambda: cfg)
    monkeypatch.setattr(acceptance, "_git_commit", lambda: "abc123")
    monkeypatch.setattr(acceptance, "_compose_digest", lambda: "compose123")
    monkeypatch.setattr(acceptance, "_file_digest", lambda _path: "scenario123")
    storage = AcceptanceStorage()

    report, metrics = acceptance.evaluate_scenarios(storage)
    by_name = {metric.metric_name: metric for metric in metrics}

    assert report.status == "passed"
    assert report.normal_scenario_count == 3
    assert report.attack_scenario_count == 3
    assert by_name["normal_false_positive_rate"].value == 0
    assert by_name["attack_detection_rate"].value == 1
    assert by_name["high_risk_detection_rate"].value == 1
    assert by_name["traceability_rate"].value == 1
    assert by_name["precision_high_risk"].value == 1
    assert by_name["attack_event_recall"].value == 1
    assert by_name["attack_type_confusion_matrix"].details["credential_stuffing"]["credential_stuffing"] == 1
    assert by_name["risk_level_accuracy"].value == 1
    assert by_name["detection_latency_p95_seconds"].value == 10
    assert by_name["notification_latency_p95_seconds"].value == 10
    assert by_name["ai_real_coverage_rate"].details["is_mock"] is False
    assert by_name["ai_mock_coverage_rate"].details["is_mock"] is True
    assert report.ai_is_mock is False
    assert report.git_commit == "abc123"
