from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import json

from src.operations.config import OperationsConfig
from src.operations.runner import OperationsRunner, _quality_blockers


NOW = datetime(2026, 6, 15, 8, 0, tzinfo=timezone.utc)
TARGET = date(2026, 6, 14)


class RunStorage:
    def __init__(self) -> None:
        self.states: list[dict[str, Any]] = []

    def insert_task_run(self, run) -> None:
        self.states.append(run.model_dump(mode="python"))

    def successful_task_run(self, idempotency_key: str):
        matches = [
            row for row in self.states if row["idempotency_key"] == idempotency_key and row["status"] == "succeeded"
        ]
        return matches[-1] if matches else None

    def max_task_attempt(self, idempotency_key: str) -> int:
        return max(
            (int(row["attempt"]) for row in self.states if row["idempotency_key"] == idempotency_key),
            default=0,
        )

    def data_watermark(self, **_kwargs):
        return {"security_logs_count": 10, "distinct_event_count": 10}

    def get_task_run(self, run_id: str):
        matches = [row for row in self.states if row["run_id"] == run_id]
        return matches[-1] if matches else None


def config(tmp_path: Path, *, attempts: int = 3) -> OperationsConfig:
    return OperationsConfig(
        timezone_name="UTC",
        lock_dir=tmp_path / "locks",
        manifest_path=tmp_path / "manifest.jsonl",
        threshold_path=tmp_path / "thresholds.json",
        scheduler_interval_seconds=60,
        max_attempts=attempts,
        retry_base_seconds=1,
        watermark_grace_minutes=0,
        notification_webhook_url="",
        notification_max_attempts=3,
        frontend_base_url="http://frontend",
    )


class HandlerRunner(OperationsRunner):
    def __init__(self, *args, handler, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = handler

    def _handler(self, _task_name):
        return self.handler


def test_same_idempotency_key_returns_existing_success(tmp_path: Path) -> None:
    storage = RunStorage()
    calls = 0

    def handler(*_args):
        nonlocal calls
        calls += 1
        return {"row_count": 1}

    runner = HandlerRunner(
        storage,
        config(tmp_path),
        clock=lambda: NOW,
        sleep=lambda _seconds: None,
        handler=handler,
    )
    first = runner.run_task("scenario_evaluate", target_date=TARGET)
    second = runner.run_task("scenario_evaluate", target_date=TARGET)

    assert first.status == "succeeded"
    assert second.run_id == first.run_id
    assert calls == 1


def test_task_lock_is_available_on_the_current_platform(tmp_path: Path) -> None:
    runner = OperationsRunner(RunStorage(), config(tmp_path))

    with runner._task_lock("platform-lock"):
        assert (tmp_path / "locks" / "platform-lock.lock").exists()


def test_failed_task_retries_and_preserves_each_attempt(tmp_path: Path) -> None:
    storage = RunStorage()
    calls = 0

    def handler(*_args):
        nonlocal calls
        calls += 1
        if calls < 3:
            raise RuntimeError("temporary failure")
        return {"ok": True}

    runner = HandlerRunner(
        storage,
        config(tmp_path, attempts=3),
        clock=lambda: NOW,
        sleep=lambda _seconds: None,
        handler=handler,
    )
    result = runner.run_task("scenario_evaluate", target_date=TARGET)

    assert result.status == "succeeded"
    terminal = [row for row in storage.states if row["version"] == 2]
    assert [row["status"] for row in terminal] == ["failed", "failed", "succeeded"]
    assert [row["attempt"] for row in terminal] == [1, 2, 3]
    assert len({row["run_id"] for row in terminal}) == 3


def test_incomplete_watermark_blocks_output(tmp_path: Path) -> None:
    storage = RunStorage()
    storage.data_watermark = lambda **_kwargs: {"security_logs_count": 0, "distinct_event_count": 0}
    called = False

    def handler(*_args):
        nonlocal called
        called = True
        return {}

    runner = HandlerRunner(
        storage,
        config(tmp_path),
        clock=lambda: NOW,
        sleep=lambda _seconds: None,
        handler=handler,
    )
    result = runner.run_task("daily_feature_aggregate", target_date=TARGET)

    assert result.status == "needs_review"
    assert result.error_code == "input_watermark_incomplete"
    assert called is False


def test_consumer_lag_above_threshold_blocks_watermark(tmp_path: Path) -> None:
    storage = RunStorage()
    (tmp_path / "thresholds.json").write_text(
        json.dumps({"version": "test", "consumer_lag_max": 1000}), encoding="utf-8"
    )
    called = False

    def handler(*_args):
        nonlocal called
        called = True
        return {}

    runner = HandlerRunner(
        storage,
        config(tmp_path),
        clock=lambda: NOW,
        sleep=lambda _seconds: None,
        handler=handler,
        lag_probe=lambda: {"raw-consumer": 5000},
    )
    result = runner.run_task("daily_feature_aggregate", target_date=TARGET)

    assert result.status == "needs_review"
    assert result.error_code == "input_watermark_incomplete"
    assert result.input_watermark["consumer_lag"] == 5000
    assert "lag" in result.input_watermark["reason"]
    assert called is False


def test_quality_blockers_flags_low_event_id_traceability() -> None:
    metric = _quality_metric(event_id_traceability_rate=0.5)
    thresholds = {
        "raw_to_parsed_loss_rate_max": 0.01,
        "parse_error_rate_max": 0.01,
        "required_field_missing_rate_max": 0.01,
        "event_id_traceability_rate_min": 0.99,
    }

    blockers = _quality_blockers([metric], thresholds)

    assert blockers
    assert "event_id_traceability_rate" in blockers[0]["failed_checks"]


def _quality_metric(**overrides):
    from datetime import datetime, timezone

    from src.schemas import DataQualityMetric

    payload = {
        "metric_date": TARGET,
        "tenant_id": "default",
        "source_type": "api",
        "generated_count": 10,
        "raw_logs_count": 10,
        "parsed_logs_count": 10,
        "clickhouse_insert_count": 10,
        "security_logs_count": 10,
        "raw_size_bytes": 100,
        "table_size_bytes": 100,
        "compression_ratio": 1.0,
        "missing_event_time_rate": 0.0,
        "missing_user_id_rate": 0.0,
        "missing_src_ip_rate": 0.0,
        "missing_action_rate": 0.0,
        "missing_result_rate": 0.0,
        "parse_error_rate": 0.0,
        "created_at": datetime.now(timezone.utc),
    }
    payload.update(overrides)
    return DataQualityMetric(**payload)
