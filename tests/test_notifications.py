from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.operations.config import OperationsConfig
from src.operations.notifications import NotificationService, NotificationWorker
from src.schemas import AnomalyEvent


NOW = datetime(2026, 6, 15, 8, 0, tzinfo=timezone.utc)


def config(tmp_path: Path, *, max_attempts: int = 3) -> OperationsConfig:
    return OperationsConfig(
        timezone_name="UTC",
        lock_dir=tmp_path,
        manifest_path=tmp_path / "manifest.jsonl",
        threshold_path=tmp_path / "thresholds.json",
        scheduler_interval_seconds=60,
        max_attempts=3,
        retry_base_seconds=1,
        watermark_grace_minutes=0,
        notification_webhook_url="http://webhook.test/alerts",
        notification_max_attempts=max_attempts,
        frontend_base_url="http://frontend",
    )


class NotificationStorage:
    def __init__(self) -> None:
        self.versions: list[dict[str, Any]] = []
        self.attempts: list[dict[str, Any]] = []

    def enqueue_notification(self, item):
        payload = item.model_dump(mode="python")
        existing = next((row for row in self.versions if row["idempotency_key"] == payload["idempotency_key"]), None)
        if existing:
            return existing
        self.versions.append(payload)
        return payload

    def get_notification(self, outbox_id):
        matches = [row for row in self.versions if row["outbox_id"] == outbox_id]
        return max(matches, key=lambda row: row["version"]) if matches else None

    def list_notifications(self, *, status=None, due_before=None, limit=50, offset=0, **_kwargs):
        latest = {}
        for row in self.versions:
            if row["outbox_id"] not in latest or row["version"] > latest[row["outbox_id"]]["version"]:
                latest[row["outbox_id"]] = row
        rows = [
            row
            for row in latest.values()
            if (status is None or row["status"] == status)
            and (due_before is None or row["next_attempt_at"] <= due_before)
        ]
        return rows[offset : offset + limit], len(rows)

    def append_notification_state(self, item):
        self.versions.append(item.model_dump(mode="python"))

    def insert_notification_attempt(self, attempt):
        self.attempts.append(attempt.model_dump(mode="python"))


def anomaly() -> AnomalyEvent:
    return AnomalyEvent(
        event_id="alert-1",
        event_time=NOW,
        detect_time=NOW,
        tenant_id="default",
        user_id="alice",
        src_ip="203.0.113.9",
        attack_type="account_takeover",
        risk_score=90,
        risk_level="critical",
        reason_codes=["new_source_then_sensitive_access"],
        created_at=NOW,
    )


class Response:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_high_risk_outbox_is_idempotent_and_payload_is_minimal(tmp_path: Path) -> None:
    storage = NotificationStorage()
    service = NotificationService(storage, config(tmp_path))
    first = service.enqueue_anomaly(anomaly())
    second = service.enqueue_anomaly(anomaly())

    assert first["outbox_id"] == second["outbox_id"]
    assert len(storage.versions) == 1
    assert first["payload"]["event_id"] == "alert-1"
    assert "raw_log" not in first["payload"]


def test_webhook_failure_uses_backoff_then_delivers(tmp_path: Path) -> None:
    storage = NotificationStorage()
    service = NotificationService(storage, config(tmp_path))
    item = service.enqueue_anomaly(anomaly())
    responses = iter([Response(503, "down"), Response(204)])
    worker = NotificationWorker(storage, config(tmp_path), sender=lambda *_args, **_kwargs: next(responses))

    assert worker.deliver_one(item["outbox_id"]) is False
    failed = storage.get_notification(item["outbox_id"])
    assert failed["status"] == "retry_wait"
    assert failed["next_attempt_at"] > failed["updated_at"]

    assert worker.deliver_one(item["outbox_id"]) is True
    delivered = storage.get_notification(item["outbox_id"])
    assert delivered["status"] == "delivered"
    assert len(storage.attempts) == 2


def test_dead_letter_can_be_manually_retried(tmp_path: Path) -> None:
    storage = NotificationStorage()
    cfg = config(tmp_path, max_attempts=1)
    service = NotificationService(storage, cfg)
    item = service.enqueue_anomaly(anomaly())
    worker = NotificationWorker(storage, cfg, sender=lambda *_args, **_kwargs: Response(500))

    assert worker.deliver_one(item["outbox_id"]) is False
    assert storage.get_notification(item["outbox_id"])["status"] == "dead_letter"
    retried = service.retry(item["outbox_id"])
    assert retried["status"] == "pending"
    assert retried["attempt_count"] == 1
