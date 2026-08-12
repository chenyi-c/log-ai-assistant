from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

import requests

from src.operations.config import OperationsConfig, load_operations_config
from src.schemas import AnomalyEvent, NotificationAttempt, NotificationOutbox


class NotificationStorage(Protocol):
    def enqueue_notification(self, item: NotificationOutbox | dict[str, Any]) -> dict[str, Any]: ...
    def get_notification(self, outbox_id: str) -> dict[str, Any] | None: ...
    def list_notifications(self, **kwargs: Any) -> tuple[list[dict[str, Any]], int]: ...
    def append_notification_state(self, item: NotificationOutbox | dict[str, Any]) -> None: ...
    def insert_notification_attempt(self, attempt: NotificationAttempt | dict[str, Any]) -> None: ...


class NotificationService:
    def __init__(self, storage: NotificationStorage, config: OperationsConfig | None = None) -> None:
        self.storage = storage
        self.config = config or load_operations_config()

    def enqueue_anomalies(self, anomalies: list[AnomalyEvent]) -> list[dict[str, Any]]:
        if not self.config.notification_webhook_url:
            return []
        enqueued: list[dict[str, Any]] = []
        for anomaly in anomalies:
            if anomaly.risk_level not in {"high", "critical"}:
                continue
            enqueued.append(self.enqueue_anomaly(anomaly))
        return enqueued

    def enqueue_anomaly(self, anomaly: AnomalyEvent) -> dict[str, Any]:
        destination = self.config.notification_webhook_url
        idempotency_key = notification_idempotency_key("webhook", anomaly.event_id, destination)
        now = datetime.now(timezone.utc)
        item = NotificationOutbox(
            outbox_id=f"out-{uuid.uuid4()}",
            idempotency_key=idempotency_key,
            event_id=anomaly.event_id,
            tenant_id=anomaly.tenant_id,
            channel="webhook",
            destination=destination,
            payload={
                "event_id": anomaly.event_id,
                "event_time": anomaly.event_time.isoformat(),
                "risk_level": anomaly.risk_level,
                "risk_score": anomaly.risk_score,
                "attack_type": anomaly.attack_type,
                "user_id": anomaly.user_id,
                "src_ip": anomaly.src_ip,
                "reason_codes": anomaly.reason_codes,
                "detail_url": f"{self.config.frontend_base_url}/?alert={anomaly.event_id}",
            },
            status="pending",
            next_attempt_at=now,
            created_at=now,
            updated_at=now,
        )
        return self.storage.enqueue_notification(item)

    def retry(self, outbox_id: str) -> dict[str, Any]:
        current = self.storage.get_notification(outbox_id)
        if not current:
            raise KeyError(outbox_id)
        now = datetime.now(timezone.utc)
        updated = NotificationOutbox.model_validate(
            {
                **current,
                "status": "pending",
                "next_attempt_at": now,
                "last_error": "",
                "updated_at": now,
                "delivered_at": None,
                "version": int(current.get("version") or 0) + 1,
            }
        )
        self.storage.append_notification_state(updated)
        return updated.model_dump(mode="python")


class NotificationWorker:
    def __init__(
        self,
        storage: NotificationStorage,
        config: OperationsConfig | None = None,
        sender: Callable[..., Any] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or load_operations_config()
        self.sender = sender or requests.post

    def deliver_due(self, *, limit: int = 100) -> dict[str, int]:
        now = datetime.now(timezone.utc)
        pending, _ = self.storage.list_notifications(status="pending", due_before=now, limit=limit, offset=0)
        retrying, _ = self.storage.list_notifications(status="retry_wait", due_before=now, limit=limit, offset=0)
        delivered = failed = 0
        for item in [*pending, *retrying][:limit]:
            if self.deliver_one(str(item["outbox_id"])):
                delivered += 1
            else:
                failed += 1
        return {"selected": delivered + failed, "delivered": delivered, "failed": failed}

    def deliver_one(self, outbox_id: str) -> bool:
        current = self.storage.get_notification(outbox_id)
        if not current:
            raise KeyError(outbox_id)
        if current.get("status") == "delivered":
            return True

        now = datetime.now(timezone.utc)
        attempt_no = int(current.get("attempt_count") or 0) + 1
        delivering = NotificationOutbox.model_validate(
            {
                **current,
                "status": "delivering",
                "attempt_count": attempt_no,
                "updated_at": now,
                "version": int(current.get("version") or 0) + 1,
            }
        )
        self.storage.append_notification_state(delivering)

        started = time.perf_counter()
        response_status: int | None = None
        response_body = ""
        error_code = ""
        error_message = ""
        success = False
        try:
            response = self.sender(
                delivering.destination,
                json=delivering.payload,
                headers={"Idempotency-Key": delivering.idempotency_key},
                timeout=10,
            )
            response_status = int(getattr(response, "status_code", 0) or 0)
            response_body = str(getattr(response, "text", ""))[:2000]
            success = 200 <= response_status < 300
            if not success:
                error_code = "webhook_http_error"
                error_message = f"webhook returned HTTP {response_status}"
        except Exception as exc:
            error_code = "webhook_request_failed"
            error_message = str(exc)

        finished = datetime.now(timezone.utc)
        duration_ms = int((time.perf_counter() - started) * 1000)
        self.storage.insert_notification_attempt(
            NotificationAttempt(
                attempt_id=f"nat-{uuid.uuid4()}",
                outbox_id=outbox_id,
                attempt=attempt_no,
                started_at=now,
                finished_at=finished,
                success=success,
                response_status=response_status,
                duration_ms=duration_ms,
                error_code=error_code,
                error_message=error_message,
                response_body=response_body,
            )
        )

        if success:
            status = "delivered"
            next_attempt_at = finished
            delivered_at = finished
            last_error = ""
        elif attempt_no >= self.config.notification_max_attempts:
            status = "dead_letter"
            next_attempt_at = finished
            delivered_at = None
            last_error = error_message
        else:
            status = "retry_wait"
            next_attempt_at = finished + timedelta(seconds=self._backoff_seconds(attempt_no))
            delivered_at = None
            last_error = error_message

        final = NotificationOutbox.model_validate(
            {
                **delivering.model_dump(mode="python"),
                "status": status,
                "next_attempt_at": next_attempt_at,
                "last_error": last_error,
                "updated_at": finished,
                "delivered_at": delivered_at,
                "version": delivering.version + 1,
            }
        )
        self.storage.append_notification_state(final)
        return success

    def _backoff_seconds(self, attempt: int) -> int:
        return min(3600, self.config.retry_base_seconds * (2 ** max(0, attempt - 1)))


def notification_idempotency_key(channel: str, event_id: str, destination: str) -> str:
    raw = f"{channel}:{event_id}:{destination}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
