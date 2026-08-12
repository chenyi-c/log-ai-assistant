"""Demo-only in-memory storage for analyst review labels on anomaly events."""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any, Callable

from src.schemas import AnomalyReviewRequest, AnomalyReviewResponse


class AnomalyReviewStore:
    """Keep the latest synthetic analyst label for each anomaly during a demo process."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._items: dict[str, AnomalyReviewResponse] = {}
        self._lock = Lock()

    def save(
        self,
        anomaly_id: str,
        request: AnomalyReviewRequest,
        *,
        reason_codes: list[str],
        evidence: dict[str, Any],
    ) -> AnomalyReviewResponse:
        """Upsert one review without persisting a reviewer identity system or raw log text."""
        review = AnomalyReviewResponse(
            anomaly_id=anomaly_id,
            status=request.status,
            reviewer_note=request.reviewer_note,
            reviewer=request.reviewer,
            reviewed_at=self._clock(),
            reason_codes=reason_codes,
            evidence=_safe_evidence(evidence),
        )
        with self._lock:
            self._items[anomaly_id] = review
        return review

    def get(self, anomaly_id: str) -> AnomalyReviewResponse | None:
        """Return the latest review label for one anomaly in this process."""
        with self._lock:
            return self._items.get(anomaly_id)


def _safe_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Drop raw payloads and mask direct identifiers in returned review evidence."""
    blocked = {"raw_log", "raw", "message", "payload", "content", "request_body"}

    def clean(key: str, value: Any) -> Any:
        lowered = key.lower()
        if lowered in blocked:
            return None
        if isinstance(value, dict):
            return {
                str(child_key): item
                for child_key, child_value in value.items()
                if (item := clean(str(child_key), child_value)) is not None
            }
        if isinstance(value, list):
            return [clean(key, item) for item in value]
        if lowered in {"src_ip", "ip", "source_ip"}:
            return _mask_ip(str(value))
        if lowered in {"user_id", "user", "account", "principal"}:
            return _mask_text(str(value))
        if lowered in {"resource", "resource_id", "object_id"}:
            return _mask_resource(str(value))
        return value

    return clean("evidence", evidence)


def _mask_text(value: str) -> str:
    return value if len(value) <= 2 else f"{value[0]}***{value[-1]}"


def _mask_ip(value: str) -> str:
    parts = value.split(".")
    return f"{parts[0]}.{parts[1]}.***.***" if len(parts) == 4 else "***"


def _mask_resource(value: str) -> str:
    parts = [part for part in value.split("/") if part]
    return f"/{parts[0]}/***" if parts else "***"
