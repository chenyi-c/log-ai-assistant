"""Demo-only in-memory storage for analyst review labels on anomaly events."""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Callable

from src.schemas import AnomalyReviewRequest, AnomalyReviewResponse


class AnomalyReviewStore:
    """Keep the latest synthetic analyst label for each anomaly during a demo process."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._items: dict[str, AnomalyReviewResponse] = {}
        self._lock = Lock()

    def save(self, anomaly_id: str, request: AnomalyReviewRequest) -> AnomalyReviewResponse:
        """Upsert one review without persisting a reviewer identity system."""
        review = AnomalyReviewResponse(
            anomaly_id=anomaly_id,
            status=request.status,
            reviewer_note=request.reviewer_note,
            reviewer=request.reviewer,
            reviewed_at=self._clock(),
        )
        with self._lock:
            self._items[anomaly_id] = review
        return review

    def get(self, anomaly_id: str) -> AnomalyReviewResponse | None:
        """Return the latest review label for one anomaly in this process."""
        with self._lock:
            return self._items.get(anomaly_id)
