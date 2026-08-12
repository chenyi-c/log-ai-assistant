"""API coverage for the demo-grade human anomaly review loop."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, get_anomaly_review_store, get_storage
from src.detection.review import AnomalyReviewStore


@pytest.fixture
def client() -> TestClient:
    store = AnomalyReviewStore(clock=lambda: datetime(2026, 8, 9, tzinfo=timezone.utc))
    app.dependency_overrides[get_anomaly_review_store] = lambda: store
    app.dependency_overrides[get_storage] = lambda: _ReviewStorage()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_anomaly_review_store, None)
        app.dependency_overrides.pop(get_storage, None)


class _ReviewStorage:
    def get_anomaly(self, event_id: str) -> dict[str, object]:
        return {
            "event_id": event_id,
            "reason_codes": ["failed_login_spike"],
            "evidence": {"failed_count_5m": 5, "raw_log": "must-not-be-stored"},
        }


@pytest.mark.parametrize("status", ["pending", "confirmed", "false_positive"])
def test_anomaly_review_round_trips_status_note_time_and_anomaly_id(client: TestClient, status: str) -> None:
    anomaly_id = f"anom-demo-{status}"
    create = client.put(
        f"/api/v1/anomalies/{anomaly_id}/review",
        json={"status": status, "reviewer_note": "Synthetic analyst review.", "reviewer": "demo-analyst"},
    )

    assert create.status_code == 200
    assert create.json() == {
        "anomalyId": anomaly_id,
        "status": status,
        "reviewerNote": "Synthetic analyst review.",
        "reviewer": "demo-analyst",
        "reviewedAt": "2026-08-09T00:00:00Z",
        "reasonCodes": ["failed_login_spike"],
        "evidence": {"failed_count_5m": 5},
    }

    query = client.get(f"/api/v1/anomalies/{anomaly_id}/review")
    assert query.status_code == 200
    assert query.json() == create.json()


def test_anomaly_review_requires_a_nonempty_note(client: TestClient) -> None:
    response = client.put(
        "/api/v1/anomalies/anom-demo-invalid/review",
        json={"status": "confirmed", "reviewer_note": ""},
    )

    assert response.status_code == 422


def test_anomaly_review_masks_direct_identifiers_in_returned_evidence(client: TestClient) -> None:
    class _IdentifierStorage:
        def get_anomaly(self, event_id: str) -> dict[str, object]:
            return {
                "event_id": event_id,
                "reason_codes": ["failed_login_spike"],
                "evidence": {
                    "src_ip": "203.0.113.10",
                    "user_id": "demo.account",
                    "resource": "/vpn/login",
                    "failed_count_5m": 5,
                },
            }

    from src.api.app import get_storage

    app.dependency_overrides[get_storage] = _IdentifierStorage
    try:
        response = client.put(
            "/api/v1/anomalies/anom-demo-identifiers/review",
            json={"status": "pending", "reviewer_note": "Synthetic review."},
        )
    finally:
        app.dependency_overrides[get_storage] = lambda: _ReviewStorage()

    assert response.status_code == 200
    assert response.json()["evidence"] == {
        "src_ip": "203.0.***.***",
        "user_id": "d***t",
        "resource": "/vpn/***",
        "failed_count_5m": 5,
    }
