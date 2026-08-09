"""API coverage for the demo-grade human anomaly review loop."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, get_anomaly_review_store
from src.detection.review import AnomalyReviewStore


@pytest.fixture
def client() -> TestClient:
    store = AnomalyReviewStore(clock=lambda: datetime(2026, 8, 9, tzinfo=timezone.utc))
    app.dependency_overrides[get_anomaly_review_store] = lambda: store
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_anomaly_review_store, None)


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
