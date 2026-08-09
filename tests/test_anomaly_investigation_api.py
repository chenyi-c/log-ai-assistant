"""Contract coverage for the synthetic, privacy-safe investigation pack."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, get_anomaly_review_store, get_storage
from src.detection.review import AnomalyReviewStore


@pytest.fixture
def client() -> TestClient:
    store = AnomalyReviewStore(clock=lambda: datetime(2026, 8, 9, tzinfo=timezone.utc))
    app.dependency_overrides[get_anomaly_review_store] = lambda: store
    app.dependency_overrides[get_storage] = lambda: _InvestigationStorage()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_anomaly_review_store, None)
        app.dependency_overrides.pop(get_storage, None)


class _InvestigationStorage:
    def get_anomaly(self, event_id: str) -> dict[str, object] | None:
        if event_id == "missing":
            return None
        return {
            "event_id": event_id,
            "risk_level": "high",
            "reason_codes": ["failed_login_spike"],
            "evidence": {
                "user_id": "demo.account",
                "src_ip": "203.0.113.10",
                "resource": "/vpn/login",
                "failed_count_5m": 5,
                "raw_log": "must-not-be-returned",
            },
            "related_event_ids": ["failed-user-005"],
        }


def test_investigation_pack_masks_identifiers_maps_attack_and_includes_pending_review(client: TestClient) -> None:
    response = client.get("/api/v1/anomalies/anom-demo/investigation")

    assert response.status_code == 200
    payload = response.json()
    assert payload["anomalyId"] == "anom-demo"
    assert payload["riskLevel"] == "high"
    assert payload["reasonCodes"] == ["failed_login_spike"]
    assert payload["sanitizedEvidence"] == {
        "user_id": "d***t",
        "src_ip": "203.0.***.***",
        "resource": "/vpn/***",
        "failed_count_5m": 5,
    }
    assert payload["attackTechniques"] == [
        {"techniqueId": "T1110", "name": "Brute Force", "source": "manual_attck_reference"}
    ]
    assert payload["whyMatched"] == {
        "timeWindow": "5m",
        "observedEventCount": 5,
        "threshold": 5,
        "relatedEventIds": ["failed-user-005"],
    }
    assert payload["reviewStatus"] == "pending"
    assert payload["reviewerNote"] is None
    assert payload["reviewedAt"] is None
    assert "raw_log" not in str(payload)


def test_investigation_pack_includes_latest_demo_review(client: TestClient) -> None:
    update = client.put(
        "/api/v1/anomalies/anom-demo/review",
        json={"status": "false_positive", "reviewer_note": "Synthetic test review."},
    )
    assert update.status_code == 200

    response = client.get("/api/v1/anomalies/anom-demo/investigation")

    assert response.status_code == 200
    assert response.json()["reviewStatus"] == "false_positive"
    assert response.json()["reviewerNote"] == "Synthetic test review."
    assert response.json()["reviewedAt"] == "2026-08-09T00:00:00Z"


def test_post_review_is_supported_for_the_investigation_demo_contract(client: TestClient) -> None:
    response = client.post(
        "/api/v1/anomalies/anom-demo/review",
        json={"status": "confirmed", "reviewer_note": "Synthetic POST review."},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "confirmed"


def test_investigation_pack_returns_404_for_missing_anomaly(client: TestClient) -> None:
    response = client.get("/api/v1/anomalies/missing/investigation")

    assert response.status_code == 404
