"""Acceptance coverage for the interview-ready anomaly detection demo."""

from src.detection.demo import run_demo


def test_demo_returns_reproducible_api_evidence_for_required_scenarios() -> None:
    report = run_demo()

    results = {item["scenario_id"]: item for item in report["scenarios"]}
    assert report["version"] == "v1"
    assert {
        "failed-login-user-spike",
        "credential-stuffing",
        "high-api-rate",
        "normal-known-source-login",
    } <= results.keys()

    failed_login = results["failed-login-user-spike"]
    assert failed_login["input_count"] == 5
    assert failed_login["anomaly_ids"]
    assert failed_login["api_evidence"] == failed_login["evidence"]

    normal = results["normal-known-source-login"]
    assert normal["anomaly_ids"] == []
    assert normal["api_evidence"] == []

    replay = report["deduplication"]
    assert replay["deduplicated"] is True
    assert replay["replayed_anomaly_count"] > replay["unique_anomaly_count"]
