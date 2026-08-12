"""Regression coverage for a replayable synthetic investigation package."""

from src.detection.investigation import run_investigation_pack


def test_investigation_pack_covers_all_scenarios_without_raw_log_bodies() -> None:
    report = run_investigation_pack()

    assert report["version"] == "v1"
    assert report["is_accuracy_metric"] is False
    assert report["summary"] == {"case_count": 10, "investigation_count": 8, "passed_case_count": 10}

    failed_login = next(item for item in report["cases"] if item["scenarioName"] == "failed-login-user-spike")
    assert failed_login["deduplicated"] is True
    assert failed_login["timeline"][0] == {"eventId": "failed-user-001", "eventTime": "2026-07-01T10:00:00Z", "action": "login", "result": "fail"}
    assert failed_login["investigation"]["attackTechniques"][0]["techniqueId"] == "T1110"
    assert failed_login["investigation"]["sanitizedEvidence"]["user_id"] == "d***t"
    assert "raw_log" not in str(failed_login)

    normal = next(item for item in report["cases"] if item["scenarioName"] == "normal-known-source-login")
    assert normal["investigation"] is None
    assert normal["deduplicated"] is True
