"""Contract coverage for the unified synthetic detection replay report."""

from src.detection.evaluation import run_detection_evaluation


def test_detection_evaluation_combines_rule_expectations_api_evidence_and_deduplication() -> None:
    report = run_detection_evaluation()

    assert report["version"] == "v1"
    assert report["metric"] == "synthetic_detection_regression"
    assert report["is_accuracy_metric"] is False
    assert report["summary"] == {"case_count": 10, "passed_case_count": 10, "failed_case_count": 0}

    failed_login = next(case for case in report["cases"] if case["scenario_name"] == "failed-login-user-spike")
    assert failed_login["input_event_count"] == 5
    assert failed_login["expected_rules"] == ["failed_login_spike"]
    assert failed_login["actual_rules"] == ["failed_login_spike"]
    assert failed_login["risk_level"] == "high"
    assert failed_login["anomaly_id"].startswith("anom-")
    assert failed_login["evidence"]["failed_count_5m"] == 5
    assert failed_login["deduplicated"] is True
    assert failed_login["trace_id"] == "detection-eval-v1-failed-login-user-spike"

    normal = next(case for case in report["cases"] if case["scenario_name"] == "normal-known-source-login")
    assert normal["anomaly_id"] is None
    assert normal["reason_codes"] == []
    assert normal["passed"] is True
