"""Regression contract for the synthetic, rule-level acceptance report."""

from src.detection.regression import run_rule_regression


def test_rule_regression_reports_expected_rules_evidence_and_pass_state() -> None:
    report = run_rule_regression()

    assert report["version"] == "v1"
    assert report["metric"] == "synthetic_rule_regression"
    assert report["is_accuracy_metric"] is False
    assert len(report["cases"]) == 10
    assert all(case["passed"] for case in report["cases"])

    failed_login = next(case for case in report["cases"] if case["scenario_id"] == "failed-login-user-spike")
    assert failed_login["input_summary"]["event_count"] == 5
    assert failed_login["expected"]["risk_level"] == "high"
    assert failed_login["expected"]["reason_codes"] == ["failed_login_spike"]
    assert failed_login["actual"]["evidence"]["failed_count_5m"] == 5

    normal = next(case for case in report["cases"] if case["scenario_id"] == "normal-known-source-login")
    assert normal["expected"]["risk_level"] == "low"
    assert normal["actual"]["anomaly_count"] == 0
