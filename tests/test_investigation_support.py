from datetime import datetime, timezone

from src.api.investigation_support import (
    build_ai_feedback_rows,
    build_ai_window_stats,
    build_evidence_chain,
    build_risk_reason,
    derive_related_log_window_stats,
    extract_baseline_deviations,
)
from src.schemas import AIJudgement


ALERT = {
    "event_id": "anom-1",
    "event_time": "2026-05-13T20:00:00Z",
    "tenant_id": "default",
    "user_id": "alice",
    "src_ip": "203.0.113.9",
    "risk_level": "high",
    "risk_score": 90,
    "risk_components": {"rule_score": 90},
    "rule_hits": ["new source then sensitive access"],
    "reason_codes": ["new_source_then_sensitive_access"],
    "evidence": {"src_ip": "203.0.113.9", "resource": "/api/export"},
    "ai_status": "pending",
}
BASELINE = {
    "location_profile": {"common_ips": ["10.0.0.7"]},
    "time_profile": {"active_hours": ["09:00-18:00"]},
    "access_profile": {"common_resources": ["/home"]},
    "result_profile": {},
}
RELATED_LOGS = [
    {
        "event_time": "2026-05-13T20:00:00Z",
        "action": "login",
        "result": "fail",
        "src_ip": "203.0.113.9",
        "resource": "",
        "risk_tags": [],
    },
    {
        "event_time": "2026-05-13T20:02:00Z",
        "action": "api_call",
        "result": "success",
        "src_ip": "203.0.113.9",
        "resource": "/api/export",
        "risk_tags": ["sensitive_resource"],
    },
]


def test_build_ai_feedback_rows_normalizes_type_target_and_confidence() -> None:
    report = AIJudgement(
        judgement_id="judge-1",
        event_id="anom-1",
        created_at=datetime(2026, 5, 13, 20, 3, tzinfo=timezone.utc),
        model_name="mock-security-analyst",
        attack_type="account_takeover",
        risk_level="high",
        judgement="Suspicious sequence.",
        key_reasons=["new source"],
        recommended_actions=["Review account."],
        confidence=0.9,
        feedback_suggestions={},
        raw_response={},
        is_mock=True,
    )

    rows = build_ai_feedback_rows(
        report,
        ALERT,
        {
            "rule_weight": "Raise the rule weight.",
            "false_positive": {
                "suggestion": "Known service account.",
                "confidence": 2,
            },
        },
    )

    assert [(row.feedback_type, row.target_component, row.confidence) for row in rows] == [
        ("rule_weight", "rule", 0.9),
        ("false_positive", "scoring", 1.0),
    ]
    assert all(row.review_status == "pending" for row in rows)


def test_evidence_chain_assembles_baseline_deviations_and_risk_reason() -> None:
    deviations = extract_baseline_deviations(ALERT, BASELINE, RELATED_LOGS)
    chain = build_evidence_chain(ALERT, BASELINE, RELATED_LOGS)

    assert "src_ip 203.0.113.9 is outside baseline location_profile.common_ips" in deviations
    assert "event hour 20:00 is outside baseline time_profile.active_hours" in deviations
    assert "resource /api/export is outside baseline access_profile.common_resources" in deviations
    assert chain.baseline_deviations == deviations
    assert chain.reason_codes == ["new_source_then_sensitive_access"]
    assert "related logs: 2" in chain.risk_reason


def test_build_risk_reason_labels_missing_baseline() -> None:
    reason = build_risk_reason(ALERT, ["rule hit"], [], [], has_baseline=False)

    assert "Risk level high" in reason
    assert "baseline is missing" in reason


def test_window_statistics_derive_counts_and_prefer_explicit_evidence() -> None:
    derived = derive_related_log_window_stats(RELATED_LOGS)

    assert derived["failed_login_count"] == 1
    assert derived["sensitive_access_count"] == 1
    assert derived["unique_src_ip_count"] == 1
    assert derived["window_seconds"] == 120
    assert build_ai_window_stats(
        evidence={"window_stats": {"failed_login_count_5m": 7}},
        related_logs=RELATED_LOGS,
        related_event_ids=[],
        storage=object(),
    ) == {"failed_login_count_5m": 7}
