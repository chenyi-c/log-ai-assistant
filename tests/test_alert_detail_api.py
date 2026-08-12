from fastapi import HTTPException

from src.api.app import app, get_alert_detail


ANOMALY_DOC = {
    "event_id": "anom-1",
    "event_time": "2026-05-13T10:00:00Z",
    "detect_time": "2026-05-13T10:00:10Z",
    "tenant_id": "default",
    "user_id": "alice",
    "src_ip": "203.0.113.9",
    "source_type": "vpn",
    "risk_level": "high",
    "risk_score": 90,
    "risk_components": {"rule_score": 90},
    "rule_hits": ["新IP登录后短时间访问敏感资源"],
    "baseline_deviations": [],
    "reason_codes": ["new_source_then_sensitive_access"],
    "evidence": {"user_id": "alice", "src_ip": "203.0.113.9", "resource": "/api/export"},
    "related_event_ids": ["evt-login", "evt-export"],
    "ai_status": "analyzed",
    "status": "investigating",
    "created_at": "2026-05-13T10:00:10Z",
}

BASELINE_DOC = {
    "baseline_date": "2026-05-13",
    "tenant_id": "default",
    "user_id": "alice",
    "model_version": "baseline-v1",
    "trained_from": "2026-05-06",
    "trained_to": "2026-05-12",
    "sample_days": 7,
    "sample_count": 100,
    "baseline_confidence": 1.0,
    "who_profile": {"user_id": "alice"},
    "time_profile": {"active_hours": ["09:00-18:00"]},
    "location_profile": {"common_ips": ["10.0.0.7"]},
    "access_profile": {
        "common_user_agents": ["Chrome"],
        "common_resources": ["/home"],
        "avg_api_calls_per_minute": 2.0,
        "sensitive_access_rate": 0.0,
    },
    "volume_profile": {},
    "result_profile": {"failed_login_count_7d": 0},
    "why_profile": {},
    "fallback_level": "none",
    "created_at": "2026-05-13T09:00:00Z",
}

RELATED_LOGS = [
    {
        "event_id": "evt-login",
        "event_time": "2026-05-13T10:00:00Z",
        "ingest_time": "2026-05-13T10:00:05Z",
        "tenant_id": "default",
        "source_type": "vpn",
        "log_type": "login",
        "user_id": "alice",
        "src_ip": "203.0.113.9",
        "action": "login",
        "resource": None,
        "result": "success",
        "message": "VPN login success",
        "raw_log": "raw login line",
        "risk_tags": [],
        "attrs": {},
    },
    {
        "event_id": "evt-export",
        "event_time": "2026-05-13T10:02:00Z",
        "ingest_time": "2026-05-13T10:02:05Z",
        "tenant_id": "default",
        "source_type": "vpn",
        "log_type": "api_call",
        "user_id": "alice",
        "src_ip": "203.0.113.9",
        "action": "api_call",
        "resource": "/api/export",
        "result": "success",
        "message": "Export API called",
        "raw_log": "raw export line",
        "risk_tags": ["sensitive_resource"],
        "attrs": {},
    },
]

AI_DOC = {
    "judgement_id": "ai-1",
    "event_id": "anom-1",
    "created_at": "2026-05-13T10:03:00Z",
    "model_name": "mock-security-analyst",
    "attack_type": "账号接管",
    "risk_level": "high",
    "judgement": "New IP followed by export.",
    "key_reasons": ["new_source_then_sensitive_access"],
    "recommended_actions": ["Review account activity."],
    "confidence": 0.9,
    "feedback_suggestions": {},
    "raw_response": {},
    "is_mock": True,
}


class FakeAlertDetailStorage:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.anomaly: dict[str, object] | None = dict(ANOMALY_DOC)
        self.baseline: dict[str, object] | None = dict(BASELINE_DOC)
        self.related_logs: list[dict[str, object]] = list(RELATED_LOGS)
        self.ai: dict[str, object] | None = dict(AI_DOC)

    def get_anomaly(self, event_id: str):
        self.calls.append({"method": "get_anomaly", "event_id": event_id})
        return self.anomaly

    def get_user_baseline(self, user_id: str, *, tenant_id: str | None = None, baseline_date=None):
        self.calls.append({"method": "get_user_baseline", "user_id": user_id, "tenant_id": tenant_id})
        return self.baseline

    def list_logs_by_event_ids(self, event_ids):
        self.calls.append({"method": "list_logs_by_event_ids", "event_ids": list(event_ids)})
        return self.related_logs

    def get_latest_ai_judgement(self, event_id: str):
        self.calls.append({"method": "get_latest_ai_judgement", "event_id": event_id})
        return self.ai


def test_alert_detail_composes_alert_baseline_related_logs_ai_report_and_evidence_chain() -> None:
    storage = FakeAlertDetailStorage()

    response = get_alert_detail(event_id="anom-1", storage=storage)
    payload = response.model_dump(mode="json")

    assert payload["anomaly"]["event_id"] == "anom-1"
    assert payload["baseline"]["user_id"] == "alice"
    assert payload["ai_judgement"]["judgement_id"] == "ai-1"
    assert [item["event_id"] for item in payload["related_logs"]] == ["evt-login", "evt-export"]
    assert payload["evidence_chain"]["rule_hits"] == ["新IP登录后短时间访问敏感资源"]
    assert (
        "src_ip 203.0.113.9 is outside baseline location_profile.common_ips"
        in payload["evidence_chain"]["baseline_deviations"]
    )
    assert (
        "resource /api/export is outside baseline access_profile.common_resources"
        in payload["evidence_chain"]["baseline_deviations"]
    )
    assert "related logs: 2" in payload["evidence_chain"]["risk_reason"]

    assert storage.calls == [
        {"method": "get_anomaly", "event_id": "anom-1"},
        {"method": "get_user_baseline", "user_id": "alice", "tenant_id": "default"},
        {"method": "list_logs_by_event_ids", "event_ids": ["evt-login", "evt-export"]},
        {"method": "get_latest_ai_judgement", "event_id": "anom-1"},
    ]


def test_alert_detail_returns_empty_related_context_when_optional_docs_are_missing() -> None:
    storage = FakeAlertDetailStorage()
    storage.anomaly = dict(ANOMALY_DOC) | {"user_id": None, "related_event_ids": []}
    storage.ai = None

    response = get_alert_detail(event_id="anom-1", storage=storage)
    payload = response.model_dump(mode="json")

    assert payload["baseline"] == {}
    assert payload["related_logs"] == []
    assert payload["ai_judgement"] == {}
    assert payload["evidence_chain"]["baseline_deviations"] == []
    assert "baseline is missing" in payload["evidence_chain"]["risk_reason"]


def test_alert_detail_returns_clear_404_error_when_missing() -> None:
    storage = FakeAlertDetailStorage()
    storage.anomaly = None

    try:
        get_alert_detail(event_id="missing-alert", storage=storage)
    except HTTPException as exc:
        assert exc.status_code == 404
        assert exc.detail == {
            "code": "anomaly_not_found",
            "message": "Anomaly event not found",
            "details": {"table": "anomaly_events", "event_id": "missing-alert"},
        }
    else:
        raise AssertionError("expected HTTPException")


def test_alert_detail_openapi_binds_contract_and_error_shape() -> None:
    operation = app.openapi()["paths"]["/api/v1/anomalies/{event_id}"]["get"]

    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AnomalyDetailResponse"
    }
    assert operation["responses"]["404"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }
    assert operation["responses"]["500"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }
