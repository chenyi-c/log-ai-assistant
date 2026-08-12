import importlib
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from src.api.app import app, create_daily_report, list_ai_reports, list_daily_reports
from src.schemas import DailyReport


api_app_module = importlib.import_module("src.api.app")


AI_REPORT_DOC = {
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

DAILY_REPORT_DOC = {
    "report_id": "default:2026-05-13",
    "date": "2026-05-13",
    "created_at": "2026-05-13T23:00:00Z",
    "overall_score": 85.0,
    "log_count": 1200,
    "alert_count": 15,
    "high_risk_count": 3,
    "major_risks": ["暴力破解", "账号接管"],
    "high_risk_users": ["alice", "bob"],
    "typical_alerts": [],
    "ai_summary": "今日共处理日志 1200 条。",
    "recommendation": "优先处置暴力破解相关事件。",
    "markdown": "# 每日安全态势简报",
}


class FakeStorage:
    def __init__(self, items=None, total=None):
        self.items = items if items is not None else []
        self.total = len(self.items) if total is None else total
        self.calls: list[dict] = []
        self.inserted_daily: list[dict] = []

    def list_ai_judgements(self, **kwargs):
        self.calls.append({"method": "list_ai_judgements", **kwargs})
        return self.items, self.total

    def list_daily_reports(self, **kwargs):
        self.calls.append({"method": "list_daily_reports", **kwargs})
        return self.items, self.total

    def insert_daily_report(self, report, *, tenant_id="default"):
        self.inserted_daily.append({"report": report, "tenant_id": tenant_id})


class FailingStorage(FakeStorage):
    def list_ai_judgements(self, **_kwargs):
        raise RuntimeError("clickhouse unavailable")

    def list_daily_reports(self, **_kwargs):
        raise RuntimeError("clickhouse unavailable")


def test_list_ai_reports_queries_clickhouse_with_pagination():
    storage = FakeStorage(items=[AI_REPORT_DOC], total=5)

    response = list_ai_reports(event_id="anom-1", limit=20, offset=10, storage=storage)
    payload = response.model_dump(mode="json")

    assert payload["items"][0]["judgement_id"] == "ai-1"
    assert response.total == 5
    assert response.limit == 20
    assert response.offset == 10
    assert storage.calls == [{"method": "list_ai_judgements", "event_id": "anom-1", "limit": 20, "offset": 10}]


def test_list_ai_reports_returns_standard_error_on_clickhouse_failure():
    with pytest.raises(HTTPException) as exc_info:
        list_ai_reports(event_id=None, limit=50, offset=0, storage=FailingStorage())

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail["code"] == "clickhouse_query_failed"
    assert exc_info.value.detail["details"]["table"] == "ai_judgements"


def test_list_daily_reports_queries_clickhouse_with_pagination():
    storage = FakeStorage(items=[DAILY_REPORT_DOC], total=3)

    response = list_daily_reports(tenant_id="default", limit=10, offset=0, storage=storage)
    payload = response.model_dump(mode="json")

    assert payload["items"][0]["report_id"] == "default:2026-05-13"
    assert response.total == 3
    assert response.limit == 10
    assert response.offset == 0
    assert storage.calls == [{"method": "list_daily_reports", "tenant_id": "default", "limit": 10, "offset": 0}]


def test_list_daily_reports_returns_standard_error_on_clickhouse_failure():
    with pytest.raises(HTTPException) as exc_info:
        list_daily_reports(tenant_id=None, limit=50, offset=0, storage=FailingStorage())

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail["code"] == "clickhouse_query_failed"
    assert exc_info.value.detail["details"]["table"] == "daily_security_reports"


def test_create_daily_report_generates_and_stores_report(monkeypatch):
    fake_report = DailyReport(
        report_id="daily-gen-1",
        date="2026-05-13",
        created_at=datetime(2026, 5, 13, 23, 0, 0, tzinfo=timezone.utc),
        overall_score=90.0,
        log_count=500,
        alert_count=5,
        high_risk_count=1,
        major_risks=["暴力破解"],
        high_risk_users=["alice"],
        typical_alerts=[],
        ai_summary="今日共处理日志 500 条。",
        recommendation="持续监控。",
        markdown="# 简报",
    )

    def fake_generate(storage, date_str=None):
        return fake_report

    monkeypatch.setattr(api_app_module, "generate_daily_report", fake_generate)
    storage = FakeStorage()

    response = create_daily_report(date="2026-05-13", tenant_id="default", storage=storage)

    assert response.report_id == "daily-gen-1"
    assert response.date == "2026-05-13"
    assert storage.inserted_daily == [{"report": fake_report, "tenant_id": "default"}]
    assert storage.calls == [
        {
            "method": "list_daily_reports",
            "tenant_id": "default",
            "start_date": datetime(2026, 5, 13, tzinfo=timezone.utc).date(),
            "end_date": datetime(2026, 5, 13, tzinfo=timezone.utc).date(),
            "limit": 1,
            "offset": 0,
        }
    ]


def test_create_daily_report_is_idempotent_for_existing_report(monkeypatch):
    def fake_generate(storage, date_str=None):
        raise AssertionError("existing daily report should be reused")

    monkeypatch.setattr(api_app_module, "generate_daily_report", fake_generate)
    storage = FakeStorage(items=[DAILY_REPORT_DOC], total=1)

    response = create_daily_report(date="2026-05-13", tenant_id="default", storage=storage)

    assert response.report_id == "default:2026-05-13"
    assert storage.inserted_daily == []


def test_create_daily_report_returns_error_on_invalid_date(monkeypatch):
    def fake_generate(storage, date_str=None):
        raise ValueError("time data 'bad-date' does not match format '%Y-%m-%d'")

    monkeypatch.setattr(api_app_module, "generate_daily_report", fake_generate)

    with pytest.raises(HTTPException) as exc_info:
        create_daily_report(date="bad-date", tenant_id="default", storage=FakeStorage())

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["code"] == "invalid_date"


def test_create_daily_report_returns_error_on_generation_failure(monkeypatch):
    def fake_generate(storage, date_str=None):
        raise RuntimeError("clickhouse unavailable")

    monkeypatch.setattr(api_app_module, "generate_daily_report", fake_generate)

    with pytest.raises(HTTPException) as exc_info:
        create_daily_report(date="2026-05-13", tenant_id="default", storage=FakeStorage())

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail["code"] == "daily_report_generation_failed"


def test_ai_reports_openapi_binds_contract():
    operation = app.openapi()["paths"]["/api/v1/ai/judgements"]["get"]

    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AIJudgementListResponse"
    }
    assert operation["responses"]["500"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }


def test_daily_reports_list_openapi_binds_contract():
    operation = app.openapi()["paths"]["/api/v1/reports/daily"]["get"]

    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/DailyReportListResponse"
    }
    assert operation["responses"]["500"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }


def test_daily_reports_create_openapi_binds_contract():
    operation = app.openapi()["paths"]["/api/v1/reports/daily"]["post"]

    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/DailyReport"
    }
    assert operation["responses"]["500"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }
