from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

import pytest

from src.schemas import AIFeedback, AIJudgement, BaselineOverride, DataQualityMetric
from src.storage.clickhouse_client import (
    AI_FEEDBACK_COLUMNS,
    AI_JUDGEMENT_COLUMNS,
    BASELINE_COLUMNS,
    BASELINE_OVERRIDE_COLUMNS,
    DATA_QUALITY_COLUMNS,
    DAILY_REPORT_COLUMNS,
    LOG_COLUMNS,
    ANOMALY_COLUMNS,
    ClickHouseStorage,
)


class QueryResult:
    def __init__(self, rows: list[tuple[Any, ...]], columns: list[str] | tuple[str, ...] | None = None) -> None:
        self.result_rows = rows
        self.column_names = list(columns or [])


class FakeClickHouseClient:
    def __init__(self, responses: list[QueryResult]) -> None:
        self.responses = responses
        self.queries: list[dict[str, Any]] = []
        self.inserts: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryResult:
        self.queries.append({"sql": _compact_sql(sql), "parameters": parameters or {}})
        return self.responses.pop(0)

    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None:
        self.inserts.append({"table": table, "data": data, "column_names": column_names})

    def command(self, sql: str, parameters: dict[str, Any] | None = None) -> None:
        self.commands.append({"sql": _compact_sql(sql), "parameters": parameters or {}})


def test_list_logs_queries_clickhouse_with_filters_and_normalizes_json() -> None:
    start = datetime(2026, 5, 13, 9, 0, tzinfo=timezone.utc)
    end = datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc)
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [
                    _row(
                        LOG_COLUMNS,
                        event_id="evt-1",
                        event_time=start,
                        ingest_time=end,
                        tenant_id="default",
                        source_type="vpn",
                        log_type="login",
                        user_id="alice",
                        src_ip="10.0.0.7",
                        geo='{"country":"CN"}',
                        action="login",
                        result="fail",
                        message="VPN login failed",
                        raw_log="raw vpn line",
                        risk_tags=["failed_login"],
                        attrs='{"vpn_result":"bad_password"}',
                    )
                ],
                LOG_COLUMNS,
            ),
            QueryResult([(7,)]),
        ]
    )
    storage = ClickHouseStorage(client=fake)

    items, total = storage.list_logs(
        tenant_id="default",
        source_type="vpn",
        user_id="alice",
        src_ip="10.0.0.7",
        result="fail",
        start_time=start,
        end_time=end,
        limit=25,
        offset=50,
    )

    assert total == 7
    assert items[0]["event_id"] == "evt-1"
    assert items[0]["geo"] == {"country": "CN"}
    assert items[0]["attrs"] == {"vpn_result": "bad_password"}
    assert "FROM security_logs" in fake.queries[0]["sql"]
    assert "tenant_id = {tenant_id:String}" in fake.queries[0]["sql"]
    assert "event_time >= {start_time:DateTime64(3)}" in fake.queries[0]["sql"]
    assert "LIMIT {limit:UInt64} OFFSET {offset:UInt64}" in fake.queries[0]["sql"]
    assert fake.queries[0]["parameters"] == {
        "tenant_id": "default",
        "source_type": "vpn",
        "user_id": "alice",
        "src_ip": "10.0.0.7",
        "result": "fail",
        "start_time": start,
        "end_time": end,
        "limit": 25,
        "offset": 50,
    }


def test_get_log_returns_none_when_event_is_missing() -> None:
    storage = ClickHouseStorage(client=FakeClickHouseClient([QueryResult([], LOG_COLUMNS)]))

    assert storage.get_log("missing") is None


def test_existing_anomaly_ids_queries_only_requested_ids() -> None:
    fake = FakeClickHouseClient([QueryResult([("anom-1",), ("anom-3",)], ["event_id"])])
    storage = ClickHouseStorage(client=fake)

    existing = storage.existing_anomaly_ids(["anom-1", "anom-2", "anom-3"])

    assert existing == {"anom-1", "anom-3"}
    assert "FROM anomaly_events" in fake.queries[0]["sql"]
    assert "event_id IN {event_ids:Array(String)}" in fake.queries[0]["sql"]
    assert fake.queries[0]["parameters"] == {"event_ids": ["anom-1", "anom-2", "anom-3"]}


def test_aggregate_logs_uses_allowed_groups_and_metrics() -> None:
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [("alice", "fail", 3, 1)],
                ["user_id", "result", "count", "unique_src_ips"],
            )
        ]
    )
    storage = ClickHouseStorage(client=fake)

    rows = storage.aggregate_logs(
        filters={"tenant_id": "default", "source_type": "vpn"},
        group_by=["user_id", "result"],
        metrics=["count", "unique_src_ips"],
        limit=10,
    )

    assert rows == [{"user_id": "alice", "result": "fail", "count": 3, "unique_src_ips": 1}]
    assert "GROUP BY user_id, result" in fake.queries[0]["sql"]
    assert "uniqExact(src_ip) AS unique_src_ips" in fake.queries[0]["sql"]
    assert fake.queries[0]["parameters"] == {
        "tenant_id": "default",
        "source_type": "vpn",
        "limit": 10,
    }


def test_aggregate_logs_rejects_unknown_sql_fields() -> None:
    storage = ClickHouseStorage(client=FakeClickHouseClient([]))

    with pytest.raises(ValueError, match="Unsupported group_by"):
        storage.aggregate_logs(group_by=["raw_log"])

    with pytest.raises(ValueError, match="Unsupported log filters"):
        storage.aggregate_logs(filters={"raw_log": "anything"})


def test_list_anomalies_supports_reason_code_and_json_fields() -> None:
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [
                    _row(
                        ANOMALY_COLUMNS,
                        event_id="anom-1",
                        event_time=datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc),
                        detect_time=datetime(2026, 5, 13, 10, 1, tzinfo=timezone.utc),
                        tenant_id="default",
                        user_id="alice",
                        risk_score=88.5,
                        risk_level="high",
                        risk_components='{"rule":60,"baseline":28.5}',
                        rule_hits=["new ip"],
                        baseline_deviations='[{"feature":"src_ip"}]',
                        reason_codes=["new_source_ip"],
                        evidence='{"src_ip":"10.0.0.7"}',
                        related_event_ids=["evt-1"],
                        ai_status="pending",
                        status="new",
                        created_at=datetime(2026, 5, 13, 10, 1, tzinfo=timezone.utc),
                    )
                ],
                ANOMALY_COLUMNS,
            ),
            QueryResult([(1,)]),
        ]
    )
    storage = ClickHouseStorage(client=fake)

    items, total = storage.list_anomalies(risk_level="high", reason_code="new_source_ip")

    assert total == 1
    assert items[0]["risk_components"] == {"rule": 60, "baseline": 28.5}
    assert items[0]["baseline_deviations"] == [{"feature": "src_ip"}]
    assert items[0]["evidence"] == {"src_ip": "10.0.0.7"}
    assert "has(reason_codes, {reason_code:String})" in fake.queries[0]["sql"]
    assert fake.queries[0]["parameters"]["reason_code"] == "new_source_ip"


def test_list_user_baselines_groups_feature_rows_into_profiles() -> None:
    baseline_day = date(2026, 5, 13)
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [
                    _row(
                        BASELINE_COLUMNS,
                        baseline_date=baseline_day,
                        tenant_id="default",
                        user_id="alice",
                        profile_group="time",
                        feature_name="active_hours",
                        common_values=["09:00-18:00"],
                        value_histogram='{"09":10}',
                        sample_days=7,
                        sample_count=120,
                        baseline_confidence=0.82,
                        trained_from=date(2026, 5, 1),
                        trained_to=date(2026, 5, 12),
                        fallback_level="none",
                        model_version="baseline-v1",
                        created_at=datetime(2026, 5, 13, 1, 0, tzinfo=timezone.utc),
                    ),
                    _row(
                        BASELINE_COLUMNS,
                        baseline_date=baseline_day,
                        tenant_id="default",
                        user_id="alice",
                        profile_group="location",
                        feature_name="common_ips",
                        common_values=["10.0.0.7"],
                        value_histogram='{"10.0.0.7":8}',
                        sample_days=7,
                        sample_count=120,
                        baseline_confidence=0.82,
                        trained_from=date(2026, 5, 1),
                        trained_to=date(2026, 5, 12),
                        fallback_level="none",
                        model_version="baseline-v1",
                        created_at=datetime(2026, 5, 13, 1, 0, tzinfo=timezone.utc),
                    ),
                ],
                BASELINE_COLUMNS,
            ),
            QueryResult([(1,)]),
        ]
    )
    storage = ClickHouseStorage(client=fake)

    items, total = storage.list_user_baselines(tenant_id="default", user_id="alice")

    assert total == 1
    assert items[0]["user_id"] == "alice"
    assert items[0]["time_profile"]["active_hours"]["common_values"] == ["09:00-18:00"]
    assert items[0]["location_profile"]["common_ips"]["value_histogram"] == {"10.0.0.7": 8}
    assert "WITH baseline_keys AS" in fake.queries[0]["sql"]


def test_ai_judgement_and_feedback_inserts_use_table_columns_and_json_strings() -> None:
    now = datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc)
    fake = FakeClickHouseClient([])
    storage = ClickHouseStorage(client=fake)

    storage.insert_ai_judgement(
        AIJudgement(
            judgement_id="ai-1",
            event_id="anom-1",
            created_at=now,
            model_name="mock-security-analyst",
            risk_level="high",
            attack_type="account_takeover",
            judgement="Suspicious login.",
            key_reasons=["new source"],
            recommended_actions=["Reset password"],
            confidence=0.9,
            feedback_suggestions={"rule_weight": "increase"},
            raw_response={"mock": True},
            is_mock=True,
        )
    )
    storage.insert_feedback(
        AIFeedback(
            feedback_id="fb-1",
            event_id="anom-1",
            tenant_id="default",
            user_id=None,
            feedback_type="false_positive",
            suggestion="Lower score for this pattern.",
            target_component="scoring",
            confidence=0.7,
            created_at=now,
        )
    )

    assert fake.inserts[0]["table"] == "ai_judgements"
    assert fake.inserts[0]["column_names"] == list(AI_JUDGEMENT_COLUMNS)
    judgement_row = dict(zip(AI_JUDGEMENT_COLUMNS, fake.inserts[0]["data"][0]))
    assert judgement_row["feedback_suggestions"] == '{"rule_weight":"increase"}'
    assert judgement_row["raw_response"] == '{"mock":true}'
    assert judgement_row["is_mock"] == 1

    assert fake.inserts[1]["table"] == "ai_feedback"
    assert fake.inserts[1]["column_names"] == list(AI_FEEDBACK_COLUMNS)
    feedback_row = dict(zip(AI_FEEDBACK_COLUMNS, fake.inserts[1]["data"][0]))
    assert feedback_row["judgement_id"] == ""
    assert feedback_row["review_status"] == "pending"


def test_baseline_override_insert_serializes_structured_value() -> None:
    fake = FakeClickHouseClient([])
    storage = ClickHouseStorage(client=fake)
    now = datetime(2026, 6, 15, 8, 0, tzinfo=timezone.utc)

    storage.insert_baseline_override(
        BaselineOverride(
            override_id="override-1",
            tenant_id="default",
            user_id="alice",
            profile_group="access",
            feature_name="common_resources",
            period_type="month_phase",
            period_key="month_end",
            merge_mode="append",
            override_value={"common_values": ["/api/reports/export"]},
            source_type="ai_feedback",
            source_feedback_id="fb-1",
            reason="confirmed month-end export",
            status="active",
            effective_from=now,
            created_by="ai-feedback-review",
            reviewed_by="reviewer",
            reviewed_at=now,
            model_version="baseline-effective-1",
            created_at=now,
            updated_at=now,
        )
    )

    assert fake.inserts[0]["table"] == "ueba_baseline_overrides"
    assert fake.inserts[0]["column_names"] == list(BASELINE_OVERRIDE_COLUMNS)
    row = dict(zip(BASELINE_OVERRIDE_COLUMNS, fake.inserts[0]["data"][0]))
    assert row["override_value"] == '{"common_values":["/api/reports/export"]}'
    assert row["source_feedback_id"] == "fb-1"


def test_data_quality_metric_insert_uses_table_columns() -> None:
    now = datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc)
    fake = FakeClickHouseClient([])
    storage = ClickHouseStorage(client=fake)

    storage.insert_data_quality_metrics(
        [
            DataQualityMetric(
                metric_date=date(2026, 5, 13),
                tenant_id="default",
                source_type="api",
                generated_count=10,
                injected_anomaly_count=2,
                injected_high_risk_count=1,
                raw_logs_count=10,
                parsed_logs_count=9,
                clickhouse_insert_count=9,
                security_logs_count=9,
                raw_size_bytes=1000,
                table_size_bytes=500,
                compression_ratio=2.0,
                missing_event_time_rate=0,
                missing_user_id_rate=0.1,
                missing_src_ip_rate=0,
                missing_action_rate=0,
                missing_result_rate=0,
                parse_error_rate=0.1,
                created_at=now,
            )
        ]
    )

    assert fake.inserts[0]["table"] == "data_quality_metrics"
    assert fake.inserts[0]["column_names"] == list(DATA_QUALITY_COLUMNS)
    row = dict(zip(DATA_QUALITY_COLUMNS, fake.inserts[0]["data"][0]))
    assert row["source_type"] == "api"
    assert row["generated_count"] == 10
    assert row["compression_ratio"] == 2.0


def test_security_log_quality_stats_queries_by_event_ids() -> None:
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [(2, 0, 1, 0, 0, 0, 1)],
                [
                    "security_logs_count",
                    "missing_event_time_count",
                    "missing_user_id_count",
                    "missing_src_ip_count",
                    "missing_action_count",
                    "missing_result_count",
                    "parse_error_count",
                ],
            )
        ]
    )
    storage = ClickHouseStorage(client=fake)

    stats = storage.security_log_quality_stats(["evt-1", "evt-2"])

    assert stats["security_logs_count"] == 2
    assert stats["missing_user_id_count"] == 1
    assert stats["parse_error_count"] == 1
    assert "FROM security_logs FINAL WHERE event_id IN {event_ids:Array(String)}" in fake.queries[0]["sql"]
    assert fake.queries[0]["parameters"] == {"event_ids": ["evt-1", "evt-2"]}


def test_security_log_quality_stats_falls_back_when_final_is_unsupported() -> None:
    class FinalFailClient(FakeClickHouseClient):
        def query(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryResult:
            self.queries.append({"sql": _compact_sql(sql), "parameters": parameters or {}})
            if "FINAL" in sql:
                raise RuntimeError("Storage MergeTree doesn't support FINAL")
            return QueryResult(
                [(1, 0, 0, 0, 0, 0, 0)],
                [
                    "security_logs_count",
                    "missing_event_time_count",
                    "missing_user_id_count",
                    "missing_src_ip_count",
                    "missing_action_count",
                    "missing_result_count",
                    "parse_error_count",
                ],
            )

    fake = FinalFailClient([])
    storage = ClickHouseStorage(client=fake)

    stats = storage.security_log_quality_stats(["evt-1"])

    assert stats["security_logs_count"] == 1
    assert "FROM security_logs FINAL" in fake.queries[0]["sql"]
    assert "FROM security_logs WHERE event_id IN" in fake.queries[1]["sql"]


def test_list_daily_reports_maps_clickhouse_report_shape_to_api_shape() -> None:
    report_day = date(2026, 5, 13)
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [
                    _row(
                        DAILY_REPORT_COLUMNS,
                        report_date=report_day,
                        tenant_id="default",
                        total_logs=100,
                        anomaly_count=4,
                        high_count=2,
                        critical_count=1,
                        overall_score=72.5,
                        top_risk_users=["alice"],
                        top_attack_types=["account_takeover"],
                        key_events=["anom-1"],
                        ai_summary="One high risk user.",
                        recommended_actions=["Reset password", "Review VPN logs"],
                        markdown_body="# Daily",
                        created_at=datetime(2026, 5, 13, 23, 0, tzinfo=timezone.utc),
                    )
                ],
                DAILY_REPORT_COLUMNS,
            ),
            QueryResult([(1,)]),
        ]
    )
    storage = ClickHouseStorage(client=fake)

    items, total = storage.list_daily_reports(tenant_id="default", start_date=report_day, end_date=report_day)

    assert total == 1
    assert items[0]["report_id"] == "default:2026-05-13"
    assert items[0]["log_count"] == 100
    assert items[0]["high_risk_count"] == 3
    assert items[0]["major_risks"] == ["account_takeover"]
    assert items[0]["typical_alerts"] == [{"event_id": "anom-1"}]
    assert items[0]["recommendation"] == "Reset password\nReview VPN logs"


def test_get_stats_overview_queries_log_and_anomaly_counts() -> None:
    now = datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc)
    report_day = date(2026, 5, 13)
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [(100, now, 5, 3, 1, 2, 7, report_day)],
                [
                    "log_count",
                    "latest_log_ingest_time",
                    "anomaly_count",
                    "high_risk_count",
                    "critical_count",
                    "ai_pending_count",
                    "baseline_user_count",
                    "latest_report_date",
                ],
            )
        ]
    )
    storage = ClickHouseStorage(client=fake)

    stats = storage.get_stats_overview(tenant_id="default")

    assert stats == {
        "log_count": 100,
        "latest_log_ingest_time": now,
        "anomaly_count": 5,
        "high_risk_count": 3,
        "critical_count": 1,
        "ai_pending_count": 2,
        "baseline_user_count": 7,
        "latest_report_date": report_day,
    }
    assert "SELECT count() FROM security_logs WHERE tenant_id = {tenant_id:String}" in fake.queries[0]["sql"]
    assert "SELECT count() FROM anomaly_events WHERE tenant_id = {anom_tenant_id:String}" in fake.queries[0]["sql"]
    assert "ai_status = 'pending'" in fake.queries[0]["sql"]
    assert (
        "SELECT uniqExact(user_id) FROM ueba_user_baseline WHERE tenant_id = {tenant_id:String}"
        in fake.queries[0]["sql"]
    )
    assert fake.queries[0]["parameters"] == {
        "tenant_id": "default",
        "anom_tenant_id": "default",
    }


def test_list_user_risk_stats_excludes_empty_users_and_orders_by_risk() -> None:
    now = datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc)
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [("alice", "7d", 4, 2, 1, 96.0, 180.0, 126.5, 1, now)],
                [
                    "user_id",
                    "window",
                    "anomaly_count",
                    "high_risk_count",
                    "critical_count",
                    "max_risk_score",
                    "active_risk_score",
                    "decayed_risk_score",
                    "false_positive_excluded_count",
                    "latest_event_time",
                ],
            ),
            QueryResult([(1,)]),
        ]
    )
    storage = ClickHouseStorage(client=fake)

    items, total = storage.list_user_risk_stats(tenant_id="default", limit=10, offset=0)

    assert total == 1
    assert items[0]["user_id"] == "alice"
    assert items[0]["window"] == "7d"
    assert items[0]["critical_count"] == 1
    assert items[0]["false_positive_excluded_count"] == 1
    assert "user_id != ''" in fake.queries[0]["sql"]
    assert "countIf(status != 'false_positive') AS anomaly_count" in fake.queries[0]["sql"]
    assert "countIf(status = 'false_positive') AS false_positive_excluded_count" in fake.queries[0]["sql"]
    assert "ORDER BY decayed_risk_score DESC, high_risk_count DESC" in fake.queries[0]["sql"]
    assert fake.queries[0]["parameters"]["tenant_id"] == "default"
    assert fake.queries[0]["parameters"]["limit"] == 10
    assert fake.queries[0]["parameters"]["offset"] == 0
    assert fake.queries[0]["parameters"]["window"] == "7d"
    assert fake.queries[0]["parameters"]["start_time"] < fake.queries[0]["parameters"]["end_time"]


def test_aggregate_daily_features_sql_groups_by_user_in_clickhouse() -> None:
    fake = FakeClickHouseClient(
        [
            QueryResult(
                [("default", "alice", ["service"], 10, 4)],
                ["tenant_id", "user_id", "account_type_top", "event_count", "login_count"],
            )
        ]
    )
    storage = ClickHouseStorage(client=fake)

    rows = storage.aggregate_daily_features_sql(metric_date=date(2026, 5, 31))

    assert rows[0]["user_id"] == "alice"
    sql = fake.queries[0]["sql"]
    assert "FROM security_logs" in sql
    assert "GROUP BY tenant_id, user_id" in sql
    assert "event_date = {metric_date:Date}" in sql
    assert fake.queries[0]["parameters"]["metric_date"] == date(2026, 5, 31)


def test_insert_user_daily_features_is_idempotent_per_day() -> None:
    fake = FakeClickHouseClient([])
    storage = ClickHouseStorage(client=fake)

    storage.insert_user_daily_features(
        [
            {"feature_date": date(2026, 5, 31), "tenant_id": "default", "user_id": "alice"},
            {"feature_date": date(2026, 5, 31), "tenant_id": "default", "user_id": "bob"},
        ]
    )

    # One DELETE for the (tenant, feature_date) scope, then a single insert.
    assert len(fake.commands) == 1
    assert "ALTER TABLE ueba_user_daily_features DELETE" in fake.commands[0]["sql"]
    assert fake.commands[0]["parameters"] == {"tenant_id": "default", "feature_date": date(2026, 5, 31)}
    assert fake.inserts[0]["table"] == "ueba_user_daily_features"
    assert len(fake.inserts[0]["data"]) == 2


def _row(columns: tuple[str, ...], **values: Any) -> tuple[Any, ...]:
    return tuple(values.get(column, _default_value(column)) for column in columns)


def _default_value(column: str) -> Any:
    if column.endswith("_time") or column == "created_at":
        return datetime(2026, 5, 13, tzinfo=timezone.utc)
    if column.endswith("_date") or column in {"trained_from", "trained_to", "report_date"}:
        return date(2026, 5, 13)
    if column in {
        "risk_tags",
        "rule_hits",
        "reason_codes",
        "related_event_ids",
        "common_values",
        "top_risk_users",
        "top_attack_types",
        "key_events",
        "recommended_actions",
    }:
        return []
    if column in {
        "src_port",
        "dst_port",
        "step_index",
        "mean_value",
        "std_value",
        "p50_value",
        "p95_value",
        "p99_value",
    }:
        return None
    if column in {
        "severity",
        "risk_score",
        "sample_days",
        "sample_count",
        "baseline_confidence",
        "total_logs",
        "anomaly_count",
        "high_count",
        "critical_count",
        "overall_score",
        "confidence",
    }:
        return 0
    if column in {"geo", "attrs", "risk_components", "evidence", "value_histogram"}:
        return "{}"
    if column == "baseline_deviations":
        return "[]"
    if column == "result":
        return "success"
    if column == "risk_level":
        return "low"
    if column == "source_type":
        return "vpn"
    if column == "feedback_type":
        return "false_positive"
    if column == "target_component":
        return "scoring"
    if column == "review_status":
        return "pending"
    if column == "is_mock":
        return 0
    return ""


def _compact_sql(sql: str) -> str:
    return " ".join(sql.split())
