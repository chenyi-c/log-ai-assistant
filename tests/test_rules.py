"""RuleEngine 的规则触发测试。

这里不重复测试 builder 的所有细节，只确认规则引擎能正确触发规则并产出新结构。
"""

from datetime import datetime, timedelta

from src.detection.rules import DetectionContext, RuleEngine, detect_batch
from src.schemas import NormalizedLog


def build_log(idx: int, **kwargs) -> NormalizedLog:
    """构造一条默认登录失败日志，测试里通过 kwargs 改成不同场景。"""

    base = {
        "event_id": f"evt-{idx}",
        "event_time": datetime(2026, 4, 1, 10, 0, 0) + timedelta(seconds=idx),
        "ingest_time": datetime(2026, 4, 1, 10, 0, 0) + timedelta(seconds=idx),
        "tenant_id": "default",
        "source_type": "vpn",
        "log_type": "login",
        "user_id": "test.user",
        "src_ip": "1.1.1.1",
        "action": "login",
        "resource": "/home",
        "result": "fail",
        "message": "failed login",
        "raw_log": "raw",
        "risk_tags": [],
        "attrs": {},
    }
    base.update(kwargs)
    return NormalizedLog.model_validate(base)


def test_bruteforce_ip_rule_triggered() -> None:
    """同一个 IP 多次登录失败时，应触发暴力破解类规则。"""

    logs = [build_log(i, src_ip="8.8.8.8", user_id=f"u{i % 2}") for i in range(10)]
    alerts = detect_batch(logs)
    rules = [rule for a in alerts for rule in a.rule_hits]
    assert "同一src_ip在5分钟内登录失败超阈值" in rules
    assert any("failed_login_spike" in alert.reason_codes for alert in alerts)
    assert all("rule_score" not in alert.risk_components for alert in alerts)
    assert all("rule_strength" in alert.risk_components for alert in alerts)
    ip_spike = next(alert for alert in alerts if "同一src_ip在5分钟内登录失败超阈值" in alert.rule_hits)
    assert ip_spike.attack_type == "brute_force"
    assert ip_spike.risk_level == "high"
    assert ip_spike.ai_status == "pending"


def test_new_ip_then_sensitive_access() -> None:
    """新 IP 登录后马上访问敏感资源，应触发关联异常。"""

    login = build_log(
        1,
        result="success",
        action="login",
        user_id="alice",
        src_ip="2.2.2.2",
        resource="vpn-gw-bj01",
    )
    sensitive = build_log(
        2,
        result="success",
        action="access",
        user_id="alice",
        src_ip="2.2.2.2",
        resource="/api/admin/export",
    )
    alerts = detect_batch([login, sensitive])
    rules = [rule for a in alerts for rule in a.rule_hits]
    assert "新IP登录后短时间访问敏感资源" in rules
    correlated = [alert for alert in alerts if "new_source_then_sensitive_access" in alert.reason_codes]
    assert correlated
    assert correlated[0].attack_type == "account_takeover"
    assert correlated[0].risk_components["event_correlation"] > 0


def test_off_hours_login_only_never_reaches_critical() -> None:
    """【误报控制回归】非工作时间登录但无任何敏感行为时，风险分绝不突破 critical 区间。

    rare_login_hour 的风险组成为：rule_strength:15 + baseline_deviation:10 = 25（low 级别）。
    即便将来附加了 time baseline 偏离（medium severity → +15 baseline_deviation），
    总分上限也仅为 ~30，严禁进入 critical（≥ 76）甚至 high（≥ 51）区间。
    """
    # 选择工作时间之外的小时（凌晨 2 点，settings.work_hour_start 默认 9）
    off_hour_time = datetime(2026, 4, 1, 2, 0, 0)
    log = build_log(
        1,
        action="login",
        result="success",
        src_ip="1.1.1.1",
        resource="/home",
        user_id="ordinary.user",
        event_time=off_hour_time,
        ingest_time=off_hour_time,
    )
    alerts = detect_batch([log])

    # 应触发非工作时间登录规则
    off_hour_alerts = [a for a in alerts if "rare_login_hour" in a.reason_codes]
    assert off_hour_alerts, "应至少产出一条 rare_login_hour 异常事件"

    for alert in off_hour_alerts:
        # 仅有 rare_login_hour，不得混入敏感操作相关 reason_code
        assert "sensitive_resource_access" not in alert.reason_codes
        assert "new_source_then_sensitive_access" not in alert.reason_codes

        # 风险分严禁突破 critical（≥ 76）
        assert alert.risk_score < 76, f"非工作时间单纯登录不应达到 critical，实际得分 {alert.risk_score}"
        # 同时也不应达到 high（≥ 51）——单独 rare_login_hour 不足以触发高风险
        assert alert.risk_score < 51, f"非工作时间单纯登录不应达到 high，实际得分 {alert.risk_score}"
        assert alert.risk_level != "critical"


def test_maintenance_and_allowlist_mitigate_without_dropping_event() -> None:
    """维护窗口/白名单命中时保留事件和 reason_code，但通过 feedback_adjustment 降权。"""
    log = build_log(
        1,
        action="api_call",
        result="success",
        user_id="ordinary.user",
        resource="/api/admin/users",
        attrs={"maintenance_window": True, "allowlisted_context": True},
    )
    alerts = RuleEngine().evaluate_log(
        log,
        DetectionContext(maintenance_window=True, allowlisted_context=True),
    )

    admin_alert = next(alert for alert in alerts if "admin_resource_access" in alert.reason_codes)
    assert "maintenance_window" in admin_alert.reason_codes
    assert "allowlisted_context" in admin_alert.reason_codes
    assert admin_alert.evidence["risk_mitigations"] == ["maintenance_window", "allowlisted_context"]
    assert admin_alert.risk_components["feedback_adjustment"] == -10
    assert admin_alert.risk_score < 51
    assert admin_alert.status == "new"


def test_direct_download_or_export_is_data_exfiltration_signal() -> None:
    log = build_log(
        1,
        action="download",
        result="success",
        source_type="api",
        log_type="api_access",
        resource="/api/files/export",
        risk_tags=["download_volume_spike"],
    )

    alerts = RuleEngine().evaluate_log(log)

    export_alert = next(alert for alert in alerts if "download_volume_spike" in alert.reason_codes)
    assert export_alert.attack_type == "data_exfiltration"
    assert "sensitive_resource_access" in export_alert.reason_codes
    assert export_alert.risk_level in {"high", "critical"}


def test_lateral_movement_signal_triggers_after_multiple_hosts() -> None:
    engine = RuleEngine()
    base_time = datetime(2026, 4, 1, 10, 0, 0)
    logs = [
        build_log(
            idx,
            action="access",
            result="success",
            source_type="system",
            log_type="host_access",
            user_id="alice",
            src_ip="10.0.0.9",
            host=f"srv-{idx}",
            resource="/ssh/session",
            event_time=base_time + timedelta(minutes=idx),
            ingest_time=base_time + timedelta(minutes=idx),
        )
        for idx in range(1, 4)
    ]

    alerts = []
    for log in logs:
        alerts.extend(engine.evaluate_log(log))

    lateral = [alert for alert in alerts if "lateral_movement_signal" in alert.reason_codes]
    assert lateral
    assert lateral[-1].attack_type == "lateral_movement"
    assert lateral[-1].evidence["count"] == 3
    assert lateral[-1].risk_level == "high"


def test_service_account_anomaly_rule_uses_registered_reason_code() -> None:
    log = build_log(
        1,
        action="login",
        result="success",
        user_id="svc-backup",
        account_type="service",
        src_ip="203.0.113.9",
        resource="vpn-gw-bj01",
        event_time=datetime(2026, 4, 1, 2, 0, 0),
        ingest_time=datetime(2026, 4, 1, 2, 0, 0),
    )

    alerts = RuleEngine().evaluate_log(log, DetectionContext(seen_source=False))

    service_alert = next(alert for alert in alerts if "service_account_anomaly" in alert.reason_codes)
    assert service_alert.attack_type == "service_account_anomaly"
    assert service_alert.evidence["account_type"] == "service"
    assert service_alert.risk_level in {"medium", "high"}


def test_service_account_off_hours_alone_is_not_anomalous() -> None:
    """【误报控制】服务账号 7x24 运行：仅“非工作时间”或“访问敏感资源”不应判异常。"""
    log = build_log(
        1,
        action="api_call",
        result="success",
        user_id="svc-report",
        account_type="service",
        src_ip="10.0.0.5",
        resource="/api/internal/config/export",
        event_time=datetime(2026, 4, 1, 2, 0, 0),
        ingest_time=datetime(2026, 4, 1, 2, 0, 0),
    )
    # 已知来源（seen_source=True），无攻击标记：服务账号常态行为，不应产出服务账号异常。
    alerts = RuleEngine().evaluate_log(log, DetectionContext(seen_source=True))
    assert not [a for a in alerts if "service_account_anomaly" in a.reason_codes]

    # 注入攻击标记或新来源时仍应判异常，保证真实场景不漏报。
    flagged = build_log(
        2,
        action="api_call",
        result="success",
        user_id="svc-report",
        account_type="service",
        src_ip="203.0.113.9",
        resource="/api/internal/config/export",
        risk_tags=["service_account_anomaly"],
        event_time=datetime(2026, 4, 1, 2, 0, 0),
        ingest_time=datetime(2026, 4, 1, 2, 0, 0),
    )
    flagged_alerts = RuleEngine().evaluate_log(flagged, DetectionContext(seen_source=True))
    assert [a for a in flagged_alerts if "service_account_anomaly" in a.reason_codes]


def test_off_hours_login_suppressed_when_baseline_marks_hour_normal() -> None:
    """【误报控制】用户有可信 baseline 且该时段属其活跃时段时，非工作时间登录不再报警。"""
    off_hour_time = datetime(2026, 4, 1, 2, 0, 0)
    log = build_log(
        1,
        action="login",
        result="success",
        src_ip="1.1.1.1",
        resource="/home",
        user_id="nightshift.user",
        event_time=off_hour_time,
        ingest_time=off_hour_time,
    )
    # baseline 可用且未给出 outside_active_hours 偏离 → 该用户夜间活跃，抑制刷报。
    ctx = DetectionContext(seen_source=True, baseline_available=True, baseline_deviations=[])
    alerts = RuleEngine().evaluate_log(log, ctx)
    assert not [a for a in alerts if "rare_login_hour" in a.reason_codes]

    # baseline 明确给出 outside_active_hours 偏离时，仍应报警。
    ctx_dev = DetectionContext(
        seen_source=True,
        baseline_available=True,
        baseline_deviations=[{"deviation_type": "outside_active_hours", "severity": "medium"}],
    )
    alerts_dev = RuleEngine().evaluate_log(log, ctx_dev)
    assert [a for a in alerts_dev if "rare_login_hour" in a.reason_codes]


def test_insufficient_history_deviation_does_not_overestimate_new_source_risk() -> None:
    log = build_log(
        1,
        action="login",
        result="success",
        user_id="new.user",
        src_ip="203.0.113.10",
        resource="vpn-gw-bj01",
    )
    context = DetectionContext(
        seen_source=False,
        baseline_deviations=[
            {
                "feature": "baseline_history",
                "profile_group": "why",
                "expected": "sufficient_user_baseline",
                "actual": "user new.user has no baseline",
                "deviation_type": "insufficient_history",
                "severity": "medium",
                "confidence": 0,
                "evidence_source": "global",
                "sample_days": 0,
            }
        ],
    )

    alerts = RuleEngine().evaluate_log(log, context)

    new_source = next(alert for alert in alerts if "new_source_ip" in alert.reason_codes)
    assert "insufficient_history" in [item["deviation_type"] for item in new_source.baseline_deviations]
    assert new_source.risk_level == "medium"
    assert new_source.ai_status == "not_required"
