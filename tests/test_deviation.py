"""evaluate_deviations 纯函数的单元测试。

覆盖范围：
- 无基线时返回空列表（离线降级）
- 三类偏离（location / time / access）各自正常触发
- 低置信度（confidence < 0.6）触发 severity 动态降级
- 9 字段契约完整性校验
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.ueba.deviation import (
    UserContext,
    _safe_severity,
    evaluate_deviations,
    is_seen_source,
    load_user_context,
)

BASE_TIME = datetime(2026, 6, 4, 10, 0, 0)  # 工作时间内，用于 time profile 正常命中


# ============================================================================
# 辅助构造
# ============================================================================


def _make_log(
    src_ip: str = "1.1.1.1",
    resource: str = "/home",
    hour: int = 10,
    attrs: dict[str, Any] | None = None,
) -> Any:
    """构造最小 log-like 对象（带必要属性）。"""

    class _FakeLog:
        def __init__(self) -> None:
            self.src_ip = src_ip
            self.resource = resource
            self.event_time = BASE_TIME.replace(hour=hour)
            self.user_id = "alice"
            self.attrs = attrs or {}

    return _FakeLog()


def _make_context(
    baseline: dict[str, Any] | None = None,
    seen_sources: set[str] | None = None,
    daily_feature: dict[str, Any] | None = None,
) -> UserContext:
    return UserContext(
        tenant_id="default",
        user_id="alice",
        baseline=baseline,
        seen_sources=seen_sources or set(),
        daily_feature=daily_feature,
    )


_HIGH_CONFIDENCE_BASELINE = {
    "baseline_confidence": 0.8,
    "sample_days": 30,
    "location_profile": {"common_ips": ["10.0.0.1"]},
    "time_profile": {"active_hours": ["09:00-18:00"]},
    "access_profile": {"common_resources": ["/home", "/api/v1"]},
    "result_profile": {"failed_login_count": {"p95": 3, "p99": 5}},
}

_LOW_CONFIDENCE_BASELINE = {
    "baseline_confidence": 0.4,
    "sample_days": 3,
    "location_profile": {"common_ips": ["10.0.0.1"]},
    "time_profile": {"active_hours": ["09:00-18:00"]},
    "access_profile": {"common_resources": ["/home"]},
    "result_profile": {"failed_login_count": {"p95": 3, "p99": 5}},
}


# ============================================================================
# 无基线场景
# ============================================================================


def test_evaluate_deviations_returns_empty_when_no_baseline() -> None:
    """无 baseline 时应返回样本不足降级证据，而不是误判为无偏离。"""
    ctx = _make_context(baseline=None)
    log = _make_log()
    result = evaluate_deviations(log, ctx)
    assert len(result) == 1
    assert result[0].deviation_type == "insufficient_history"
    assert result[0].severity == "medium"
    assert result[0].evidence_source == "global"
    assert result[0].sample_days == 0


def test_evaluate_deviations_returns_empty_for_anonymous_user() -> None:
    """user_id=None 且无 baseline 的上下文返回样本不足降级证据。"""
    ctx = UserContext(tenant_id="default", user_id=None)
    log = _make_log()
    result = evaluate_deviations(log, ctx)
    assert len(result) == 1
    assert result[0].deviation_type == "insufficient_history"


# ============================================================================
# location 偏离：新来源 IP
# ============================================================================


def test_evaluate_deviations_new_src_ip_triggers_location_deviation() -> None:
    """src_ip 不在 common_ips 时，应产出 location deviation。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="9.9.9.9", hour=10)
    result = evaluate_deviations(log, ctx)

    assert len(result) == 1
    d = result[0]
    assert d.feature == "src_ip"
    assert d.profile_group == "location"
    assert d.deviation_type == "new_source_ip"
    assert d.severity == "high"
    assert d.actual == "9.9.9.9"
    assert "10.0.0.1" in d.expected
    assert d.evidence_source == "user_baseline"
    assert d.confidence == 0.8
    assert d.sample_days == 30


def test_evaluate_deviations_known_src_ip_no_location_deviation() -> None:
    """src_ip 在 common_ips 中时，不应产出 location deviation。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="10.0.0.1", hour=10)
    result = evaluate_deviations(log, ctx)
    features = [d.feature for d in result]
    assert "src_ip" not in features


def test_evaluate_deviations_seen_source_suppresses_new_src_ip_deviation() -> None:
    """持久化 seen_sources 已见过的来源不应再作为强新来源证据。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE, seen_sources={"9.9.9.9"})
    log = _make_log(src_ip="9.9.9.9", hour=10)
    result = evaluate_deviations(log, ctx)
    assert "src_ip" not in [d.feature for d in result]


def test_evaluate_deviations_seen_sources_can_prove_new_src_ip() -> None:
    """无 common_ips 但有持久化 seen_sources 时，陌生来源证据来自 seen_sources。"""
    baseline = {
        **_HIGH_CONFIDENCE_BASELINE,
        "location_profile": {},
    }
    ctx = _make_context(baseline=baseline, seen_sources={"10.0.0.1"})
    log = _make_log(src_ip="9.9.9.9", hour=10)

    result = evaluate_deviations(log, ctx)

    src_ip = [d for d in result if d.feature == "src_ip"]
    assert len(src_ip) == 1
    assert src_ip[0].deviation_type == "new_source_ip"
    assert src_ip[0].evidence_source == "seen_sources"


# ============================================================================
# time 偏离：非活跃时段
# ============================================================================


def test_evaluate_deviations_off_hours_triggers_time_deviation() -> None:
    """非工作时段（active_hours 09:00-18:00 之外）应产出 time deviation。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="10.0.0.1", hour=2)  # 凌晨 2 点
    result = evaluate_deviations(log, ctx)

    time_deviations = [d for d in result if d.feature == "event_hour"]
    assert len(time_deviations) == 1
    d = time_deviations[0]
    assert d.profile_group == "time"
    assert d.deviation_type == "outside_active_hours"
    assert d.severity == "medium"
    assert d.actual == "02:00"
    assert d.evidence_source == "user_baseline"


def test_evaluate_deviations_work_hours_no_time_deviation() -> None:
    """工作时段内登录不应产出 time deviation。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="10.0.0.1", hour=10)
    result = evaluate_deviations(log, ctx)
    features = [d.feature for d in result]
    assert "event_hour" not in features


# ============================================================================
# access 偏离：非常见资源
# ============================================================================


def test_evaluate_deviations_new_resource_triggers_access_deviation() -> None:
    """访问不在 common_resources 中的资源应产出 access deviation。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="10.0.0.1", resource="/api/admin/export", hour=10)
    result = evaluate_deviations(log, ctx)

    access_deviations = [d for d in result if d.feature == "resource"]
    assert len(access_deviations) == 1
    d = access_deviations[0]
    assert d.profile_group == "access"
    assert d.deviation_type == "sensitive_resource_access"
    assert d.severity == "high"
    assert d.actual == "/api/admin/export"
    assert d.evidence_source == "user_baseline"


def test_evaluate_deviations_known_resource_no_access_deviation() -> None:
    """访问 common_resources 中的资源不应产出 access deviation。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="10.0.0.1", resource="/home", hour=10)
    result = evaluate_deviations(log, ctx)
    features = [d.feature for d in result]
    assert "resource" not in features


def test_evaluate_deviations_failed_login_spike_reads_p95_p99() -> None:
    """失败登录数超过 result_profile p99 时，产出数值偏离并随幅度升高 severity。"""
    ctx = _make_context(
        baseline=_HIGH_CONFIDENCE_BASELINE,
        daily_feature={"failed_login_count": 12},
    )
    log = _make_log(src_ip="10.0.0.1", hour=10)

    result = evaluate_deviations(log, ctx)

    failed = [d for d in result if d.deviation_type == "failed_login_spike"]
    assert len(failed) == 1
    assert failed[0].feature == "failed_login_count"
    assert failed[0].profile_group == "result"
    assert failed[0].expected == "<= 5"
    assert failed[0].actual == 12
    assert failed[0].severity == "high"
    assert failed[0].evidence_source == "daily_feature"


def test_evaluate_deviations_download_volume_spike_reads_access_profile_p99() -> None:
    """下载量超过 access_profile.download_count p99 时，产出下载量偏离。"""
    baseline = {
        **_HIGH_CONFIDENCE_BASELINE,
        "access_profile": {
            "common_resources": ["/home", "/api/v1"],
            "download_count": {"p95": 2, "p99": 4},
        },
    }
    ctx = _make_context(baseline=baseline, daily_feature={"download_count": 13})
    log = _make_log(src_ip="10.0.0.1", resource="/home", hour=10)

    result = evaluate_deviations(log, ctx)

    download = [d for d in result if d.deviation_type == "download_volume_spike"]
    assert len(download) == 1
    assert download[0].feature == "download_count"
    assert download[0].profile_group == "access"
    assert download[0].expected == "<= 4"
    assert download[0].actual == 13
    assert download[0].severity == "critical"
    assert download[0].evidence_source == "daily_feature"


def test_evaluate_deviations_numeric_spike_can_read_log_attrs() -> None:
    """没有 daily_feature 时，数值偏离可从日志 attrs 读取，证据来源回落为 user_baseline。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="10.0.0.1", hour=10, attrs={"failed_login_count": 6})

    result = evaluate_deviations(log, ctx)

    failed = [d for d in result if d.deviation_type == "failed_login_spike"]
    assert len(failed) == 1
    assert failed[0].severity == "medium"
    assert failed[0].evidence_source == "user_baseline"


# ============================================================================
# 9 字段契约完整性
# ============================================================================


def test_baseline_deviation_to_dict_has_all_9_fields() -> None:
    """BaselineDeviation.to_dict() 必须包含所有 9 个契约字段，不多不少。"""
    ctx = _make_context(baseline=_HIGH_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="9.9.9.9", hour=10)
    result = evaluate_deviations(log, ctx)

    assert result
    d = result[0].to_dict()
    expected_keys = {
        "feature",
        "profile_group",
        "expected",
        "actual",
        "deviation_type",
        "severity",
        "confidence",
        "evidence_source",
        "sample_days",
    }
    assert set(d.keys()) == expected_keys


def test_baseline_deviation_includes_effective_baseline_audit_metadata() -> None:
    baseline = {
        **_HIGH_CONFIDENCE_BASELINE,
        "period_type": "weekday",
        "period_key": "monday",
        "model_version": "baseline-effective-1",
        "selected_baseline": {
            "period_type": "weekday",
            "period_key": "monday",
            "fallback_level": "none",
            "override_ids": ["override-1"],
            "model_version": "baseline-effective-1",
        },
    }
    result = evaluate_deviations(
        _make_log(src_ip="9.9.9.9"),
        _make_context(baseline=baseline),
    )

    payload = result[0].to_dict()
    assert payload["period_type"] == "weekday"
    assert payload["period_key"] == "monday"
    assert payload["model_version"] == "baseline-effective-1"
    assert payload["override_ids"] == ["override-1"]
    assert payload["fallback_level"] == "none"


# ============================================================================
# 低置信度动态降级（核心误报控制逻辑）
# ============================================================================


def test_safe_severity_does_not_downgrade_when_confidence_above_threshold() -> None:
    """confidence >= 0.6 时 severity 不应降级。"""
    assert _safe_severity("high", 0.6) == "high"
    assert _safe_severity("high", 0.8) == "high"
    assert _safe_severity("medium", 0.61) == "medium"
    assert _safe_severity("critical", 1.0) == "critical"


def test_safe_severity_downgrades_when_confidence_below_threshold() -> None:
    """confidence < 0.6 时，severity 应降级一级。"""
    assert _safe_severity("critical", 0.5) == "high"
    assert _safe_severity("high", 0.4) == "medium"
    assert _safe_severity("medium", 0.3) == "low"
    assert _safe_severity("low", 0.0) == "low"  # low 不再降


def test_evaluate_deviations_low_confidence_downgrades_severity() -> None:
    """低置信度（0.4）基线产出的偏离 severity 应自动降级。"""
    ctx = _make_context(baseline=_LOW_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="9.9.9.9", resource="/api/admin/export", hour=2)
    result = evaluate_deviations(log, ctx)

    for d in result:
        # high → medium, medium → low
        assert d.severity in ("medium", "low"), (
            f"低置信度下 {d.feature} severity 应为 medium 或 low，实际为 {d.severity}"
        )
        assert d.confidence == 0.4


def test_evaluate_deviations_low_confidence_location_deviation_is_medium() -> None:
    """低置信度下，location deviation 的 severity 应由 high 降为 medium。"""
    ctx = _make_context(baseline=_LOW_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="9.9.9.9", hour=10)
    result = evaluate_deviations(log, ctx)

    loc = [d for d in result if d.feature == "src_ip"]
    assert loc
    assert loc[0].severity == "medium"


def test_evaluate_deviations_low_confidence_time_deviation_is_low() -> None:
    """低置信度下，time deviation 的 severity 应由 medium 降为 low。"""
    ctx = _make_context(baseline=_LOW_CONFIDENCE_BASELINE)
    log = _make_log(src_ip="10.0.0.1", hour=2)
    result = evaluate_deviations(log, ctx)

    time_d = [d for d in result if d.feature == "event_hour"]
    assert time_d
    assert time_d[0].severity == "low"


# ============================================================================
# is_seen_source 辅助函数
# ============================================================================


def test_is_seen_source_returns_true_for_known_ip() -> None:
    ctx = _make_context(seen_sources={"10.0.0.1", "192.168.1.1"})
    assert is_seen_source(ctx, "10.0.0.1") is True


def test_is_seen_source_returns_false_for_unknown_ip() -> None:
    ctx = _make_context(seen_sources={"10.0.0.1"})
    assert is_seen_source(ctx, "9.9.9.9") is False


def test_is_seen_source_returns_false_for_empty_seen_sources() -> None:
    ctx = _make_context(seen_sources=set())
    assert is_seen_source(ctx, "1.2.3.4") is False


# ============================================================================
# load_user_context（FakeStorage）
# ============================================================================


class _FakeDeviationStorage:
    """最小 FakeStorage，实现 DeviationStorage Protocol。"""

    def __init__(
        self,
        baselines: dict[tuple[str, str], dict[str, Any]] | None = None,
        seen_sources: list[dict[str, Any]] | None = None,
    ) -> None:
        self.baselines = baselines or {}
        self._seen_sources = seen_sources or []

    def get_user_baseline(
        self, user_id: str, *, tenant_id: str | None = None, baseline_date: Any = None
    ) -> dict[str, Any] | None:
        return self.baselines.get((tenant_id or "default", user_id))

    def query_user_seen_sources(
        self,
        *,
        tenant_id: str = "default",
        user_id: str | None = None,
        source_type: str | None = None,
        source_key: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        return self._seen_sources[:limit]


def test_load_user_context_returns_empty_for_none_user_id() -> None:
    storage = _FakeDeviationStorage()
    ctx = load_user_context(storage, "default", None)
    assert ctx.baseline is None
    assert ctx.seen_sources == set()
    assert ctx.user_id is None


def test_load_user_context_populates_baseline_and_seen_sources() -> None:
    bl = {"baseline_confidence": 0.9, "sample_days": 60}
    storage = _FakeDeviationStorage(
        baselines={("default", "bob"): bl},
        seen_sources=[{"source_key": "10.0.0.1"}, {"source_key": "172.16.0.1"}],
    )
    ctx = load_user_context(storage, "default", "bob")
    assert ctx.baseline == bl
    assert ctx.seen_sources == {"10.0.0.1", "172.16.0.1"}
    assert ctx.confidence == 0.9
    assert ctx.sample_days == 60
