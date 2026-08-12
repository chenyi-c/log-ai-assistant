from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from src.schemas import AIFeedback, AIJudgement, EvidenceChain


AI_CANDIDATE_RISK_LEVELS = {"high", "critical"}
FEEDBACK_TYPE_TO_COMPONENT: dict[str, str] = {
    "rule_weight": "rule",
    "baseline_threshold": "baseline",
    "false_positive": "scoring",
    "new_pattern": "rule",
    "data_contract": "data_contract",
}
VALID_FEEDBACK_TARGETS = {"rule", "baseline", "scoring", "data_contract"}


def fetch_alert_baseline(storage: Any, alert: dict[str, Any]) -> dict[str, Any]:
    user_id = alert.get("user_id")
    if not user_id:
        return {}
    event_time = parse_datetime_value(alert.get("event_time"))
    item = storage.get_user_baseline(
        str(user_id),
        tenant_id=str(alert.get("tenant_id") or "default"),
        baseline_date=event_time.date() if event_time else None,
    )
    return item or {}


def fetch_related_logs(storage: Any, alert: dict[str, Any]) -> list[dict[str, Any]]:
    related_event_ids = string_list(alert.get("related_event_ids"))
    return storage.list_logs_by_event_ids(related_event_ids) if related_event_ids else []


def fetch_ai_report(storage: Any, alert: dict[str, Any]) -> dict[str, Any]:
    event_id = alert.get("event_id")
    return storage.get_latest_ai_judgement(str(event_id)) or {} if event_id else {}


def reason_codes_combo(alert: dict[str, Any]) -> str:
    return ",".join(sorted(str(code) for code in (alert.get("reason_codes") or [])))


def is_ai_judgement_candidate(alert: dict[str, Any]) -> bool:
    risk_level = str(alert.get("risk_level") or "").lower()
    ai_status = str(alert.get("ai_status") or "").lower()
    return risk_level in AI_CANDIDATE_RISK_LEVELS or ai_status == "pending"


def build_ai_window_stats(
    *,
    evidence: dict[str, Any],
    related_logs: list[dict[str, Any]],
    related_event_ids: list[str],
    storage: Any,
) -> dict[str, Any]:
    evidence_stats = evidence.get("window_stats") if isinstance(evidence, dict) else None
    if isinstance(evidence_stats, dict) and evidence_stats:
        return dict(evidence_stats)
    derived_stats = derive_related_log_window_stats(related_logs)
    if derived_stats:
        return derived_stats
    quality_stats = getattr(storage, "security_log_quality_stats", None)
    if callable(quality_stats) and related_event_ids:
        try:
            stats = quality_stats(related_event_ids)
        except Exception:
            return {}
        return stats if isinstance(stats, dict) else {}
    return {}


def derive_related_log_window_stats(related_logs: list[dict[str, Any]]) -> dict[str, Any]:
    if not related_logs:
        return {}
    result_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    src_ips: set[str] = set()
    times: list[datetime] = []
    failed_login_count = 0
    successful_login_count = 0
    denied_count = 0
    sensitive_access_count = 0
    for log in related_logs:
        action = str(log.get("action") or "").lower()
        result = str(log.get("result") or "").lower()
        resource = str(log.get("resource") or log.get("object_id") or "").lower()
        risk_tags = string_list(log.get("risk_tags"))
        if action:
            action_counts[action] = action_counts.get(action, 0) + 1
        if result:
            result_counts[result] = result_counts.get(result, 0) + 1
        src_ip = log.get("src_ip")
        if src_ip:
            src_ips.add(str(src_ip))
        event_time = parse_datetime_value(log.get("event_time"))
        if event_time is not None:
            times.append(event_time)
        if "login" in action and result in {"fail", "failed", "denied", "error"}:
            failed_login_count += 1
        if "login" in action and result == "success":
            successful_login_count += 1
        if result == "denied":
            denied_count += 1
        if "sensitive_resource" in risk_tags or any(
            marker in resource for marker in ("admin", "export", "secret", "sensitive")
        ):
            sensitive_access_count += 1
    stats: dict[str, Any] = {
        "related_log_count": len(related_logs),
        "failed_login_count": failed_login_count,
        "successful_login_count": successful_login_count,
        "denied_count": denied_count,
        "sensitive_access_count": sensitive_access_count,
        "unique_src_ip_count": len(src_ips),
        "action_counts": action_counts,
        "result_counts": result_counts,
    }
    if times:
        start = min(times)
        end = max(times)
        stats.update(
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            window_seconds=max(0, int((end - start).total_seconds())),
        )
    return stats


def store_ai_feedback_suggestions(storage: Any, report: AIJudgement, alert: dict[str, Any]) -> None:
    suggestions = getattr(report, "feedback_suggestions", None)
    if not suggestions:
        return
    insert = getattr(storage, "insert_feedback", None)
    if insert is None:
        return
    try:
        for feedback in build_ai_feedback_rows(report, alert, suggestions):
            insert(feedback)
    except Exception:
        return


def build_ai_feedback_rows(
    report: AIJudgement,
    alert: dict[str, Any],
    suggestions: Any,
) -> list[AIFeedback]:
    if isinstance(suggestions, dict):
        items: list[tuple[str | None, Any]] = list(suggestions.items())
    elif isinstance(suggestions, list):
        items = [(None, entry) for entry in suggestions]
    else:
        return []
    rows: list[AIFeedback] = []
    for key, value in items:
        feedback = coerce_ai_feedback(report, alert, key, value)
        if feedback is not None:
            rows.append(feedback)
    return rows


def coerce_ai_feedback(
    report: AIJudgement,
    alert: dict[str, Any],
    key: str | None,
    value: Any,
) -> AIFeedback | None:
    detail = value if isinstance(value, dict) else {}
    feedback_type = resolve_feedback_type(key, detail)
    target_component = resolve_feedback_target(detail, feedback_type)
    suggestion = resolve_feedback_suggestion(key, value, detail)
    if not suggestion:
        return None
    confidence = detail.get("confidence", report.confidence)
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = report.confidence
    return AIFeedback(
        feedback_id=f"fb-ai-{uuid.uuid4()}",
        event_id=report.event_id,
        judgement_id=report.judgement_id,
        tenant_id=str(alert.get("tenant_id") or "default"),
        user_id=alert.get("user_id"),
        feedback_type=feedback_type,
        suggestion=suggestion,
        target_component=target_component,
        confidence=confidence,
        review_status="pending",
        created_at=datetime.now(timezone.utc),
    )


def resolve_feedback_type(key: str | None, detail: dict[str, Any]) -> str:
    candidate = str(detail.get("feedback_type") or key or "").strip()
    return candidate if candidate in FEEDBACK_TYPE_TO_COMPONENT else "new_pattern"


def resolve_feedback_target(detail: dict[str, Any], feedback_type: str) -> str:
    candidate = str(detail.get("target_component") or "").strip()
    return candidate if candidate in VALID_FEEDBACK_TARGETS else FEEDBACK_TYPE_TO_COMPONENT.get(feedback_type, "rule")


def resolve_feedback_suggestion(key: str | None, value: Any, detail: dict[str, Any]) -> str:
    if detail:
        text = detail.get("suggestion")
        return str(text) if text else json.dumps(detail, ensure_ascii=False)
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    prefix = f"{key}: " if key else ""
    return f"{prefix}{value}"


def build_evidence_chain(
    alert: dict[str, Any], baseline: dict[str, Any], related_logs: list[dict[str, Any]]
) -> EvidenceChain:
    rule_hits = string_list(alert.get("rule_hits"))
    baseline_deviations = extract_baseline_deviations(alert, baseline, related_logs)
    risk_reason = build_risk_reason(
        alert,
        rule_hits,
        baseline_deviations,
        related_logs,
        has_baseline=bool(baseline),
    )
    return EvidenceChain(
        rule_hits=rule_hits,
        baseline_deviations=baseline_deviations,
        reason_codes=string_list(alert.get("reason_codes")),
        risk_components=alert.get("risk_components") if isinstance(alert.get("risk_components"), dict) else {},
        ai_status=str(alert.get("ai_status") or "not_required"),
        risk_reason=risk_reason,
    )


def extract_baseline_deviations(
    alert: dict[str, Any],
    baseline: dict[str, Any],
    related_logs: list[dict[str, Any]],
) -> list[str]:
    evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
    explicit = evidence.get("baseline_deviations")
    if isinstance(explicit, list):
        return [str(item) for item in explicit]
    if not baseline:
        return []
    deviations: list[str] = []
    src_ip = first_string(evidence.get("src_ip"), evidence.get("new_ip"), alert.get("src_ip"))
    location_profile = baseline.get("location_profile") if isinstance(baseline.get("location_profile"), dict) else {}
    access_profile = baseline.get("access_profile") if isinstance(baseline.get("access_profile"), dict) else {}
    time_profile = baseline.get("time_profile") if isinstance(baseline.get("time_profile"), dict) else {}
    result_profile = baseline.get("result_profile") if isinstance(baseline.get("result_profile"), dict) else {}
    common_ips = string_list(location_profile.get("common_ips"))
    if src_ip and common_ips and src_ip not in common_ips:
        deviations.append(f"src_ip {src_ip} is outside baseline location_profile.common_ips")
    event_hour = event_hour_from_value(alert.get("event_time"))
    active_hours = string_list(time_profile.get("active_hours"))
    if event_hour is not None and active_hours and not hour_in_ranges(event_hour, active_hours):
        deviations.append(f"event hour {event_hour:02d}:00 is outside baseline time_profile.active_hours")
    resource = first_string(evidence.get("resource"), first_related_value(related_logs, "resource"))
    common_resources = string_list(access_profile.get("common_resources"))
    if resource and common_resources and resource not in common_resources:
        deviations.append(f"resource {resource} is outside baseline access_profile.common_resources")
    user_agent = first_related_value(related_logs, "user_agent")
    common_user_agents = string_list(access_profile.get("common_user_agents"))
    if user_agent and common_user_agents and user_agent not in common_user_agents:
        deviations.append("user_agent is outside baseline access_profile.common_user_agents")
    api_calls = numeric(evidence.get("api_calls_1m"))
    avg_api = numeric(access_profile.get("avg_api_calls_per_minute"))
    if api_calls is not None and avg_api is not None and api_calls > max(avg_api * 2, avg_api + 5):
        deviations.append(
            f"api_calls_1m {api_calls:g} exceeds baseline access_profile.avg_api_calls_per_minute {avg_api:g}"
        )
    failed_count = numeric(evidence.get("failed_count_5m"))
    failed_baseline = numeric(result_profile.get("failed_login_count_7d"))
    if failed_count is not None and failed_baseline is not None and failed_count > max(3, failed_baseline):
        deviations.append(
            f"failed_count_5m {failed_count:g} exceeds baseline result_profile.failed_login_count_7d {failed_baseline:g}"
        )
    sensitive_count = numeric(evidence.get("sensitive_count_5m"))
    sensitive_rate = numeric(access_profile.get("sensitive_access_rate"))
    if sensitive_count is not None and sensitive_count > 0 and sensitive_rate is not None and sensitive_rate < 0.1:
        deviations.append(
            f"sensitive access count {sensitive_count:g} is unusual for baseline access_profile.sensitive_access_rate {sensitive_rate:g}"
        )
    return deviations


def build_risk_reason(
    alert: dict[str, Any],
    rule_hits: list[str],
    baseline_deviations: list[str],
    related_logs: list[dict[str, Any]],
    *,
    has_baseline: bool,
) -> str:
    rule_text = "、".join(rule_hits) if rule_hits else "no rule hits"
    pieces = [
        f"Risk level {alert.get('risk_level') or 'unknown'}",
        f"score {alert.get('risk_score')}",
        f"rule evidence: {rule_text}",
    ]
    if baseline_deviations:
        pieces.append(f"baseline deviations: {'; '.join(baseline_deviations)}")
    elif has_baseline:
        pieces.append("no baseline deviation was derived from the available evidence")
    else:
        pieces.append("baseline is missing, so the explanation relies on rule evidence only")
    pieces.append(f"related logs: {len(related_logs)}")
    return "; ".join(pieces)


def string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, (tuple, set)):
        return [str(item) for item in value if item is not None]
    return []


def first_string(*values: Any) -> str | None:
    for value in values:
        if value is not None and str(value):
            return str(value)
    return None


def first_related_value(items: list[dict[str, Any]], field: str) -> str | None:
    for item in items:
        value = item.get(field)
        if value is not None and str(value):
            return str(value)
    return None


def event_hour_from_value(value: Any) -> int | None:
    parsed = parse_datetime_value(value)
    return parsed.hour if parsed is not None else None


def parse_datetime_value(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def hour_in_ranges(hour: int, ranges: list[str]) -> bool:
    parsed_ranges = [parse_hour_range(value) for value in ranges]
    valid_ranges = [value for value in parsed_ranges if value is not None]
    if not valid_ranges:
        return True
    for start, end in valid_ranges:
        if start <= end and start <= hour < end:
            return True
        if start > end and (hour >= start or hour < end):
            return True
    return False


def parse_hour_range(value: str) -> tuple[int, int] | None:
    try:
        start, end = value.split("-", 1)
        return int(start.split(":", 1)[0]), int(end.split(":", 1)[0])
    except (ValueError, IndexError):
        return None


def numeric(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except ValueError:
        return None
