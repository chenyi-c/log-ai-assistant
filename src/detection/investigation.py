"""Privacy-safe investigation summaries derived from existing anomaly evidence."""

from __future__ import annotations

from typing import Any

from src.config import settings
from src.detection.worker import _dedupe_anomalies
from src.schemas import AnomalyReviewResponse, InvestigationResponse


_ATTACK_REFERENCES = {
    "failed_login_spike": ("T1110", "Brute Force"),
    "credential_stuffing_pattern": ("T1110.004", "Credential Stuffing"),
}

_RULE_CONTEXT = {
    "failed_login_spike": ("5m", "failed_count_5m"),
    "credential_stuffing_pattern": ("5m", "count"),
    "high_api_rate": ("1m", "api_calls_1m"),
    "sensitive_resource_access": ("5m", "sensitive_count_5m"),
}


def build_investigation(
    anomaly: dict[str, Any], review: AnomalyReviewResponse | None = None
) -> InvestigationResponse:
    """Create a demo-grade investigation response without retaining raw log bodies."""
    evidence = _sanitize_evidence(dict(anomaly.get("evidence") or {}))
    reason_codes = [str(code) for code in anomaly.get("reason_codes") or []]
    related_event_ids = [str(item) for item in anomaly.get("related_event_ids") or []]
    return InvestigationResponse(
        anomaly_id=str(anomaly["event_id"]),
        risk_level=str(anomaly.get("risk_level") or "low"),
        reason_codes=reason_codes,
        sanitized_evidence=evidence,
        attack_techniques=[
            {"techniqueId": technique_id, "name": name, "source": "manual_attck_reference"}
            for reason_code in reason_codes
            if (reference := _ATTACK_REFERENCES.get(reason_code))
            for technique_id, name in [reference]
        ],
        why_matched=_why_matched(reason_codes, evidence, related_event_ids),
        manual_check_steps=_manual_check_steps(reason_codes),
        review_status=review.status if review else "pending",
        reviewer_note=review.reviewer_note if review else None,
        reviewed_at=review.reviewed_at if review else None,
    )


def run_investigation_pack() -> dict[str, Any]:
    """Replay synthetic logs into a shareable investigation report, not a detection metric."""
    # demo imports the API list route, so keep it out of the API import path.
    from src.detection.demo import _detect, _load_scenarios, _materialize_logs
    from src.detection.regression import _matching_anomalies, run_rule_regression

    regression_cases = {case["scenario_id"]: case for case in run_rule_regression()["cases"]}
    cases = []
    for scenario in _load_scenarios():
        logs = _materialize_logs(scenario)
        anomalies = _detect(scenario, logs)
        matches = _matching_anomalies(anomalies, scenario["expected"])
        selected = matches[0] if matches else None
        deduplicated = _dedupe_anomalies([*anomalies, *anomalies], set())
        cases.append(
            {
                "scenarioName": scenario["id"],
                "inputEventCount": len(logs),
                "timeline": [
                    {
                        "eventId": log.event_id,
                        "eventTime": log.event_time.isoformat().replace("+00:00", "Z"),
                        "action": log.action,
                        "result": log.result,
                    }
                    for log in logs
                ],
                "deduplicated": len(deduplicated) < len(anomalies) * 2 if anomalies else True,
                "investigation": (
                    build_investigation(selected.model_dump(mode="json")).model_dump(by_alias=True, mode="json")
                    if selected
                    else None
                ),
                "passed": regression_cases[scenario["id"]]["passed"],
            }
        )
    return {
        "version": "v1",
        "metric": "synthetic_investigation_replay",
        "is_accuracy_metric": False,
        "sanitization": "Synthetic fixture only; raw log bodies and direct identifiers are excluded or masked.",
        "summary": {
            "case_count": len(cases),
            "investigation_count": sum(item["investigation"] is not None for item in cases),
            "passed_case_count": sum(item["passed"] for item in cases),
        },
        "cases": cases,
    }


def render_investigation_pack_markdown(report: dict[str, Any]) -> str:
    """Render a compact, no-raw-log evidence artifact for the repository."""
    lines = ["# Synthetic Investigation Pack", "", "This is a fixed synthetic replay report, not a detection accuracy measurement.", ""]
    for case in report["cases"]:
        investigation = case["investigation"]
        lines.extend([f"## {case['scenarioName']}", f"- Input events: {case['inputEventCount']}", f"- Deduplicated replay: {case['deduplicated']}"])
        if investigation is None:
            lines.append("- Result: no anomaly expected and none emitted.")
        else:
            techniques = ", ".join(item["techniqueId"] for item in investigation["attackTechniques"]) or "No ATT&CK mapping asserted"
            lines.extend([
                f"- Anomaly ID: {investigation['anomalyId']}",
                f"- Risk / reasons: {investigation['riskLevel']} / {', '.join(investigation['reasonCodes'])}",
                f"- ATT&CK references: {techniques}",
                f"- Review status: {investigation['reviewStatus']}",
            ])
        lines.append("")
    return "\n".join(lines) + "\n"


def _sanitize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    blocked = {"raw_log", "raw", "message", "payload", "content", "request_body"}

    def clean(key: str, value: Any) -> Any:
        lowered = key.lower()
        if lowered in blocked:
            return None
        if isinstance(value, dict):
            return {str(child_key): item for child_key, child_value in value.items() if (item := clean(str(child_key), child_value)) is not None}
        if isinstance(value, list):
            if lowered.startswith("distinct_users"):
                return [_mask_text(str(item)) for item in value]
            return [clean(key, item) for item in value]
        if lowered in {"src_ip", "ip", "source_ip"}:
            return _mask_ip(str(value))
        if lowered in {"user_id", "user", "account", "principal"}:
            return _mask_text(str(value))
        if lowered in {"resource", "resource_id", "object_id"}:
            return _mask_resource(str(value))
        return value

    return {key: item for key, value in evidence.items() if (item := clean(key, value)) is not None}


def _mask_text(value: str) -> str:
    return value if len(value) <= 2 else f"{value[0]}***{value[-1]}"


def _mask_ip(value: str) -> str:
    parts = value.split(".")
    return f"{parts[0]}.{parts[1]}.***.***" if len(parts) == 4 else "***"


def _mask_resource(value: str) -> str:
    parts = [part for part in value.split("/") if part]
    return f"/{parts[0]}/***" if parts else "***"


def _why_matched(reason_codes: list[str], evidence: dict[str, Any], related_event_ids: list[str]) -> dict[str, Any]:
    primary = next((reason for reason in reason_codes if reason in _RULE_CONTEXT), None)
    if primary is None:
        return {"timeWindow": "rule-specific", "observedEventCount": len(related_event_ids), "threshold": None, "relatedEventIds": related_event_ids}
    time_window, field = _RULE_CONTEXT[primary]
    threshold = {
        "failed_login_spike": settings.threshold_user_fail_5m if "user_id" in evidence else settings.threshold_ip_fail_5m,
        "credential_stuffing_pattern": settings.threshold_multi_user_fail_ip_5m,
        "high_api_rate": settings.threshold_api_call_1m,
        "sensitive_resource_access": settings.threshold_sensitive_5m,
    }[primary]
    return {"timeWindow": time_window, "observedEventCount": int(evidence.get(field, len(related_event_ids))), "threshold": threshold, "relatedEventIds": related_event_ids}


def _manual_check_steps(reason_codes: list[str]) -> list[str]:
    steps = ["Verify the masked event sequence against the authorized source system before any response action."]
    if any(reason in {"failed_login_spike", "credential_stuffing_pattern"} for reason in reason_codes):
        steps.append("Check whether the account or source has an approved access-change or lockout explanation.")
    if "high_api_rate" in reason_codes:
        steps.append("Check whether the masked caller matches a documented batch job or rate-limit exception.")
    if "sensitive_resource_access" in reason_codes or "admin_resource_access" in reason_codes:
        steps.append("Verify the masked resource access against the user's approved role and change record.")
    return steps
