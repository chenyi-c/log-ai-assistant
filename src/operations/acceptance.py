from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from src.config import PROJECT_ROOT, settings
from src.operations.config import load_operations_config, load_thresholds
from src.schemas import AcceptanceMetric, AcceptanceReport


def evaluate_scenarios(
    storage: Any,
    *,
    tenant_id: str = "default",
    run_id: str = "",
    sample_from: datetime | None = None,
    sample_to: datetime | None = None,
) -> tuple[AcceptanceReport, list[AcceptanceMetric]]:
    config = load_operations_config()
    thresholds = load_thresholds(config.threshold_path)
    rows = storage.acceptance_scenario_rows(
        tenant_id=tenant_id,
        start_time=sample_from,
        end_time=sample_to,
    )
    logs = rows.get("logs", [])
    anomalies = rows.get("anomalies", [])
    judgements = rows.get("judgements", [])
    deliveries = rows.get("deliveries", [])

    normal_logs = [row for row in logs if str(row.get("injected_label") or "") == "normal"]
    attack_logs = [row for row in logs if str(row.get("injected_label") or "").startswith("attack_")]
    chain_roots = [row for row in attack_logs if int(row.get("step_index") or 0) == 1]
    if not chain_roots:
        chain_roots = attack_logs
    normal_scenarios = {f"normal_{row.get('source_type') or 'unknown'}" for row in normal_logs}
    attack_chains = {str(row.get("attack_chain_id")) for row in chain_roots if row.get("attack_chain_id")}
    high_risk_chains = {
        str(row.get("attack_chain_id"))
        for row in chain_roots
        if row.get("attack_chain_id") and _is_high_risk_label(str(row.get("injected_label") or ""))
    }
    anomaly_chains = {str(row.get("attack_chain_id")) for row in anomalies if row.get("attack_chain_id")}
    high_anomaly_chains = {
        str(row.get("attack_chain_id"))
        for row in anomalies
        if row.get("attack_chain_id") and row.get("risk_level") in {"high", "critical"}
    }

    normal_event_ids = {str(row.get("event_id")) for row in normal_logs}
    normal_high_events = {
        event_id
        for row in anomalies
        if row.get("risk_level") in {"high", "critical"}
        for event_id in _string_list(row.get("related_event_ids"))
        if event_id in normal_event_ids
    }
    detected_chains = attack_chains & anomaly_chains
    high_detected_chains = high_risk_chains & high_anomaly_chains
    traced_chains = {
        chain
        for chain in attack_chains
        if chain in anomaly_chains and any(str(row.get("attack_chain_id")) == chain for row in attack_logs)
    }
    precision_numerator, precision_denominator, precision_details = _high_risk_precision(anomalies, attack_logs)
    event_recall_numerator, event_recall_denominator, event_recall_details = _attack_event_recall(
        anomalies, attack_logs
    )
    confusion_matrix = _attack_type_confusion_matrix(anomalies, attack_logs)
    risk_accuracy_numerator, risk_accuracy_denominator, risk_accuracy_details = _risk_level_accuracy(anomalies, logs)

    detection_latencies = _detection_latencies(attack_logs, anomalies)
    notification_latencies = _notification_latencies(anomalies, deliveries)
    candidate_ids = {str(row.get("event_id")) for row in anomalies if row.get("risk_level") in {"high", "critical"}}
    real_judgements = [
        row for row in judgements if not bool(row.get("is_mock")) and str(row.get("event_id")) in candidate_ids
    ]
    mock_judgements = [
        row for row in judgements if bool(row.get("is_mock")) and str(row.get("event_id")) in candidate_ids
    ]

    now = datetime.now(timezone.utc)
    report_id = f"acc-{uuid.uuid4()}"
    metrics = [
        _ratio_metric(
            report_id,
            "normal_false_positive_rate",
            len(normal_high_events),
            len(normal_event_ids),
            "<=",
            thresholds["normal_false_positive_rate_max"],
            now,
        ),
        _ratio_metric(
            report_id,
            "attack_detection_rate",
            len(detected_chains),
            len(attack_chains),
            ">=",
            thresholds["attack_detection_rate_min"],
            now,
        ),
        _ratio_metric(
            report_id,
            "high_risk_detection_rate",
            len(high_detected_chains),
            len(high_risk_chains),
            ">=",
            thresholds["high_risk_detection_rate_min"],
            now,
        ),
        _ratio_metric(
            report_id,
            "traceability_rate",
            len(traced_chains),
            len(attack_chains),
            ">=",
            thresholds["traceability_rate_min"],
            now,
        ),
        _ratio_metric(
            report_id,
            "precision_high_risk",
            precision_numerator,
            precision_denominator,
            ">=",
            thresholds["precision_high_risk_min"],
            now,
            details=precision_details,
        ),
        _ratio_metric(
            report_id,
            "attack_event_recall",
            event_recall_numerator,
            event_recall_denominator,
            ">=",
            thresholds["attack_event_recall_min"],
            now,
            details=event_recall_details,
        ),
        _detail_metric(
            report_id,
            "attack_type_confusion_matrix",
            confusion_matrix,
            now,
        ),
        _ratio_metric(
            report_id,
            "risk_level_accuracy",
            risk_accuracy_numerator,
            risk_accuracy_denominator,
            ">=",
            thresholds["risk_level_accuracy_min"],
            now,
            details=risk_accuracy_details,
        ),
        _latency_metric(
            report_id,
            "detection_latency_p50_seconds",
            _percentile(detection_latencies, 50),
            len(detection_latencies),
            "<=",
            thresholds["detection_latency_p95_seconds_max"],
            now,
        ),
        _latency_metric(
            report_id,
            "detection_latency_p95_seconds",
            _percentile(detection_latencies, 95),
            len(detection_latencies),
            "<=",
            thresholds["detection_latency_p95_seconds_max"],
            now,
        ),
        _latency_metric(
            report_id,
            "detection_latency_max_seconds",
            max(detection_latencies, default=0),
            len(detection_latencies),
            "<=",
            thresholds["detection_latency_p95_seconds_max"],
            now,
        ),
        _latency_metric(
            report_id,
            "notification_latency_p50_seconds",
            _percentile(notification_latencies, 50),
            len(notification_latencies),
            "<=",
            thresholds["notification_latency_p95_seconds_max"],
            now,
        ),
        _latency_metric(
            report_id,
            "notification_latency_p95_seconds",
            _percentile(notification_latencies, 95),
            len(notification_latencies),
            "<=",
            thresholds["notification_latency_p95_seconds_max"],
            now,
        ),
        _latency_metric(
            report_id,
            "notification_latency_max_seconds",
            max(notification_latencies, default=0),
            len(notification_latencies),
            "<=",
            thresholds["notification_latency_p95_seconds_max"],
            now,
        ),
        _coverage_metric(report_id, "ai_real_coverage_rate", real_judgements, candidate_ids, now, is_mock=False),
        _coverage_metric(report_id, "ai_mock_coverage_rate", mock_judgements, candidate_ids, now, is_mock=True),
    ]

    minimum_scenarios_met = len(normal_scenarios) >= 3 and len(attack_chains) >= 3 and len(high_risk_chains) >= 3
    required_metric_names = {
        "normal_false_positive_rate",
        "attack_detection_rate",
        "high_risk_detection_rate",
        "traceability_rate",
        "precision_high_risk",
        "attack_event_recall",
        "risk_level_accuracy",
        "detection_latency_p95_seconds",
        "notification_latency_p95_seconds",
    }
    required_metrics = [item for item in metrics if item.metric_name in required_metric_names]
    status = "passed" if minimum_scenarios_met and all(item.passed for item in required_metrics) else "failed"
    ai_model, ai_is_mock = _ai_evidence(judgements)
    if not real_judgements:
        ai_model = ai_model or settings.dashscope_model
        ai_is_mock = True

    sample_times = [_as_datetime(row.get("event_time")) for row in logs]
    sample_times = [item for item in sample_times if item is not None]
    report = AcceptanceReport(
        report_id=report_id,
        tenant_id=tenant_id,
        status=status,
        git_commit=_git_commit(),
        compose_config_digest=_compose_digest(),
        scenario_version=_file_digest(PROJECT_ROOT / "log-generator" / "scenarios" / "default.json"),
        policy_version=os.getenv("DETECTION_POLICY_VERSION", "rules-v1"),
        baseline_model_version=storage.latest_baseline_model_version(tenant_id),
        ai_model=ai_model,
        ai_is_mock=ai_is_mock,
        threshold_version=str(thresholds["version"]),
        sample_from=min(sample_times) if sample_times else None,
        sample_to=max(sample_times) if sample_times else None,
        normal_scenario_count=len(normal_scenarios),
        attack_scenario_count=len(attack_chains),
        created_at=now,
        run_id=run_id,
        summary={
            "normal_scenarios": sorted(normal_scenarios),
            "attack_chains": sorted(attack_chains),
            "high_risk_attack_chains": sorted(high_risk_chains),
            "real_ai_judgement_count": len(real_judgements),
            "mock_ai_judgement_count": len(mock_judgements),
            "real_ai_acceptance_passed": bool(real_judgements),
            "minimum_scenarios_met": minimum_scenarios_met,
            "attack_type_confusion_matrix": confusion_matrix,
        },
    )
    storage.insert_acceptance_report(report, metrics)
    return report, metrics


def _ratio_metric(
    report_id: str,
    name: str,
    numerator: int,
    denominator: int,
    op: str,
    threshold: float,
    created_at: datetime,
    *,
    details: dict[str, Any] | None = None,
) -> AcceptanceMetric:
    value = numerator / denominator if denominator else 0.0
    return AcceptanceMetric(
        report_id=report_id,
        metric_name=name,
        numerator=numerator,
        denominator=denominator,
        value=round(value, 6),
        threshold_operator=op,
        threshold_value=float(threshold),
        passed=denominator > 0 and _compare(value, op, float(threshold)),
        details=details or {},
        created_at=created_at,
    )


def _detail_metric(report_id: str, name: str, details: dict[str, Any], created_at: datetime) -> AcceptanceMetric:
    total = _sum_nested_counts(details)
    return AcceptanceMetric(
        report_id=report_id,
        metric_name=name,
        numerator=total,
        denominator=total,
        value=1.0 if total else 0.0,
        threshold_operator=">=",
        threshold_value=0.0,
        passed=total > 0,
        unit="matrix",
        details=details,
        created_at=created_at,
    )


def _latency_metric(
    report_id: str, name: str, value: float, sample_count: int, op: str, threshold: float, created_at: datetime
) -> AcceptanceMetric:
    return AcceptanceMetric(
        report_id=report_id,
        metric_name=name,
        numerator=sample_count,
        denominator=sample_count,
        value=round(value, 3),
        threshold_operator=op,
        threshold_value=float(threshold),
        passed=sample_count > 0 and _compare(value, op, float(threshold)),
        unit="seconds",
        details={"sample_count": sample_count},
        created_at=created_at,
    )


def _coverage_metric(
    report_id: str,
    name: str,
    judgements: list[dict[str, Any]],
    candidates: set[str],
    created_at: datetime,
    *,
    is_mock: bool,
) -> AcceptanceMetric:
    covered = {str(row.get("event_id")) for row in judgements} & candidates
    metric = _ratio_metric(report_id, name, len(covered), len(candidates), ">=", 0.0, created_at)
    metric.passed = bool(judgements) and bool(candidates)
    metric.details = {"is_mock": is_mock, "candidate_count": len(candidates)}
    return metric


def _high_risk_precision(
    anomalies: list[dict[str, Any]], attack_logs: list[dict[str, Any]]
) -> tuple[int, int, dict[str, Any]]:
    attack_event_ids = {str(row.get("event_id")) for row in attack_logs if row.get("event_id")}
    attack_chains = {str(row.get("attack_chain_id")) for row in attack_logs if row.get("attack_chain_id")}
    high_anomalies = [row for row in anomalies if row.get("risk_level") in {"high", "critical"}]
    true_positive_ids: list[str] = []
    false_positive_ids: list[str] = []
    for row in high_anomalies:
        event_id = str(row.get("event_id") or "")
        related_ids = set(_string_list(row.get("related_event_ids")))
        chain = str(row.get("attack_chain_id") or "")
        if related_ids & attack_event_ids or (chain and chain in attack_chains):
            true_positive_ids.append(event_id)
        else:
            false_positive_ids.append(event_id)
    details = {
        "true_positive_alert_ids": sorted(true_positive_ids),
        "false_positive_alert_ids": sorted(false_positive_ids),
    }
    return len(true_positive_ids), len(high_anomalies), details


def _attack_event_recall(
    anomalies: list[dict[str, Any]], attack_logs: list[dict[str, Any]]
) -> tuple[int, int, dict[str, Any]]:
    attack_event_ids = {str(row.get("event_id")) for row in attack_logs if row.get("event_id")}
    detected_event_ids: set[str] = set()
    for row in anomalies:
        detected_event_ids |= set(_string_list(row.get("related_event_ids"))) & attack_event_ids
    missed = attack_event_ids - detected_event_ids
    return (
        len(detected_event_ids),
        len(attack_event_ids),
        {
            "detected_event_ids": sorted(detected_event_ids),
            "missed_event_ids": sorted(missed),
        },
    )


def _attack_type_confusion_matrix(anomalies: list[dict[str, Any]], attack_logs: list[dict[str, Any]]) -> dict[str, Any]:
    logs_by_event_id = {str(row.get("event_id")): row for row in attack_logs if row.get("event_id")}
    logs_by_chain: dict[str, list[dict[str, Any]]] = {}
    for row in attack_logs:
        chain = str(row.get("attack_chain_id") or "")
        if chain:
            logs_by_chain.setdefault(chain, []).append(row)

    matrix: dict[str, dict[str, int]] = {}
    for row in anomalies:
        matched_logs = _matched_logs(row, logs_by_event_id, logs_by_chain)
        if not matched_logs:
            continue
        predicted = str(row.get("attack_type") or "unknown")
        for expected in sorted({_expected_attack_type(item) for item in matched_logs}):
            matrix.setdefault(expected, {})
            matrix[expected][predicted] = matrix[expected].get(predicted, 0) + 1
    return matrix


def _risk_level_accuracy(
    anomalies: list[dict[str, Any]], logs: list[dict[str, Any]]
) -> tuple[int, int, dict[str, Any]]:
    logs_by_event_id = {str(row.get("event_id")): row for row in logs if row.get("event_id")}
    logs_by_chain: dict[str, list[dict[str, Any]]] = {}
    for row in logs:
        chain = str(row.get("attack_chain_id") or "")
        if chain:
            logs_by_chain.setdefault(chain, []).append(row)

    correct = 0
    total = 0
    by_expected: dict[str, dict[str, int]] = {}
    mismatches: list[dict[str, Any]] = []
    for row in anomalies:
        matched_logs = _matched_logs(row, logs_by_event_id, logs_by_chain)
        if not matched_logs:
            continue
        predicted = str(row.get("risk_level") or "low")
        for log in matched_logs:
            expected = _expected_risk_level(str(log.get("injected_label") or ""))
            by_expected.setdefault(expected, {})
            by_expected[expected][predicted] = by_expected[expected].get(predicted, 0) + 1
            total += 1
            if _risk_level_matches(expected, predicted):
                correct += 1
            else:
                mismatches.append(
                    {
                        "event_id": str(log.get("event_id") or ""),
                        "alert_id": str(row.get("event_id") or ""),
                        "expected": expected,
                        "predicted": predicted,
                    }
                )
    return correct, total, {"by_expected": by_expected, "mismatches": mismatches[:20]}


def _matched_logs(
    anomaly: dict[str, Any],
    logs_by_event_id: dict[str, dict[str, Any]],
    logs_by_chain: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    matched: dict[str, dict[str, Any]] = {}
    for event_id in _string_list(anomaly.get("related_event_ids")):
        if event_id in logs_by_event_id:
            matched[event_id] = logs_by_event_id[event_id]
    chain = str(anomaly.get("attack_chain_id") or "")
    if chain and chain in logs_by_chain:
        for row in logs_by_chain[chain]:
            event_id = str(row.get("event_id") or "")
            if event_id:
                matched.setdefault(event_id, row)
    return list(matched.values())


def _expected_attack_type(log: dict[str, Any]) -> str:
    label = str(log.get("injected_label") or "")
    if label.startswith("attack_"):
        return label.removeprefix("attack_")
    return "normal"


def _expected_risk_level(label: str) -> str:
    if label == "normal":
        return "low"
    attack_type = label.removeprefix("attack_") if label.startswith("attack_") else label
    if _is_high_risk_label(attack_type):
        return "high"
    if attack_type:
        return "medium"
    return "low"


def _risk_level_matches(expected: str, predicted: str) -> bool:
    if expected == "high":
        return predicted in {"high", "critical"}
    return expected == predicted


def _sum_nested_counts(value: Any) -> int:
    if isinstance(value, dict):
        return sum(_sum_nested_counts(item) for item in value.values())
    if isinstance(value, int):
        return value
    return 0


def _detection_latencies(logs: list[dict[str, Any]], anomalies: list[dict[str, Any]]) -> list[float]:
    first_log: dict[str, datetime] = {}
    for row in logs:
        chain = str(row.get("attack_chain_id") or "")
        event_time = _as_datetime(row.get("event_time"))
        if chain and event_time and (chain not in first_log or event_time < first_log[chain]):
            first_log[chain] = event_time
    first_detection: dict[str, datetime] = {}
    for row in anomalies:
        chain = str(row.get("attack_chain_id") or "")
        detect_time = _as_datetime(row.get("detect_time"))
        if chain and detect_time and (chain not in first_detection or detect_time < first_detection[chain]):
            first_detection[chain] = detect_time
    return [
        max(0.0, (first_detection[chain] - event_time).total_seconds())
        for chain, event_time in first_log.items()
        if chain in first_detection
    ]


def _notification_latencies(anomalies: list[dict[str, Any]], deliveries: list[dict[str, Any]]) -> list[float]:
    detection = {
        str(row.get("event_id")): _as_datetime(row.get("detect_time"))
        for row in anomalies
        if row.get("risk_level") in {"high", "critical"}
    }
    values: list[float] = []
    for row in deliveries:
        event_id = str(row.get("event_id") or "")
        delivered_at = _as_datetime(row.get("delivered_at"))
        if event_id in detection and detection[event_id] and delivered_at:
            values.append(max(0.0, (delivered_at - detection[event_id]).total_seconds()))
    return values


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    if percentile == 50:
        return float(median(values))
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
    return float(ordered[index])


def _compare(value: float, operator: str, threshold: float) -> bool:
    return {
        "<=": value <= threshold,
        ">=": value >= threshold,
        "<": value < threshold,
        ">": value > threshold,
    }[operator]


def _ai_evidence(rows: list[dict[str, Any]]) -> tuple[str, bool]:
    if not rows:
        return settings.dashscope_model, True
    real = [row for row in rows if not bool(row.get("is_mock"))]
    selected = real[-1] if real else rows[-1]
    version = str(selected.get("model_version") or "")
    name = str(selected.get("model_name") or settings.dashscope_model)
    return f"{name}:{version}" if version else name, not bool(real)


def _is_high_risk_label(label: str) -> bool:
    return any(
        item in label
        for item in (
            "credential_stuffing",
            "account_takeover",
            "data_exfiltration",
            "privilege_abuse",
            "lateral_movement",
        )
    )


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return [value] if value else []
        return [str(item) for item in parsed] if isinstance(parsed, list) else []
    return []


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        head_path = PROJECT_ROOT / ".git" / "HEAD"
        if head_path.exists():
            head = head_path.read_text(encoding="utf-8").strip()
            if head.startswith("ref: "):
                ref_path = PROJECT_ROOT / ".git" / head.removeprefix("ref: ")
                if ref_path.exists():
                    return ref_path.read_text(encoding="utf-8").strip()
            elif head:
                return head
        return os.getenv("CODE_VERSION", "unknown")


def _compose_digest() -> str:
    try:
        output = subprocess.check_output(["docker", "compose", "config"], cwd=PROJECT_ROOT)
    except (FileNotFoundError, subprocess.CalledProcessError):
        output = (PROJECT_ROOT / "docker-compose.yml").read_bytes()
    return hashlib.sha256(output).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
