from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from src.schemas import DataQualityMetric
from src.storage import ClickHouseStorage


HIGH_RISK_LABEL_HINTS = (
    "account_takeover",
    "data_exfiltration",
    "credential_stuffing",
    "privilege_abuse",
    "lateral_movement",
)

# Number of manifest event_ids sampled per (tenant, source) group to estimate the
# end-to-end traceability rate from manifest to security_logs.
TRACEABILITY_SAMPLE_SIZE = 50


def load_manifest_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
    return rows


def build_data_quality_metrics(
    *,
    storage: ClickHouseStorage,
    manifest_path: Path,
    metric_date: date | None = None,
) -> list[DataQualityMetric]:
    rows = load_manifest_rows(manifest_path)
    if metric_date is not None:
        rows = [row for row in rows if _manifest_row_date(row) == metric_date]
    if not rows:
        return []

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        tenant_id = str(row.get("tenant_id") or "default")
        source_type = str(row.get("source_type") or "unknown")
        grouped[(tenant_id, source_type)].append(row)

    table_size = storage.security_logs_table_size_bytes()
    created_at = datetime.now(timezone.utc)
    metrics: list[DataQualityMetric] = []

    use_real_counts = hasattr(storage, "security_logs_daily_counts")

    for (tenant_id, source_type), items in grouped.items():
        resolved_date = metric_date or _manifest_metric_date(items)
        generated_count = len(items)
        raw_size_bytes = sum(int(item.get("raw_size_bytes") or 0) for item in items)
        injected_labels = [
            str(item.get("injected_label") or "")
            for item in items
            if str(item.get("injected_label") or "") not in {"", "normal"}
        ]

        if use_real_counts:
            # Real per-stage counts straight from ClickHouse for this (date, source).
            stats = storage.security_logs_daily_counts(
                metric_date=resolved_date,
                tenant_id=tenant_id,
                source_type=source_type,
            )
            clickhouse_insert_count = int(stats.get("clickhouse_insert_count") or 0)
            parsed_logs_count = int(stats.get("parsed_logs_count") or 0)
            security_logs_count = parsed_logs_count
            parse_error_count = int(stats.get("parse_error_count") or 0)
            missing_denominator = clickhouse_insert_count
            parse_error_denominator = clickhouse_insert_count or generated_count
        else:
            # Fallback: estimate from the manifest event_id list (no ClickHouse
            # date-scoped count available, e.g. older storage adapters).
            event_ids = [str(item["event_id"]) for item in items if item.get("event_id")]
            stats = storage.security_log_quality_stats(event_ids)
            security_logs_count = int(stats.get("security_logs_count") or 0)
            parsed_logs_count = security_logs_count
            clickhouse_insert_count = security_logs_count
            parse_error_count = int(stats.get("parse_error_count") or 0)
            missing_denominator = security_logs_count
            parse_error_denominator = generated_count

        metric = DataQualityMetric(
            metric_date=resolved_date,
            tenant_id=tenant_id,
            source_type=source_type,
            generated_count=generated_count,
            injected_anomaly_count=len(injected_labels),
            injected_high_risk_count=sum(_is_high_risk_label(label) for label in injected_labels),
            raw_logs_count=_raw_line_count(items),
            parsed_logs_count=parsed_logs_count,
            clickhouse_insert_count=clickhouse_insert_count,
            security_logs_count=security_logs_count,
            raw_size_bytes=raw_size_bytes,
            table_size_bytes=table_size,
            compression_ratio=round(raw_size_bytes / table_size, 4) if table_size else 0,
            missing_event_time_rate=_rate(stats.get("missing_event_time_count"), missing_denominator),
            missing_user_id_rate=_rate(stats.get("missing_user_id_count"), missing_denominator),
            missing_src_ip_rate=_rate(stats.get("missing_src_ip_count"), missing_denominator),
            missing_action_rate=_rate(stats.get("missing_action_count"), missing_denominator),
            missing_result_rate=_rate(stats.get("missing_result_count"), missing_denominator),
            parse_error_rate=_rate(parse_error_count, parse_error_denominator),
            event_id_traceability_rate=_group_traceability_rate(storage, items),
            created_at=created_at,
        )
        metrics.append(metric)

    return sorted(metrics, key=lambda item: (item.tenant_id, str(item.source_type)))


def write_data_quality_metrics(
    *,
    storage: ClickHouseStorage,
    manifest_path: Path,
    metric_date: date | None = None,
) -> list[DataQualityMetric]:
    metrics = build_data_quality_metrics(
        storage=storage,
        manifest_path=manifest_path,
        metric_date=metric_date,
    )
    storage.insert_data_quality_metrics(metrics)
    return metrics


def build_reconciliation_report(metrics: list[DataQualityMetric]) -> list[dict[str, Any]]:
    return [_reconcile_metric(metric) for metric in metrics]


def verify_manifest_event_ids(
    *,
    storage: ClickHouseStorage,
    manifest_path: Path,
    sample_size: int = 20,
) -> dict[str, Any]:
    rows = load_manifest_rows(manifest_path)
    event_ids = [str(row.get("event_id")) for row in rows if row.get("event_id")]
    sampled_event_ids = event_ids[: max(0, sample_size)]
    if not sampled_event_ids:
        return {
            "sampled_count": 0,
            "found_count": 0,
            "missing_count": 0,
            "missing_event_ids": [],
        }

    logs = storage.list_logs_by_event_ids(sampled_event_ids)
    found_event_ids = {str(log.get("event_id")) for log in logs if isinstance(log, dict) and log.get("event_id")}
    missing_event_ids = [event_id for event_id in sampled_event_ids if event_id not in found_event_ids]
    return {
        "sampled_count": len(sampled_event_ids),
        "found_count": len(found_event_ids),
        "missing_count": len(missing_event_ids),
        "missing_event_ids": missing_event_ids,
    }


def _group_traceability_rate(storage: Any, items: list[dict[str, Any]]) -> float:
    """Estimate how many sampled manifest event_ids are traceable to security_logs.

    Returns 1.0 (treated as "not blocking") when the storage adapter cannot resolve
    event_ids, so older adapters without ``list_logs_by_event_ids`` keep working.
    """

    lookup = getattr(storage, "list_logs_by_event_ids", None)
    if lookup is None:
        return 1.0
    event_ids = [str(item["event_id"]) for item in items if item.get("event_id")]
    sampled = event_ids[:TRACEABILITY_SAMPLE_SIZE]
    if not sampled:
        return 1.0
    logs = lookup(sampled)
    found = {str(log.get("event_id")) for log in logs if isinstance(log, dict) and log.get("event_id")}
    traced = sum(1 for event_id in sampled if event_id in found)
    return round(traced / len(sampled), 6)


def _reconcile_metric(metric: DataQualityMetric) -> dict[str, Any]:
    counts = {
        "generated_count": metric.generated_count,
        "raw_logs_count": metric.raw_logs_count,
        "parsed_logs_count": metric.parsed_logs_count,
        "clickhouse_insert_count": metric.clickhouse_insert_count,
        "security_logs_count": metric.security_logs_count,
    }
    deltas = {
        "generated_to_raw": metric.raw_logs_count - metric.generated_count,
        "raw_to_parsed": metric.parsed_logs_count - metric.raw_logs_count,
        "parsed_to_clickhouse_insert": metric.clickhouse_insert_count - metric.parsed_logs_count,
        "clickhouse_insert_to_security": metric.security_logs_count - metric.clickhouse_insert_count,
    }
    explanations = _reconciliation_explanations(metric, deltas)
    return {
        "metric_date": metric.metric_date.isoformat(),
        "tenant_id": metric.tenant_id,
        "source_type": str(metric.source_type),
        "counts": counts,
        "deltas": deltas,
        "explanations": explanations,
        "status": "ok" if not explanations else "needs_review",
    }


def _reconciliation_explanations(
    metric: DataQualityMetric,
    deltas: dict[str, int],
) -> list[str]:
    explanations: list[str] = []

    if deltas["generated_to_raw"] < 0:
        explanations.append(
            "raw_logs_count is below generated_count; inspect Filebeat/Kafka lag, raw file rotation, or manifest rows not yet collected."
        )
    elif deltas["generated_to_raw"] > 0:
        explanations.append(
            "raw_logs_count exceeds generated_count; likely log replay, duplicate collection, or an appended manifest window overlap."
        )

    if deltas["raw_to_parsed"] < 0:
        explanations.append(
            "parsed_logs_count is below raw_logs_count; parse errors, parser lag, or filtered malformed records can explain the gap."
        )
    elif deltas["raw_to_parsed"] > 0:
        explanations.append(
            "parsed_logs_count exceeds raw_logs_count; check replayed parsed topic messages or date/source filter mismatch."
        )

    if deltas["parsed_to_clickhouse_insert"] < 0:
        explanations.append(
            "clickhouse_insert_count is below parsed_logs_count; inspect sink lag, failed insert batches, or retry backoff."
        )
    elif deltas["parsed_to_clickhouse_insert"] > 0:
        explanations.append(
            "clickhouse_insert_count exceeds parsed_logs_count; duplicate sink retries or Kafka replay can produce extra raw inserts."
        )

    if deltas["clickhouse_insert_to_security"] < 0:
        explanations.append(
            "security_logs_count is below clickhouse_insert_count; ReplacingMergeTree deduplication or FINAL query collapse can explain the difference."
        )
    elif deltas["clickhouse_insert_to_security"] > 0:
        explanations.append(
            "security_logs_count exceeds clickhouse_insert_count; verify metric date/source filters and previous retained rows."
        )

    if metric.parse_error_rate > 0:
        explanations.append(
            f"parse_error_rate is {metric.parse_error_rate}; parser failures should be sampled before treating the gap as data loss."
        )
    if metric.event_id_traceability_rate < 1:
        explanations.append(
            f"event_id_traceability_rate is {metric.event_id_traceability_rate}; some sampled manifest event_ids were not found in security_logs (silent drop or parser loss)."
        )
    missing_rates = {
        "missing_event_time_rate": metric.missing_event_time_rate,
        "missing_user_id_rate": metric.missing_user_id_rate,
        "missing_src_ip_rate": metric.missing_src_ip_rate,
        "missing_action_rate": metric.missing_action_rate,
        "missing_result_rate": metric.missing_result_rate,
    }
    for name, value in missing_rates.items():
        if value > 0:
            explanations.append(f"{name} is {value}; check parser field mapping and source contract coverage.")

    return explanations


def _manifest_metric_date(items: list[dict[str, Any]]) -> date:
    for item in items:
        raw = item.get("timestamp")
        if not raw:
            continue
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
        except ValueError:
            continue
    return datetime.now(timezone.utc).date()


def _manifest_row_date(item: dict[str, Any]) -> date | None:
    raw = item.get("timestamp")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _raw_line_count(items: list[dict[str, Any]]) -> int:
    by_file: dict[str, int] = defaultdict(int)
    for item in items:
        raw_file = str(item.get("raw_file") or "")
        if raw_file:
            by_file[raw_file] += 1
    return sum(by_file.values()) or len(items)


def _is_high_risk_label(label: str) -> bool:
    lowered = label.lower()
    return any(hint in lowered for hint in HIGH_RISK_LABEL_HINTS)


def _rate(value: Any, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(value or 0) / denominator, 6)
