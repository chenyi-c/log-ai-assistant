from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import date, datetime
from typing import Any


def build_filters(
    *,
    equals: dict[str, Any],
    time_field: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[list[str], dict[str, Any]]:
    filters: list[str] = []
    parameters: dict[str, Any] = {}
    for field, value in equals.items():
        if value is None:
            continue
        filters.append(f"{field} = {{{field}:{clickhouse_type(value)}}}")
        parameters[field] = value
    if time_field and (start_time or end_time):
        if start_time:
            filters.append(f"{time_field} >= {{start_time:DateTime64(3)}}")
            parameters["start_time"] = start_time
        if end_time:
            filters.append(f"{time_field} <= {{end_time:DateTime64(3)}}")
            parameters["end_time"] = end_time
    return filters, parameters


def where(filters: Sequence[str]) -> str:
    return f"WHERE {' AND '.join(filters)}" if filters else ""


def columns_sql(columns: Sequence[str], table_alias: str | None = None) -> str:
    if not table_alias:
        return ", ".join(columns)
    return ", ".join(f"{table_alias}.{column} AS {column}" for column in columns)


def pagination_parameters(*, limit: int, offset: int) -> dict[str, int]:
    return {
        "limit": normalize_limit(limit),
        "offset": max(0, int(offset)),
    }


def normalize_limit(
    limit: int | None,
    *,
    default: int = 1,
    maximum: int | None = None,
) -> int:
    normalized = default if limit is None else max(1, int(limit))
    return min(normalized, maximum) if maximum is not None else normalized


def clickhouse_type(value: Any) -> str:
    if isinstance(value, datetime):
        return "DateTime64(3)"
    if isinstance(value, date):
        return "Date"
    if isinstance(value, int):
        return "Int64"
    if isinstance(value, float):
        return "Float64"
    return "String"


def coerce_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def split_non_empty_lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def json_loads(value: Any, *, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return default


def json_dumps(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        value if value is not None else {},
        ensure_ascii=False,
        separators=(",", ":"),
        default=json_default,
    )


def json_default(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return str(value)


def string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Iterable):
        return [str(item) for item in value if item is not None]
    return []


def model_payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="python")
    return dict(value)


def row_from_payload(
    payload: dict[str, Any],
    columns: Sequence[str],
    *,
    json_fields: set[str] | None = None,
    defaults: dict[str, Any] | None = None,
) -> list[Any]:
    resolved_defaults = defaults or {}
    resolved_json_fields = json_fields or set()
    row: list[Any] = []
    for column in columns:
        value = payload.get(column, resolved_defaults.get(column))
        if value is None and column in resolved_defaults:
            value = resolved_defaults[column]
        if column in resolved_json_fields:
            value = json_dumps(value)
        if isinstance(value, bool):
            value = int(value)
        row.append(value)
    return row


def assert_allowed_values(values: Sequence[str], allowed: Iterable[str], label: str) -> None:
    invalid = sorted(set(values) - set(allowed))
    if invalid:
        raise ValueError(f"Unsupported {label}: {', '.join(invalid)}")


def parse_select_aliases(sql: str) -> list[str]:
    upper_sql = sql.upper()
    if "SELECT" not in upper_sql or "FROM" not in upper_sql:
        return []
    select_sql = sql[upper_sql.index("SELECT") + len("SELECT") : upper_sql.index("FROM")]
    aliases: list[str] = []
    for raw_part in select_sql.split(","):
        part = raw_part.strip()
        if " AS " in part.upper():
            aliases.append(part.rsplit(" ", 1)[-1])
        elif part and "(" not in part:
            aliases.append(part.split(".")[-1])
    return aliases
