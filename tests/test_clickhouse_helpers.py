from datetime import date, datetime, timezone

import pytest

from src.storage.clickhouse_helpers import (
    build_filters,
    clickhouse_type,
    columns_sql,
    json_loads,
    normalize_limit,
    pagination_parameters,
    where,
)


def test_build_filters_composes_typed_equalities_and_time_bounds() -> None:
    start = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)

    filters, parameters = build_filters(
        equals={"tenant_id": "default", "severity": 3, "ignored": None},
        time_field="event_time",
        start_time=start,
    )

    assert filters == [
        "tenant_id = {tenant_id:String}",
        "severity = {severity:Int64}",
        "event_time >= {start_time:DateTime64(3)}",
    ]
    assert parameters == {"tenant_id": "default", "severity": 3, "start_time": start}
    assert where(filters) == "WHERE " + " AND ".join(filters)
    assert where([]) == ""


def test_pagination_normalization_preserves_client_defaults_and_supports_caps() -> None:
    assert pagination_parameters(limit=0, offset=-4) == {"limit": 1, "offset": 0}
    assert normalize_limit(50_000, default=100, maximum=1_000) == 1_000
    assert normalize_limit(None, default=100, maximum=1_000) == 100


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (datetime(2026, 8, 12, tzinfo=timezone.utc), "DateTime64(3)"),
        (date(2026, 8, 12), "Date"),
        (1, "Int64"),
        (1.5, "Float64"),
        ("value", "String"),
    ],
)
def test_clickhouse_type_maps_supported_values(value: object, expected: str) -> None:
    assert clickhouse_type(value) == expected


def test_columns_sql_renders_plain_and_aliased_columns() -> None:
    assert columns_sql(("event_id", "event_time")) == "event_id, event_time"
    assert columns_sql(("event_id", "event_time"), "a") == ("a.event_id AS event_id, a.event_time AS event_time")


def test_json_loads_normalizes_structured_values_without_mutation() -> None:
    payload = {"key": "value"}

    assert json_loads('{"key":"value"}', default={}) == payload
    assert json_loads(payload, default={}) is payload
    assert json_loads("not-json", default={}) == {}
