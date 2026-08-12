from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from src.api.app import (
    app,
    create_baseline_override,
    review_feedback,
    revoke_baseline_override,
)
from src.schemas import (
    BaselineOverrideCreateRequest,
    BaselineOverrideRevokeRequest,
    FeedbackReviewOverride,
    FeedbackReviewRequest,
)
from src.ueba.effective import resolve_effective_baseline, select_periodic_baseline


EVENT_DATE = date(2026, 6, 29)
NOW = datetime(2026, 6, 15, 8, 0, tzinfo=timezone.utc)


def _baseline(
    period_type: str,
    period_key: str,
    *,
    sample_days: int = 10,
    resources: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "baseline_date": date(2026, 6, 15),
        "tenant_id": "default",
        "user_id": "alice",
        "model_version": f"baseline-v2-{period_type}-{period_key}",
        "period_type": period_type,
        "period_key": period_key,
        "trained_from": date(2026, 5, 1),
        "trained_to": date(2026, 6, 14),
        "sample_days": sample_days,
        "sample_count": 100,
        "baseline_confidence": 0.9,
        "who_profile": {"user_id": "alice"},
        "time_profile": {},
        "location_profile": {},
        "access_profile": {
            "common_resources": {
                "common_values": resources or ["/home"],
                "value_histogram": {},
            }
        },
        "volume_profile": {},
        "result_profile": {},
        "why_profile": {},
        "fallback_level": "none",
        "created_at": NOW,
    }


def _override(
    override_id: str,
    *,
    status: str = "active",
    period_type: str = "weekday_month_phase",
    period_key: str = "monday:month_end",
    values: list[str] | None = None,
    updated_at: datetime = NOW,
) -> dict[str, Any]:
    return {
        "override_id": override_id,
        "tenant_id": "default",
        "user_id": "alice",
        "profile_group": "access",
        "feature_name": "common_resources",
        "period_type": period_type,
        "period_key": period_key,
        "merge_mode": "append",
        "override_value": {"common_values": values or ["/api/reports/export"]},
        "source_type": "manual",
        "source_feedback_id": "",
        "reason": "confirmed business context",
        "status": status,
        "effective_from": NOW - timedelta(days=1),
        "effective_to": None,
        "created_by": "analyst",
        "reviewed_by": "analyst",
        "reviewed_at": NOW,
        "model_version": f"effective-{override_id}",
        "created_at": NOW,
        "updated_at": updated_at,
    }


def test_period_selection_uses_specific_to_general_fallback_order() -> None:
    baselines = [
        _baseline("global", "all"),
        _baseline("rolling", "30d"),
        _baseline("weekday", "monday"),
        _baseline("weekday_month_phase", "monday:month_end", sample_days=2),
    ]

    selected = select_periodic_baseline(baselines, event_time=EVENT_DATE)

    assert selected is not None
    assert selected["period_type"] == "weekday"
    assert selected["period_key"] == "monday"


def test_effective_baseline_applies_only_active_matching_overrides() -> None:
    baselines = [
        _baseline("global", "all"),
        _baseline("weekday_month_phase", "monday:month_end", sample_days=5),
    ]
    overrides = [
        _override("global", period_type="global", period_key="all", values=["/global"]),
        _override("exact", values=["/month-end"], updated_at=NOW + timedelta(seconds=1)),
        _override("revoked", status="revoked", values=["/revoked"]),
        {
            **_override("expired", values=["/expired"]),
            "effective_to": NOW - timedelta(seconds=1),
        },
    ]

    selected = resolve_effective_baseline(baselines, overrides, event_time=EVENT_DATE)

    assert selected is not None
    assert selected["period_type"] == "weekday_month_phase"
    assert selected["access_profile"]["common_resources"]["common_values"] == [
        "/home",
        "/global",
        "/month-end",
    ]
    assert selected["selected_baseline"]["override_ids"] == ["global", "exact"]
    assert selected["model_version"] == "effective-exact"


class FakeGovernanceStorage:
    def __init__(self, feedback: dict[str, Any] | None = None) -> None:
        self.feedback = feedback
        self.inserted_overrides: list[Any] = []
        self.feedback_updates: list[dict[str, Any]] = []
        self.override: dict[str, Any] | None = None

    def insert_baseline_override(self, override: Any) -> None:
        self.inserted_overrides.append(override)
        self.override = override.model_dump(mode="python") if hasattr(override, "model_dump") else dict(override)

    def get_feedback(self, _feedback_id: str) -> dict[str, Any] | None:
        return self.feedback

    def update_feedback_review(self, feedback_id: str, **kwargs: Any) -> None:
        self.feedback_updates.append({"feedback_id": feedback_id, **kwargs})

    def get_baseline_override(self, _override_id: str) -> dict[str, Any] | None:
        return self.override

    def update_baseline_override_status(self, override_id: str, **kwargs: Any) -> dict[str, Any] | None:
        assert self.override is not None
        self.override = {**self.override, "override_id": override_id, **kwargs}
        return self.override


def _feedback() -> dict[str, Any]:
    return {
        "feedback_id": "fb-1",
        "event_id": "anom-1",
        "judgement_id": "ai-1",
        "tenant_id": "default",
        "user_id": "alice",
        "feedback_type": "baseline_threshold",
        "suggestion": "Allow the confirmed month-end export.",
        "target_component": "baseline",
        "confidence": 0.9,
        "review_status": "pending",
        "created_at": NOW,
    }


def test_manual_override_is_created_active_without_mutating_statistical_baseline() -> None:
    storage = FakeGovernanceStorage()
    request = BaselineOverrideCreateRequest(
        user_id="alice",
        profile_group="time",
        feature_name="active_hours",
        period_type="weekday",
        period_key="saturday",
        merge_mode="append",
        override_value={"common_values": ["09:00-13:00"]},
        reason="confirmed Saturday duty",
        effective_from=NOW,
        created_by="alice-admin",
    )

    response = create_baseline_override(request=request, storage=storage)

    assert response.status == "active"
    assert response.source_type == "manual"
    assert response.created_by == "alice-admin"
    assert response.model_version.startswith("baseline-effective-")
    assert storage.inserted_overrides == [response]


def test_accepting_baseline_feedback_creates_override_and_records_applied_version() -> None:
    storage = FakeGovernanceStorage(feedback=_feedback())
    request = FeedbackReviewRequest(
        decision="accepted",
        reviewed_by="reviewer",
        review_reason="confirmed month-end workflow",
        override=FeedbackReviewOverride(
            profile_group="access",
            feature_name="common_resources",
            period_type="month_phase",
            period_key="month_end",
            merge_mode="append",
            override_value={"common_values": ["/api/reports/export"]},
            effective_from=NOW,
        ),
    )

    response = review_feedback("fb-1", request=request, storage=storage)

    assert response.feedback.review_status == "accepted"
    assert response.override is not None
    assert response.override.source_type == "ai_feedback"
    assert response.override.source_feedback_id == "fb-1"
    assert response.applied_override_id == response.override.override_id
    assert storage.feedback_updates[0]["applied_version"] == response.override.model_version


def test_rejecting_feedback_does_not_create_override() -> None:
    storage = FakeGovernanceStorage(feedback=_feedback())
    request = FeedbackReviewRequest(
        decision="rejected",
        reviewed_by="reviewer",
        review_reason="suggestion does not match evidence",
    )

    response = review_feedback("fb-1", request=request, storage=storage)

    assert response.feedback.review_status == "rejected"
    assert response.override is None
    assert storage.inserted_overrides == []
    assert storage.feedback_updates[0]["applied_override_id"] == ""


def test_revoke_keeps_override_history_and_changes_status() -> None:
    storage = FakeGovernanceStorage()
    created = create_baseline_override(
        request=BaselineOverrideCreateRequest(
            user_id="alice",
            profile_group="location",
            feature_name="common_ips",
            period_type="global",
            period_key="all",
            merge_mode="append",
            override_value={"common_values": ["10.0.0.7"]},
            reason="temporary office source",
            effective_from=NOW,
        ),
        storage=storage,
    )

    revoked = revoke_baseline_override(
        created.override_id,
        request=BaselineOverrideRevokeRequest(revoked_by="reviewer", reason="office task ended"),
        storage=storage,
    )

    assert revoked.status == "revoked"
    assert revoked.override_id == created.override_id


def test_governance_openapi_exposes_override_and_feedback_review_contracts() -> None:
    paths = app.openapi()["paths"]

    assert paths["/api/v1/baselines/overrides"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/BaselineOverrideListResponse"
    }
    assert paths["/api/v1/baselines/overrides"]["post"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "#/components/schemas/BaselineOverride"}
    assert paths["/api/v1/feedback/{feedback_id}/review"]["post"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "#/components/schemas/FeedbackReviewResponse"}
