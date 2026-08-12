from __future__ import annotations

import uuid
from datetime import date as Date, datetime, timezone
from threading import Lock
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.ai_engine import AIAnalyzer
from src.api.investigation_support import (
    build_ai_window_stats as _build_ai_window_stats,
    build_evidence_chain as _build_evidence_chain,
    fetch_ai_report as _fetch_ai_report,
    fetch_alert_baseline as _fetch_alert_baseline,
    fetch_related_logs as _fetch_related_logs,
    is_ai_judgement_candidate as _is_ai_judgement_candidate,
    reason_codes_combo as _reason_codes_combo,
    store_ai_feedback_suggestions as _store_ai_feedback_suggestions,
)
from src.config import settings
from src.detection.review import AnomalyReviewStore
from src.detection.investigation import build_investigation
from src.health import HealthResponse, get_health_status
from src.operations import NotificationService, OperationsRunner
from src.operations.runner import TASK_DEPENDENCIES
from src.report.daily_report import generate_daily_report
from src.schemas import (
    AIFeedback,
    AIFeedbackListResponse,
    AcceptanceReport,
    AcceptanceReportDetail,
    AcceptanceReportListResponse,
    AIJudgement,
    AIJudgementListResponse,
    AnomalyDetailResponse,
    AnomalyEvent,
    AnomalyEventListResponse,
    AnomalyReviewRequest,
    AnomalyReviewResponse,
    InvestigationResponse,
    BaselineRebuildResponse,
    BaselineOverride,
    BaselineOverrideCreateRequest,
    BaselineOverrideListResponse,
    BaselineOverrideRevokeRequest,
    DailyReport,
    DailyReportListResponse,
    ErrorResponse,
    FeedbackCreateRequest,
    FeedbackReviewRequest,
    FeedbackReviewResponse,
    LogAggregateRequest,
    LogAggregateResponse,
    NormalizedLog,
    NormalizedLogListResponse,
    NotificationOutbox,
    NotificationOutboxListResponse,
    OperationsTaskRun,
    OperationsTaskRunListResponse,
    RiskLevel,
    SourceType,
    StatsOverviewResponse,
    UserBaseline,
    UserBaselineListResponse,
    UserRiskStatsListResponse,
    UserRiskWindow,
)
from src.storage import ClickHouseStorage
from src.ueba import build_and_store_baselines


ERROR_RESPONSE_SCHEMA = {
    "model": ErrorResponse,
    "description": "Standard error response with code, message, and details.",
}
STANDARD_ERROR_RESPONSES = {
    400: ERROR_RESPONSE_SCHEMA,
    404: ERROR_RESPONSE_SCHEMA,
    422: ERROR_RESPONSE_SCHEMA,
    500: ERROR_RESPONSE_SCHEMA,
}
HTTP_ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "validation_error",
    500: "internal_error",
}
_daily_report_locks_guard = Lock()
_daily_report_locks: dict[tuple[str, str], Lock] = {}
_anomaly_review_store = AnomalyReviewStore()


app = FastAPI(
    title="Log AI Assistant API",
    version="0.1.0",
    description="FastAPI layer for the formal Filebeat -> Kafka -> Flink -> ClickHouse -> FastAPI -> React path.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["system"],
    summary="System health status",
    description="REQ-001, REQ-002, REQ-007: report Kafka, Flink, ClickHouse, DashScope config, latest log ingest time, and consumer lag.",
)
def health_check() -> HealthResponse:
    return get_health_status()


def get_storage() -> ClickHouseStorage:
    return ClickHouseStorage()


def get_anomaly_review_store() -> AnomalyReviewStore:
    """Return the process-local store used only by the interview demo review loop."""
    return _anomaly_review_store


def get_analyzer() -> AIAnalyzer:
    return AIAnalyzer()


def get_operations_runner(storage: ClickHouseStorage = Depends(get_storage)) -> OperationsRunner:
    return OperationsRunner(storage)


@app.get(
    "/api/v1/logs",
    response_model=NormalizedLogListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["logs"],
    summary="Query structured security logs",
    description="REQ-002, REQ-006: query normalized logs for the React realtime log view.",
)
def list_logs(
    tenant_id: str | None = Query(default=None),
    source_type: SourceType | None = Query(default=None),
    log_type: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    action: str | None = Query(default=None),
    result: str | None = Query(default=None),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> NormalizedLogListResponse:
    try:
        items, total = storage.list_logs(
            tenant_id=tenant_id,
            source_type=source_type,
            log_type=log_type,
            user_id=user_id,
            src_ip=src_ip,
            action=action,
            result=result,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query structured logs from ClickHouse",
                "details": {"table": "security_logs"},
            },
        ) from exc

    return NormalizedLogListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/api/v1/logs/{event_id}",
    response_model=NormalizedLog,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["logs"],
    summary="Get structured security log detail",
    description="REQ-002, REQ-006: fetch one normalized log by event_id.",
)
def get_log_detail(
    event_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> NormalizedLog:
    try:
        item = storage.get_log(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query structured log detail from ClickHouse",
                "details": {"table": "security_logs", "event_id": event_id},
            },
        ) from exc

    if not item:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "log_not_found",
                "message": "Structured log not found",
                "details": {"table": "security_logs", "event_id": event_id},
            },
        )

    return NormalizedLog(**item)


@app.post(
    "/api/v1/logs/aggregate",
    response_model=LogAggregateResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["logs"],
    summary="Aggregate structured security logs",
    description="REQ-002, REQ-006: aggregate normalized logs for trend and distribution views.",
)
def aggregate_logs(
    request: LogAggregateRequest,
    storage: ClickHouseStorage = Depends(get_storage),
) -> LogAggregateResponse:
    try:
        rows = storage.aggregate_logs(
            time_from=request.time_range.from_ if request.time_range else None,
            time_to=request.time_range.to if request.time_range else None,
            filters=request.filters,
            group_by=request.group_by,
            metrics=request.metrics,
            limit=request.limit,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_log_aggregate_request",
                "message": str(exc),
                "details": {},
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to aggregate structured logs from ClickHouse",
                "details": {"table": "security_logs"},
            },
        ) from exc

    return LogAggregateResponse(items=rows)


@app.get(
    "/api/v1/anomalies",
    response_model=AnomalyEventListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Query anomaly events",
    description="REQ-004, REQ-006, REQ-008: query anomaly events for the React abnormal event view.",
)
def list_alerts(
    tenant_id: str | None = Query(default=None),
    risk_level: RiskLevel | None = Query(default=None),
    user_id: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    reason_code: str | None = Query(default=None),
    ai_status: str | None = Query(default=None),
    status: str | None = Query(default=None),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> AnomalyEventListResponse:
    try:
        items, total = storage.list_anomalies(
            tenant_id=tenant_id,
            risk_level=risk_level,
            user_id=user_id,
            src_ip=src_ip,
            reason_code=reason_code,
            ai_status=ai_status,
            status=status,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query anomaly events from ClickHouse",
                "details": {"table": "anomaly_events"},
            },
        ) from exc

    return AnomalyEventListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/api/v1/anomalies/{event_id}",
    response_model=AnomalyDetailResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Get anomaly detail with evidence chain",
    description="REQ-004, REQ-006: fetch anomaly, user baseline, related logs, AI judgement, and evidence chain.",
)
def get_alert_detail(
    event_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> AnomalyDetailResponse:
    try:
        alert = storage.get_anomaly(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query anomaly detail from ClickHouse",
                "details": {"table": "anomaly_events", "event_id": event_id},
            },
        ) from exc

    if not alert:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "anomaly_not_found",
                "message": "Anomaly event not found",
                "details": {"table": "anomaly_events", "event_id": event_id},
            },
        )

    try:
        baseline = _fetch_alert_baseline(storage, alert)
        related_logs = _fetch_related_logs(storage, alert)
        ai_report = _fetch_ai_report(storage, alert)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to assemble anomaly evidence from ClickHouse",
                "details": {"event_id": event_id},
            },
        ) from exc

    return AnomalyDetailResponse(
        anomaly=alert,
        baseline=baseline,
        related_logs=related_logs,
        ai_judgement=ai_report,
        evidence_chain=_build_evidence_chain(alert, baseline, related_logs),
    )


@app.get(
    "/api/v1/demo/investigation-replay",
    tags=["demo"],
    summary="Replay fixed synthetic detection cases through the investigation demo",
    description="No-key, synthetic-only interview replay. It does not read or persist real security logs.",
)
def replay_investigation_demo() -> dict[str, Any]:
    """Expose the same deterministic detector-to-review replay used by the interview script."""
    from src.detection.interview_demo import run_interview_investigation_demo

    return run_interview_investigation_demo()


@app.get(
    "/api/v1/demo/evidence-brief",
    tags=["demo"],
    summary="Summarize fixed synthetic anomaly evidence for a local demo",
    description="No-key, synthetic-only summary. It does not read or persist real security logs.",
)
def get_evidence_demo_brief() -> dict[str, Any]:
    """Expose the deterministic demo scope and limitations without external services."""
    from src.detection.evidence_demo_brief import build_evidence_demo_brief

    return build_evidence_demo_brief()


@app.put(
    "/api/v1/anomalies/{event_id}/review",
    response_model=AnomalyReviewResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Record a demo analyst review label",
    description=(
        "Demo-only process-local review record for an anomaly ID. It has no account system or durable storage; "
        "records reset when the API process restarts."
    ),
)
@app.post(
    "/api/v1/anomalies/{event_id}/review",
    response_model=AnomalyReviewResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Record a demo analyst review label",
)
def save_anomaly_review(
    event_id: str,
    request: AnomalyReviewRequest,
    review_store: AnomalyReviewStore = Depends(get_anomaly_review_store),
    storage: ClickHouseStorage = Depends(get_storage),
) -> AnomalyReviewResponse:
    try:
        anomaly = storage.get_anomaly(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to load anomaly evidence for demo review",
                "details": {"table": "anomaly_events", "event_id": event_id},
            },
        ) from exc
    if anomaly is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "anomaly_not_found",
                "message": "Anomaly event not found",
                "details": {"table": "anomaly_events", "event_id": event_id},
            },
        )
    return review_store.save(
        event_id,
        request,
        reason_codes=[str(code) for code in anomaly.get("reason_codes") or []],
        evidence=dict(anomaly.get("evidence") or {}),
    )


@app.get(
    "/api/v1/anomalies/{event_id}/review",
    response_model=AnomalyReviewResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Read the latest demo analyst review label",
)
def get_anomaly_review(
    event_id: str,
    review_store: AnomalyReviewStore = Depends(get_anomaly_review_store),
) -> AnomalyReviewResponse:
    review = review_store.get(event_id)
    if review is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "anomaly_review_not_found",
                "message": "No demo analyst review exists for this anomaly",
                "details": {"event_id": event_id},
            },
        )
    return review


@app.get(
    "/api/v1/anomalies/{event_id}/investigation",
    response_model=InvestigationResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Build a sanitized, demo-grade anomaly investigation package",
)
def get_anomaly_investigation(
    event_id: str,
    review_store: AnomalyReviewStore = Depends(get_anomaly_review_store),
    storage: ClickHouseStorage = Depends(get_storage),
) -> InvestigationResponse:
    try:
        anomaly = storage.get_anomaly(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "clickhouse_query_failed", "message": "Failed to load anomaly investigation evidence", "details": {"event_id": event_id}},
        ) from exc
    if anomaly is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "anomaly_not_found", "message": "Anomaly event not found", "details": {"event_id": event_id}},
        )
    return build_investigation(anomaly, review_store.get(event_id))


@app.post(
    "/api/v1/anomalies/{event_id}/flag-false-positive",
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Flag an anomaly as potential false positive for review",
)
def flag_false_positive(
    event_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> dict[str, str]:
    try:
        alert = storage.get_anomaly(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query anomaly",
                "details": {"event_id": event_id},
            },
        ) from exc
    if not alert:
        raise HTTPException(
            status_code=404,
            detail={"code": "anomaly_not_found", "message": "Anomaly not found", "details": {"event_id": event_id}},
        )

    storage.update_anomaly_status(event_id, "pending_review")
    storage.insert_feedback(
        AIFeedback(
            feedback_id=f"fb-{uuid.uuid4()}",
            event_id=event_id,
            tenant_id=str(alert.get("tenant_id", "default")),
            user_id=str(alert.get("user_id", "")),
            feedback_type="false_positive",
            suggestion="分析员将此异常标记为误报复核。",
            target_component="scoring",
            confidence=1,
            review_status="pending",
            created_at=datetime.now(timezone.utc),
        )
    )
    return {"status": "ok", "event_id": event_id, "anomaly_status": "pending_review"}


@app.post(
    "/api/v1/anomalies/{event_id}/confirm-false-positive",
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Confirm a reviewed anomaly as false positive",
)
def confirm_false_positive(
    event_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> dict[str, str]:
    try:
        alert = storage.get_anomaly(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query anomaly",
                "details": {"event_id": event_id},
            },
        ) from exc
    if not alert:
        raise HTTPException(
            status_code=404,
            detail={"code": "anomaly_not_found", "message": "Anomaly not found", "details": {"event_id": event_id}},
        )

    storage.update_anomaly_status(event_id, "false_positive")
    # Feedback loop: increment false-positive count for this reason-code combo
    combo = _reason_codes_combo(alert)
    if combo:
        storage.upsert_reason_code_feedback_stats(
            tenant_id=str(alert.get("tenant_id", "default")),
            user_id=str(alert.get("user_id", "")),
            reason_codes_combo=combo,
            fp_delta=1,
        )
    return {"status": "ok", "event_id": event_id, "anomaly_status": "false_positive"}


@app.post(
    "/api/v1/anomalies/{event_id}/reject-false-positive",
    responses=STANDARD_ERROR_RESPONSES,
    tags=["anomalies"],
    summary="Reject a false-positive review — send back to anomaly list",
)
def reject_false_positive(
    event_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> dict[str, str]:
    try:
        alert = storage.get_anomaly(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query anomaly",
                "details": {"event_id": event_id},
            },
        ) from exc
    if not alert:
        raise HTTPException(
            status_code=404,
            detail={"code": "anomaly_not_found", "message": "Anomaly not found", "details": {"event_id": event_id}},
        )

    storage.update_anomaly_status(event_id, "rejected")
    # Feedback loop: increment confirmed (true-positive) count for this reason-code combo
    combo = _reason_codes_combo(alert)
    if combo:
        storage.upsert_reason_code_feedback_stats(
            tenant_id=str(alert.get("tenant_id", "default")),
            user_id=str(alert.get("user_id", "")),
            reason_codes_combo=combo,
            confirmed_delta=1,
        )
    return {"status": "ok", "event_id": event_id, "anomaly_status": "rejected"}


@app.post(
    "/api/v1/ai/judge/{event_id}",
    response_model=AIJudgement,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["ai"],
    summary="Judge an anomaly with AI",
    description="REQ-004: analyze an existing anomaly with anomaly, baseline, related_logs, and window_stats context, then store the AI judgement.",
)
def analyze_alert(
    event_id: str,
    # Plain bool default (not Query(...)) so direct callers get a real False;
    # FastAPI still exposes it as a `force` query parameter. Setting it overrides
    # the high/critical candidate gate and judges the anomaly anyway.
    force: bool = False,
    storage: ClickHouseStorage = Depends(get_storage),
    analyzer: AIAnalyzer = Depends(get_analyzer),
) -> AIJudgement:
    try:
        alert = storage.get_anomaly(event_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query anomaly for AI judgement",
                "details": {"table": "anomaly_events", "event_id": event_id},
            },
        ) from exc

    if not alert:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "anomaly_not_found",
                "message": "Anomaly event not found",
                "details": {"table": "anomaly_events", "event_id": event_id},
            },
        )

    # Candidate gate: the LLM only judges high-suspicion events (baseline rule:
    # "LLM 只处理高可疑事件的结构化证据包"). Allow high/critical risk or events
    # already queued (ai_status == pending); `force=true` overrides for re-runs.
    if not force and not _is_ai_judgement_candidate(alert):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_judgement_not_candidate",
                "message": "Anomaly is not an AI judgement candidate; only high/critical or pending events are analyzed. Pass force=true to override.",
                "details": {
                    "event_id": event_id,
                    "risk_level": str(alert.get("risk_level") or "unknown"),
                    "ai_status": str(alert.get("ai_status") or "not_required"),
                },
            },
        )

    try:
        baseline = _fetch_alert_baseline(storage, alert)
        related_logs = _fetch_related_logs(storage, alert)
        anomaly_event = AnomalyEvent.model_validate(alert)
        window_stats = _build_ai_window_stats(
            evidence=anomaly_event.evidence,
            related_logs=related_logs,
            related_event_ids=anomaly_event.related_event_ids,
            storage=storage,
        )
        report = analyzer.analyze(
            event=anomaly_event,
            baseline=baseline,
            related_logs=related_logs,
            window_stats=window_stats,
        )
        storage.insert_ai_judgement(report)
        storage.update_anomaly_ai_status(event_id, "analyzed")
        # Close the AI feedback loop: structured suggestions from the judgement
        # become pending ai_feedback rows (REQ-004). Best-effort so an enrichment
        # failure never voids an already-stored judgement.
        _store_ai_feedback_suggestions(storage, report, alert)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "ai_judgement_failed",
                "message": "Failed to judge anomaly and store AI judgement",
                "details": {"event_id": event_id},
            },
        ) from exc

    return report


@app.get(
    "/api/v1/baselines/users",
    response_model=UserBaselineListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["baselines"],
    summary="Query user behavior baselines",
    description="REQ-003, REQ-006: query user behavior baselines for the React baseline view.",
)
def list_baselines(
    tenant_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> UserBaselineListResponse:
    try:
        items, total = storage.list_user_baselines(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query user baselines from ClickHouse",
                "details": {"table": "ueba_user_baseline"},
            },
        ) from exc

    return UserBaselineListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.post(
    "/api/v1/baselines/rebuild",
    response_model=BaselineRebuildResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["baselines"],
    summary="Rebuild user behavior baselines",
    description="REQ-003: rebuild user behavior baselines from stored security logs.",
)
def rebuild_baselines(
    storage: ClickHouseStorage = Depends(get_storage),
) -> BaselineRebuildResponse:
    """Request the governed baseline task; lightweight adapters retain unit-test compatibility."""
    try:
        if hasattr(storage, "insert_task_run"):
            run = OperationsRunner(storage).run_task("baseline_rebuild")
            if run.status != "succeeded":
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": run.error_code or "baseline_rebuild_blocked",
                        "message": run.error_message or "Baseline rebuild did not pass operations gates",
                        "details": {"run_id": run.run_id, "status": run.status},
                    },
                )
            rebuilt_count = int(run.output_refs.get("row_count") or 0)
        else:
            rebuilt_count = len(build_and_store_baselines(storage))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "baseline_rebuild_failed",
                "message": "Failed to rebuild user baselines",
                "details": {"source_table": "security_logs", "target_table": "ueba_user_baseline"},
            },
        ) from exc

    return BaselineRebuildResponse(rebuilt_count=rebuilt_count)


@app.get(
    "/api/v1/baselines/overrides",
    response_model=BaselineOverrideListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["baselines"],
    summary="Query baseline overrides",
    description="REQ-003, REQ-006: query manual and reviewed baseline overrides.",
)
def list_baseline_overrides(
    tenant_id: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    source_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> BaselineOverrideListResponse:
    try:
        items, total = storage.list_baseline_overrides(
            tenant_id=tenant_id,
            user_id=user_id,
            status=status,
            source_type=source_type,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query baseline overrides from ClickHouse",
                "details": {"table": "ueba_baseline_overrides"},
            },
        ) from exc
    return BaselineOverrideListResponse(items=items, total=total, limit=limit, offset=offset)


@app.post(
    "/api/v1/baselines/overrides",
    response_model=BaselineOverride,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["baselines"],
    summary="Create a manual baseline override",
    description="REQ-003: append an auditable manual policy layer without changing statistical baselines.",
)
def create_baseline_override(
    request: BaselineOverrideCreateRequest,
    storage: ClickHouseStorage = Depends(get_storage),
) -> BaselineOverride:
    _validate_effective_range(request.effective_from, request.effective_to)
    now = datetime.now(timezone.utc)
    override = BaselineOverride(
        override_id=f"override-{uuid.uuid4()}",
        **request.model_dump(),
        source_type="manual",
        status="active",
        reviewed_by=request.created_by,
        reviewed_at=now,
        model_version=_new_effective_version(),
        created_at=now,
        updated_at=now,
    )
    try:
        storage.insert_baseline_override(override)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "baseline_override_write_failed",
                "message": "Failed to create baseline override",
                "details": {"table": "ueba_baseline_overrides", "user_id": request.user_id},
            },
        ) from exc
    return override


@app.post(
    "/api/v1/baselines/overrides/{override_id}/revoke",
    response_model=BaselineOverride,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["baselines"],
    summary="Revoke a baseline override",
    description="REQ-003: revoke an active override while retaining its audit history.",
)
def revoke_baseline_override(
    override_id: str,
    request: BaselineOverrideRevokeRequest,
    storage: ClickHouseStorage = Depends(get_storage),
) -> BaselineOverride:
    try:
        existing = storage.get_baseline_override(override_id)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "baseline_override_not_found",
                    "message": "Baseline override not found",
                    "details": {"override_id": override_id},
                },
            )
        if str(existing.get("status")) not in {"active", "pending"}:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "baseline_override_not_active",
                    "message": "Only active or pending overrides can be revoked",
                    "details": {"override_id": override_id, "status": existing.get("status")},
                },
            )
        updated = storage.update_baseline_override_status(
            override_id,
            status="revoked",
            reviewed_by=request.revoked_by,
            reason=request.reason,
            updated_at=datetime.now(timezone.utc),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "baseline_override_revoke_failed",
                "message": "Failed to revoke baseline override",
                "details": {"override_id": override_id},
            },
        ) from exc
    return BaselineOverride(**updated)


@app.get(
    "/api/v1/baselines/users/{user_id}",
    response_model=UserBaseline,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["baselines"],
    summary="Get user behavior baseline detail",
    description="REQ-003, REQ-006: fetch one user behavior baseline.",
)
def get_baseline_detail(
    user_id: str,
    tenant_id: str | None = Query(default=None),
    storage: ClickHouseStorage = Depends(get_storage),
) -> UserBaseline:
    try:
        item = storage.get_user_baseline(user_id, tenant_id=tenant_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query user baseline from ClickHouse",
                "details": {"table": "ueba_user_baseline", "user_id": user_id},
            },
        ) from exc

    if not item:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "baseline_not_found",
                "message": "User baseline not found",
                "details": {"table": "ueba_user_baseline", "user_id": user_id},
            },
        )

    return UserBaseline(**item)


@app.get(
    "/api/v1/ai/judgements",
    response_model=AIJudgementListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["ai"],
    summary="Query AI judgements",
    description="REQ-004, REQ-006: query AI judgements for the React AI analysis view.",
)
def list_ai_reports(
    event_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> AIJudgementListResponse:
    try:
        items, total = storage.list_ai_judgements(
            event_id=event_id,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query AI judgements from ClickHouse",
                "details": {"table": "ai_judgements"},
            },
        ) from exc

    return AIJudgementListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.post(
    "/api/v1/feedback",
    response_model=AIFeedback,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["feedback"],
    summary="Submit AI or analyst feedback",
    description="REQ-004: write AI or analyst feedback into ai_feedback for later review.",
)
def create_feedback(
    request: FeedbackCreateRequest,
    storage: ClickHouseStorage = Depends(get_storage),
) -> AIFeedback:
    feedback = AIFeedback(
        feedback_id=f"fb-{uuid.uuid4()}",
        event_id=request.event_id,
        judgement_id=request.judgement_id,
        tenant_id=request.tenant_id,
        user_id=request.user_id,
        feedback_type=request.feedback_type,
        suggestion=request.suggestion,
        target_component=request.target_component,
        confidence=request.confidence,
        review_status="pending",
        created_at=datetime.now(timezone.utc),
    )
    try:
        storage.insert_feedback(feedback)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "feedback_write_failed",
                "message": "Failed to write AI feedback into ClickHouse",
                "details": {"table": "ai_feedback", "event_id": request.event_id},
            },
        ) from exc
    return feedback


@app.get(
    "/api/v1/feedback",
    response_model=AIFeedbackListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["feedback"],
    summary="Query AI and analyst feedback",
    description="REQ-004, REQ-006: query pending and reviewed feedback for governance.",
)
def list_feedback(
    tenant_id: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
    target_component: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> AIFeedbackListResponse:
    try:
        items, total = storage.list_feedback(
            tenant_id=tenant_id,
            user_id=user_id,
            review_status=review_status,
            target_component=target_component,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query AI feedback from ClickHouse",
                "details": {"table": "ai_feedback"},
            },
        ) from exc
    return AIFeedbackListResponse(items=items, total=total, limit=limit, offset=offset)


@app.post(
    "/api/v1/feedback/{feedback_id}/review",
    response_model=FeedbackReviewResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["feedback"],
    summary="Review AI feedback",
    description="REQ-003, REQ-004: accept or reject feedback and create a versioned baseline override when required.",
)
def review_feedback(
    feedback_id: str,
    request: FeedbackReviewRequest,
    storage: ClickHouseStorage = Depends(get_storage),
) -> FeedbackReviewResponse:
    try:
        existing = storage.get_feedback(feedback_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "feedback_query_failed",
                "message": "Failed to query AI feedback",
                "details": {"feedback_id": feedback_id},
            },
        ) from exc
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "feedback_not_found",
                "message": "AI feedback not found",
                "details": {"feedback_id": feedback_id},
            },
        )
    if str(existing.get("review_status") or "pending") != "pending":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "feedback_already_reviewed",
                "message": "AI feedback has already been reviewed",
                "details": {"feedback_id": feedback_id, "review_status": existing.get("review_status")},
            },
        )

    now = datetime.now(timezone.utc)
    applied_override: BaselineOverride | None = None
    if request.decision == "accepted" and str(existing.get("target_component")) == "baseline":
        if request.override is None:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "baseline_override_required",
                    "message": "Accepted baseline feedback requires override details",
                    "details": {"feedback_id": feedback_id},
                },
            )
        _validate_effective_range(request.override.effective_from, request.override.effective_to)
        applied_override = BaselineOverride(
            override_id=f"override-{uuid.uuid4()}",
            tenant_id=str(existing.get("tenant_id") or "default"),
            user_id=str(existing.get("user_id") or ""),
            **request.override.model_dump(),
            source_type="ai_feedback",
            source_feedback_id=feedback_id,
            reason=request.review_reason,
            status="active",
            created_by="ai-feedback-review",
            reviewed_by=request.reviewed_by,
            reviewed_at=now,
            model_version=_new_effective_version(),
            created_at=now,
            updated_at=now,
        )

    applied_override_id = applied_override.override_id if applied_override else ""
    applied_version = applied_override.model_version if applied_override else ""
    try:
        if applied_override is not None:
            storage.insert_baseline_override(applied_override)
        storage.update_feedback_review(
            feedback_id,
            review_status=request.decision,
            reviewed_by=request.reviewed_by,
            reviewed_at=now,
            review_reason=request.review_reason,
            applied_override_id=applied_override_id,
            applied_version=applied_version,
        )
    except Exception as exc:
        if applied_override is not None:
            try:
                storage.update_baseline_override_status(
                    applied_override.override_id,
                    status="revoked",
                    reviewed_by=request.reviewed_by,
                    reason="Compensating revoke because feedback review persistence failed.",
                    updated_at=datetime.now(timezone.utc),
                )
            except Exception:
                pass
        raise HTTPException(
            status_code=500,
            detail={
                "code": "feedback_review_failed",
                "message": "Failed to review feedback and apply its governed change",
                "details": {"feedback_id": feedback_id},
            },
        ) from exc

    feedback = AIFeedback(
        **{
            **existing,
            "review_status": request.decision,
            "reviewed_by": request.reviewed_by,
            "reviewed_at": now,
            "review_reason": request.review_reason,
            "applied_override_id": applied_override_id or None,
            "applied_version": applied_version or None,
        }
    )
    return FeedbackReviewResponse(
        feedback=feedback,
        override=applied_override,
        applied_override_id=applied_override_id or None,
        applied_version=applied_version or None,
    )


@app.get(
    "/api/v1/reports/daily",
    response_model=DailyReportListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["daily-reports"],
    summary="Query daily security reports",
    description="REQ-005, REQ-006: query daily security posture reports.",
)
def list_daily_reports(
    tenant_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> DailyReportListResponse:
    try:
        items, total = storage.list_daily_reports(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query daily reports from ClickHouse",
                "details": {"table": "daily_security_reports"},
            },
        ) from exc

    return DailyReportListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/api/v1/reports/daily/{report_date}/markdown",
    responses={200: {"content": {"text/markdown": {}}}, **STANDARD_ERROR_RESPONSES},
    tags=["daily-reports"],
    summary="Download the canonical daily report Markdown",
)
def download_daily_report_markdown(
    report_date: Date,
    tenant_id: str = Query(default="default"),
    storage: ClickHouseStorage = Depends(get_storage),
) -> Response:
    try:
        report = storage.get_daily_report(tenant_id=tenant_id, report_date=report_date)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query daily report Markdown",
                "details": {"table": "daily_security_reports", "report_date": report_date.isoformat()},
            },
        ) from exc
    if not report:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "daily_report_not_found",
                "message": "Daily report not found",
                "details": {"tenant_id": tenant_id, "report_date": report_date.isoformat()},
            },
        )
    filename = f"daily-security-report-{tenant_id}-{report_date.isoformat()}.md"
    return Response(
        content=str(report.get("markdown") or ""),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get(
    "/api/v1/operations/tasks",
    responses=STANDARD_ERROR_RESPONSES,
    tags=["operations"],
    summary="List operations task definitions and latest runs",
)
def list_operations_tasks(
    tenant_id: str = Query(default="default"),
    storage: ClickHouseStorage = Depends(get_storage),
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for task_name, dependencies in TASK_DEPENDENCIES.items():
        runs, _ = storage.list_task_runs(task_name=task_name, tenant_id=tenant_id, limit=1, offset=0)
        items.append(
            {
                "task_name": task_name,
                "dependencies": list(dependencies),
                "latest_run": runs[0] if runs else None,
            }
        )
    return {"items": items}


@app.get(
    "/api/v1/operations/runs",
    response_model=OperationsTaskRunListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["operations"],
    summary="List operations task runs",
)
def list_operations_runs(
    task_name: str | None = Query(default=None),
    tenant_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    target_date: Date | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> OperationsTaskRunListResponse:
    items, total = storage.list_task_runs(
        task_name=task_name,
        tenant_id=tenant_id,
        status=status,
        target_date=target_date,
        limit=limit,
        offset=offset,
    )
    return OperationsTaskRunListResponse(items=items, total=total, limit=limit, offset=offset)


@app.get(
    "/api/v1/operations/runs/{run_id}",
    response_model=OperationsTaskRun,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["operations"],
    summary="Get one operations task run",
)
def get_operations_run(
    run_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> OperationsTaskRun:
    item = storage.get_task_run(run_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"code": "task_run_not_found", "message": "Task run not found", "details": {"run_id": run_id}},
        )
    return OperationsTaskRun.model_validate(item)


@app.post(
    "/api/v1/operations/runs/{run_id}/retry",
    response_model=OperationsTaskRun,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["operations"],
    summary="Retry a failed or needs-review operations task",
)
def retry_operations_run(
    run_id: str,
    runner: OperationsRunner = Depends(get_operations_runner),
) -> OperationsTaskRun:
    try:
        return runner.retry_run(run_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "task_run_not_found", "message": "Task run not found", "details": {"run_id": run_id}},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "task_run_not_retryable", "message": str(exc), "details": {"run_id": run_id}},
        ) from exc


@app.get(
    "/api/v1/acceptance/reports",
    response_model=AcceptanceReportListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["acceptance"],
    summary="List persisted acceptance reports",
)
def list_acceptance_reports(
    tenant_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=30, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> AcceptanceReportListResponse:
    items, total = storage.list_acceptance_reports(
        tenant_id=tenant_id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return AcceptanceReportListResponse(items=items, total=total, limit=limit, offset=offset)


@app.get(
    "/api/v1/acceptance/reports/{report_id}",
    response_model=AcceptanceReportDetail,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["acceptance"],
    summary="Get acceptance report metrics and bound versions",
)
def get_acceptance_report(
    report_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> AcceptanceReportDetail:
    report, metrics = storage.get_acceptance_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "acceptance_report_not_found",
                "message": "Acceptance report not found",
                "details": {"report_id": report_id},
            },
        )
    return AcceptanceReportDetail(report=AcceptanceReport.model_validate(report), metrics=metrics)


@app.get(
    "/api/v1/notifications",
    response_model=NotificationOutboxListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["notifications"],
    summary="List notification delivery state",
)
def list_notifications(
    tenant_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> NotificationOutboxListResponse:
    items, total = storage.list_notifications(
        tenant_id=tenant_id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return NotificationOutboxListResponse(items=items, total=total, limit=limit, offset=offset)


@app.get(
    "/api/v1/notifications/{outbox_id}",
    responses=STANDARD_ERROR_RESPONSES,
    tags=["notifications"],
    summary="Get notification state and delivery attempts",
)
def get_notification(
    outbox_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> dict[str, Any]:
    item = storage.get_notification(outbox_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "notification_not_found",
                "message": "Notification not found",
                "details": {"outbox_id": outbox_id},
            },
        )
    return {
        "notification": NotificationOutbox.model_validate(item),
        "attempts": storage.list_notification_attempts(outbox_id),
    }


@app.post(
    "/api/v1/notifications/{outbox_id}/retry",
    response_model=NotificationOutbox,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["notifications"],
    summary="Manually retry a notification",
)
def retry_notification(
    outbox_id: str,
    storage: ClickHouseStorage = Depends(get_storage),
) -> NotificationOutbox:
    try:
        item = NotificationService(storage).retry(outbox_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "notification_not_found",
                "message": "Notification not found",
                "details": {"outbox_id": outbox_id},
            },
        ) from exc
    return NotificationOutbox.model_validate(item)


@app.post(
    "/api/v1/reports/daily",
    response_model=DailyReport,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["daily-reports"],
    summary="Generate a daily security report",
    description="REQ-005: generate a daily security posture report for the specified date.",
)
def create_daily_report(
    date: str | None = Query(default=None, description="Date in YYYY-MM-DD format. Defaults to today (UTC)."),
    tenant_id: str = Query(default="default"),
    storage: ClickHouseStorage = Depends(get_storage),
) -> DailyReport:
    try:
        report_day = _resolve_daily_report_date(date)
        if hasattr(storage, "insert_task_run"):
            run = OperationsRunner(storage).run_task(
                "daily_report_generate",
                tenant_id=tenant_id,
                target_date=report_day,
            )
            if run.status != "succeeded":
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": run.error_code or "daily_report_blocked",
                        "message": run.error_message or "Daily report did not pass operations gates",
                        "details": {"run_id": run.run_id, "status": run.status},
                    },
                )
            stored = storage.get_daily_report(tenant_id=tenant_id, report_date=report_day)
            if not stored:
                raise RuntimeError("daily report task succeeded without a persisted report")
            report = DailyReport(**stored)
        else:
            lock = _daily_report_lock(tenant_id, report_day.isoformat())
            with lock:
                existing, _total = storage.list_daily_reports(
                    tenant_id=tenant_id,
                    start_date=report_day,
                    end_date=report_day,
                    limit=1,
                    offset=0,
                )
                if existing:
                    return DailyReport(**existing[0])
                report = generate_daily_report(storage, date_str=report_day.isoformat())
                storage.insert_daily_report(report, tenant_id=tenant_id)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_date",
                "message": str(exc),
                "details": {"date": date},
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "daily_report_generation_failed",
                "message": "Failed to generate daily report",
                "details": {"date": date, "source_table": "security_logs", "target_table": "daily_security_reports"},
            },
        ) from exc

    return report


@app.get(
    "/api/v1/stats/overview",
    response_model=StatsOverviewResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["stats"],
    summary="Get workbench overview statistics",
    description="REQ-006: query ClickHouse-backed counters for the workbench overview.",
)
def get_stats_overview(
    tenant_id: str | None = Query(default=None),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    storage: ClickHouseStorage = Depends(get_storage),
) -> StatsOverviewResponse:
    try:
        stats = storage.get_stats_overview(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query overview statistics from ClickHouse",
                "details": {"tables": ["security_logs", "anomaly_events"]},
            },
        ) from exc
    return StatsOverviewResponse(**stats)


@app.get(
    "/api/v1/stats/users/risk",
    response_model=UserRiskStatsListResponse,
    responses=STANDARD_ERROR_RESPONSES,
    tags=["stats"],
    summary="Get user risk ranking",
    description="REQ-003, REQ-006: rank users by anomaly-derived risk, with room for baseline enrichment later.",
)
def list_user_risk_stats(
    tenant_id: str | None = Query(default=None),
    window: UserRiskWindow = Query(default="7d", description="Risk aggregation window: 24h, 7d, 30d, or custom."),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    limit: int = Query(default=20, ge=1),
    offset: int = Query(default=0, ge=0),
    storage: ClickHouseStorage = Depends(get_storage),
) -> UserRiskStatsListResponse:
    try:
        items, total = storage.list_user_risk_stats(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
            window=window,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "clickhouse_query_failed",
                "message": "Failed to query user risk statistics from ClickHouse",
                "details": {"table": "anomaly_events"},
            },
        ) from exc
    return UserRiskStatsListResponse(items=items, total=total, limit=limit, offset=offset)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return _error_response(exc.status_code, exc.detail)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return _error_response(
        422,
        "Request validation failed",
        code="validation_error",
        details={"errors": jsonable_encoder(exc.errors())},
    )


def _error_response(
    status_code: int,
    detail: Any,
    *,
    code: str | None = None,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    payload = _build_error_response(status_code, detail, code=code, details=details)
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))


def _build_error_response(
    status_code: int,
    detail: Any,
    *,
    code: str | None = None,
    details: dict[str, Any] | None = None,
) -> ErrorResponse:
    if isinstance(detail, dict):
        detail_code = detail.get("code")
        detail_message = detail.get("message")
        detail_details = detail.get("details")
        if isinstance(detail_code, str) and isinstance(detail_message, str):
            return ErrorResponse(
                code=code or detail_code,
                message=detail_message,
                details=detail_details if isinstance(detail_details, dict) else details or {},
            )

    message = detail if isinstance(detail, str) else "Request failed"
    return ErrorResponse(
        code=code or HTTP_ERROR_CODES.get(status_code, "http_error"),
        message=message,
        details=details or {},
    )


def _resolve_daily_report_date(date_str: str | None) -> Date:
    if date_str is None:
        return datetime.now(timezone.utc).date()
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def _daily_report_lock(tenant_id: str, report_date: str) -> Lock:
    key = (tenant_id, report_date)
    with _daily_report_locks_guard:
        if key not in _daily_report_locks:
            _daily_report_locks[key] = Lock()
        return _daily_report_locks[key]


def _new_effective_version() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"baseline-effective-{timestamp}-{uuid.uuid4().hex[:8]}"


def _validate_effective_range(effective_from: datetime, effective_to: datetime | None) -> None:
    if effective_to is not None and effective_to <= effective_from:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_effective_range",
                "message": "effective_to must be later than effective_from",
                "details": {
                    "effective_from": effective_from.isoformat(),
                    "effective_to": effective_to.isoformat(),
                },
            },
        )
