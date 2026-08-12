from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import uuid
from contextlib import contextmanager
from datetime import date, datetime, time as day_time, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable
from zoneinfo import ZoneInfo

try:  # Linux containers use POSIX advisory locks.
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - exercised by Windows local runs.
    fcntl = None  # type: ignore[assignment]

from src.config import PROJECT_ROOT
from src.operations.acceptance import evaluate_scenarios
from src.operations.config import OperationsConfig, load_operations_config, load_thresholds
from src.operations.notifications import NotificationWorker
from src.operations.notifications import NotificationService
from src.schemas import AnomalyEvent
from src.quality.data_quality import build_reconciliation_report, write_data_quality_metrics
from src.report.daily_report import generate_daily_report
from src.schemas import OperationsTaskRun
from src.ueba.baseline import aggregate_daily_features, build_and_store_baselines


TASK_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "daily_feature_aggregate": (),
    "baseline_rebuild": ("daily_feature_aggregate",),
    "data_quality_reconcile": (),
    "daily_report_generate": ("baseline_rebuild", "data_quality_reconcile"),
    "scenario_evaluate": (),
    "notification_deliver": (),
}
WATERMARK_TASKS = {
    "daily_feature_aggregate",
    "baseline_rebuild",
    "data_quality_reconcile",
    "daily_report_generate",
}
_WINDOWS_LOCKS: dict[str, Lock] = {}
_WINDOWS_LOCKS_GUARD = Lock()


class TaskNeedsReview(RuntimeError):
    def __init__(self, code: str, message: str, output_refs: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.output_refs = output_refs or {}


class OperationsRunner:
    def __init__(
        self,
        storage: Any,
        config: OperationsConfig | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] | None = None,
        lag_probe: Callable[[], dict[str, int]] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or load_operations_config()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep or time.sleep
        self.lag_probe = lag_probe
        self.code_version = _git_commit()

    def run_task(
        self,
        task_name: str,
        *,
        tenant_id: str = "default",
        target_date: date | None = None,
        force: bool = False,
    ) -> OperationsTaskRun:
        if task_name not in TASK_DEPENDENCIES:
            raise ValueError(f"unknown operations task: {task_name}")
        target = target_date or self.default_target_date(task_name)
        idempotency_key = self.idempotency_key(task_name, tenant_id, target)

        existing = self.storage.successful_task_run(idempotency_key)
        if existing:
            return OperationsTaskRun.model_validate(existing)

        with self._task_lock(idempotency_key):
            existing = self.storage.successful_task_run(idempotency_key)
            if existing:
                return OperationsTaskRun.model_validate(existing)

            for dependency in TASK_DEPENDENCIES[task_name]:
                result = self.run_task(
                    dependency,
                    tenant_id=tenant_id,
                    target_date=target,
                    force=False,
                )
                if result.status != "succeeded":
                    return self._record_terminal(
                        task_name,
                        tenant_id,
                        target,
                        idempotency_key,
                        status="needs_review",
                        error_code="dependency_not_satisfied",
                        error_message=f"dependency {dependency} ended with {result.status}",
                        input_watermark=result.input_watermark,
                    )

            watermark = self._watermark(tenant_id, target)
            if task_name in WATERMARK_TASKS and not bool(watermark.get("ready")):
                return self._record_terminal(
                    task_name,
                    tenant_id,
                    target,
                    idempotency_key,
                    status="needs_review",
                    error_code="input_watermark_incomplete",
                    error_message=str(watermark.get("reason") or "input watermark is incomplete"),
                    input_watermark=watermark,
                )

            start_attempt = self.storage.max_task_attempt(idempotency_key) + 1
            last: OperationsTaskRun | None = None
            for offset in range(self.config.max_attempts):
                attempt = start_attempt + offset
                last = self._execute_attempt(
                    task_name,
                    tenant_id,
                    target,
                    idempotency_key,
                    attempt,
                    watermark,
                )
                if last.status in {"succeeded", "needs_review"}:
                    return last
                if offset + 1 < self.config.max_attempts:
                    self.sleep(self.config.retry_base_seconds * (2**offset))
            assert last is not None
            return last

    def run_scheduler_forever(self) -> None:
        while True:
            local_now = self.clock().astimezone(_timezone(self.config.timezone_name))
            target = local_now.date() - timedelta(days=1)
            for task_name in (
                "daily_feature_aggregate",
                "data_quality_reconcile",
                "baseline_rebuild",
                "daily_report_generate",
            ):
                if self._task_due(task_name, local_now):
                    self.run_task(task_name, target_date=target)
            self.run_task("notification_deliver", target_date=local_now.date(), force=True)
            self.sleep(self.config.scheduler_interval_seconds)

    def default_target_date(self, task_name: str) -> date:
        local_now = self.clock().astimezone(_timezone(self.config.timezone_name))
        if task_name in WATERMARK_TASKS:
            return local_now.date() - timedelta(days=1)
        return local_now.date()

    def idempotency_key(self, task_name: str, tenant_id: str, target_date: date) -> str:
        if task_name == "baseline_rebuild":
            raw = f"{tenant_id}:{task_name}:{target_date.isoformat()}:baseline-v2"
        elif task_name == "scenario_evaluate":
            scenario_version = _file_digest(PROJECT_ROOT / "log-generator" / "scenarios" / "default.json")
            policy_version = os.getenv("DETECTION_POLICY_VERSION", "rules-v1")
            raw = f"{self.code_version}:{scenario_version}:{policy_version}"
        elif task_name == "notification_deliver":
            raw = f"{tenant_id}:{task_name}:{target_date.isoformat()}:{self.clock().strftime('%Y%m%d%H%M')}"
        else:
            raw = f"{tenant_id}:{task_name}:{target_date.isoformat()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def retry_run(self, run_id: str) -> OperationsTaskRun:
        existing = self.storage.get_task_run(run_id)
        if not existing:
            raise KeyError(run_id)
        if existing.get("status") not in {"failed", "needs_review"}:
            raise ValueError("only failed or needs_review task runs can be retried")
        return self.run_task(
            str(existing["task_name"]),
            tenant_id=str(existing.get("tenant_id") or "default"),
            target_date=_as_date(existing["target_date"]),
            force=True,
        )

    def _execute_attempt(
        self,
        task_name: str,
        tenant_id: str,
        target_date: date,
        idempotency_key: str,
        attempt: int,
        watermark: dict[str, Any],
    ) -> OperationsTaskRun:
        now = self.clock()
        run = OperationsTaskRun(
            run_id=f"run-{uuid.uuid4()}",
            task_name=task_name,
            tenant_id=tenant_id,
            target_date=target_date,
            idempotency_key=idempotency_key,
            scheduled_at=now,
            started_at=now,
            status="running",
            attempt=attempt,
            input_watermark=watermark,
            code_version=self.code_version,
            version=1,
        )
        self.storage.insert_task_run(run)
        try:
            output_refs = self._handler(task_name)(tenant_id, target_date, run.run_id, watermark)
            final = run.model_copy(
                update={
                    "status": "succeeded",
                    "finished_at": self.clock(),
                    "output_refs": output_refs,
                    "version": 2,
                }
            )
        except TaskNeedsReview as exc:
            final = run.model_copy(
                update={
                    "status": "needs_review",
                    "finished_at": self.clock(),
                    "output_refs": exc.output_refs,
                    "error_code": exc.code,
                    "error_message": str(exc),
                    "version": 2,
                }
            )
        except Exception as exc:
            final = run.model_copy(
                update={
                    "status": "failed",
                    "finished_at": self.clock(),
                    "error_code": type(exc).__name__,
                    "error_message": str(exc),
                    "version": 2,
                }
            )
        self.storage.insert_task_run(final)
        return final

    def _record_terminal(
        self,
        task_name: str,
        tenant_id: str,
        target_date: date,
        idempotency_key: str,
        *,
        status: str,
        error_code: str,
        error_message: str,
        input_watermark: dict[str, Any],
    ) -> OperationsTaskRun:
        attempt = self.storage.max_task_attempt(idempotency_key) + 1
        now = self.clock()
        run = OperationsTaskRun(
            run_id=f"run-{uuid.uuid4()}",
            task_name=task_name,
            tenant_id=tenant_id,
            target_date=target_date,
            idempotency_key=idempotency_key,
            scheduled_at=now,
            started_at=now,
            finished_at=now,
            status=status,
            attempt=attempt,
            input_watermark=input_watermark,
            code_version=self.code_version,
            error_code=error_code,
            error_message=error_message,
            version=1,
        )
        self.storage.insert_task_run(run)
        return run

    def _handler(self, task_name: str) -> Callable[[str, date, str, dict[str, Any]], dict[str, Any]]:
        return {
            "daily_feature_aggregate": self._daily_feature,
            "baseline_rebuild": self._baseline,
            "data_quality_reconcile": self._quality,
            "daily_report_generate": self._daily_report,
            "scenario_evaluate": self._scenario,
            "notification_deliver": self._notifications,
        }[task_name]

    def _daily_feature(self, tenant_id: str, target_date: date, _run_id: str, _watermark: dict[str, Any]) -> dict[str, Any]:
        count = aggregate_daily_features(self.storage, target_date)
        return {"table": "ueba_user_daily_features", "feature_date": target_date.isoformat(), "row_count": count}

    def _baseline(self, tenant_id: str, target_date: date, _run_id: str, _watermark: dict[str, Any]) -> dict[str, Any]:
        baselines = build_and_store_baselines(self.storage)
        if not baselines:
            raise TaskNeedsReview("baseline_training_data_missing", "no daily features were available for baseline training")
        unique_users = len({(item.tenant_id, item.user_id) for item in baselines})
        return {
            "table": "ueba_user_baseline",
            "baseline_date": target_date.isoformat(),
            "row_count": unique_users,
            "model_versions": sorted({item.model_version for item in baselines}),
        }

    def _quality(self, tenant_id: str, target_date: date, _run_id: str, _watermark: dict[str, Any]) -> dict[str, Any]:
        thresholds = load_thresholds(self.config.threshold_path)
        metrics = write_data_quality_metrics(
            storage=self.storage,
            manifest_path=self.config.manifest_path,
            metric_date=target_date,
        )
        report = build_reconciliation_report(metrics)
        if not metrics:
            raise TaskNeedsReview("quality_manifest_missing", "no manifest rows matched the target date")
        blocking = _quality_blockers(metrics, thresholds)
        output = {"table": "data_quality_metrics", "metric_count": len(metrics), "reconciliation": report, "blocking": blocking}
        if blocking:
            raise TaskNeedsReview("data_quality_gate_failed", "data quality contains unexplained or threshold-breaking differences", output)
        return output

    def _daily_report(self, tenant_id: str, target_date: date, run_id: str, watermark: dict[str, Any]) -> dict[str, Any]:
        existing, _ = self.storage.list_daily_reports(
            tenant_id=tenant_id,
            start_date=target_date,
            end_date=target_date,
            limit=1,
            offset=0,
        )
        if existing:
            return {"table": "daily_security_reports", "report_id": existing[0]["report_id"], "deduplicated": True}
        report = generate_daily_report(self.storage, date_str=target_date.isoformat())
        report.run_id = run_id
        report.input_watermark = watermark
        report.quality_status = "succeeded"
        self.storage.insert_daily_report(report, tenant_id=tenant_id)
        return {"table": "daily_security_reports", "report_id": report.report_id, "report_date": report.date}

    def _scenario(self, tenant_id: str, target_date: date, run_id: str, _watermark: dict[str, Any]) -> dict[str, Any]:
        now = self.clock()
        if target_date == now.date():
            sample_to = now
            sample_from = now - timedelta(minutes=int(os.getenv("ACCEPTANCE_LOOKBACK_MINUTES", "2")))
        else:
            sample_from = datetime.combine(target_date, day_time.min, tzinfo=timezone.utc)
            sample_to = sample_from + timedelta(days=1)
        report, metrics = evaluate_scenarios(
            self.storage,
            tenant_id=tenant_id,
            run_id=run_id,
            sample_from=sample_from,
            sample_to=sample_to,
        )
        if report.status != "passed":
            raise TaskNeedsReview(
                "scenario_acceptance_failed",
                "scenario acceptance thresholds were not met",
                {"report_id": report.report_id, "metric_count": len(metrics), "status": report.status},
            )
        return {"table": "acceptance_reports", "report_id": report.report_id, "metric_count": len(metrics)}

    def _notifications(self, _tenant_id: str, target_date: date, _run_id: str, _watermark: dict[str, Any]) -> dict[str, Any]:
        now = self.clock()
        if target_date == now.date():
            end = now
            start = now - timedelta(minutes=int(os.getenv("ACCEPTANCE_LOOKBACK_MINUTES", "2")))
        else:
            start = datetime.combine(target_date, day_time.min, tzinfo=timezone.utc)
            end = start + timedelta(days=1)
        high, _ = self.storage.list_anomalies(
            risk_level="high", start_time=start, end_time=end, limit=1000, offset=0
        )
        critical, _ = self.storage.list_anomalies(
            risk_level="critical", start_time=start, end_time=end, limit=1000, offset=0
        )
        enqueued = NotificationService(self.storage, self.config).enqueue_anomalies(
            [AnomalyEvent.model_validate(item) for item in [*high, *critical]]
        )
        delivered = NotificationWorker(self.storage, self.config).deliver_due(limit=10000)
        output = {"backfilled": len(enqueued), **delivered}
        if delivered["failed"]:
            raise RuntimeError(f"{delivered['failed']} notification deliveries are waiting for retry")
        return output

    def _watermark(self, tenant_id: str, target_date: date) -> dict[str, Any]:
        values = dict(self.storage.data_watermark(tenant_id=tenant_id, target_date=target_date))
        local_zone = _timezone(self.config.timezone_name)
        target_end_local = datetime.combine(target_date + timedelta(days=1), day_time.min, tzinfo=local_zone)
        target_end_utc = target_end_local.astimezone(timezone.utc)
        ready_after = target_end_utc + timedelta(minutes=self.config.watermark_grace_minutes)
        now = self.clock()
        count = int(values.get("distinct_event_count") or values.get("security_logs_count") or 0)
        window_closed = now >= ready_after
        lag_ok, max_lag, lag_limit = self._consumer_lag_ready()
        ready = window_closed and count > 0 and lag_ok
        if not ready:
            if not window_closed:
                reason = "target window is still open"
            elif count <= 0:
                reason = "no target-date logs reached ClickHouse"
            else:
                reason = f"kafka consumer lag {max_lag} exceeds threshold {lag_limit}"
        else:
            reason = ""
        values.update(
            {
                "target_end": target_end_utc.isoformat(),
                "ready_after": ready_after.isoformat(),
                "checked_at": now.isoformat(),
                "window_closed": window_closed,
                "consumer_lag": max_lag,
                "ready": ready,
                "reason": reason,
            }
        )
        return values

    def _consumer_lag_ready(self) -> tuple[bool, int, int]:
        """Return (within_threshold, observed_max_lag, threshold).

        When no lag probe is configured the check is skipped (treated as ready), so
        unit tests and environments without Kafka access keep working.
        """

        if self.lag_probe is None:
            return True, 0, 0
        try:
            lags = self.lag_probe() or {}
            max_lag = max((int(value) for value in lags.values()), default=0)
        except Exception:
            return True, 0, 0
        limit = int(load_thresholds(self.config.threshold_path).get("consumer_lag_max", 0))
        return max_lag <= limit, max_lag, limit

    def _task_due(self, task_name: str, local_now: datetime) -> bool:
        default_hours = {
            "daily_feature_aggregate": 1,
            "data_quality_reconcile": 2,
            "baseline_rebuild": 3,
            "daily_report_generate": 4,
        }
        env_name = f"OPERATIONS_{task_name.upper()}_HOUR"
        hour = int(os.getenv(env_name, str(default_hours[task_name])))
        return local_now.hour >= hour

    @contextmanager
    def _task_lock(self, idempotency_key: str):
        self.config.lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.config.lock_dir / f"{idempotency_key}.lock"
        if fcntl is None:
            with _windows_lock(lock_path):
                yield
            return
        with lock_path.open("a+b") as handle:
            _lock_file(handle)
            try:
                yield
            finally:
                _unlock_file(handle)


def _lock_file(handle: Any) -> None:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(handle: Any) -> None:
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _windows_lock(lock_path: Path):
    """Keep local Windows demos single-process without changing Docker locking."""
    key = str(lock_path.resolve()).casefold()
    with _WINDOWS_LOCKS_GUARD:
        lock = _WINDOWS_LOCKS.setdefault(key, Lock())
    with lock:
        yield


def _timezone(name: str):
    """Avoid an unnecessary tzdata dependency for the universal UTC setting."""
    return timezone.utc if name.upper() == "UTC" else ZoneInfo(name)


def _quality_blockers(metrics: list[Any], thresholds: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    for metric in metrics:
        raw = int(metric.raw_logs_count)
        parsed = int(metric.parsed_logs_count)
        inserted = int(metric.clickhouse_insert_count)
        security = int(metric.security_logs_count)
        loss_rate = max(0.0, (raw - parsed) / raw) if raw else 0.0
        missing_rate = max(
            metric.missing_event_time_rate,
            metric.missing_user_id_rate,
            metric.missing_src_ip_rate,
            metric.missing_action_rate,
            metric.missing_result_rate,
        )
        checks = {
            "generated_to_raw_difference": metric.generated_count != raw,
            "raw_to_parsed_loss_rate": loss_rate > float(thresholds["raw_to_parsed_loss_rate_max"]),
            "parsed_to_security_difference": parsed != security,
            "clickhouse_insert_underflow": inserted < parsed,
            "parse_error_rate": metric.parse_error_rate > float(thresholds["parse_error_rate_max"]),
            "required_field_missing_rate": missing_rate > float(thresholds["required_field_missing_rate_max"]),
            "event_id_traceability_rate": metric.event_id_traceability_rate
            < float(thresholds["event_id_traceability_rate_min"]),
        }
        failed = [name for name, value in checks.items() if value]
        if failed:
            blockers.append(
                {
                    "tenant_id": metric.tenant_id,
                    "source_type": str(metric.source_type),
                    "failed_checks": failed,
                    "counts": {
                        "generated": metric.generated_count,
                        "raw": raw,
                        "parsed": parsed,
                        "clickhouse_insert": inserted,
                        "security": security,
                    },
                }
            )
    return blockers


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True).strip()
    except Exception:
        return _read_git_head() or os.getenv("CODE_VERSION", "unknown")


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _as_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def _read_git_head() -> str:
    head_path = PROJECT_ROOT / ".git" / "HEAD"
    if not head_path.exists():
        return ""
    head = head_path.read_text(encoding="utf-8").strip()
    if head.startswith("ref: "):
        ref_path = PROJECT_ROOT / ".git" / head.removeprefix("ref: ")
        return ref_path.read_text(encoding="utf-8").strip() if ref_path.exists() else ""
    return head
