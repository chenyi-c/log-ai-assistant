from __future__ import annotations

"""异常检测自动入库 worker。

从 ClickHouse security_logs 增量读取日志，复用 RuleEngine 生成 AnomalyEvent，
统一写入 anomaly_events。偏离求值与 seen_source 判定已收敛到 src/ueba/deviation.py。
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import time
from typing import Any, Protocol

from src.detection.rules import DetectionContext, RuleEngine
from src.operations.notifications import NotificationService
from src.schemas import AnomalyEvent, NormalizedLog
from src.ueba.deviation import (
    UserContext,
    evaluate_deviations,
    is_seen_source,
    load_user_context,
)


class DetectionStorage(Protocol):
    def list_logs(
        self,
        *,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], int]:
        ...

    def insert_anomalies(self, anomalies: list[AnomalyEvent]) -> None:
        ...

    def existing_anomaly_ids(self, event_ids: list[str]) -> set[str]:
        ...

    def get_user_baseline(self, user_id: str, *, tenant_id: str | None = None, baseline_date=None) -> dict[str, Any] | None:
        ...

    def query_user_seen_sources(
        self,
        tenant_id: str = "default",
        user_id: str | None = None,
        source_type: str | None = None,
        source_key: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        ...

    def upsert_user_seen_sources(self, sources: list[dict[str, Any]]) -> None:
        ...

    def get_user_reason_feedback_stats(
        self,
        tenant_id: str = "default",
        user_id: str | None = None,
    ) -> dict[str, dict[str, int]]:
        ...


@dataclass(frozen=True)
class DetectionRunSummary:
    logs_read: int
    anomalies_detected: int
    anomalies_inserted: int
    last_event_time: datetime | None
    duration_ms: int


class AnomalyDetectorWorker:
    def __init__(
        self,
        *,
        storage: DetectionStorage,
        lookback_minutes: int = 10,
        batch_size: int = 1000,
        recover_state_on_start: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.storage = storage
        self.lookback_minutes = lookback_minutes
        self.batch_size = batch_size
        self.recover_state_on_start = recover_state_on_start
        self._clock = clock or _now
        self._last_event_time: datetime | None = None
        self._seen_anomaly_ids: set[str] = set()
        self._engine = RuleEngine()
        self._batch_seen_sources: set[tuple[str, str, str, str]] = set()
        self._state_recovered = False
        # 每轮检测前按用户预取一次持久化上下文，避免逐条日志重复查询 ClickHouse 拖慢吞吐。
        self._round_contexts: dict[tuple[str, str, object], UserContext] = {}

    def run_once(self) -> DetectionRunSummary:
        started = time.perf_counter()
        end_time = self._clock()
        if self.recover_state_on_start and not self._state_recovered:
            self.recover_recent_state(end_time=end_time)
        start_time = self._start_time(end_time)
        items, total = self.storage.list_logs(
            start_time=start_time,
            end_time=end_time,
            limit=self.batch_size,
            offset=0,
        )
        if total > self.batch_size:
            oldest_page_offset = max(total - self.batch_size, 0)
            items, _total = self.storage.list_logs(
                start_time=start_time,
                end_time=end_time,
                limit=self.batch_size,
                offset=oldest_page_offset,
            )
        logs = [NormalizedLog.model_validate(item) for item in items]
        logs.sort(key=lambda item: item.event_time)

        self._round_contexts = self._prefetch_contexts(logs)
        try:
            self._engine.feedback_stats = self.storage.get_user_reason_feedback_stats()
        except Exception:
            self._engine.feedback_stats = {}
        anomalies = _dedupe_anomalies(self._detect_logs(logs), self._seen_anomaly_ids)
        if anomalies:
            existing_ids = self.storage.existing_anomaly_ids([item.event_id for item in anomalies])
            anomalies = [item for item in anomalies if item.event_id not in existing_ids]
        if anomalies:
            self.storage.insert_anomalies(anomalies)
            try:
                NotificationService(self.storage).enqueue_anomalies(anomalies)
            except Exception:
                # The anomaly event is the security fact. Notification intent is
                # retried independently and must never roll back anomaly storage.
                pass

        self._upsert_seen_sources(logs)

        if logs:
            self._last_event_time = max(item.event_time for item in logs)

        return DetectionRunSummary(
            logs_read=len(logs),
            anomalies_detected=len(anomalies),
            anomalies_inserted=len(anomalies),
            last_event_time=self._last_event_time,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def recover_recent_state(self, *, end_time: datetime | None = None) -> int:
        """Warm up short sliding windows from recent logs without inserting anomalies."""

        if self._state_recovered:
            return 0
        resolved_end = end_time or self._clock()
        start_time = resolved_end - timedelta(minutes=self.lookback_minutes)
        items, total = self.storage.list_logs(
            start_time=start_time,
            end_time=resolved_end,
            limit=self.batch_size,
            offset=0,
        )
        if total > self.batch_size:
            oldest_page_offset = max(total - self.batch_size, 0)
            items, _total = self.storage.list_logs(
                start_time=start_time,
                end_time=resolved_end,
                limit=self.batch_size,
                offset=oldest_page_offset,
            )
        logs = [NormalizedLog.model_validate(item) for item in items]
        logs.sort(key=lambda item: item.event_time)
        if not logs:
            self._state_recovered = True
            return 0

        self._round_contexts = self._prefetch_contexts(logs)
        warmed_anomalies = self._detect_logs(logs)
        self._seen_anomaly_ids.update(item.event_id for item in warmed_anomalies)
        self._last_event_time = max(item.event_time for item in logs)
        self._state_recovered = True
        return len(logs)

    def run_forever(self, *, interval_seconds: int = 30) -> None:
        while True:
            summary = self.run_once()
            print(_summary_line(summary), flush=True)
            time.sleep(interval_seconds)

    def _start_time(self, end_time: datetime) -> datetime:
        if self._last_event_time is not None:
            return self._last_event_time
        return end_time - timedelta(minutes=self.lookback_minutes)

    def _detect_logs(self, logs: list[NormalizedLog]) -> list[AnomalyEvent]:
        anomalies: list[AnomalyEvent] = []
        for log in logs:
            context = self._context_for_log(log)
            anomalies.extend(self._engine.evaluate_log(log, context))
            source = _source_identity(log)
            if source:
                self._batch_seen_sources.add(source)
        return anomalies

    def _prefetch_contexts(self, logs: list[NormalizedLog]) -> dict[tuple[str, str, object], UserContext]:
        """按 (tenant, user, event_date) 预取上下文，保证跨周期事件选对 baseline。"""

        cache: dict[tuple[str, str, object], UserContext] = {}
        for log in logs:
            if not log.user_id:
                continue
            key = (log.tenant_id, log.user_id, log.event_time.date())
            if key not in cache:
                cache[key] = load_user_context(self.storage, log.tenant_id, log.user_id, log.event_time)
        return cache

    def _context_for_log(self, log: NormalizedLog) -> DetectionContext:
        ctx = self._round_contexts.get((log.tenant_id, log.user_id, log.event_time.date())) if log.user_id else None
        if ctx is None:
            ctx = load_user_context(self.storage, log.tenant_id, log.user_id, log.event_time)
        deviations = [d.to_dict() for d in evaluate_deviations(log, ctx)]
        baseline_available = ctx.baseline is not None
        source = _source_identity(log)
        if not source:
            return DetectionContext(
                baseline_deviations=deviations,
                baseline_available=baseline_available,
            )

        _, _, _, source_key = source
        seen = (source in self._batch_seen_sources) or is_seen_source(ctx, source_key)
        return DetectionContext(
            seen_source=seen,
            baseline_deviations=deviations,
            baseline_available=baseline_available,
        )

    def _upsert_seen_sources(self, logs: list[NormalizedLog]) -> None:
        sources: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for log in logs:
            source = _source_identity(log)
            if not source:
                continue
            tenant_id, user_id, source_type, source_key = source
            current = sources.get(source)
            if current is None:
                sources[source] = {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "source_type": source_type,
                    "source_key": source_key,
                    "first_seen_time": log.event_time,
                    "last_seen_time": log.event_time,
                    "seen_count": 1,
                }
            else:
                current["first_seen_time"] = min(current["first_seen_time"], log.event_time)
                current["last_seen_time"] = max(current["last_seen_time"], log.event_time)
                current["seen_count"] = int(current.get("seen_count") or 0) + 1

        if sources:
            self.storage.upsert_user_seen_sources(
                [self._merge_existing_seen_source(source) for source in sources.values()]
            )

    def _merge_existing_seen_source(self, source: dict[str, Any]) -> dict[str, Any]:
        existing = self.storage.query_user_seen_sources(
            tenant_id=str(source["tenant_id"]),
            user_id=str(source["user_id"]),
            source_type=str(source["source_type"]),
            source_key=str(source["source_key"]),
            limit=1,
        )
        if not existing:
            return source

        row = existing[0]
        return {
            **source,
            "first_seen_time": row.get("first_seen_time") or source["first_seen_time"],
            "seen_count": int(row.get("seen_count") or 0) + int(source.get("seen_count") or 0),
        }


def _dedupe_anomalies(
    anomalies: list[AnomalyEvent],
    seen_ids: set[str],
) -> list[AnomalyEvent]:
    result: list[AnomalyEvent] = []
    for anomaly in anomalies:
        if anomaly.event_id in seen_ids:
            continue
        seen_ids.add(anomaly.event_id)
        result.append(anomaly)
    return result


def _source_identity(log: NormalizedLog) -> tuple[str, str, str, str] | None:
    if not log.user_id or not log.src_ip:
        return None
    return (log.tenant_id, log.user_id, "ip", log.src_ip)


def _summary_line(summary: DetectionRunSummary) -> str:
    last = summary.last_event_time.isoformat() if summary.last_event_time else "-"
    return (
        "detector round finished: "
        f"logs_read={summary.logs_read} "
        f"anomalies_detected={summary.anomalies_detected} "
        f"anomalies_inserted={summary.anomalies_inserted} "
        f"last_event_time={last} "
        f"duration_ms={summary.duration_ms}"
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)
