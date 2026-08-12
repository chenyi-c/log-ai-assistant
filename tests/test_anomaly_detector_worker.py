"""Anomaly detector worker 的单元测试。"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from src.config import settings
from src.detection.worker import AnomalyDetectorWorker
from src.schemas import AnomalyEvent, NormalizedLog


BASE_TIME = datetime(2026, 6, 4, 10, 0, 0)


def build_log(idx: int, **kwargs: Any) -> dict[str, Any]:
    base = {
        "event_id": f"evt-{idx}",
        "event_time": BASE_TIME + timedelta(seconds=idx),
        "ingest_time": BASE_TIME + timedelta(seconds=idx),
        "tenant_id": "default",
        "source_type": "vpn",
        "log_type": "login",
        "user_id": "alice",
        "src_ip": "8.8.8.8",
        "action": "login",
        "resource": "/login",
        "result": "fail",
        "message": "failed login",
        "raw_log": "raw",
        "risk_tags": [],
        "attrs": {},
    }
    base.update(kwargs)
    return NormalizedLog.model_validate(base).model_dump(mode="json")


class FakeStorage:
    def __init__(
        self,
        logs: list[dict[str, Any]],
        seen_sources: set[tuple[str, str, str, str]] | None = None,
        baselines: dict[tuple[str, str], dict[str, Any]] | None = None,
    ) -> None:
        self.logs = logs
        self.seen_sources = seen_sources or set()
        self.baselines = baselines or {}
        self.list_calls: list[dict[str, Any]] = []
        self.inserted_batches: list[list[AnomalyEvent]] = []
        self.upserted_sources: list[dict[str, Any]] = []

    def list_logs(self, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        self.list_calls.append(kwargs)
        start_time = kwargs.get("start_time")
        end_time = kwargs.get("end_time")
        limit = kwargs.get("limit") or len(self.logs)
        offset = kwargs.get("offset") or 0
        items = [
            item
            for item in self.logs
            if (start_time is None or NormalizedLog.model_validate(item).event_time > start_time)
            and (end_time is None or NormalizedLog.model_validate(item).event_time <= end_time)
        ]
        items.sort(key=lambda item: NormalizedLog.model_validate(item).event_time, reverse=True)
        return items[offset : offset + limit], len(items)

    def insert_anomalies(self, anomalies: list[AnomalyEvent]) -> None:
        self.inserted_batches.append(list(anomalies))

    def existing_anomaly_ids(self, event_ids: list[str]) -> set[str]:
        inserted_ids = {anomaly.event_id for batch in self.inserted_batches for anomaly in batch}
        return inserted_ids.intersection(event_ids)

    def query_user_seen_sources(
        self,
        tenant_id: str = "default",
        user_id: str | None = None,
        source_type: str | None = None,
        source_key: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        # 支持两种调用模式：
        # 1. 精确四元组查询（_merge_existing_seen_source 传入完整 key）
        # 2. 批量过滤查询（load_user_context 只传 tenant/user/source_type，无 source_key）
        results = []
        for t, u, st, sk in self.seen_sources:
            if tenant_id and t != tenant_id:
                continue
            if user_id and u != (user_id or ""):
                continue
            if source_type and st != source_type:
                continue
            if source_key and sk != source_key:
                continue
            results.append(
                {
                    "tenant_id": t,
                    "user_id": u,
                    "source_type": st,
                    "source_key": sk,
                    "first_seen_time": BASE_TIME - timedelta(days=1),
                    "last_seen_time": BASE_TIME - timedelta(days=1),
                    "seen_count": 3,
                }
            )
        return results[:limit]

    def upsert_user_seen_sources(self, sources: list[dict[str, Any]]) -> None:
        self.upserted_sources.extend(sources)
        for item in sources:
            self.seen_sources.add(
                (
                    str(item.get("tenant_id") or "default"),
                    str(item.get("user_id") or ""),
                    str(item.get("source_type") or ""),
                    str(item.get("source_key") or ""),
                )
            )

    def get_user_baseline(self, user_id: str, *, tenant_id: str | None = None, baseline_date=None):
        return self.baselines.get((tenant_id or "default", user_id))


def test_worker_run_once_inserts_detected_anomalies_and_advances_checkpoint() -> None:
    logs = [build_log(i) for i in range(10)]
    storage = FakeStorage(logs)
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    first = worker.run_once()
    second = worker.run_once()

    assert first.logs_read == 10
    assert first.anomalies_detected > 0
    assert first.anomalies_inserted == first.anomalies_detected
    assert len(storage.inserted_batches) == 1
    assert second.logs_read == 0
    assert second.anomalies_inserted == 0


def test_notification_enqueue_failure_does_not_rollback_anomaly_insert(monkeypatch) -> None:
    logs = [build_log(i) for i in range(10)]
    storage = FakeStorage(logs)
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_URL", "http://unavailable.test/webhook")
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    summary = worker.run_once()

    assert summary.anomalies_inserted > 0
    assert len(storage.inserted_batches) == 1


def test_worker_uses_stable_event_ids_for_detected_anomalies() -> None:
    logs = [build_log(i) for i in range(10)]
    first_storage = FakeStorage(logs)
    second_storage = FakeStorage(logs)

    first_worker = AnomalyDetectorWorker(
        storage=first_storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )
    second_worker = AnomalyDetectorWorker(
        storage=second_storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    first_worker.run_once()
    second_worker.run_once()

    first_ids = [item.event_id for item in first_storage.inserted_batches[0]]
    second_ids = [item.event_id for item in second_storage.inserted_batches[0]]
    assert first_ids == second_ids


def test_worker_deduplicates_replayed_source_event_within_a_batch() -> None:
    """同一条源日志重复投递时，只写入一个稳定异常事件。"""

    logs = [build_log(index, src_ip=f"198.51.100.{index}") for index in range(1, 5)]
    replayed = build_log(99, event_id="evt-replayed", src_ip="198.51.100.99")
    storage = FakeStorage([*logs, replayed, replayed])
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=2),
    )

    summary = worker.run_once()

    assert summary.anomalies_detected == 1
    assert summary.anomalies_inserted == 1
    assert len(storage.inserted_batches) == 1
    assert len(storage.inserted_batches[0]) == 1
    assert storage.inserted_batches[0][0].related_event_ids == ["evt-replayed"]


def test_worker_deduplicates_stable_ids_already_persisted_by_a_previous_worker() -> None:
    """重启后的 worker 也不能把已有稳定异常 ID 再次写入。"""

    logs = [build_log(index) for index in range(1, settings.threshold_user_fail_5m + 1)]
    storage = FakeStorage(logs)
    first_worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=2),
    )
    second_worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=2),
    )

    first = first_worker.run_once()
    second = second_worker.run_once()

    assert first.anomalies_inserted == 1
    assert second.anomalies_detected == 0
    assert second.anomalies_inserted == 0
    assert len(storage.inserted_batches) == 1


def test_worker_processes_oldest_page_first_when_backlog_exceeds_batch_size() -> None:
    logs = [build_log(i) for i in range(12)]
    storage = FakeStorage(logs)
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=5,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    worker.run_once()
    worker.run_once()

    assert len(storage.inserted_batches) == 2
    assert storage.list_calls[1]["offset"] == 7
    assert storage.list_calls[3]["offset"] == 2
    assert storage.inserted_batches[0][0].related_event_ids[0] == "evt-4"


def test_worker_uses_seen_sources_to_suppress_known_source_login() -> None:
    logs = [
        build_log(
            1,
            action="login",
            result="success",
            src_ip="10.0.0.7",
            resource="/home",
            message="login success",
        )
    ]
    storage = FakeStorage(
        logs,
        seen_sources={("default", "alice", "ip", "10.0.0.7")},
    )
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    summary = worker.run_once()

    assert summary.anomalies_detected == 0
    assert storage.inserted_batches == []
    assert storage.upserted_sources == [
        {
            "tenant_id": "default",
            "user_id": "alice",
            "source_type": "ip",
            "source_key": "10.0.0.7",
            "first_seen_time": BASE_TIME - timedelta(days=1),
            "last_seen_time": BASE_TIME + timedelta(seconds=1),
            "seen_count": 4,
        }
    ]


def test_worker_records_new_seen_source_after_new_source_login_anomaly() -> None:
    logs = [
        build_log(
            1,
            action="login",
            result="success",
            src_ip="203.0.113.9",
            resource="/home",
            message="login success",
        )
    ]
    storage = FakeStorage(logs)
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    summary = worker.run_once()

    assert summary.anomalies_detected == 1
    assert storage.inserted_batches[0][0].reason_codes == ["new_source_ip"]
    assert storage.upserted_sources == [
        {
            "tenant_id": "default",
            "user_id": "alice",
            "source_type": "ip",
            "source_key": "203.0.113.9",
            "first_seen_time": BASE_TIME + timedelta(seconds=1),
            "last_seen_time": BASE_TIME + timedelta(seconds=1),
            "seen_count": 1,
        }
    ]


def test_worker_attaches_baseline_deviations_to_rule_anomaly() -> None:
    logs = [
        build_log(
            1,
            action="access",
            result="success",
            src_ip="10.0.0.7",
            resource="/api/admin/export",
            message="admin export",
        )
    ]
    storage = FakeStorage(
        logs,
        seen_sources={("default", "alice", "ip", "10.0.0.7")},
        baselines={
            ("default", "alice"): {
                "tenant_id": "default",
                "user_id": "alice",
                "baseline_confidence": 0.8,
                "sample_days": 30,
                "location_profile": {"common_ips": ["10.0.0.7"]},
                "time_profile": {"active_hours": ["09:00-18:00"]},
                "access_profile": {"common_resources": ["/home"]},
                "result_profile": {},
            }
        },
    )
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        clock=lambda: BASE_TIME + timedelta(minutes=1),
    )

    summary = worker.run_once()

    assert summary.anomalies_detected == 1
    anomaly = storage.inserted_batches[0][0]
    assert anomaly.reason_codes == ["admin_resource_access"]
    assert anomaly.baseline_deviations == [
        {
            "feature": "resource",
            "profile_group": "access",
            "expected": ["/home"],
            "actual": "/api/admin/export",
            "deviation_type": "sensitive_resource_access",
            "severity": "high",
            "confidence": 0.8,
            "evidence_source": "user_baseline",
            "sample_days": 30,
        }
    ]
    assert anomaly.risk_components["baseline_deviation"] == 25


def test_worker_recovers_recent_window_state_without_reinserting_warmup_anomalies() -> None:
    warmup_count = settings.threshold_ip_fail_5m - 1
    logs = [
        build_log(
            idx,
            event_time=BASE_TIME + timedelta(seconds=idx),
            ingest_time=BASE_TIME + timedelta(seconds=idx),
            src_ip="198.51.100.7",
            user_id=f"user-{idx}",
        )
        for idx in range(1, warmup_count + 1)
    ]
    logs.append(
        build_log(
            99,
            event_time=BASE_TIME + timedelta(minutes=1),
            ingest_time=BASE_TIME + timedelta(minutes=1),
            src_ip="198.51.100.7",
            user_id="user-new",
        )
    )
    storage = FakeStorage(logs)
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=5,
        batch_size=100,
        recover_state_on_start=True,
        clock=lambda: BASE_TIME + timedelta(minutes=2),
    )

    warmed = worker.recover_recent_state(end_time=BASE_TIME + timedelta(seconds=warmup_count + 1))
    summary = worker.run_once()

    assert warmed == warmup_count
    assert summary.logs_read == 1
    assert summary.anomalies_inserted > 0
    assert len(storage.inserted_batches) == 1
    assert all("evt-99" in anomaly.related_event_ids for anomaly in storage.inserted_batches[0])
