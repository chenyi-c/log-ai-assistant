from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from kafka import KafkaAdminClient, KafkaProducer
from kafka.admin import NewTopic
from kafka.errors import TopicAlreadyExistsError

from src.ai_engine import AIAnalyzer
from src.collector import run_generator_once, stream_file_to_kafka
from src.config import PROJECT_ROOT, settings
from src.detection import detect_batch
from src.detection.worker import AnomalyDetectorWorker, DetectionRunSummary
from src.health import get_cli_health_payload
from src.operations.notifications import NotificationService
from src.parser import normalize_raw_record, run_raw_to_parsed_worker
from src.report import generate_daily_report
from src.schemas import AnomalyEvent, NormalizedLog
from src.storage import ClickHouseStorage
from src.ueba import build_and_store_baselines


def ensure_topics() -> None:
    admin = KafkaAdminClient(bootstrap_servers=settings.kafka_bootstrap_servers)
    topics = [
        settings.kafka_raw_topic,
        settings.kafka_parsed_topic,
        settings.kafka_alert_topic,
        settings.kafka_ai_topic,
        settings.kafka_metrics_topic,
    ]
    new_topics = [NewTopic(name=t, num_partitions=3, replication_factor=1) for t in topics]
    try:
        admin.create_topics(new_topics=new_topics, validate_only=False)
    except TopicAlreadyExistsError:
        pass
    except Exception:
        existing = set(admin.list_topics())
        missing = [t for t in topics if t not in existing]
        if missing:
            admin.create_topics(
                new_topics=[NewTopic(name=t, num_partitions=3, replication_factor=1) for t in missing],
                validate_only=False,
            )
    finally:
        admin.close()


def cmd_init(_: argparse.Namespace) -> None:
    ensure_topics()
    storage = ClickHouseStorage()
    clickhouse_ok = storage.health()
    print(f"Init completed: Kafka topics are ready; ClickHouse connection={'ok' if clickhouse_ok else 'failed'}.")


def cmd_inspect_generator(args: argparse.Namespace) -> None:
    outdir = PROJECT_ROOT / "log-generator" / "vpn_output"
    outdir.mkdir(parents=True, exist_ok=True)
    result = run_generator_once(outdir=outdir, fmt="all", days=1, count=args.count)

    print("=== log-generator inspect ===")
    print(f"script: {settings.generator_script}")
    print(f"return_code: {result.returncode}")
    if result.stdout:
        print("stdout:")
        print(result.stdout[:600])
    if result.stderr:
        print("stderr:")
        print(result.stderr[:600])

    jsonl = outdir / "vpn_logs.jsonl"
    syslog = outdir / "vpn_logs.log"
    csv_path = outdir / "vpn_logs.csv"

    print(f"output_jsonl: {jsonl} exists={jsonl.exists()}")
    print(f"output_syslog: {syslog} exists={syslog.exists()}")
    print(f"output_csv: {csv_path} exists={csv_path.exists()}")

    if jsonl.exists():
        with jsonl.open("r", encoding="utf-8") as f:
            sample = f.readline().strip()
            print("sample_jsonl_line:")
            print(sample[:1000])
            parsed = normalize_raw_record(sample)
            print("mapped_normalized_fields:")
            print(json.dumps(parsed.model_dump(mode="json"), ensure_ascii=False, indent=2)[:1500])


def _produce_from_path(path: Path, source_type: str, follow: bool) -> int:
    sent = stream_file_to_kafka(
        file_path=path,
        source_type=source_type,
        from_beginning=True,
        follow=follow,
        stop_after_eof=not follow,
    )
    return sent


def cmd_produce(args: argparse.Namespace) -> None:
    if args.run_generator:
        outdir = PROJECT_ROOT / "log-generator" / "vpn_output"
        result = run_generator_once(outdir=outdir, fmt=args.format, days=args.days, count=args.count, start=args.start)
        if result.returncode != 0:
            print(result.stderr)
            raise SystemExit("log-generator run failed")

    if args.path:
        source_path = Path(args.path).resolve()
    else:
        source_path = settings.generator_jsonl if args.format in {"jsonl", "all"} else settings.generator_syslog

    if not source_path.exists():
        raise SystemExit(f"source log file not found: {source_path}")

    sent = _produce_from_path(source_path, source_type=args.source_type, follow=args.follow)
    print(f"Produced {sent} lines to Kafka topic: {settings.kafka_raw_topic}")


def cmd_process_raw(args: argparse.Namespace) -> None:
    processed = run_raw_to_parsed_worker(
        max_messages=args.max_messages,
        from_beginning=not args.from_latest,
        idle_timeout_ms=args.idle_timeout_ms,
        group_id=args.group_id,
    )
    print(f"python raw->parsed finished, processed={processed}")


def cmd_build_baseline(_: argparse.Namespace) -> None:
    storage = ClickHouseStorage()
    output = PROJECT_ROOT / "data" / "user_baselines.json"
    baselines = build_and_store_baselines(storage, output_path=output)
    print(f"built baselines={len(baselines)}, output={output}")


def cmd_detect(args: argparse.Namespace) -> None:
    storage = ClickHouseStorage()
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=args.hours)
    logs, _total = storage.list_logs(start_time=start_time, end_time=end_time, limit=args.size, offset=0)
    normalized = [NormalizedLog.model_validate(item) for item in logs]
    anomalies = detect_batch(normalized)
    storage.insert_anomalies(anomalies)
    try:
        NotificationService(storage).enqueue_anomalies(anomalies)
    except Exception:
        pass
    anomaly_docs = [a.model_dump(mode="json") for a in anomalies]

    producer = KafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
    )
    for item in anomaly_docs:
        producer.send(settings.kafka_alert_topic, item)
    producer.flush()
    producer.close()

    print(f"offline detect finished, anomalies={len(anomalies)}")


def cmd_detect_worker(args: argparse.Namespace) -> None:
    storage = ClickHouseStorage()
    worker = AnomalyDetectorWorker(
        storage=storage,
        lookback_minutes=args.lookback_minutes,
        batch_size=args.batch_size,
        recover_state_on_start=args.recover_state_on_start,
    )
    if args.once:
        summary = worker.run_once()
        print(_detection_summary_line(summary))
        return
    worker.run_forever(interval_seconds=args.interval_seconds)


def cmd_analyze_alerts(args: argparse.Namespace) -> None:
    storage = ClickHouseStorage()
    analyzer = AIAnalyzer()

    pending, _total = storage.list_anomalies(ai_status="pending", limit=args.limit, offset=0)

    if not pending:
        print("no pending anomalies to analyze")
        return

    producer = KafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
    )

    analyzed = 0
    for item in pending:
        alert = AnomalyEvent.model_validate(item)
        baseline = storage.get_user_baseline(alert.user_id) if alert.user_id else {}
        related_logs = storage.list_logs_by_event_ids(alert.related_event_ids)

        report = analyzer.analyze(event=alert, baseline=baseline, related_logs=related_logs)
        storage.insert_ai_judgement(report)
        storage.update_anomaly_ai_status(alert.event_id, "analyzed")
        producer.send(settings.kafka_ai_topic, report.model_dump(mode="json"))
        analyzed += 1

    producer.flush()
    producer.close()
    print(f"analyzed alerts={analyzed}, mode={'mock' if analyzer.mock_mode else 'dashscope'}")


def cmd_report(args: argparse.Namespace) -> None:
    storage = ClickHouseStorage()
    report = generate_daily_report(storage, date_str=args.date)
    storage.insert_daily_report(report)

    out_path = PROJECT_ROOT / "data" / f"daily_report_{report.date}.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.markdown, encoding="utf-8")
    print(f"daily report generated: {out_path}")
    print(report.markdown)


def cmd_health(_: argparse.Namespace) -> None:
    print(json.dumps(get_cli_health_payload(), ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Log Analysis AI Assistant CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="初始化 Kafka topics 并检查 ClickHouse 连接")
    p_init.set_defaults(func=cmd_init)

    p_inspect = sub.add_parser("inspect-generator", help="检查导师 log-generator 输出格式")
    p_inspect.add_argument("--count", type=int, default=20)
    p_inspect.set_defaults(func=cmd_inspect_generator)

    p_produce = sub.add_parser("produce", help="读取 log-generator 输出并写入 Kafka raw_logs")
    p_produce.add_argument("--run-generator", action="store_true", help="先执行一次 log-generator")
    p_produce.add_argument("--format", choices=["jsonl", "syslog", "all"], default="jsonl")
    p_produce.add_argument("--days", type=int, default=1)
    p_produce.add_argument("--count", type=int, default=120)
    p_produce.add_argument("--start", default=None)
    p_produce.add_argument("--path", default=None, help="直接指定输入文件")
    p_produce.add_argument("--source-type", default="vpn")
    p_produce.add_argument("--follow", action="store_true", help="持续监听文件新增内容")
    p_produce.set_defaults(func=cmd_produce)

    p_process = sub.add_parser("process-raw", help="Python fallback: 消费 raw_logs 转换并写入 parsed_logs")
    p_process.add_argument("--max-messages", type=int, default=None)
    p_process.add_argument("--from-latest", action="store_true", help="从最新offset开始消费（默认从最早）")
    p_process.add_argument("--idle-timeout-ms", type=int, default=5000, help="空闲超时后退出，-1 表示持续运行")
    p_process.add_argument("--group-id", default="python-raw-to-parsed")
    p_process.set_defaults(func=cmd_process_raw)

    p_baseline = sub.add_parser("build-baseline", help="从 ClickHouse security_logs 生成用户行为基线")
    p_baseline.set_defaults(func=cmd_build_baseline)

    p_detect = sub.add_parser("detect", help="执行离线/准实时异常检测")
    p_detect.add_argument("--hours", type=int, default=24)
    p_detect.add_argument("--size", type=int, default=5000)
    p_detect.set_defaults(func=cmd_detect)

    p_detect_worker = sub.add_parser("detect-worker", help="持续运行异常检测并写入 anomaly_events")
    p_detect_worker.add_argument("--once", action="store_true", help="只执行一轮检测后退出")
    p_detect_worker.add_argument("--interval-seconds", type=int, default=30, help="持续运行时每轮间隔秒数")
    p_detect_worker.add_argument("--lookback-minutes", type=int, default=10, help="首次启动回看多少分钟日志")
    p_detect_worker.add_argument("--batch-size", type=int, default=1000, help="每轮最多读取多少条日志")
    p_detect_worker.add_argument(
        "--recover-state-on-start", action="store_true", help="启动时用回看窗口日志恢复短期规则状态但不写入历史异常"
    )
    p_detect_worker.set_defaults(func=cmd_detect_worker)

    p_analyze = sub.add_parser("analyze-alerts", help="对未研判异常事件调用大模型")
    p_analyze.add_argument("--limit", type=int, default=100)
    p_analyze.set_defaults(func=cmd_analyze_alerts)

    p_report = sub.add_parser("report", help="生成每日安全态势简报")
    p_report.add_argument("--date", default=None, help="YYYY-MM-DD")
    p_report.set_defaults(func=cmd_report)

    p_health = sub.add_parser("health", help="检查 Kafka/ClickHouse/Flink/DashScope 状态")
    p_health.set_defaults(func=cmd_health)

    return parser


def _detection_summary_line(summary: DetectionRunSummary) -> str:
    last = summary.last_event_time.isoformat() if summary.last_event_time else "-"
    return (
        "detector round finished: "
        f"logs_read={summary.logs_read} "
        f"anomalies_detected={summary.anomalies_detected} "
        f"anomalies_inserted={summary.anomalies_inserted} "
        f"last_event_time={last} "
        f"duration_ms={summary.duration_ms}"
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
