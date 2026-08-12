from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pandas as pd
import streamlit as st

# Ensure project root is importable when launched via `streamlit run src/dashboard/app.py`
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ai_engine import AIAnalyzer  # noqa: E402
from src.config import settings  # noqa: E402
from src.report.daily_report import generate_daily_report  # noqa: E402
from src.schemas import AnomalyEvent  # noqa: E402
from src.storage import ClickHouseStorage  # noqa: E402

st.set_page_config(page_title="日志分析 AI 助手", layout="wide")


@st.cache_resource
def get_storage() -> ClickHouseStorage:
    return ClickHouseStorage()


@st.cache_resource
def get_analyzer() -> AIAnalyzer:
    return AIAnalyzer()


def page_overview(storage: ClickHouseStorage) -> None:
    st.title("系统概览")
    now = datetime.now(timezone.utc)
    start = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc)

    stats = storage.get_stats_overview(start_time=start, end_time=now)
    log_count = int(stats.get("log_count") or 0)
    alert_count = int(stats.get("anomaly_count") or 0)
    high_alert_count = int(stats.get("high_risk_count") or 0)
    _, ai_count = storage.list_ai_judgements(limit=1, offset=0)
    user_rows = storage.aggregate_logs(
        time_from=start,
        time_to=now,
        group_by=["event_date"],
        metrics=["unique_users", "unique_src_ips"],
        limit=1,
    )
    users = int(user_rows[0].get("unique_users") or 0) if user_rows else 0
    ips = int(user_rows[0].get("unique_src_ips") or 0) if user_rows else 0

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("今日日志总量", log_count)
    c2.metric("今日异常数量", alert_count)
    c3.metric("高危异常数量", high_alert_count)
    c4.metric("涉及用户数量", users)
    c5.metric("涉及来源IP数量", ips)
    c6.metric("AI已研判数量", ai_count)


def page_recent_logs(storage: ClickHouseStorage) -> None:
    st.title("最近日志")
    col1, col2, col3, col4 = st.columns(4)
    source_type = col1.selectbox("source_type", ["全部", "vpn", "oa", "api", "system", "security_device"])
    user_id = col2.text_input("user_id")
    src_ip = col3.text_input("src_ip")
    result = col4.selectbox("result", ["全部", "success", "fail", "denied", "error"])
    now_utc = datetime.now(timezone.utc)
    t1, t2, t3, t4 = st.columns(4)
    start_date = t1.date_input("开始日期", value=(now_utc - timedelta(days=1)).date())
    start_clock = t2.time_input("开始时刻", value=(now_utc - timedelta(days=1)).time().replace(microsecond=0))
    end_date = t3.date_input("结束日期", value=now_utc.date())
    end_clock = t4.time_input("结束时刻", value=now_utc.time().replace(microsecond=0))
    start_time = datetime.combine(start_date, start_clock).replace(tzinfo=timezone.utc)
    end_time = datetime.combine(end_date, end_clock).replace(tzinfo=timezone.utc)
    if end_time < start_time:
        st.warning("结束时间早于开始时间，已自动交换。")
        start_time, end_time = end_time, start_time

    logs, _total = storage.list_logs(
        source_type=None if source_type == "全部" else source_type,
        user_id=user_id or None,
        src_ip=src_ip or None,
        result=None if result == "全部" else result,
        start_time=start_time,
        end_time=end_time,
        limit=300,
        offset=0,
    )
    df = pd.DataFrame(logs)
    st.dataframe(df, use_container_width=True)


def _load_alerts(storage: ClickHouseStorage, risk: str, user_id: str, reason_code: str) -> list[dict]:
    items, _total = storage.list_anomalies(
        risk_level=None if risk == "全部" else risk,
        user_id=user_id or None,
        reason_code=reason_code or None,
        start_time=datetime.now(timezone.utc) - timedelta(days=7),
        limit=500,
        offset=0,
    )
    return items


def page_alerts(storage: ClickHouseStorage, analyzer: AIAnalyzer) -> None:
    st.title("异常事件")
    c1, c2, c3 = st.columns(3)
    risk = c1.selectbox("风险等级", ["全部", "low", "medium", "high", "critical"])
    user_id = c2.text_input("用户")
    reason_code = c3.text_input("reason_code")

    alerts = _load_alerts(storage, risk, user_id, reason_code)
    if not alerts:
        st.info("暂无异常事件")
        return

    df = pd.DataFrame(alerts)
    st.dataframe(
        df[["event_id", "detect_time", "user_id", "src_ip", "risk_level", "rule_hits", "status"]],
        use_container_width=True,
    )

    selected_id = st.selectbox("选择异常事件", options=df["event_id"].tolist())
    selected = next(item for item in alerts if item.get("event_id") == selected_id)

    st.subheader("异常详情")
    st.json(selected)

    related_logs = storage.list_logs_by_event_ids(selected.get("related_event_ids", []))
    st.subheader("相关日志摘要")
    st.dataframe(pd.DataFrame(related_logs), use_container_width=True)

    baseline_doc = storage.get_user_baseline(str(selected.get("user_id"))) if selected.get("user_id") else None
    st.subheader("用户行为基线")
    st.json(baseline_doc or {})

    ai_report = storage.get_latest_ai_judgement(selected_id)
    st.subheader("AI 研判结果")
    st.json(ai_report or {})

    if st.button("重新 AI 研判", key=f"reanalyze-{selected_id}"):
        alert = AnomalyEvent.model_validate(selected)
        report = analyzer.analyze(event=alert, baseline=baseline_doc or {}, related_logs=related_logs)
        storage.insert_ai_judgement(report)
        storage.update_anomaly_ai_status(selected_id, "analyzed")
        st.success("已重新生成 AI 研判")


def page_ai_reports(storage: ClickHouseStorage) -> None:
    st.title("AI 研判")
    reports, _total = storage.list_ai_judgements(limit=200, offset=0)
    st.dataframe(pd.DataFrame(reports), use_container_width=True)


def page_user_risk(storage: ClickHouseStorage) -> None:
    st.title("用户风险排行")
    rows = storage.aggregate_anomalies(field="user_id", limit=20)
    df = pd.DataFrame([{"user_id": row.get("key"), "异常数量": row.get("count", 0)} for row in rows])
    st.dataframe(df, use_container_width=True)


def page_rule_stats(storage: ClickHouseStorage) -> None:
    st.title("规则命中统计")
    rows = [
        {"attack_type": row.get("key"), "count": row.get("count")}
        for row in storage.aggregate_anomalies(field="attack_type", limit=20)
    ]
    st.dataframe(pd.DataFrame(rows), use_container_width=True)


def page_daily_report(storage: ClickHouseStorage) -> None:
    st.title("每日安全态势简报")
    if st.button("生成今日简报"):
        report = generate_daily_report(storage)
        storage.insert_daily_report(report)
        st.success("简报已生成")
        st.markdown(report.markdown)

    reports, _total = storage.list_daily_reports(limit=20, offset=0)
    if reports:
        selected = st.selectbox("历史简报", options=[r["report_id"] for r in reports])
        report = next(r for r in reports if r["report_id"] == selected)
        st.markdown(report.get("markdown", ""))


def page_system_health(storage: ClickHouseStorage, analyzer: AIAnalyzer) -> None:
    st.title("系统运行状态")

    kafka_ok = True
    try:
        from kafka import KafkaAdminClient

        admin = KafkaAdminClient(bootstrap_servers=settings.kafka_bootstrap_servers)
        admin.list_topics()
        admin.close()
    except Exception:
        kafka_ok = False

    clickhouse_ok = storage.health()

    flink_ok = False
    try:
        import requests

        resp = requests.get(f"{settings.flink_dashboard_url}/overview", timeout=3)
        flink_ok = resp.ok
    except Exception:
        flink_ok = False

    st.write(f"Kafka 连接: {'正常' if kafka_ok else '异常'}")
    st.write(f"ClickHouse 连接: {'正常' if clickhouse_ok else '异常'}")
    st.write(f"Flink Dashboard: {settings.flink_dashboard_url} ({'正常' if flink_ok else '异常'})")
    st.write(f"DashScope API: {'已配置' if not analyzer.mock_mode else '未配置，当前为mock模式'}")

    latest_time = storage.latest_security_log_ingest_time() or "N/A"
    st.write(f"最近一次数据更新时间: {latest_time}")


def main() -> None:
    storage = get_storage()
    analyzer = get_analyzer()

    page = st.sidebar.radio(
        "页面",
        [
            "系统概览",
            "最近日志",
            "异常事件",
            "AI 研判",
            "用户风险排行",
            "规则命中统计",
            "每日安全态势简报",
            "系统运行状态",
        ],
    )

    if page == "系统概览":
        page_overview(storage)
    elif page == "最近日志":
        page_recent_logs(storage)
    elif page == "异常事件":
        page_alerts(storage, analyzer)
    elif page == "AI 研判":
        page_ai_reports(storage)
    elif page == "用户风险排行":
        page_user_risk(storage)
    elif page == "规则命中统计":
        page_rule_stats(storage)
    elif page == "每日安全态势简报":
        page_daily_report(storage)
    elif page == "系统运行状态":
        page_system_health(storage, analyzer)


if __name__ == "__main__":
    main()
