import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertCircle,
  BarChart3,
  Brain,
  CheckCircle2,
  Clock3,
  Database,
  FileText,
  Filter,
  ListFilter,
  Pause,
  Play,
  RadioTower,
  RefreshCcw,
  Search,
  Server,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  UserRound,
  XCircle,
} from "lucide-react";

import {
  analyzeAlert,
  confirmFalsePositive,
  rejectFalsePositive,
  createBaselineOverride,
  createDailyReport,
  dailyReportMarkdownUrl,
  fetchAcceptanceReport,
  fetchAcceptanceReports,
  fetchAIReports,
  fetchAlertDetail,
  flagFalsePositive,
  fetchAlerts,
  fetchBaselines,
  fetchBaselineOverrides,
  fetchDailyReports,
  fetchFeedback,
  fetchHealth,
  fetchLogs,
  fetchNotifications,
  fetchOperationsRuns,
  fetchStatsOverview,
  fetchUserRiskStats,
  rebuildBaselines,
  retryNotification,
  retryOperationsRun,
  reviewFeedback,
  revokeBaselineOverride
} from "./api";
import {
  EmptyState,
  ErrorBanner,
  Metric,
  PageHeader,
  PaginationControls,
  ServiceCard,
  StatusPill,
  TableSkeleton,
  alertStatusTone,
  dateInShanghai,
  formatAIStatus,
  formatAlertStatus,
  formatDateTime,
  formatError,
  formatFallbackLevel,
  formatNumber,
  formatResult,
  formatResultRange,
  formatReviewStatus,
  formatRiskLevel,
  formatSource,
  isEmptyRecord,
  localDateTimeValue,
  riskTone,
  statusTone,
  toApiDateTime,
  toDatetimeLocalInput,
  todayInShanghai
} from "./components/common";
import type {
  AIFeedback,
  AcceptanceReport,
  AcceptanceReportDetail,
  AIJudgement,
  AnomalyDetailResponse,
  AnomalyEvent,
  AlertsQuery,
  BaselineMergeMode,
  BaselineOverride,
  BaselinePeriodType,
  DailyReport,
  HealthResponse,
  LogsQuery,
  NormalizedLog,
  NotificationOutbox,
  OperationsTaskRun,
  StatsOverview,
  UserBaseline,
  UserRiskStats,
  RiskLevel,
  SourceType
} from "./types";

type PageKey = "logs" | "anomalies" | "users" | "ai" | "reports" | "operations" | "status";

type LoadState<T> = {
  data: T | null;
  loading: boolean;
  error: string | null;
  updatedAt: Date | null;
};

const initialLogsQuery: LogsQuery = {
  source_type: "",
  user_id: "",
  src_ip: "",
  result: "",
  start_time: "",
  end_time: "",
  limit: 50,
  offset: 0
};

const sourceTypes: Array<{ label: string; value: SourceType | "" }> = [
  { label: "全部来源", value: "" },
  { label: "VPN", value: "vpn" },
  { label: "OA", value: "oa" },
  { label: "API", value: "api" },
  { label: "系统", value: "system" },
  { label: "文件", value: "file" },
  { label: "数据库", value: "database" },
  { label: "安全设备", value: "security_device" }
];

const resultOptions = ["", "success", "fail", "denied", "error"];
const alertStatusOptions = ["", "new", "investigating", "closed", "false_positive"];
const riskLevelOptions: Array<{ label: string; value: RiskLevel | "" }> = [
  { label: "全部风险等级", value: "" },
  { label: "低", value: "low" },
  { label: "中", value: "medium" },
  { label: "高", value: "high" },
  { label: "严重", value: "critical" }
];

const initialAlertsQuery: AlertsQuery = {
  risk_level: "",
  user_id: "",
  reason_code: "",
  status: "",
  start_time: "",
  end_time: "",
  limit: 50,
  offset: 0
};

function App() {
  const [page, setPage] = useState<PageKey>("logs");

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck aria-hidden="true" />
          <div>
            <strong>日志 AI 助手</strong>
            <span>安全运营工作台</span>
          </div>
        </div>

        <nav className="nav" aria-label="主导航">
          <button className={page === "logs" ? "active" : ""} type="button" onClick={() => setPage("logs")}>
            <TerminalSquare aria-hidden="true" />
            实时日志
          </button>
          <button className={page === "anomalies" ? "active" : ""} type="button" onClick={() => setPage("anomalies")}>
            <AlertCircle aria-hidden="true" />
            异常事件
          </button>
          <button className={page === "users" ? "active" : ""} type="button" onClick={() => setPage("users")}>
            <UserRound aria-hidden="true" />
            用户画像
          </button>
          <button className={page === "ai" ? "active" : ""} type="button" onClick={() => setPage("ai")}>
            <Brain aria-hidden="true" />
            AI 研判
          </button>
          <button className={page === "reports" ? "active" : ""} type="button" onClick={() => setPage("reports")}>
            <FileText aria-hidden="true" />
            日报
          </button>
          <button className={page === "operations" ? "active" : ""} type="button" onClick={() => setPage("operations")}>
            <Activity aria-hidden="true" />
            运营验收
          </button>
          <button className={page === "status" ? "active" : ""} type="button" onClick={() => setPage("status")}>
            <Activity aria-hidden="true" />
            系统状态
          </button>
        </nav>

        <div className="chain">
          <span>Filebeat</span>
          <span>Kafka</span>
          <span>Flink</span>
          <span>ClickHouse</span>
          <span>FastAPI</span>
          <span>React</span>
        </div>
      </aside>

      <main className="workspace">
        {page === "logs" ? <RealtimeLogsPage /> : null}
        {page === "anomalies" ? <AlertsPage /> : null}
        {page === "users" ? <UserProfilesPage /> : null}
        {page === "ai" ? <AIJudgementPage /> : null}
        {page === "reports" ? <DailyReportsPage /> : null}
        {page === "operations" ? <OperationsPage /> : null}
        {page === "status" ? <SystemStatusPage /> : null}
      </main>
    </div>
  );
}

function OperationsPage() {
  const [runs, setRuns] = useState<LoadState<{ items: OperationsTaskRun[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [reports, setReports] = useState<LoadState<{ items: AcceptanceReport[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [notifications, setNotifications] = useState<LoadState<{ items: NotificationOutbox[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [selectedReport, setSelectedReport] = useState<LoadState<AcceptanceReportDetail>>({
    data: null,
    loading: false,
    error: null,
    updatedAt: null
  });

  const load = useCallback((signal?: AbortSignal) => {
    setRuns((current) => ({ ...current, loading: true, error: null }));
    setReports((current) => ({ ...current, loading: true, error: null }));
    setNotifications((current) => ({ ...current, loading: true, error: null }));
    fetchOperationsRuns({ limit: 50, offset: 0 }, signal)
      .then((data) => setRuns({ data, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => setRuns((current) => ({ ...current, loading: false, error: formatError(error) })));
    fetchAcceptanceReports({ limit: 20, offset: 0 }, signal)
      .then((data) => {
        setReports({ data, loading: false, error: null, updatedAt: new Date() });
        const first = data.items[0];
        if (first) {
          setSelectedReport((current) => ({ ...current, loading: true, error: null }));
          fetchAcceptanceReport(first.report_id, signal)
            .then((detail) => setSelectedReport({ data: detail, loading: false, error: null, updatedAt: new Date() }))
            .catch((error: unknown) => setSelectedReport((current) => ({ ...current, loading: false, error: formatError(error) })));
        }
      })
      .catch((error: unknown) => setReports((current) => ({ ...current, loading: false, error: formatError(error) })));
    fetchNotifications({ limit: 50, offset: 0 }, signal)
      .then((data) => setNotifications({ data, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => setNotifications((current) => ({ ...current, loading: false, error: formatError(error) })));
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const retryRun = (runId: string) => {
    retryOperationsRun(runId).then(() => load()).catch((error: unknown) => setRuns((current) => ({ ...current, error: formatError(error) })));
  };
  const retryDelivery = (outboxId: string) => {
    retryNotification(outboxId).then(() => load()).catch((error: unknown) => setNotifications((current) => ({ ...current, error: formatError(error) })));
  };

  return (
    <section className="page">
      <PageHeader
        kicker="ADR-011"
        title="运营控制面与量化验收"
        description="查看周期任务 attempt、水位门禁、版本化验收指标和通知投递状态。"
        action={
          <button className="icon-button primary" type="button" onClick={() => load()}>
            <RefreshCcw aria-hidden="true" />
            刷新
          </button>
        }
      />

      {runs.error ? <ErrorBanner message={runs.error} /> : null}
      {reports.error ? <ErrorBanner message={reports.error} /> : null}
      {notifications.error ? <ErrorBanner message={notifications.error} /> : null}

      <div className="metrics-band">
        <Metric icon={Activity} label="任务运行" value={formatNumber(runs.data?.total)} hint="保留每次 attempt" />
        <Metric icon={ShieldCheck} label="验收报告" value={formatNumber(reports.data?.total)} hint="后端持久化结论" />
        <Metric icon={RadioTower} label="通知任务" value={formatNumber(notifications.data?.total)} hint="outbox 与 dead-letter" />
      </div>

      <div className="section-title">
        <h2>最近任务运行</h2>
        <span>水位、幂等键、attempt 与失败原因</span>
      </div>
      <div className="log-table-wrap">
        <table className="log-table">
          <thead><tr><th>任务</th><th>业务日期</th><th>状态</th><th>Attempt</th><th>完成时间</th><th>操作</th></tr></thead>
          <tbody>
            {runs.data?.items.map((run) => (
              <tr key={run.run_id}>
                <td><strong>{run.task_name}</strong><small>{run.error_message || run.run_id}</small></td>
                <td>{run.target_date}</td>
                <td><StatusPill ok={run.status === "succeeded"} label={run.status} /></td>
                <td>{run.attempt}</td>
                <td>{formatDateTime(run.finished_at)}</td>
                <td>
                  {run.status === "failed" || run.status === "needs_review" ? (
                    <button className="text-button" type="button" onClick={() => retryRun(run.run_id)}>重试</button>
                  ) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="section-title">
        <h2>最新验收指标</h2>
        <span>误报、检出、追踪、检测延迟和通知延迟分别判定</span>
      </div>
      {selectedReport.data ? (
        <>
          <div className="status-summary">
            <div>
              <span className="eyebrow">{selectedReport.data.report.report_id}</span>
              <strong>{selectedReport.data.report.status}</strong>
              <p>commit {selectedReport.data.report.git_commit.slice(0, 12)} · 阈值 {selectedReport.data.report.threshold_version} · AI {selectedReport.data.report.ai_is_mock ? "mock" : "真实模型"}</p>
            </div>
            <StatusPill ok={selectedReport.data.report.status === "passed"} label={selectedReport.data.report.status} />
          </div>
          <div className="log-table-wrap">
            <table className="log-table">
              <thead><tr><th>指标</th><th>结果</th><th>阈值</th><th>样本</th><th>结论</th></tr></thead>
              <tbody>
                {selectedReport.data.metrics.map((metric) => (
                  <tr key={`${metric.metric_name}-${metric.scenario_type}`}>
                    <td>{metric.metric_name}</td>
                    <td>{metric.value} {metric.unit}</td>
                    <td>{metric.threshold_operator} {metric.threshold_value}</td>
                    <td>{metric.numerator}/{metric.denominator}</td>
                    <td><StatusPill ok={metric.passed} label={metric.passed ? "通过" : "未通过"} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : <EmptyState title="暂无验收报告" detail="运行 scenario_evaluate 后将在这里展示持久化指标。" />}

      <div className="section-title">
        <h2>通知投递</h2>
        <span>webhook 幂等、指数退避与 dead-letter</span>
      </div>
      <div className="log-table-wrap">
        <table className="log-table">
          <thead><tr><th>事件</th><th>渠道</th><th>状态</th><th>Attempt</th><th>下次投递</th><th>操作</th></tr></thead>
          <tbody>
            {notifications.data?.items.map((item) => (
              <tr key={item.outbox_id}>
                <td><strong>{item.event_id}</strong><small>{item.last_error || item.outbox_id}</small></td>
                <td>{item.channel}</td>
                <td><StatusPill ok={item.status === "delivered"} label={item.status} /></td>
                <td>{item.attempt_count}</td>
                <td>{formatDateTime(item.next_attempt_at)}</td>
                <td>
                  {item.status === "dead_letter" || item.status === "retry_wait" ? (
                    <button className="text-button" type="button" onClick={() => retryDelivery(item.outbox_id)}>人工重试</button>
                  ) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SystemStatusPage() {
  const [state, setState] = useState<LoadState<HealthResponse>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [statsState, setStatsState] = useState<LoadState<StatsOverview>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [riskState, setRiskState] = useState<LoadState<{ items: UserRiskStats[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });

  const load = useCallback((signal?: AbortSignal) => {
    setState((current) => ({ ...current, loading: true, error: null }));
    fetchHealth(signal)
      .then((data) => {
        setState({ data, loading: false, error: null, updatedAt: new Date() });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setState((current) => ({
          ...current,
          loading: false,
          error: formatError(error)
        }));
      });
  }, []);

  const loadStats = useCallback((signal?: AbortSignal) => {
    setStatsState((current) => ({ ...current, loading: true, error: null }));
    setRiskState((current) => ({ ...current, loading: true, error: null }));
    fetchStatsOverview({}, signal)
      .then((data) => setStatsState({ data, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setStatsState((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
    fetchUserRiskStats({ limit: 5, offset: 0, window: "7d" }, signal)
      .then((data) => setRiskState({ data: { items: data.items, total: data.total }, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setRiskState((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    loadStats(controller.signal);
    const interval = window.setInterval(() => {
      load();
      loadStats();
    }, 15000);

    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [load, loadStats]);

  const services = useMemo(() => {
    const health = state.data;
    return [
      {
        name: "Kafka",
        ok: health?.kafka ?? false,
        description: "raw_logs、parsed_logs 与异常事件传输",
        icon: RadioTower
      },
      {
        name: "Flink",
        ok: health?.flink ?? false,
        description: "将 raw_logs 处理为标准化 parsed_logs",
        icon: Activity
      },
      {
        name: "ClickHouse",
        ok: health?.clickhouse ?? false,
        description: "security_logs 持久化与分析",
        icon: Database
      },
      {
        name: "DashScope",
        ok: health?.dashscope_configured ?? false,
        description: "AI 分析配置",
        icon: Sparkles
      }
    ];
  }, [state.data]);

  const onlineCount = services.filter((service) => service.ok).length;
  const pipelineReady = state.data ? state.data.kafka && state.data.flink && state.data.clickhouse : false;

  return (
    <section className="page">
      <PageHeader
        kicker="系统健康"
        title="系统状态"
        description="展示 Filebeat 到 React 全链路的 FastAPI 实时健康状态。"
        action={
          <button className="icon-button primary" type="button" onClick={() => load()} disabled={state.loading}>
            <RefreshCcw aria-hidden="true" className={state.loading ? "spin" : ""} />
            刷新
          </button>
        }
      />

      {state.error ? <ErrorBanner message={state.error} /> : null}

      <div className="status-summary">
        <div>
          <span className="eyebrow">链路就绪度</span>
          <strong>{pipelineReady ? "运行正常" : "需要关注"}</strong>
          <p>当前 {services.length} 项检查中有 {onlineCount} 项通过。</p>
        </div>
        <StatusPill ok={pipelineReady} label={pipelineReady ? "数据链路可用" : "数据链路降级"} />
      </div>

      <div className="status-grid">
        {services.map((service) => (
          <ServiceCard key={service.name} {...service} loading={state.loading && !state.data} />
        ))}
      </div>

      <div className="metrics-band">
        <Metric
          icon={Clock3}
          label="最近写入"
          value={formatDateTime(state.data?.latest_log_ingest_time)}
          hint="最新 security_logs ingest_time"
        />
        <Metric
          icon={BarChart3}
          label="异常事件"
          value={formatNumber(statsState.data?.anomaly_count)}
          hint={`${formatNumber(statsState.data?.high_risk_count)} 个高危或严重`}
        />
        <Metric
          icon={Server}
          label="日志量"
          value={formatNumber(statsState.data?.log_count)}
          hint={`最近 ${formatDateTime(statsState.data?.latest_log_ingest_time)}`}
        />
      </div>

      <div className="metrics-band">
        <Metric
          icon={Brain}
          label="AI 待处理"
          value={formatNumber(statsState.data?.ai_pending_count)}
          hint="等待 AI 研判的异常事件"
        />
        <Metric
          icon={UserRound}
          label="基线覆盖"
          value={formatNumber(statsState.data?.baseline_user_count)}
          hint="已有行为基线的用户数"
        />
        <Metric
          icon={FileText}
          label="最新日报"
          value={statsState.data?.latest_report_date ?? "无"}
          hint="最新 daily_security_reports 日期"
        />
      </div>

      {statsState.error ? <ErrorBanner message={statsState.error} /> : null}

      <div className="section-title">
        <h2>用户风险排行</h2>
        <span>7 天窗口，已剔除确认误报</span>
      </div>
      <div className="compact-list">
        {riskState.data?.items.map((item) => (
          <article key={item.user_id} className="compact-row">
            <div>
              <strong>{item.user_id}</strong>
              <span>{formatDateTime(item.latest_event_time)}</span>
            </div>
            <div className="tag-list">
              <span>{item.anomaly_count} 个异常</span>
              <span>{item.high_risk_count} 个高危+</span>
              <span>衰减 {formatNumber(item.decayed_risk_score)}</span>
              <span>误报剔除 {item.false_positive_excluded_count}</span>
            </div>
          </article>
        ))}
        {!riskState.loading && riskState.data?.items.length === 0 ? <EmptyState title="暂无排行用户" detail="异常事件包含 user_id 后，用户风险排行会在这里展示。" /> : null}
        {riskState.error ? <ErrorBanner message={riskState.error} /> : null}
      </div>

      <div className="section-title">
        <h2>消费延迟</h2>
        <span>来自 /api/v1/health 的 Kafka 消费组</span>
      </div>
      <div className="lag-table" role="table" aria-label="消费延迟">
        <div role="row" className="lag-row lag-head">
          <span role="columnheader">消费组</span>
          <span role="columnheader">延迟</span>
          <span role="columnheader">状态</span>
        </div>
        {Object.entries(state.data?.consumer_lag ?? {}).map(([group, lag]) => (
          <div role="row" className="lag-row" key={group}>
            <span role="cell">{group}</span>
            <span role="cell">{lag.toLocaleString()}</span>
            <span role="cell">
              <StatusPill ok={lag === 0} label={lag === 0 ? "已追平" : "有积压"} />
            </span>
          </div>
        ))}
        {state.data && Object.keys(state.data.consumer_lag).length === 0 ? (
          <EmptyState title="暂无消费组延迟" detail="健康检查接口返回的 consumer_lag 为空。" />
        ) : null}
      </div>
    </section>
  );
}

function RealtimeLogsPage() {
  const [query, setQuery] = useState<LogsQuery>(initialLogsQuery);
  const [draft, setDraft] = useState<LogsQuery>(initialLogsQuery);
  const [live, setLive] = useState(true);
  const [state, setState] = useState<LoadState<{ items: NormalizedLog[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });

  const load = useCallback((activeQuery: LogsQuery, signal?: AbortSignal) => {
    setState((current) => ({ ...current, loading: true, error: null }));
    fetchLogs(activeQuery, signal)
      .then((data) => {
        setState({
          data: { items: data.items, total: data.total },
          loading: false,
          error: null,
          updatedAt: new Date()
        });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setState((current) => ({
          ...current,
          loading: false,
          error: formatError(error)
        }));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(query, controller.signal);

    return () => controller.abort();
  }, [load, query]);

  useEffect(() => {
    if (!live) {
      return;
    }

    const interval = window.setInterval(() => {
      load(query);
    }, 10000);

    return () => window.clearInterval(interval);
  }, [live, load, query]);

  const applyFilters = () => {
    setQuery({ ...draft, offset: 0 });
  };

  const clearFilters = () => {
    setDraft(initialLogsQuery);
    setQuery(initialLogsQuery);
  };

  const canGoPrevious = query.offset > 0;
  const canGoNext = Boolean(state.data && query.offset + query.limit < state.data.total);

  return (
    <section className="page">
      <PageHeader
        kicker="实时日志"
        title="实时日志"
        description="通过 FastAPI 查询由 ClickHouse 支撑的结构化安全事件。"
        action={
          <div className="header-actions">
            <button className="icon-button" type="button" onClick={() => setLive((value) => !value)}>
              {live ? <Pause aria-hidden="true" /> : <Play aria-hidden="true" />}
              {live ? "暂停轮询" : "恢复轮询"}
            </button>
            <button className="icon-button primary" type="button" onClick={() => load(query)} disabled={state.loading}>
              <RefreshCcw aria-hidden="true" className={state.loading ? "spin" : ""} />
              刷新
            </button>
          </div>
        }
      />

      {state.error ? <ErrorBanner message={state.error} /> : null}

      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault();
          applyFilters();
        }}
      >
        <label>
          <span>来源</span>
          <select
            value={draft.source_type}
            onChange={(event) => setDraft((current) => ({ ...current, source_type: event.target.value as SourceType | "" }))}
          >
            {sourceTypes.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>

        <label>
          <span>用户 ID</span>
          <input
            value={draft.user_id}
            placeholder="alice"
            onChange={(event) => setDraft((current) => ({ ...current, user_id: event.target.value }))}
          />
        </label>

        <label>
          <span>源 IP</span>
          <input
            value={draft.src_ip}
            placeholder="10.0.1.20"
            onChange={(event) => setDraft((current) => ({ ...current, src_ip: event.target.value }))}
          />
        </label>

        <label>
          <span>结果</span>
          <select value={draft.result} onChange={(event) => setDraft((current) => ({ ...current, result: event.target.value as LogsQuery["result"] }))}>
            {resultOptions.map((option) => (
              <option key={option || "all"} value={option}>
                {option ? formatResult(option) : "全部结果"}
              </option>
            ))}
          </select>
        </label>

        <label>
          <span>开始时间</span>
          <input
            type="datetime-local"
            value={toDatetimeLocalInput(draft.start_time)}
            onChange={(event) => setDraft((current) => ({ ...current, start_time: toApiDateTime(event.target.value) }))}
          />
        </label>

        <label>
          <span>结束时间</span>
          <input
            type="datetime-local"
            value={toDatetimeLocalInput(draft.end_time)}
            onChange={(event) => setDraft((current) => ({ ...current, end_time: toApiDateTime(event.target.value) }))}
          />
        </label>

        <label>
          <span>条数</span>
          <select
            value={draft.limit}
            onChange={(event) => setDraft((current) => ({ ...current, limit: Number(event.target.value) }))}
          >
            {[25, 50, 100, 200].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>

        <div className="filter-actions">
          <button className="icon-button primary" type="submit">
            <Search aria-hidden="true" />
            应用
          </button>
          <button className="icon-button" type="button" onClick={clearFilters}>
            <Filter aria-hidden="true" />
            清空
          </button>
        </div>
      </form>

      <div className="table-toolbar">
        <div>
          <strong>{state.data?.total.toLocaleString() ?? "0"} 条事件</strong>
          <span>{formatResultRange(query.offset, query.limit, state.data?.total ?? 0, state.data?.items.length ?? 0)}，来自 /api/v1/logs</span>
        </div>
        <div className="toolbar-meta">
          <StatusPill ok={live} label={live ? "实时轮询" : "已暂停"} />
          <span>{state.updatedAt ? `更新于 ${state.updatedAt.toLocaleTimeString()}` : "等待数据"}</span>
        </div>
      </div>

      <div className="log-table-wrap">
        <table className="log-table">
          <thead>
            <tr>
              <th>事件时间</th>
              <th>来源</th>
              <th>用户</th>
              <th>源 IP</th>
              <th>动作</th>
              <th>结果</th>
              <th>消息</th>
              <th>风险标签</th>
            </tr>
          </thead>
          <tbody>
            {state.data?.items.map((log) => (
              <tr key={log.event_id}>
                <td>
                  <time dateTime={log.event_time}>{formatDateTime(log.event_time)}</time>
                  <small>{log.event_id}</small>
                </td>
                <td>{formatSource(log.source_type)}</td>
                <td>{log.user_id || "未知"}</td>
                <td>{log.src_ip || "无"}</td>
                <td>{log.action}</td>
                <td>
                  <span className={`status-chip ${statusTone(log.result)}`}>{formatResult(log.result)}</span>
                </td>
                <td className="message-cell">{log.message}</td>
                <td>
                  <div className="tag-list">
                    {log.risk_tags.length > 0 ? log.risk_tags.map((tag) => <span key={tag}>{tag}</span>) : <span className="muted">无</span>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {state.loading && !state.data ? <TableSkeleton /> : null}
        {!state.loading && state.data?.items.length === 0 ? (
          <EmptyState title="没有匹配的日志" detail="请调整筛选条件，或确认 Filebeat、Flink 与 ClickHouse 正在处理当前数据。" />
        ) : null}
      </div>

      <div className="pagination">
        <button
          className="icon-button"
          type="button"
          disabled={!canGoPrevious}
          onClick={() => setQuery((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}
        >
          上一页
        </button>
        <span>偏移 {query.offset.toLocaleString()}</span>
        <button
          className="icon-button"
          type="button"
          disabled={!canGoNext}
          onClick={() => setQuery((current) => ({ ...current, offset: current.offset + current.limit }))}
        >
          下一页
        </button>
      </div>
    </section>
  );
}

function AlertsPage() {
  const [query, setQuery] = useState<AlertsQuery>(initialAlertsQuery);
  const [draft, setDraft] = useState<AlertsQuery>(initialAlertsQuery);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [listState, setListState] = useState<LoadState<{ items: AnomalyEvent[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [detailState, setDetailState] = useState<LoadState<AnomalyDetailResponse>>({
    data: null,
    loading: false,
    error: null,
    updatedAt: null
  });

  const loadAlerts = useCallback((activeQuery: AlertsQuery, signal?: AbortSignal) => {
    setListState((current) => ({ ...current, loading: true, error: null }));
    fetchAlerts(activeQuery, signal)
      .then((data) => {
        setListState({
          data: { items: data.items, total: data.total },
          loading: false,
          error: null,
          updatedAt: new Date()
        });
        setSelectedAlertId((current) => {
          if (current && data.items.some((alert) => alert.event_id === current)) {
            return current;
          }
          return data.items[0]?.event_id ?? null;
        });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setListState((current) => ({
          ...current,
          loading: false,
          error: formatError(error)
        }));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    loadAlerts(query, controller.signal);

    return () => controller.abort();
  }, [loadAlerts, query]);

  const loadDetail = useCallback((alertId: string, signal?: AbortSignal) => {
    setDetailState((current) => ({ ...current, loading: true, error: null }));
    fetchAlertDetail(alertId, signal)
      .then((data) => {
        setDetailState({ data, loading: false, error: null, updatedAt: new Date() });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setDetailState((current) => ({
          ...current,
          loading: false,
          error: formatError(error)
        }));
      });
  }, []);

  useEffect(() => {
    if (!selectedAlertId) {
      setDetailState({ data: null, loading: false, error: null, updatedAt: null });
      return;
    }

    const controller = new AbortController();
    loadDetail(selectedAlertId, controller.signal);
    return () => controller.abort();
  }, [loadDetail, selectedAlertId]);

  const applyFilters = () => {
    setQuery({ ...draft, offset: 0 });
  };

  const clearFilters = () => {
    setDraft(initialAlertsQuery);
    setQuery(initialAlertsQuery);
  };

  const canGoPrevious = query.offset > 0;
  const canGoNext = Boolean(listState.data && query.offset + query.limit < listState.data.total);

  return (
    <section className="page">
      <PageHeader
        kicker="异常检测"
        title="异常事件"
        description="通过 FastAPI 查询写入 ClickHouse 的异常检测结果。"
        action={
          <button className="icon-button primary" type="button" onClick={() => loadAlerts(query)} disabled={listState.loading}>
            <RefreshCcw aria-hidden="true" className={listState.loading ? "spin" : ""} />
            刷新
          </button>
        }
      />

      {listState.error ? <ErrorBanner message={listState.error} /> : null}

      <form
        className="filters alerts-filters"
        onSubmit={(event) => {
          event.preventDefault();
          applyFilters();
        }}
      >
        <label>
          <span>风险</span>
          <select
            value={draft.risk_level}
            onChange={(event) => setDraft((current) => ({ ...current, risk_level: event.target.value as RiskLevel | "" }))}
          >
            {riskLevelOptions.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>

        <label>
          <span>用户 ID</span>
          <input
            value={draft.user_id}
            placeholder="alice"
            onChange={(event) => setDraft((current) => ({ ...current, user_id: event.target.value }))}
          />
        </label>

        <label>
          <span>原因码</span>
          <input
            value={draft.reason_code}
            placeholder="new_source_ip"
            onChange={(event) => setDraft((current) => ({ ...current, reason_code: event.target.value }))}
          />
        </label>

        <label>
          <span>状态</span>
          <select value={draft.status} onChange={(event) => setDraft((current) => ({ ...current, status: event.target.value }))}>
            {alertStatusOptions.map((option) => (
              <option key={option || "all"} value={option}>
                {option ? formatAlertStatus(option) : "全部状态"}
              </option>
            ))}
          </select>
        </label>

        <label>
          <span>开始时间</span>
          <input
            type="datetime-local"
            value={toDatetimeLocalInput(draft.start_time)}
            onChange={(event) => setDraft((current) => ({ ...current, start_time: toApiDateTime(event.target.value) }))}
          />
        </label>

        <label>
          <span>结束时间</span>
          <input
            type="datetime-local"
            value={toDatetimeLocalInput(draft.end_time)}
            onChange={(event) => setDraft((current) => ({ ...current, end_time: toApiDateTime(event.target.value) }))}
          />
        </label>

        <label>
          <span>条数</span>
          <select
            value={draft.limit}
            onChange={(event) => setDraft((current) => ({ ...current, limit: Number(event.target.value) }))}
          >
            {[25, 50, 100].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>

        <div className="filter-actions">
          <button className="icon-button primary" type="submit">
            <Search aria-hidden="true" />
            应用
          </button>
          <button className="icon-button" type="button" onClick={clearFilters}>
            <Filter aria-hidden="true" />
            清空
          </button>
        </div>
      </form>

      <div className="alerts-layout">
        <section className="alerts-list-panel" aria-label="异常事件列表">
          <div className="table-toolbar">
            <div>
              <strong>{listState.data?.total.toLocaleString() ?? "0"} 个异常</strong>
              <span>{formatResultRange(query.offset, query.limit, listState.data?.total ?? 0, listState.data?.items.length ?? 0)}，来自 /api/v1/anomalies</span>
            </div>
            <div className="toolbar-meta">
              <span>{listState.updatedAt ? `更新于 ${listState.updatedAt.toLocaleTimeString()}` : "等待数据"}</span>
            </div>
          </div>

          <div className="log-table-wrap alerts-table-wrap">
            <table className="log-table alerts-table">
              <thead>
                <tr>
                  <th>检测时间</th>
                  <th>风险</th>
                  <th>用户</th>
                  <th>源 IP</th>
                  <th>命中规则</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {listState.data?.items.map((alert) => (
                  <tr
                    key={alert.event_id}
                    className={selectedAlertId === alert.event_id ? "selected-row" : ""}
                    tabIndex={0}
                    onClick={() => setSelectedAlertId(alert.event_id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedAlertId(alert.event_id);
                      }
                    }}
                  >
                    <td>
                      <time dateTime={alert.detect_time}>{formatDateTime(alert.detect_time)}</time>
                      <small>{alert.event_id}</small>
                    </td>
                    <td>
                      <span className={`risk-chip ${riskTone(alert.risk_level)}`}>{formatRiskLevel(alert.risk_level)}</span>
                      <small>分数 {alert.risk_score}</small>
                    </td>
                    <td>{alert.user_id || "未知"}</td>
                    <td>{alert.src_ip || "无"}</td>
                    <td>
                      <div className="tag-list">
                        {alert.rule_hits.length > 0 ? alert.rule_hits.map((rule) => <span key={rule}>{rule}</span>) : <span className="muted">无</span>}
                      </div>
                    </td>
                    <td>
                      <span className={`status-chip ${alertStatusTone(alert.status)}`}>{formatAlertStatus(alert.status)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {listState.loading && !listState.data ? <TableSkeleton /> : null}
            {!listState.loading && listState.data?.items.length === 0 ? (
              <EmptyState title="没有匹配的异常" detail="请调整筛选条件，或确认检测链路已经写入异常事件。" />
            ) : null}
          </div>

          <div className="pagination">
            <button
              className="icon-button"
              type="button"
              disabled={!canGoPrevious}
              onClick={() => setQuery((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}
            >
              上一页
            </button>
            <span>偏移 {query.offset.toLocaleString()}</span>
            <button
              className="icon-button"
              type="button"
              disabled={!canGoNext}
              onClick={() => setQuery((current) => ({ ...current, offset: current.offset + current.limit }))}
            >
              下一页
            </button>
          </div>
        </section>

        <AlertDetailPanel
          state={detailState}
          selectedAlertId={selectedAlertId}
          onRefresh={() => {
            if (selectedAlertId) {
              loadDetail(selectedAlertId);
            }
            loadAlerts(query);
          }}
        />
      </div>
    </section>
  );
}

function AlertDetailPanel({
  state,
  selectedAlertId,
  onRefresh
}: {
  state: LoadState<AnomalyDetailResponse>;
  selectedAlertId: string | null;
  onRefresh: () => void;
}) {
  const detail = state.data;
  const [flagState, setFlagState] = useState<{ loading: boolean; message: string | null; error: string | null }>({
    loading: false,
    message: null,
    error: null
  });

  const handleFlagFalsePositive = () => {
    if (!selectedAlertId) return;
    setFlagState({ loading: true, message: null, error: null });
    flagFalsePositive(selectedAlertId)
      .then(() => {
        setFlagState({ loading: false, message: "已标记为待审核，请在 AI 研判页面进一步处理。", error: null });
        onRefresh();
      })
      .catch((error: unknown) => setFlagState({ loading: false, message: null, error: formatError(error) }));
  };

  if (!selectedAlertId) {
    return (
      <aside className="detail-panel">
        <EmptyState title="选择一个异常事件" detail="详情会展示证据链、相关日志、基线与 FastAPI 返回的 AI 报告。" />
      </aside>
    );
  }

  return (
    <aside className="detail-panel">
      <div className="detail-panel-header">
        <div>
          <span className="eyebrow">异常详情</span>
          <h2>{detail?.anomaly.event_id ?? selectedAlertId}</h2>
        </div>
        {detail ? <StatusPill ok={detail.anomaly.ai_status === "analyzed"} label={formatAIStatus(detail.anomaly.ai_status)} /> : null}
      </div>

      {state.error ? <ErrorBanner message={state.error} /> : null}
      {flagState.error ? <ErrorBanner message={flagState.error} /> : null}
      {flagState.message ? <div className="success-banner">{flagState.message}</div> : null}
      {state.loading && !detail ? <TableSkeleton /> : null}

      {detail ? (
        <div className="detail-stack">
          <section className="detail-section">
            <div className="detail-section-title">
              <h3>操作</h3>
              <span>{formatAIStatus(detail.anomaly.ai_status)}</span>
            </div>
            <div className="inline-actions">
              <button className="icon-button" type="button" onClick={handleFlagFalsePositive} disabled={flagState.loading}>
                <CheckCircle2 aria-hidden="true" />
                标记误报
              </button>
            </div>
          </section>

          <section className="detail-section">
            <div className="detail-section-title">
              <h3>风险摘要</h3>
              <span>{formatRiskLevel(detail.anomaly.risk_level)}</span>
            </div>
            <div className="metrics-band compact-metrics">
              <Metric icon={BarChart3} label="风险分数" value={String(detail.anomaly.risk_score)} hint="0 到 100" />
              <Metric icon={ShieldCheck} label="评分版本" value={detail.anomaly.scoring_version || "-"} hint={detail.anomaly.model_version || "检测模型未声明"} />
              <Metric icon={ListFilter} label="原因码" value={String(detail.anomaly.reason_codes.length)} hint={detail.anomaly.reason_codes.slice(0, 2).join(", ") || "无"} />
              <Metric icon={Sparkles} label="AI 状态" value={formatAIStatus(detail.anomaly.ai_status)} hint={isEmptyRecord(detail.ai_judgement) ? "暂无研判记录" : "已有研判结果"} />
            </div>
            <JsonBlock value={detail.anomaly.risk_components} />
          </section>

          <section className="detail-section">
            <div className="detail-section-title">
              <h3>命中规则</h3>
              <span>{detail.evidence_chain.rule_hits.length} 条规则</span>
            </div>
            <div className="tag-list">
              {detail.evidence_chain.rule_hits.length > 0 ? (
                detail.evidence_chain.rule_hits.map((rule) => <span key={rule}>{rule}</span>)
              ) : (
                <span className="muted">无</span>
              )}
            </div>
            <div className="tag-list">
              {detail.evidence_chain.reason_codes.length > 0 ? (
                detail.evidence_chain.reason_codes.map((code) => <span key={code}>{code}</span>)
              ) : (
                <span className="muted">无原因码</span>
              )}
            </div>
          </section>

          <section className="detail-section">
            <div className="detail-section-title">
              <h3>证据链</h3>
              <span>{detail.anomaly.baseline_deviations.length} 个基线偏离</span>
            </div>
            <p className="risk-reason">{detail.evidence_chain.risk_reason || "未返回风险原因。"}</p>
            {detail.anomaly.baseline_deviations.length > 0 ? (
              <ul className="evidence-list">
                {detail.anomaly.baseline_deviations.map((deviation) => {
                  const feature = String(deviation.feature ?? deviation.name ?? "未知");
                  const actual = String(deviation.actual ?? deviation.value ?? "-");
                  const source = String(deviation.evidence_source ?? "");
                  const sourceLabel = formatEvidenceSource(source);
                  const sampleDays = deviation.sample_days != null ? Number(deviation.sample_days) : undefined;
                  return (
                    <li key={`${feature}-${actual}`}>
                      <strong>{feature}</strong>: {actual}
                      <span className="evidence-meta">
                        <span className="evidence-source">{sourceLabel}</span>
                        {sampleDays !== undefined ? <span className="evidence-days">{sampleDays} 天</span> : null}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="muted">未返回基线偏离。</p>
            )}
            <JsonBlock value={detail.anomaly.evidence} />
          </section>

          <section className="detail-section">
            <div className="detail-section-title">
              <h3>相关日志</h3>
              <span>{detail.related_logs.length} 条事件</span>
            </div>
            <div className="related-log-list">
              {detail.related_logs.map((log) => (
                <article key={log.event_id} className="related-log-item">
                  <div>
                    <strong>{log.action}</strong>
                    <span>{formatDateTime(log.event_time)}</span>
                  </div>
                  <p>{log.message}</p>
                  <small>{log.event_id}</small>
                </article>
              ))}
              {detail.related_logs.length === 0 ? <p className="muted">未返回相关日志。</p> : null}
            </div>
          </section>

          <section className="detail-section">
            <div className="detail-section-title">
              <h3>基线</h3>
              <span>{isEmptyRecord(detail.baseline) ? "缺失" : "可用"}</span>
            </div>
            {isEmptyRecord(detail.baseline) ? <p className="muted">该异常未返回基线。</p> : <JsonBlock value={detail.baseline} />}
          </section>

          <section className="detail-section">
            <div className="detail-section-title">
              <h3>AI 研判</h3>
              <span>{isEmptyRecord(detail.ai_judgement) ? "未生成" : "已保存"}</span>
            </div>
            {isEmptyRecord(detail.ai_judgement) ? (
              <p className="muted">该异常未返回 AI 研判。</p>
            ) : (
              <JsonBlock value={detail.ai_judgement} />
            )}
          </section>
        </div>
      ) : null}
    </aside>
  );
}

function UserProfilesPage() {
  const [query, setQuery] = useState({ limit: 25, offset: 0 });
  const [state, setState] = useState<LoadState<{ items: UserBaseline[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [overrides, setOverrides] = useState<LoadState<{ items: BaselineOverride[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [feedback, setFeedback] = useState<LoadState<{ items: AIFeedback[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [action, setAction] = useState<{ loading: boolean; message: string | null; error: string | null }>({
    loading: false,
    message: null,
    error: null
  });
  const [overrideDraft, setOverrideDraft] = useState({
    user_id: "",
    profile_group: "time" as BaselineOverride["profile_group"],
    feature_name: "active_hours",
    period_type: "weekday" as BaselinePeriodType,
    period_key: "saturday",
    merge_mode: "append" as BaselineMergeMode,
    override_value: '{"common_values":["09:00-13:00"]}',
    reason: "",
    effective_from: localDateTimeValue(new Date()),
    effective_to: "",
    created_by: "analyst"
  });

  const load = useCallback((activeQuery = query, signal?: AbortSignal) => {
    setState((current) => ({ ...current, loading: true, error: null }));
    fetchBaselines(activeQuery, signal)
      .then((data) => setState({ data: { items: data.items, total: data.total }, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setState((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
  }, [query]);

  const loadGovernance = useCallback((signal?: AbortSignal) => {
    setOverrides((current) => ({ ...current, loading: true, error: null }));
    setFeedback((current) => ({ ...current, loading: true, error: null }));
    fetchBaselineOverrides({ limit: 100, offset: 0 }, signal)
      .then((data) => setOverrides({ data, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setOverrides((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
    fetchFeedback({ review_status: "pending", target_component: "baseline", limit: 100, offset: 0 }, signal)
      .then((data) => setFeedback({ data, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setFeedback((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(query, controller.signal);
    loadGovernance(controller.signal);
    return () => controller.abort();
  }, [load, loadGovernance, query]);

  const refreshAll = useCallback(() => {
    load();
    loadGovernance();
  }, [load, loadGovernance]);

  const submitOverride = () => {
    let overrideValue: Record<string, unknown>;
    try {
      overrideValue = JSON.parse(overrideDraft.override_value) as Record<string, unknown>;
    } catch {
      setAction({ loading: false, message: null, error: "覆盖值必须是合法 JSON 对象。" });
      return;
    }
    setAction({ loading: true, message: null, error: null });
    createBaselineOverride({
      tenant_id: "default",
      user_id: overrideDraft.user_id,
      profile_group: overrideDraft.profile_group,
      feature_name: overrideDraft.feature_name,
      period_type: overrideDraft.period_type,
      period_key: overrideDraft.period_key,
      merge_mode: overrideDraft.merge_mode,
      override_value: overrideValue,
      reason: overrideDraft.reason,
      effective_from: new Date(overrideDraft.effective_from).toISOString(),
      effective_to: overrideDraft.effective_to ? new Date(overrideDraft.effective_to).toISOString() : null,
      created_by: overrideDraft.created_by
    })
      .then((item) => {
        setAction({ loading: false, message: `已创建覆盖项 ${item.override_id}，版本 ${item.model_version}。`, error: null });
        setOverrideDraft((current) => ({ ...current, reason: "" }));
        refreshAll();
      })
      .catch((error: unknown) => setAction({ loading: false, message: null, error: formatError(error) }));
  };

  const rebuild = () => {
    setAction({ loading: true, message: null, error: null });
    rebuildBaselines()
      .then((result) => {
        setAction({ loading: false, message: `周期基线重建完成，共为 ${result.rebuilt_count} 位用户生成画像。`, error: null });
        refreshAll();
      })
      .catch((error: unknown) => setAction({ loading: false, message: null, error: formatError(error) }));
  };

  return (
    <section className="page">
      <PageHeader
        kicker="行为基线"
        title="用户画像"
        description="管理周期行为画像、有效覆盖项与待审核的 baseline 反馈。"
        action={
          <div className="header-actions">
            <button className="icon-button" type="button" onClick={rebuild} disabled={action.loading}>
              <Database aria-hidden="true" />
              重建周期基线
            </button>
            <button className="icon-button primary" type="button" onClick={refreshAll} disabled={state.loading}>
              <RefreshCcw aria-hidden="true" className={state.loading ? "spin" : ""} />
              刷新
            </button>
          </div>
        }
      />
      {state.error ? <ErrorBanner message={state.error} /> : null}
      {action.error ? <ErrorBanner message={action.error} /> : null}
      {action.message ? <div className="success-banner">{action.message}</div> : null}
      <div className="profile-grid">
        {state.data?.items.map((profile) => (
          <article className="profile-card" key={`${profile.tenant_id}:${profile.user_id}:${profile.period_type}:${profile.period_key}`}>
            <div className="profile-card-head">
              <div>
                <span className="eyebrow">{profile.tenant_id}</span>
                <h2>{profile.user_id}</h2>
              </div>
              <StatusPill ok={profile.baseline_confidence >= 0.7} label={`置信度 ${profile.baseline_confidence}`} />
            </div>
            <div className="profile-meta">
              <span>{profile.baseline_date}</span>
              <span>{profile.sample_days} 天</span>
              <span>{profile.sample_count} 个样本</span>
              <span>{profile.period_type}:{profile.period_key}</span>
              <span>{formatFallbackLevel(profile.fallback_level)}</span>
              <span>模型 {profile.model_version}</span>
              <span>训练窗口 {profile.trained_from} ~ {profile.trained_to}</span>
              <span>覆盖项 {profile.selected_baseline?.override_ids?.length ?? 0} 个</span>
            </div>
            <FiveW1HSections profile={profile} />
            <details className="profile-raw">
              <summary>原始画像（调试）</summary>
              <div className="profile-sections">
                <ProfileSection title="who_profile" value={profile.who_profile} />
                <ProfileSection title="time_profile" value={profile.time_profile} />
                <ProfileSection title="location_profile" value={profile.location_profile} />
                <ProfileSection title="access_profile" value={profile.access_profile} />
                <ProfileSection title="volume_profile" value={profile.volume_profile} />
                <ProfileSection title="result_profile" value={profile.result_profile} />
                <ProfileSection title="why_profile" value={profile.why_profile} />
              </div>
            </details>
          </article>
        ))}
        {!state.loading && state.data?.items.length === 0 ? <EmptyState title="暂无用户画像" detail="当前还没有可用的基线记录。" /> : null}
      </div>
      <PaginationControls
        limit={query.limit}
        offset={query.offset}
        total={state.data?.total ?? 0}
        onPrevious={() => setQuery((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}
        onNext={() => setQuery((current) => ({ ...current, offset: current.offset + current.limit }))}
      />

      <section className="governance-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">人工追加</span>
            <h2>Baseline Override</h2>
          </div>
          <span>{overrides.data?.total ?? 0} 条审计记录</span>
        </div>
        {overrides.error ? <ErrorBanner message={overrides.error} /> : null}
        <div className="governance-layout">
          <div className="management-form">
            <label>用户<input value={overrideDraft.user_id} onChange={(event) => setOverrideDraft((current) => ({ ...current, user_id: event.target.value }))} placeholder="alice" /></label>
            <label>Profile<select value={overrideDraft.profile_group} onChange={(event) => setOverrideDraft((current) => ({ ...current, profile_group: event.target.value as BaselineOverride["profile_group"] }))}>{["who", "time", "location", "access", "volume", "result", "why"].map((item) => <option key={item}>{item}</option>)}</select></label>
            <label>Feature<input value={overrideDraft.feature_name} onChange={(event) => setOverrideDraft((current) => ({ ...current, feature_name: event.target.value }))} /></label>
            <label>周期类型<select value={overrideDraft.period_type} onChange={(event) => setOverrideDraft((current) => ({ ...current, period_type: event.target.value as BaselinePeriodType }))}>{baselinePeriodOptions.map((item) => <option key={item}>{item}</option>)}</select></label>
            <label>周期值<input value={overrideDraft.period_key} onChange={(event) => setOverrideDraft((current) => ({ ...current, period_key: event.target.value }))} /></label>
            <label>合并方式<select value={overrideDraft.merge_mode} onChange={(event) => setOverrideDraft((current) => ({ ...current, merge_mode: event.target.value as BaselineMergeMode }))}>{["append", "replace", "adjust"].map((item) => <option key={item}>{item}</option>)}</select></label>
            <label className="form-span-2">覆盖值 JSON<textarea value={overrideDraft.override_value} onChange={(event) => setOverrideDraft((current) => ({ ...current, override_value: event.target.value }))} rows={3} /></label>
            <label>生效时间<input type="datetime-local" value={overrideDraft.effective_from} onChange={(event) => setOverrideDraft((current) => ({ ...current, effective_from: event.target.value }))} /></label>
            <label>失效时间<input type="datetime-local" value={overrideDraft.effective_to} onChange={(event) => setOverrideDraft((current) => ({ ...current, effective_to: event.target.value }))} /></label>
            <label>操作者<input value={overrideDraft.created_by} onChange={(event) => setOverrideDraft((current) => ({ ...current, created_by: event.target.value }))} /></label>
            <label className="form-span-2">原因<textarea value={overrideDraft.reason} onChange={(event) => setOverrideDraft((current) => ({ ...current, reason: event.target.value }))} rows={2} /></label>
            <button className="icon-button primary form-submit" type="button" disabled={action.loading || !overrideDraft.user_id || !overrideDraft.reason} onClick={submitOverride}>
              <CheckCircle2 aria-hidden="true" />
              创建 active override
            </button>
          </div>
          <div className="override-list">
            {overrides.data?.items.map((item) => (
              <article className="override-card" key={item.override_id}>
                <div className="profile-card-head">
                  <div><span className="eyebrow">{item.source_type}</span><h3>{item.user_id || "全局"} · {item.profile_group}.{item.feature_name}</h3></div>
                  <StatusPill ok={item.status === "active"} label={item.status} />
                </div>
                <p>{item.reason}</p>
                <div className="profile-meta"><span>{item.period_type}:{item.period_key}</span><span>{item.merge_mode}</span><span>{formatDateTime(item.effective_from)}</span><span>{item.model_version}</span></div>
                <JsonBlock value={item.override_value} />
                {item.status === "active" ? (
                  <button className="icon-button danger" type="button" onClick={() => {
                    const reason = window.prompt("请输入撤销原因");
                    if (!reason) return;
                    revokeBaselineOverride(item.override_id, { revoked_by: "analyst", reason })
                      .then(() => refreshAll())
                      .catch((error: unknown) => setAction({ loading: false, message: null, error: formatError(error) }));
                  }}>
                    <XCircle aria-hidden="true" />
                    撤销
                  </button>
                ) : null}
              </article>
            ))}
            {!overrides.loading && overrides.data?.items.length === 0 ? <EmptyState title="暂无覆盖项" detail="人工追加或审核通过后会在这里形成独立审计记录。" /> : null}
          </div>
        </div>
      </section>

      <section className="governance-section">
        <div className="section-heading">
          <div><span className="eyebrow">反馈治理</span><h2>待审核 Baseline 反馈</h2></div>
          <span>{feedback.data?.total ?? 0} 条待处理</span>
        </div>
        {feedback.error ? <ErrorBanner message={feedback.error} /> : null}
        <div className="compact-list">
          {feedback.data?.items.map((item) => <FeedbackReviewCard key={item.feedback_id} feedback={item} onReviewed={refreshAll} onError={(error) => setAction({ loading: false, message: null, error })} />)}
          {!feedback.loading && feedback.data?.items.length === 0 ? <EmptyState title="暂无待审核反馈" detail="AI baseline 建议会先进入 pending，审核后才可能生成 override。" /> : null}
        </div>
      </section>
    </section>
  );
}

const baselinePeriodOptions: BaselinePeriodType[] = [
  "global",
  "rolling",
  "weekday",
  "calendar_month",
  "month_phase",
  "weekday_month_phase"
];

function FeedbackReviewCard({
  feedback,
  onReviewed,
  onError
}: {
  feedback: AIFeedback;
  onReviewed: () => void;
  onError: (message: string) => void;
}) {
  const [loading, setLoading] = useState(false);
  const [draft, setDraft] = useState({
    review_reason: "",
    profile_group: "access" as BaselineOverride["profile_group"],
    feature_name: "common_resources",
    period_type: "global" as BaselinePeriodType,
    period_key: "all",
    merge_mode: "append" as BaselineMergeMode,
    override_value: '{"common_values":[]}',
    effective_from: localDateTimeValue(new Date()),
    effective_to: ""
  });

  const submit = (decision: "accepted" | "rejected") => {
    let overrideValue: Record<string, unknown> = {};
    if (decision === "accepted") {
      try {
        overrideValue = JSON.parse(draft.override_value) as Record<string, unknown>;
      } catch {
        onError("反馈覆盖值必须是合法 JSON 对象。");
        return;
      }
    }
    setLoading(true);
    reviewFeedback(feedback.feedback_id, {
      decision,
      reviewed_by: "analyst",
      review_reason: draft.review_reason,
      override: decision === "accepted" ? {
        profile_group: draft.profile_group,
        feature_name: draft.feature_name,
        period_type: draft.period_type,
        period_key: draft.period_key,
        merge_mode: draft.merge_mode,
        override_value: overrideValue,
        effective_from: new Date(draft.effective_from).toISOString(),
        effective_to: draft.effective_to ? new Date(draft.effective_to).toISOString() : null
      } : undefined
    })
      .then(onReviewed)
      .catch((error: unknown) => onError(formatError(error)))
      .finally(() => setLoading(false));
  };

  return (
    <article className="judgement-card feedback-review-card">
      <div className="profile-card-head">
        <div><span className="eyebrow">{feedback.feedback_id}</span><h3>{feedback.user_id || "未绑定用户"}</h3></div>
        <StatusPill ok={false} label={feedback.review_status} />
      </div>
      <p>{feedback.suggestion}</p>
      <div className="management-form compact-form">
        <label>Profile<select value={draft.profile_group} onChange={(event) => setDraft((current) => ({ ...current, profile_group: event.target.value as BaselineOverride["profile_group"] }))}>{["who", "time", "location", "access", "volume", "result", "why"].map((item) => <option key={item}>{item}</option>)}</select></label>
        <label>Feature<input value={draft.feature_name} onChange={(event) => setDraft((current) => ({ ...current, feature_name: event.target.value }))} /></label>
        <label>周期类型<select value={draft.period_type} onChange={(event) => setDraft((current) => ({ ...current, period_type: event.target.value as BaselinePeriodType }))}>{baselinePeriodOptions.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label>周期值<input value={draft.period_key} onChange={(event) => setDraft((current) => ({ ...current, period_key: event.target.value }))} /></label>
        <label>合并方式<select value={draft.merge_mode} onChange={(event) => setDraft((current) => ({ ...current, merge_mode: event.target.value as BaselineMergeMode }))}>{["append", "replace", "adjust"].map((item) => <option key={item}>{item}</option>)}</select></label>
        <label className="form-span-2">覆盖值 JSON<textarea rows={2} value={draft.override_value} onChange={(event) => setDraft((current) => ({ ...current, override_value: event.target.value }))} /></label>
        <label>生效时间<input type="datetime-local" value={draft.effective_from} onChange={(event) => setDraft((current) => ({ ...current, effective_from: event.target.value }))} /></label>
        <label>失效时间<input type="datetime-local" value={draft.effective_to} onChange={(event) => setDraft((current) => ({ ...current, effective_to: event.target.value }))} /></label>
        <label className="form-span-2">审核原因<textarea rows={2} value={draft.review_reason} onChange={(event) => setDraft((current) => ({ ...current, review_reason: event.target.value }))} /></label>
      </div>
      <div className="review-actions">
        <button className="icon-button primary" type="button" disabled={loading || !draft.review_reason} onClick={() => submit("accepted")}><CheckCircle2 aria-hidden="true" />接受并追加</button>
        <button className="icon-button danger" type="button" disabled={loading || !draft.review_reason} onClick={() => submit("rejected")}><XCircle aria-hidden="true" />拒绝</button>
      </div>
    </article>
  );
}

function formatEvidenceSource(source: string): string {
  const labels: Record<string, string> = {
    user_baseline: "来自用户历史基线",
    user_history: "来自用户历史基线",
    daily_feature: "来自日级行为特征",
    seen_sources: "来自持久化已见来源表",
    peer_group: "来自同组用户基线",
    global: "来自全局基线"
  };
  return (labels[source] ?? source) || "未知来源";
}

function ProfileSection({ title, value }: { title: string; value: Record<string, unknown> }) {
  return (
    <section>
      <h3>{title}</h3>
      <JsonBlock value={value} />
    </section>
  );
}

type ProfileFeature = { name: string; display: string };

// Keyword routing: access_profile feeds both "What" (resources/actions) and
// "How" (device/agent/auth/protocol); these names go to How, the rest to What.
const HOW_FEATURE_HINTS = ["agent", "auth", "device", "protocol"];

function FiveW1HSections({ profile }: { profile: UserBaseline }) {
  const access = flattenProfileFeatures(profile.access_profile);
  const howFromAccess = access.filter((feature) =>
    HOW_FEATURE_HINTS.some((hint) => feature.name.toLowerCase().includes(hint))
  );
  const whatFromAccess = access.filter((feature) => !howFromAccess.includes(feature));

  const whoItems = flattenProfileFeatures(profile.who_profile);
  const whoWithMeta: ProfileFeature[] = [
    { name: "user_id", display: profile.user_id },
    { name: "user_role", display: String(profile.who_profile?.user_role ?? profile.user_id ?? "未知") },
    ...whoItems
  ];

  const whyItems = flattenProfileFeatures(profile.why_profile);
  const whyWithMeta: ProfileFeature[] = [
    { name: "baseline_confidence", display: `${Math.round(profile.baseline_confidence * 100)}%` },
    { name: "fallback_level", display: formatFallbackLevel(profile.fallback_level) },
    ...whyItems
  ];

  const dimensionEmptyLabels: Record<string, string> = {
    who: "尚无用户身份与角色数据",
    when: "尚无活跃时间分布数据",
    where: "尚无登录源 IP / 地理位置记录",
    what: "尚无资源访问与行为体量数据",
    why: "尚无业务上下文数据",
    how: "尚无接入设备与认证方式数据"
  };

  const dimensions: Array<{ key: string; title: string; subtitle: string; icon: typeof Activity; items: ProfileFeature[] }> = [
    { key: "who", title: "Who", subtitle: "用户、角色、部门、账号类型", icon: UserRound, items: whoWithMeta },
    { key: "when", title: "When", subtitle: "活跃时段与星期分布", icon: Clock3, items: flattenProfileFeatures(profile.time_profile) },
    { key: "where", title: "Where", subtitle: "常见 IP 与地理位置", icon: RadioTower, items: flattenProfileFeatures(profile.location_profile) },
    {
      key: "what",
      title: "What",
      subtitle: "资源、动作、体量与结果",
      icon: ListFilter,
      items: [...whatFromAccess, ...flattenProfileFeatures(profile.volume_profile), ...flattenProfileFeatures(profile.result_profile)]
    },
    { key: "why", title: "Why", subtitle: "业务上下文与资源用途", icon: Sparkles, items: whyWithMeta },
    { key: "how", title: "How", subtitle: "设备、User-Agent 与认证方式", icon: Server, items: howFromAccess }
  ];

  return (
    <div className="w1h-grid">
      {dimensions.map(({ key, title, subtitle, icon: Icon, items }) => (
        <section key={key} className="w1h-card">
          <header className="w1h-card-head">
            <Icon aria-hidden="true" />
            <div>
              <h3>{title}</h3>
              <span>{subtitle}</span>
            </div>
          </header>
          {items.length > 0 ? (
            <dl className="w1h-list">
              {items.map((item) => (
                <div key={item.name} className="w1h-row">
                  <dt>{item.name}</dt>
                  <dd>{item.display}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="muted">{dimensionEmptyLabels[key] ?? "暂无数据"}</p>
          )}
        </section>
      ))}
    </div>
  );
}

function flattenProfileFeatures(profile: Record<string, unknown> | undefined | null): ProfileFeature[] {
  if (!profile || typeof profile !== "object") {
    return [];
  }
  return Object.entries(profile)
    .map(([name, value]) => ({ name, display: displayFeatureValue(value) }))
    .filter((feature) => feature.display !== "");
}

function displayFeatureValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (Array.isArray(value)) {
    return value
      .filter((item) => item !== null && item !== undefined && item !== "")
      .map((item) => String(item))
      .join(", ");
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (Array.isArray(record.common_values) && record.common_values.length > 0) {
      return (record.common_values as unknown[]).map((item) => String(item)).join(", ");
    }
    if (typeof record.mean_value === "number") {
      const parts = [`平均 ${roundNumber(record.mean_value)}`];
      if (typeof record.p95_value === "number") {
        parts.push(`p95 ${roundNumber(record.p95_value)}`);
      }
      return parts.join(", ");
    }
    const entries = Object.entries(record).filter(([, item]) => item !== null && item !== undefined && item !== "");
    if (entries.length === 0) {
      return "";
    }
    return entries
      .map(([entryKey, item]) => `${entryKey}: ${Array.isArray(item) ? item.join("/") : String(item)}`)
      .join("; ");
  }
  return String(value);
}

function roundNumber(value: number): number {
  return Math.round(value * 100) / 100;
}

function AIJudgementPage() {
  const [pendingReviewQuery] = useState({ limit: 100, offset: 0, status: "pending_review" });
  const [pending, setPending] = useState<LoadState<AnomalyEvent[]>>({
    data: null, loading: true, error: null, updatedAt: null
  });
  const [processed, setProcessed] = useState<LoadState<AnomalyEvent[]>>({
    data: null, loading: true, error: null, updatedAt: null
  });
  const [analysisResults, setAnalysisResults] = useState<Map<string, AIJudgement>>(new Map());
  const [analyzingSet, setAnalyzingSet] = useState<Set<string>>(new Set());

  const loadPending = useCallback((signal?: AbortSignal) => {
    setPending((current) => ({ ...current, loading: true, error: null }));
    fetchAlerts(pendingReviewQuery, signal)
      .then((data) => setPending({ data: data.items, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setPending((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
  }, [pendingReviewQuery]);

  const loadProcessed = useCallback((signal?: AbortSignal) => {
    setProcessed((current) => ({ ...current, loading: true, error: null }));
    Promise.all([
      fetchAlerts({ limit: 100, offset: 0, status: "false_positive" }, signal),
      fetchAlerts({ limit: 100, offset: 0, status: "rejected" }, signal),
    ])
      .then(([fp, rej]) => {
        const all = [...fp.items, ...rej.items].sort(
          (a, b) => new Date(b.event_time).getTime() - new Date(a.event_time).getTime()
        );
        setProcessed({ data: all, loading: false, error: null, updatedAt: new Date() });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setProcessed((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    loadPending(controller.signal);
    loadProcessed(controller.signal);
    return () => controller.abort();
  }, [loadPending, loadProcessed]);

  const runAnalysis = (alertId: string) => {
    if (analyzingSet.has(alertId)) return;
    setAnalyzingSet((prev) => new Set(prev).add(alertId));
    analyzeAlert(alertId)
      .then((report) => {
        setAnalysisResults((prev) => new Map(prev).set(alertId, report));
      })
      .catch((error: unknown) => { alert(formatError(error)); })
      .finally(() => {
        setAnalyzingSet((prev) => { const next = new Set(prev); next.delete(alertId); return next; });
      });
  };

  const handleConfirmFalsePositive = (alertId: string) => {
    if (!window.confirm("确认将此项标记为误报？")) return;
    confirmFalsePositive(alertId)
      .then(() => {
        setPending((current) => {
          if (!current.data) return current;
          return { ...current, data: current.data.filter((a) => a.event_id !== alertId) };
        });
        loadProcessed();
      })
      .catch((error: unknown) => { alert(formatError(error)); });
  };

  const handleReject = (alertId: string) => {
    if (!window.confirm("驳回此项误报标记，返回异常列表？")) return;
    rejectFalsePositive(alertId)
      .then(() => {
        setPending((current) => {
          if (!current.data) return current;
          return { ...current, data: current.data.filter((a) => a.event_id !== alertId) };
        });
        loadProcessed();
      })
      .catch((error: unknown) => { alert(formatError(error)); });
  };

  return (
    <section className="page">
      <PageHeader
        kicker="AI 研判"
        title="AI 研判"
        description="审核已标记为待复核的异常事件，通过 AI 辅助分析后确认误报或驳回。"
        action={
          <button className="icon-button primary" type="button" onClick={() => { loadPending(); loadProcessed(); }} disabled={pending.loading}>
            <RefreshCcw aria-hidden="true" className={pending.loading ? "spin" : ""} />
            刷新
          </button>
        }
      />

      {pending.error ? <ErrorBanner message={pending.error} /> : null}
      {processed.error ? <ErrorBanner message={processed.error} /> : null}

      <div className="split-panels">
        {/* Left panel: pending review */}
        <section className="page-panel">
          <div className="section-header">
            <h3>待处理 ({pending.data?.length ?? 0})</h3>
          </div>
          {pending.loading ? <TableSkeleton /> : null}
          <div className="compact-list">
            {pending.data?.map((alert) => {
              const report = analysisResults.get(alert.event_id);
              return (
                <article className="judgement-card" key={alert.event_id}>
                  <div className="profile-card-head">
                    <div>
                      <span className="eyebrow">{alert.event_id}</span>
                      <h2>{alert.attack_type || "未知攻击"}</h2>
                    </div>
                    <span className={`risk-chip ${riskTone(alert.risk_level)}`}>{formatRiskLevel(alert.risk_level)}</span>
                  </div>
                  <div className="tag-list">
                    <span>{alert.user_id || "未知用户"}</span>
                    <span>{alert.src_ip || "未知IP"}</span>
                    <span>分数 {alert.risk_score}</span>
                  </div>
                  <JsonBlock value={{ reason_codes: alert.reason_codes, evidence: alert.evidence }} />
                  {report ? (
                    <div className="ai-result-inline">
                      <p>{report.judgement}</p>
                      <div className="tag-list">
                        <span>{report.model_name}</span>
                        <span>置信度 {report.confidence}</span>
                      </div>
                    </div>
                  ) : null}
                  <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
                    <button className="icon-button primary" type="button" onClick={() => runAnalysis(alert.event_id)} disabled={analyzingSet.has(alert.event_id)}>
                      <Brain aria-hidden="true" className={analyzingSet.has(alert.event_id) ? "spin" : ""} />
                      {analyzingSet.has(alert.event_id) ? "分析中…" : report ? "重新分析" : "AI 分析"}
                    </button>
                    <button className="icon-button" type="button" onClick={() => handleConfirmFalsePositive(alert.event_id)}>
                      <CheckCircle2 aria-hidden="true" />
                      确认误报
                    </button>
                    <button className="icon-button" type="button" onClick={() => handleReject(alert.event_id)}>
                      <XCircle aria-hidden="true" />
                      驳回
                    </button>
                  </div>
                </article>
              );
            })}
            {!pending.loading && pending.data?.length === 0 ? <EmptyState title="暂无待处理异常" detail="请在异常事件页面标记误报后在此审核。" /> : null}
          </div>
        </section>

        {/* Right panel: processed */}
        <section className="page-panel">
          <div className="section-header">
            <h3>已处理 ({processed.data?.length ?? 0})</h3>
          </div>
          {processed.loading ? <TableSkeleton /> : null}
          <div className="compact-list">
            {processed.data?.map((alert) => (
              <article className="judgement-card processed" key={alert.event_id}>
                <div className="profile-card-head">
                  <div>
                    <span className="eyebrow">{alert.event_id}</span>
                    <h2>{alert.attack_type || "未知攻击"}</h2>
                  </div>
                  <span className={`risk-chip ${alert.status === "false_positive" ? "ok" : ""}`}>
                    {alert.status === "false_positive" ? "已确认误报" : "已驳回"}
                  </span>
                </div>
                <div className="tag-list">
                  <span>{alert.user_id || "未知用户"}</span>
                  <span>{alert.src_ip || "未知IP"}</span>
                  <span>分数 {alert.risk_score}</span>
                </div>
              </article>
            ))}
            {!processed.loading && processed.data?.length === 0 ? <EmptyState title="暂无已处理记录" detail="确认误报或驳回后将出现在此处。" /> : null}
          </div>
        </section>
      </div>
    </section>
  );
}

function DailyReportsPage() {
  const [query, setQuery] = useState({ limit: 20, offset: 0 });
  const [date, setDate] = useState(dateInShanghai(-1));
  const [state, setState] = useState<LoadState<{ items: DailyReport[]; total: number }>>({
    data: null,
    loading: true,
    error: null,
    updatedAt: null
  });
  const [createState, setCreateState] = useState<{ loading: boolean; message: string | null; error: string | null }>({
    loading: false,
    message: null,
    error: null
  });

  const load = useCallback((activeQuery = query, signal?: AbortSignal) => {
    setState((current) => ({ ...current, loading: true, error: null }));
    fetchDailyReports(activeQuery, signal)
      .then((data) => setState({ data: { items: data.items, total: data.total }, loading: false, error: null, updatedAt: new Date() }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        setState((current) => ({ ...current, loading: false, error: formatError(error) }));
      });
  }, [query]);

  useEffect(() => {
    const controller = new AbortController();
    load(query, controller.signal);
    return () => controller.abort();
  }, [load, query]);

  const generate = () => {
    if (createState.loading) {
      return;
    }
    setCreateState({ loading: true, message: null, error: null });
    createDailyReport({ date })
      .then((report) => {
        setCreateState({ loading: false, message: `${report.date} 的日报已生成。`, error: null });
        load();
      })
      .catch((error: unknown) => setCreateState({ loading: false, message: null, error: formatError(error) }));
  };

  return (
    <section className="page">
      <PageHeader
        kicker="安全日报"
        title="日报"
        description="基于日志、异常事件和 AI 研判生成每日安全态势报告。"
        action={
          <div className="header-actions">
            <input className="date-input" type="date" value={date} onChange={(event) => setDate(event.target.value)} />
            <button className="icon-button primary" type="button" onClick={generate} disabled={createState.loading}>
              <FileText aria-hidden="true" />
              生成
            </button>
          </div>
        }
      />
      {state.error ? <ErrorBanner message={state.error} /> : null}
      {createState.error ? <ErrorBanner message={createState.error} /> : null}
      {createState.message ? <div className="success-banner">{createState.message}</div> : null}
      <div className="report-grid">
        {state.data?.items.map((report) => (
          <article className="report-card" key={report.report_id}>
            <div className="profile-card-head">
              <div>
                <span className="eyebrow">{report.date}</span>
                <h2>评分 {report.overall_score}</h2>
              </div>
              <StatusPill ok={report.high_risk_count === 0} label={`${report.high_risk_count} 个高风险`} />
            </div>
            <div className="metrics-band compact-metrics">
              <Metric icon={Database} label="日志" value={formatNumber(report.log_count)} hint="security_logs" />
              <Metric icon={AlertCircle} label="异常事件" value={formatNumber(report.alert_count)} hint="anomaly_events" />
              <Metric icon={UserRound} label="风险用户" value={String(report.high_risk_users.length)} hint={report.high_risk_users.slice(0, 2).join(", ") || "无"} />
            </div>
            <p>{report.ai_summary}</p>
            <p className="risk-reason">{report.recommendation}</p>
            <a className="text-button" href={dailyReportMarkdownUrl(report.date)} download>
              下载 Markdown
            </a>
            <JsonBlock value={{ major_risks: report.major_risks, typical_alerts: report.typical_alerts }} />
          </article>
        ))}
        {!state.loading && state.data?.items.length === 0 ? <EmptyState title="暂无日报" detail="ClickHouse 中有源数据后，可以为所选日期生成日报。" /> : null}
      </div>
      <PaginationControls
        limit={query.limit}
        offset={query.offset}
        total={state.data?.total ?? 0}
        onPrevious={() => setQuery((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}
        onNext={() => setQuery((current) => ({ ...current, offset: current.offset + current.limit }))}
      />
    </section>
  );
}

function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>;
}

export default App;
