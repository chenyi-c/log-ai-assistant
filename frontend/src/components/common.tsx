import type { ReactNode } from "react";
import { Activity, AlertCircle, CheckCircle2, XCircle } from "lucide-react";

import { ApiRequestError } from "../api";
import type { RiskLevel, SourceType, UserBaseline } from "../types";


export function PaginationControls({
  limit,
  offset,
  total,
  onPrevious,
  onNext
}: {
  limit: number;
  offset: number;
  total: number;
  onPrevious: () => void;
  onNext: () => void;
}) {
  return (
    <div className="pagination">
      <button className="icon-button" type="button" disabled={offset <= 0} onClick={onPrevious}>
        上一页
      </button>
      <span>偏移 {offset.toLocaleString()}</span>
      <button className="icon-button" type="button" disabled={offset + limit >= total} onClick={onNext}>
        下一页
      </button>
    </div>
  );
}

export function PageHeader({
  kicker,
  title,
  description,
  action
}: {
  kicker: string;
  title: string;
  description: string;
  action: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">{kicker}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </header>
  );
}

export function ServiceCard({
  name,
  ok,
  description,
  icon: Icon,
  loading
}: {
  name: string;
  ok: boolean;
  description: string;
  icon: typeof Activity;
  loading: boolean;
}) {
  return (
    <article className="service-card">
      <div className="service-icon">
        <Icon aria-hidden="true" />
      </div>
      <div>
        <div className="service-title">
          <h2>{name}</h2>
          <StatusPill ok={ok} label={loading ? "检查中" : ok ? "健康" : "不可用"} />
        </div>
        <p>{description}</p>
      </div>
    </article>
  );
}

export function Metric({
  icon: Icon,
  label,
  value,
  hint
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className="metric">
      <Icon aria-hidden="true" />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{hint}</small>
      </div>
    </div>
  );
}

export function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`pill ${ok ? "ok" : "bad"}`}>
      {ok ? <CheckCircle2 aria-hidden="true" /> : <XCircle aria-hidden="true" />}
      {label}
    </span>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="error-banner" role="alert">
      <AlertCircle aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

export function TableSkeleton() {
  return (
    <div className="table-skeleton" aria-hidden="true">
      {Array.from({ length: 7 }).map((_, index) => (
        <span key={index} />
      ))}
    </div>
  );
}

export function formatError(error: unknown): string {
  if (error instanceof ApiRequestError) {
    return `${error.message} (${error.code})`;
  }
  if (error instanceof Error) {
    if (error instanceof TypeError && error.message.toLowerCase().includes("fetch")) {
      return "FastAPI 请求失败。请确认后端运行在 127.0.0.1:8000，且 Vite /api 代理已启用。";
    }
    return error.message;
  }
  return "请求失败";
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "无";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function formatNumber(value?: number | null): string {
  return typeof value === "number" ? value.toLocaleString() : "0";
}

export function localDateTimeValue(value: Date): string {
  const offset = value.getTimezoneOffset() * 60_000;
  return new Date(value.getTime() - offset).toISOString().slice(0, 16);
}

export function dateInShanghai(dayOffset = 0): string {
  const target = new Date(Date.now() + dayOffset * 86_400_000);
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(target);
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day}`;
}

export function todayInShanghai(): string {
  return dateInShanghai();
}

export function formatSource(value: SourceType): string {
  const labels: Partial<Record<SourceType, string>> = {
    vpn: "VPN",
    oa: "OA",
    api: "API",
    system: "系统",
    file: "文件",
    database: "数据库",
    security_device: "安全设备"
  };
  return labels[value] ?? value;
}

export function formatResult(value: string): string {
  const labels: Record<string, string> = {
    success: "成功", fail: "失败", failed: "失败", denied: "拒绝", error: "错误",
    ok: "正常", allow: "允许", allowed: "允许", blocked: "阻断"
  };
  return labels[value] ?? value;
}

export function formatRiskLevel(value: RiskLevel): string {
  return { low: "低", medium: "中", high: "高", critical: "严重" }[value];
}

export function formatAlertStatus(value: string): string {
  const labels: Record<string, string> = {
    new: "新建", investigating: "调查中", closed: "已关闭", false_positive: "误报", analyzed: "已分析"
  };
  return labels[value] ?? value;
}

export function formatAIStatus(value: string): string {
  const labels: Record<string, string> = {
    not_required: "无需分析", pending: "待分析", analyzed: "已分析", failed: "分析失败"
  };
  return labels[value] ?? value;
}

export function formatReviewStatus(value: string): string {
  const labels: Record<string, string> = { pending: "待审核", accepted: "已接受", rejected: "已拒绝" };
  return labels[value] ?? value;
}

export function formatFallbackLevel(value?: UserBaseline["fallback_level"]): string {
  const labels: Record<NonNullable<UserBaseline["fallback_level"]>, string> = {
    none: "无回退", peer_group: "同组用户", department: "部门", global: "全局"
  };
  return value ? labels[value] : "无回退";
}

export function statusTone(status: string): string {
  const normalized = status.toLowerCase();
  if (["success", "ok", "allow", "allowed"].includes(normalized)) return "good";
  if (["failed", "fail", "denied", "blocked", "error"].includes(normalized)) return "danger";
  return "neutral";
}

export function alertStatusTone(status: string): string {
  const normalized = status.toLowerCase();
  if (normalized === "analyzed" || normalized === "closed") return "good";
  return normalized === "new" ? "danger" : "neutral";
}

export function riskTone(riskLevel: RiskLevel): string {
  if (riskLevel === "critical") return "critical";
  if (riskLevel === "high") return "high";
  if (riskLevel === "medium") return "medium";
  return "low";
}

export function isEmptyRecord(value: Record<string, unknown>): boolean {
  return Object.keys(value).length === 0;
}

export function formatResultRange(offset: number, limit: number, total: number, itemCount: number): string {
  if (itemCount === 0 || total === 0) return "显示 0-0";
  return `显示 ${offset + 1}-${Math.min(offset + limit, total)}`;
}

export function toApiDateTime(value: string): string {
  return value ? new Date(value).toISOString() : "";
}

export function toDatetimeLocalInput(value?: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const offsetMs = date.getTimezoneOffset() * 60 * 1000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}
