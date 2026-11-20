"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  ArrowLeftRightIcon,
  CircleCheckIcon,
  Clock3Icon,
  GaugeIcon,
  RotateCcwIcon,
  ShieldAlertIcon,
  TimerResetIcon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { Activity, WatchdogRequest, WatchdogRun } from "@/lib/types";
import { cn } from "@/lib/utils";

const classificationLabel: Record<string, string> = {
  continue: "继续",
  terminate: "终止",
  ask_user: "交给用户",
  provider_error: "供应商错误",
};

const phaseLabel: Record<string, string> = {
  idle: "空闲",
  llm: "模型",
  tool: "工具",
  approval: "等待审批",
  paused: "暂停",
  settling: "收尾",
};

const providerKindLabel: Record<string, string> = {
  quota: "余额或额度不足",
  auth: "鉴权失败",
  rate_limit: "限流",
  server_error: "服务端错误",
  network: "网络连接失败",
  timeout: "请求超时",
  chain_exhausted: "模型配置链耗尽",
};

function firstText(...values: Array<string | undefined>): string {
  for (const value of values) {
    const text = value?.trim();
    if (text) return text;
  }
  return "";
}

function fmtTime(value?: string): string {
  if (!value) return "无";
  const d = new Date(value);
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() <= 1) return "无";
  return d.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function fmtRemaining(deadline: string | undefined, now: number, kind: "decision" | "retry" = "decision"): string {
  if (!deadline) return "";
  const at = new Date(deadline).getTime();
  if (Number.isNaN(at)) return "";
  const left = at - now;
  if (left <= 0) return kind === "retry" ? "可立即重试" : "已到默认处理时间";
  const sec = Math.floor(left / 1000);
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}分${String(s).padStart(2, "0")}秒后${kind === "retry" ? "重试" : "按默认规则处理"}`;
}

function CardShell({
  tone,
  icon,
  title,
  subtitle,
  children,
}: {
  tone: "amber" | "red" | "blue" | "slate" | "violet";
  icon: React.ReactNode;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
}) {
  const tones = {
    amber: "border-amber-400/50 bg-amber-50/40 dark:border-amber-500/30 dark:bg-amber-950/15",
    red: "border-red-400/50 bg-red-50/40 dark:border-red-500/30 dark:bg-red-950/15",
    blue: "border-blue-400/50 bg-blue-50/40 dark:border-blue-500/30 dark:bg-blue-950/15",
    slate: "border-border bg-muted/30",
    violet: "border-violet-400/50 bg-violet-50/40 dark:border-violet-500/30 dark:bg-violet-950/15",
  } as const;
  return (
    <Alert className={cn("my-2 px-3 py-2.5", tones[tone])}>
      {icon}
      <AlertTitle className="flex flex-wrap items-center gap-2 text-sm">{title}</AlertTitle>
      <AlertDescription className="col-start-2 mt-1 text-xs">
        {subtitle && <div className="text-muted-foreground">{subtitle}</div>}
        <div className="mt-2 text-sm">{children}</div>
      </AlertDescription>
    </Alert>
  );
}

function EvidenceList({ evidence }: { evidence?: string[] }) {
  if (!evidence?.length) return null;
  return (
    <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-muted-foreground">
      {evidence.map((item) => (
        <li key={item} className="break-words">
          {item}
        </li>
      ))}
    </ul>
  );
}

// WatchdogCard renders one system-audit record. The card is also the only entry
// point for the user decision and Try again APIs, so the SSE row alone is enough
// to drive the workflow (no separate page state).
export function WatchdogCard({
  activity,
  taskId,
  fetchDetail,
  onOpenIntent,
  onChanged,
}: {
  activity: Activity;
  taskId: string;
  fetchDetail?: (seq: number) => Promise<string>;
  onOpenIntent?: (intentId: string) => void;
  onChanged?: () => void;
}) {
  const kind = activity.kind;
  const meta = activity.metadata?.watchdog;
  const requestId = meta?.request_id;
  const [request, setRequest] = React.useState<WatchdogRequest | null>(null);
  const [run, setRun] = React.useState<WatchdogRun | null>(null);
  const [fetchedDetail, setFetchedDetail] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState<"continue" | "stop" | "retry" | "rerun" | null>(null);
  const [now, setNow] = React.useState(Date.now());

  React.useEffect(() => {
    if (activity.detail || !fetchDetail) return;
    let alive = true;
    fetchDetail(activity.seq)
      .then((text) => {
        if (alive) setFetchedDetail(text);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [activity.detail, activity.seq, fetchDetail]);
  const detail = activity.detail || fetchedDetail;

  const load = React.useCallback(() => {
    if (!requestId) return;
    api
      .watchdogRequests(taskId)
      .then((rows) => {
        setRequest(rows.find((r) => r.id === requestId) ?? null);
        setError("");
      })
      .catch((e) => setError((e as Error).message));
  }, [requestId, taskId]);

  React.useEffect(() => {
    if (!requestId) return;
    load();
  }, [load, requestId]);

  React.useEffect(() => {
    if (!requestId) return;
    if (request && request.status !== "open" && !error) return;
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [error, load, request, requestId]);

  React.useEffect(() => {
    if (request?.status !== "open" || (!request.deadline_at && !request.next_retry_at)) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [request?.deadline_at, request?.next_retry_at, request?.status]);

  const currentRunID = request?.run_id ?? "";
  const currentIntentID = request?.intent_id ? String(request.intent_id) : activity.intent_id;
  React.useEffect(() => {
    if (kind !== "watchdog_ask" || request?.status !== "open") return;
    let alive = true;
    const loadRun = () =>
      api
        .watchdogRuns(taskId)
        .then((runs) => {
          if (!alive) return;
          setRun(
            runs.find(
              (r) =>
                (currentRunID && r.run_id === currentRunID) ||
                (!currentRunID && currentIntentID && String(r.intent_id) === currentIntentID),
            ) ?? null,
          );
        })
        .catch(() => undefined);
    void loadRun();
    const timer = setInterval(loadRun, 5000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [currentIntentID, currentRunID, kind, request?.status, taskId]);

  async function decide(answer: "continue" | "stop") {
    if (!request || busy) return;
    setBusy(answer);
    try {
      const updated = await api.watchdogDecide(request.id, answer, "");
      setRequest(updated);
      toast.success(answer === "continue" ? "已允许进入下一周期" : "已终止该 Worker");
      onChanged?.();
    } catch (e) {
      toast.error((e as Error).message);
      load();
    } finally {
      setBusy(null);
    }
  }

  async function retry() {
    if (!request || busy) return;
    setBusy("retry");
    try {
      const updated = await api.watchdogRetry(request.id);
      setRequest(updated);
      toast.success("已请求立即重试 Watchdog Agent");
      onChanged?.();
    } catch (e) {
      toast.error((e as Error).message);
      load();
    } finally {
      setBusy(null);
    }
  }

  async function rerunBlocked() {
    if (busy) return;
    setBusy("rerun");
    try {
      await api.rerunBlocked(taskId);
      toast.success("已重跑被拦意图");
      onChanged?.();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function rerunIntent() {
    const intentId = activity.intent_id ?? (request?.intent_id ? String(request.intent_id) : "");
    if (!intentId || busy) return;
    setBusy("rerun");
    try {
      await api.rerunIntent(taskId, intentId);
      toast.success(`已重跑意图 #${intentId}`);
      onChanged?.();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  if (kind.startsWith("peer_")) {
    const peer = activity.metadata?.peer;
    const status = peer?.status ?? "";
    const decision = peer?.decision ?? (kind === "peer_arbitration_failed" ? "failed" : "");
    const pair = (
      <>
        {peer?.from_intent_id != null && <Badge variant="outline">#{peer.from_intent_id}</Badge>}
        {peer?.to_intent_id != null && (
          <>
            <span className="text-muted-foreground">→</span>
            <Badge variant="outline">#{peer.to_intent_id}</Badge>
          </>
        )}
      </>
    );
    const peerMeta =
      peer?.from_worker || peer?.to_worker || peer?.cooldown_sec || peer?.upgrade_sec ? (
        <div className="mt-1 grid gap-0.5 text-[10px] text-muted-foreground">
          {(peer?.from_worker || peer?.to_worker) && (
            <span>
              Worker：{peer?.from_worker || "?"} → {peer?.to_worker || "?"}
            </span>
          )}
          {peer?.cooldown_sec ? <span>冷却：{Math.round(peer.cooldown_sec / 60)} 分钟</span> : null}
          {peer?.upgrade_sec ? (
            <span>释放确认超过 {Math.round(peer.upgrade_sec / 60)} 分钟可申请仲裁</span>
          ) : null}
        </div>
      ) : null;
    if (kind === "peer_request") {
      return (
        <CardShell
          tone="blue"
          icon={<ArrowLeftRightIcon className="size-4 text-blue-500" />}
          title={
            <>
              <span>Worker 资源请求</span>
              {pair}
              {peer?.request_type && <Badge variant="outline">{peer.request_type}</Badge>}
              {status && <Badge variant="outline">{status}</Badge>}
            </>
          }
          subtitle={fmtTime(activity.ts)}
        >
          <p className="break-words text-sm">{activity.summary}</p>
          {(peer?.reason || detail) && (
            <p className="mt-1 break-words text-xs text-muted-foreground">{firstText(peer?.reason, detail)}</p>
          )}
          {peer?.request_id && <p className="mt-1 break-all text-[10px] text-muted-foreground">request_id: {peer.request_id}</p>}
          {peerMeta}
        </CardShell>
      );
    }
    if (kind === "peer_answer") {
      const answer = peer?.answer || status;
      const rejected = answer === "rejected";
      return (
        <CardShell
          tone={rejected ? "red" : "blue"}
          icon={rejected ? <XCircleIcon className="size-4 text-red-500" /> : <CircleCheckIcon className="size-4 text-blue-500" />}
          title={
            <>
              <span>Worker 资源应答</span>
              {pair}
              {answer && <Badge variant="outline">{answer}</Badge>}
            </>
          }
          subtitle={fmtTime(activity.ts)}
        >
          <p className="break-words text-sm">{activity.summary}</p>
          {(peer?.reason || detail) && (
            <p className="mt-1 break-words text-xs text-muted-foreground">{firstText(peer?.reason, detail)}</p>
          )}
          {peerMeta}
        </CardShell>
      );
    }
    if (kind === "peer_arbitration" || kind === "peer_arbitration_failed") {
      const tone = decision === "terminate" || decision === "failed" ? "red" : decision === "release" ? "amber" : "blue";
      return (
        <CardShell
          tone={tone}
          icon={<ShieldAlertIcon className="size-4 text-muted-foreground" />}
          title={
            <>
              <span>{kind === "peer_arbitration_failed" ? "Watchdog 资源仲裁失败" : "Watchdog 资源仲裁"}</span>
              {pair}
              {decision && <Badge variant="outline">{decision}</Badge>}
            </>
          }
          subtitle={fmtTime(activity.ts)}
        >
          <p className="break-words text-sm">{activity.summary}</p>
          {(peer?.reason || detail) && (
            <p className="mt-1 break-words text-xs text-muted-foreground">{firstText(peer?.reason, detail)}</p>
          )}
          {peer?.request_id && <p className="mt-1 break-all text-[10px] text-muted-foreground">request_id: {peer.request_id}</p>}
          {peerMeta}
        </CardShell>
      );
    }
    return (
      <CardShell
        tone="slate"
        icon={<TimerResetIcon className="size-4 text-muted-foreground" />}
        title={
          <>
            <span>{kind === "peer_request_expired" ? "资源请求已过期" : "请求状态变更"}</span>
            {pair}
            {status && <Badge variant="outline">{status}</Badge>}
          </>
        }
        subtitle={fmtTime(activity.ts)}
      >
        <p className="break-words text-sm">{activity.summary}</p>
        {(peer?.reason || detail) && (
          <p className="mt-1 break-words text-xs text-muted-foreground">{firstText(peer?.reason, detail)}</p>
        )}
        {peerMeta}
      </CardShell>
    );
  }

  if (kind === "watchdog_pressure") {
    return (
      <CardShell
        tone="amber"
        icon={<GaugeIcon className="size-4 text-amber-500" />}
        title="Watchdog 压力提示"
        subtitle={fmtTime(activity.ts)}
      >
        <p className="break-words text-sm">{activity.summary}</p>
        {detail && <p className="mt-1 break-words text-xs text-muted-foreground">{detail}</p>}
      </CardShell>
    );
  }

  if (kind === "watchdog_cycle") {
    return (
      <CardShell
        tone="blue"
        icon={<TimerResetIcon className="size-4 text-blue-500" />}
        title={activity.summary || "周期推进"}
        subtitle={fmtTime(activity.ts)}
      >
        {detail && <p className="break-words text-xs text-muted-foreground">{detail}</p>}
      </CardShell>
    );
  }

  if (kind === "watchdog_report") {
    const classification = meta?.classification ?? "";
    return (
      <CardShell
        tone={classification === "terminate" ? "red" : "slate"}
        icon={<ShieldAlertIcon className="size-4 text-muted-foreground" />}
        title={
          <>
            <span>慢速判断</span>
            {classification && <Badge variant="outline">{classificationLabel[classification] ?? classification}</Badge>}
            {typeof meta?.cycle_no === "number" && <Badge variant="outline">C{meta.cycle_no}</Badge>}
          </>
        }
        subtitle={fmtTime(activity.ts)}
      >
        <p className="break-words text-sm">{activity.summary}</p>
        {detail && <p className="mt-1 break-words text-xs text-muted-foreground">{detail}</p>}
        <EvidenceList evidence={meta?.evidence} />
      </CardShell>
    );
  }

  if (kind === "watchdog_run_finished") {
    return (
      <CardShell
        tone="slate"
        icon={<TimerResetIcon className="size-4 text-muted-foreground" />}
        title={
          <>
            <span>运行已结束</span>
            {meta?.state && <Badge variant="outline">{meta.state === "abandoned" ? "已放弃" : "已结束"}</Badge>}
            {typeof meta?.cycle_no === "number" && <Badge variant="outline">C{meta.cycle_no}</Badge>}
          </>
        }
        subtitle={fmtTime(activity.ts)}
      >
        <p className="break-words text-sm">{activity.summary}</p>
        {detail && <p className="mt-1 break-words text-xs text-muted-foreground">{detail}</p>}
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>事实 {meta?.facts ?? 0}</span>
          <span>资产 {meta?.assets ?? 0}</span>
          <span>漏洞 {meta?.findings ?? 0}</span>
        </div>
      </CardShell>
    );
  }

  if (kind === "watchdog_decision") {
    return (
      <CardShell
        tone="blue"
        icon={<CircleCheckIcon className="size-4 text-blue-500" />}
        title="用户判断已记录"
        subtitle={fmtTime(activity.ts)}
      >
        <p className="break-words text-sm">{activity.summary}</p>
        {detail && <p className="mt-1 break-words text-xs text-muted-foreground">{detail}</p>}
      </CardShell>
    );
  }

  if (kind === "watchdog_terminated") {
    const state = meta?.state ?? "";
    return (
      <CardShell
        tone="red"
        icon={<XCircleIcon className="size-4 text-red-500" />}
        title={
          <>
            <span>Watchdog 终止了 Worker</span>
            <Badge variant="outline">{state === "exhausted" ? "预算耗尽" : "已停止"}</Badge>
            {typeof meta?.cycle_no === "number" && <Badge variant="outline">C{meta.cycle_no}</Badge>}
            {activity.intent_id && <Badge variant="outline">#{activity.intent_id}</Badge>}
          </>
        }
        subtitle={fmtTime(activity.ts)}
      >
        <p className="break-words text-sm">{firstText(meta?.reason, detail, activity.summary)}</p>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>最后一次有效写入：{fmtTime(meta?.last_output_at)}</span>
          <span>阶段：{phaseLabel[meta?.phase ?? ""] ?? (firstText(meta?.phase) || "未知")}</span>
          <span>事实 {meta?.facts ?? 0}</span>
          <span>资产 {meta?.assets ?? 0}</span>
          <span>漏洞 {meta?.findings ?? 0}</span>
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          {activity.intent_id && onOpenIntent && (
            <Button size="sm" variant="outline" onClick={() => onOpenIntent(String(activity.intent_id))}>
              查看意图
            </Button>
          )}
          {activity.intent_id && (
            <Button size="sm" variant="outline" onClick={() => void rerunIntent()} disabled={busy !== null}>
              <RotateCcwIcon className={cn("size-3.5", busy === "rerun" && "animate-spin")} />
              重跑意图
            </Button>
          )}
        </div>
      </CardShell>
    );
  }

  if (kind === "provider_error") {
    const providerKind = meta?.provider_kind ?? "";
    return (
      <CardShell
        tone="red"
        icon={<AlertTriangleIcon className="size-4 text-red-500" />}
        title={
          <>
            <span>供应商错误</span>
            {providerKind && <Badge variant="outline">{providerKindLabel[providerKind] ?? providerKind}</Badge>}
          </>
        }
        subtitle={fmtTime(activity.ts)}
      >
        <p className="break-words text-sm">{activity.summary}</p>
        <p className="mt-1 break-words text-xs text-muted-foreground">
          任务模型链会按配置切换备用模型；修复配置后可在总览重跑被拦意图。
        </p>
        <div className="mt-2 flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onClick={() => void rerunBlocked()} disabled={busy !== null}>
            <RotateCcwIcon className={cn("size-3.5", busy === "rerun" && "animate-spin")} />
            重跑被拦意图
          </Button>
        </div>
      </CardShell>
    );
  }

  if (kind === "watchdog_unavailable") {
    // 不可用卡片只展示任务级队列状态，不展示 worker、intent、当前工具、心跳、
    // 失败原因或队列内容。系统审计里已有的 watchdog_* / provider_error 历史
    // 仍保留：审计是追加式事实流，不因当前不可用而隐藏或回写。
    const open = request?.status === "open";
    const loading = request === null && !error;
    let action: React.ReactNode = null;
    if (!loading && !error && open) {
      action = (
        <Button size="sm" variant="outline" className="mt-2" onClick={() => void retry()} disabled={busy !== null}>
          <RotateCcwIcon className={cn("size-3.5", busy === "retry" && "animate-spin")} />
          Try again
        </Button>
      );
    } else if (!loading && !error) {
      action = (
        <p className="mt-2 text-xs text-muted-foreground">
          该卡片已关闭{request?.answer_reason ? `：${request.answer_reason}` : "。"}
        </p>
      );
    }
    return (
      <CardShell
        tone="amber"
        icon={<Clock3Icon className="size-4 text-amber-500" />}
        title="Watchdog Agent 不可用"
        subtitle="请检查 Watchdog Agent 配置"
      >
        {error && <p className="text-xs text-red-500">卡片状态读取失败：{error}</p>}
        {loading && <p className="text-xs text-muted-foreground">正在读取卡片状态…</p>}
        <div className="grid gap-1 text-xs text-muted-foreground">
          <span>累积告警：{request?.alert_count ?? meta?.alert_count ?? 0} 次</span>
          <span>最早告警：{fmtTime(request?.first_alert_at)}</span>
          <span>最新告警：{fmtTime(request?.last_alert_at)}</span>
          <span>系统每 {request?.auto_retry_sec ?? 300} 秒自动尝试启动</span>
          {open && request?.next_retry_at && (
            <span>下次尝试：{fmtRemaining(request.next_retry_at, now, "retry")}</span>
          )}
        </div>
        {action}
      </CardShell>
    );
  }

  if (kind === "watchdog_ask") {
    const open = request?.status === "open";
    const loading = request === null && !error;
    const cycle = request?.cycle_no ?? meta?.cycle_no ?? 0;
    const nextCycle = cycle + 1;
    const defaultRule = request?.default_rule ?? (cycle === 0 ? "c0_continue" : "c1_plus_terminate");
    let statusLabel = "已过期";
    if (loading) statusLabel = "加载中";
    else if (open) statusLabel = "等待选择";
    else if (request?.status === "answered") statusLabel = "已选择";
    else if (request?.status === "superseded") statusLabel = "已替代";
    else if (request?.status === "cancelled") statusLabel = "已取消";
    let action: React.ReactNode = null;
    if (!loading && open) {
      action = (
        <div className="mt-2 flex flex-wrap gap-2">
          <Button size="sm" onClick={() => void decide("continue")} disabled={busy !== null}>
            <CircleCheckIcon className="size-3.5" />
            申请额外周期（C{nextCycle}）
          </Button>
          <Button size="sm" variant="outline" onClick={() => void decide("stop")} disabled={busy !== null}>
            <XCircleIcon className="size-3.5" />
            不申请
          </Button>
          {request?.intent_id && onOpenIntent && (
            <Button size="sm" variant="outline" onClick={() => onOpenIntent(String(request.intent_id))}>
              查看意图
            </Button>
          )}
        </div>
      );
    } else if (!loading && request?.answer) {
      action = (
        <p className="mt-2 text-xs text-muted-foreground">
          {request.status === "answered" ? "用户选择" : "默认结果"}：
          {request.answer === "continue" ? "申请额外周期" : "终止"}
          {request.answer_reason ? `（${request.answer_reason}）` : ""}
        </p>
      );
    }
    return (
      <CardShell
        tone={open ? "violet" : "slate"}
        icon={<ShieldAlertIcon className={cn("size-4", open ? "text-violet-500" : "text-muted-foreground")} />}
        title={
          <>
            <span>需要用户判断</span>
            <Badge variant="outline">C{cycle}</Badge>
            <Badge variant="outline">{statusLabel}</Badge>
          </>
        }
        subtitle={fmtTime(activity.ts)}
      >
        {error && <p className="text-xs text-red-500">卡片状态读取失败：{error}</p>}
        {loading && <p className="text-xs text-muted-foreground">正在读取卡片状态…</p>}
        <p className="break-words text-sm">{request?.question || activity.summary}</p>
        <div className="mt-1 grid gap-0.5 text-xs text-muted-foreground">
          {request?.intent_id ? <span>意图 #{request.intent_id}</span> : null}
          {typeof request?.evidence?.phase === "string" && (
            <span>当前阶段：{phaseLabel[String(request.evidence.phase)] ?? String(request.evidence.phase)}</span>
          )}
          {typeof request?.evidence?.tool === "string" && request.evidence.tool && (
            <span>当前工具：{String(request.evidence.tool)}</span>
          )}
          {typeof request?.evidence?.last_output_at === "string" && (
            <span>最后一次有效写入：{fmtTime(String(request.evidence.last_output_at))}</span>
          )}
          {typeof request?.evidence?.slow_path_class === "string" && request.evidence.slow_path_class && (
            <span>
              慢速判断：
              {classificationLabel[String(request.evidence.slow_path_class)] ??
                String(request.evidence.slow_path_class)}
              {typeof request?.evidence?.slow_path_summary === "string" && request.evidence.slow_path_summary
                ? ` · ${String(request.evidence.slow_path_summary)}`
                : ""}
            </span>
          )}
          <span>
            目标周期：C{nextCycle}（同意后进入）
          </span>
          {run?.max_auto_cycles != null && (
            <span>
              自主放行预算：已用 {run.auto_cycles_used ?? 0}/{run.max_auto_cycles}，剩余{" "}
              {run.auto_cycles_remaining ?? 0}
            </span>
          )}
          <span>
            默认规则：
            {defaultRule === "c0_continue" ? "C0 静默默认同意，进入 C1" : "C1 及以后静默，默认终止"}
          </span>
          {open && request?.hard_deadline_at && <span>{fmtRemaining(request.hard_deadline_at, now)}</span>}
          {run && (
            <span>
              实时状态：{phaseLabel[run.phase] ?? run.phase}
              {run.tool ? ` / ${run.tool}` : ""} · 心跳 {fmtTime(run.heartbeat_at)} · 最后事件{" "}
              {fmtTime(run.last_event_at)} · 周期 C{run.cycle_no}
            </span>
          )}
        </div>
        {action}
      </CardShell>
    );
  }

  return null;
}
