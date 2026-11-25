"use client";

import * as React from "react";

import {
  ActivityIcon,
  AlertTriangleIcon,
  CheckCircle2Icon,
  ChevronRightIcon,
  CoinsIcon,
  DatabaseIcon,
  FileSearchIcon,
  FingerprintIcon,
  FlaskConicalIcon,
  GitBranchIcon,
  Link2Icon,
  NetworkIcon,
  RouteIcon,
  ShieldCheckIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { StatusBadge } from "@/components/status-badge";
import { api } from "@/lib/api";
import type {
  EvidenceRef,
  EvidenceResponse,
  InformationNode,
  InformationResponse,
  RouteBudget,
  RouteBudgetUsed,
  TaskRoute,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const TYPE_META: Record<string, { label: string; tone: string; icon: React.ElementType }> = {
  observation: {
    label: "观察",
    tone: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
    icon: FingerprintIcon,
  },
  claim: {
    label: "主张",
    tone: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
    icon: CheckCircle2Icon,
  },
  hypothesis: {
    label: "假设",
    tone: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
    icon: FlaskConicalIcon,
  },
  decision: {
    label: "决策",
    tone: "border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300",
    icon: GitBranchIcon,
  },
  finding_candidate: {
    label: "候选漏洞",
    tone: "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300",
    icon: AlertTriangleIcon,
  },
  finding: {
    label: "确认漏洞",
    tone: "border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300",
    icon: ShieldCheckIcon,
  },
  legacy_unknown: { label: "历史事实", tone: "border-border bg-muted text-muted-foreground", icon: DatabaseIcon },
};

const TYPE_ORDER = ["observation", "claim", "hypothesis", "decision", "finding_candidate", "finding", "legacy_unknown"];

function typeMeta(type: string) {
  return (
    TYPE_META[type] ?? {
      label: type || "事实",
      tone: "border-border bg-muted text-muted-foreground",
      icon: DatabaseIcon,
    }
  );
}

function fmtNumber(value?: number) {
  if (value === undefined || value === null || Number.isNaN(value)) return "—";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return String(value);
}

function fmtDuration(seconds?: number) {
  if (!seconds || seconds <= 0) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
}

function budgetPercent(budget?: RouteBudget, used?: RouteBudgetUsed) {
  if (!budget || !used) return null;
  const parts: number[] = [];
  if (budget.max_tool_calls) parts.push(((used.tool_calls ?? 0) / budget.max_tool_calls) * 100);
  if (budget.max_input_tokens) parts.push(((used.input_tokens ?? 0) / budget.max_input_tokens) * 100);
  if (budget.max_wall_seconds) parts.push(((used.wall_ms ?? 0) / 1000 / budget.max_wall_seconds) * 100);
  if (parts.length === 0) return null;
  return Math.min(100, Math.max(0, Math.max(...parts)));
}

function Chip({ children, mono, className }: { children: React.ReactNode; mono?: boolean; className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn("max-w-full truncate font-normal", mono && "font-mono text-[10px]", className)}
    >
      {children}
    </Badge>
  );
}

function IntelStatCard({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: React.ElementType;
  label: string;
  value: React.ReactNode;
  hint?: string;
}) {
  return (
    <Card className="gap-1.5">
      <CardHeader className="pb-0">
        <CardDescription className="flex items-center gap-1.5">
          <Icon className="size-3.5" /> {label}
        </CardDescription>
        <CardTitle className="text-2xl tabular-nums">{value}</CardTitle>
      </CardHeader>
      {hint ? <CardContent className="text-xs text-muted-foreground">{hint}</CardContent> : null}
    </Card>
  );
}

function EmptyView({ icon: Icon, title, hint }: { icon: React.ElementType; title: string; hint: string }) {
  return (
    <Empty className="min-h-44 border">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Icon className="size-5" />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription className="text-xs">{hint}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  );
}

function RouteCard({ route, selected, onSelect }: { route: TaskRoute; selected: boolean; onSelect: () => void }) {
  const percent = budgetPercent(route.budget, route.budget_used);
  const latest = route.checkpoints.at(-1);
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "group w-full rounded-lg border p-3 text-left transition-colors",
        selected ? "border-primary/50 bg-primary/5" : "hover:bg-muted/50",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Chip mono>route #{route.route_id}</Chip>
        <StatusBadge domain="route" value={route.status} />
        {route.phase ? <Chip>{route.phase}</Chip> : null}
        <ChevronRightIcon className="text-muted-foreground ml-auto size-4 shrink-0 transition-transform group-hover:translate-x-0.5" />
      </div>
      <div className="mt-2 line-clamp-2 text-sm font-medium">
        {route.objective || route.success_condition || "未标注路线目标"}
      </div>
      <div className="text-muted-foreground mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
        <span>{route.intent_count} 个意图</span>
        {route.active_intents > 0 ? (
          <span className="text-emerald-600 dark:text-emerald-400">{route.active_intents} 个运行中</span>
        ) : null}
        {route.findings.length > 0 ? <span>{route.findings.length} 个漏洞</span> : null}
        {route.asset_ids?.length ? <span>{route.asset_ids.length} 个资产</span> : null}
      </div>
      {percent !== null ? (
        <div className="mt-3">
          <div className="text-muted-foreground mb-1 flex justify-between text-[10px]">
            <span>路线预算</span>
            <span>{Math.round(percent)}%</span>
          </div>
          <Progress value={percent} className="h-1.5" />
        </div>
      ) : null}
      {latest ? (
        <div className="text-muted-foreground mt-2 line-clamp-2 text-[11px]">checkpoint：{latest.summary}</div>
      ) : null}
    </button>
  );
}

function RouteDetail({ route }: { route: TaskRoute }) {
  const budget = route.budget;
  const used = route.budget_used;
  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border p-4">
        <div className="flex flex-wrap items-center gap-2">
          <RouteIcon className="text-muted-foreground size-4" />
          <span className="font-mono text-sm">route #{route.route_id}</span>
          <StatusBadge domain="route" value={route.status} />
          {route.route_kind ? <Chip>{route.route_kind}</Chip> : null}
          {route.phase ? <Chip>{route.phase}</Chip> : null}
        </div>
        <div className="mt-3 text-base font-medium">{route.objective || "未标注路线目标"}</div>
        {route.success_condition ? (
          <div className="text-muted-foreground mt-1 text-xs">成功条件：{route.success_condition}</div>
        ) : null}
        {route.expected_evidence?.length ? (
          <div className="mt-3 flex flex-wrap gap-1">
            {route.expected_evidence.map((item) => (
              <Chip key={item}>{item}</Chip>
            ))}
          </div>
        ) : null}
        {budget || used.tool_calls ? (
          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            <BudgetCell label="工具调用" used={used.tool_calls} max={budget?.max_tool_calls} />
            <BudgetCell label="输入 token" used={used.input_tokens} max={budget?.max_input_tokens} />
            <BudgetCell
              label="墙钟"
              used={used.wall_ms ? used.wall_ms / 1000 : undefined}
              max={budget?.max_wall_seconds}
              unit="s"
            />
          </div>
        ) : null}
        {route.asset_ids?.length ? (
          <div className="mt-4 flex flex-wrap items-center gap-1">
            <span className="text-muted-foreground text-xs">关联资产</span>
            {route.asset_ids.map((id) => (
              <Chip key={id} mono>
                #{id}
              </Chip>
            ))}
          </div>
        ) : null}
      </div>

      <div>
        <div className="text-muted-foreground mb-2 flex items-center gap-2 text-xs font-medium">
          <GitBranchIcon className="size-3.5" /> 检查点
        </div>
        {route.checkpoints.length === 0 ? (
          <div className="text-muted-foreground rounded-md border border-dashed p-3 text-xs">
            这条路线还没有 checkpoint。
          </div>
        ) : (
          <div className="relative flex flex-col gap-3 pl-4">
            <span className="bg-border absolute bottom-2 left-1 top-2 w-px" />
            {route.checkpoints.map((cp) => (
              <div key={cp.id} className="relative rounded-lg border bg-card p-3">
                <span className="bg-background border-primary absolute -left-3.5 top-4 size-2.5 rounded-full border" />
                <div className="flex flex-wrap items-center gap-2">
                  <Chip mono>#{cp.id}</Chip>
                  {cp.path_phase ? <Chip>{cp.path_phase}</Chip> : null}
                  {cp.run_id ? (
                    <span className="text-muted-foreground truncate font-mono text-[10px]">{cp.run_id}</span>
                  ) : null}
                  <span className="text-muted-foreground ml-auto text-[10px]">{cp.created_at}</span>
                </div>
                <div className="mt-2 text-sm">{cp.summary}</div>
                {cp.next_actions?.length ? (
                  <div className="mt-2 text-xs">
                    <span className="text-muted-foreground">下一步：</span>
                    {cp.next_actions.join("；")}
                  </div>
                ) : null}
                {cp.evidence_refs?.length ? (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {cp.evidence_refs.slice(0, 8).map((ref) => (
                      <Chip key={ref} mono>
                        {ref}
                      </Chip>
                    ))}
                    {cp.evidence_refs.length > 8 ? <Chip mono>+{cp.evidence_refs.length - 8}</Chip> : null}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <div className="text-muted-foreground mb-2 flex items-center gap-2 text-xs font-medium">
          <ActivityIcon className="size-3.5" /> 意图
        </div>
        <div className="flex flex-col gap-2">
          {route.intents.map((intent) => (
            <div key={intent.id} className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-xs">
              <Chip mono>#{intent.id}</Chip>
              <StatusBadge domain="intent" value={intent.state} dot />
              {intent.phase ? <Chip>{intent.phase}</Chip> : null}
              <span className="min-w-40 flex-1 break-words">{intent.summary}</span>
              <span className="text-muted-foreground">{fmtDuration(intent.worker_seconds)}</span>
              {intent.worker_runs > 1 ? <span className="text-muted-foreground">{intent.worker_runs} runs</span> : null}
            </div>
          ))}
        </div>
      </div>

      {route.findings.length > 0 ? (
        <div>
          <div className="text-muted-foreground mb-2 flex items-center gap-2 text-xs font-medium">
            <ShieldCheckIcon className="size-3.5" /> 路线产出漏洞
          </div>
          <div className="flex flex-col gap-2">
            {route.findings.map((finding) => (
              <div key={finding.id} className="flex flex-col gap-1 rounded-md border px-3 py-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip mono>#{finding.id}</Chip>
                  {finding.severity ? <StatusBadge domain="severity" value={finding.severity} /> : null}
                  {finding.vulnclass ? <Chip>{finding.vulnclass}</Chip> : null}
                  <span className="min-w-40 flex-1 break-words">{finding.summary}</span>
                  {finding.traffic_count ? (
                    <Chip mono>
                      <Link2Icon className="mr-1 inline size-3" />
                      {finding.traffic_count} 条流量
                    </Chip>
                  ) : null}
                  <StatusBadge domain="finding" value={finding.state} />
                </div>
                {finding.evidence_refs?.length ? (
                  <div className="flex flex-wrap gap-1">
                    {finding.evidence_refs.slice(0, 8).map((ref) => (
                      <Chip key={ref} mono>
                        {ref}
                      </Chip>
                    ))}
                    {finding.evidence_refs.length > 8 ? (
                      <Chip mono>+{finding.evidence_refs.length - 8}</Chip>
                    ) : null}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function BudgetCell({ label, used, max, unit }: { label: string; used?: number; max?: number; unit?: string }) {
  const percent = max ? Math.min(100, Math.max(0, ((used ?? 0) / max) * 100)) : 0;
  return (
    <div className="rounded-md bg-muted/50 px-3 py-2">
      <div className="text-muted-foreground flex justify-between text-[10px]">
        <span>{label}</span>
        <span>{max ? `${Math.round(percent)}%` : "不限"}</span>
      </div>
      <div className="mt-1 font-mono text-sm">
        {fmtNumber(used)}
        {unit ?? ""}
        {max ? (
          <span className="text-muted-foreground">
            {" "}
            / {fmtNumber(max)}
            {unit ?? ""}
          </span>
        ) : null}
      </div>
      {max ? <Progress value={percent} className="mt-1.5 h-1" /> : null}
    </div>
  );
}

function InformationRow({ node, open, onToggle }: { node: InformationNode; open: boolean; onToggle: () => void }) {
  const meta = typeMeta(node.fact_type);
  const Icon = meta.icon;
  return (
    <div className={cn("rounded-lg border transition-colors", open && "bg-muted/30")}>
      <button type="button" onClick={onToggle} className="flex w-full items-start gap-3 p-3 text-left">
        <span className={cn("mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-md border", meta.tone)}>
          <Icon className="size-3.5" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-1.5">
            <Badge variant="outline" className={meta.tone}>
              {meta.label}
            </Badge>
            <Chip mono>#{node.id}</Chip>
            {node.confidence ? <Chip>{node.confidence}</Chip> : null}
            {node.state ? <Chip>{node.state}</Chip> : null}
            {node.validation_state ? <Chip>{node.validation_state}</Chip> : null}
            {node.route_id ? <Chip mono>route #{node.route_id}</Chip> : null}
            {node.inherited ? <Chip mono>from task #{node.source_task_id ?? "?"}</Chip> : null}
            {node.expired ? <Chip className="border-orange-500/40 text-orange-700 dark:text-orange-300">已过期</Chip> : null}
            {node.sensitivity && node.sensitivity !== "normal" ? <Chip>{node.sensitivity}</Chip> : null}
          </span>
          <span className="mt-1 block text-sm break-words">{node.summary || "—"}</span>
          {node.severity || node.vulnclass ? (
            <span className="text-muted-foreground mt-1 block text-[11px]">
              {[node.severity, node.vulnclass].filter(Boolean).join(" · ")}
            </span>
          ) : null}
        </span>
        <ChevronRightIcon
          className={cn("text-muted-foreground mt-1 size-4 shrink-0 transition-transform", open && "rotate-90")}
        />
      </button>
      {open ? (
        <div className="border-t px-3 py-3 text-xs">
          {node.detail ? (
            <div className="text-muted-foreground max-h-64 overflow-auto whitespace-pre-wrap break-words">
              {node.detail}
            </div>
          ) : null}
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            {node.intent_id ? (
              <span>
                intent <span className="font-mono">#{node.intent_id}</span>
              </span>
            ) : null}
            {node.run_id ? <span className="truncate font-mono text-[10px]">{node.run_id}</span> : null}
            {node.observed_at ? <span>observed {node.observed_at}</span> : null}
            {node.valid_until ? <span>valid until {node.valid_until}</span> : null}
            {node.finding_id ? (
              <span>
                finding <span className="font-mono">{node.finding_id}</span>
              </span>
            ) : null}
          </div>
          {node.claim_ids?.length ? (
            <div className="mt-2 text-muted-foreground">
              支撑 claim：{node.claim_ids.map((id) => `#${id}`).join("、")}
            </div>
          ) : null}
          {node.hypothesis_ids?.length ? (
            <div className="mt-1 text-muted-foreground">
              关联假设：{node.hypothesis_ids.map((id) => `#${id}`).join("、")}
            </div>
          ) : null}
          {node.alternatives_rejected?.length ? (
            <div className="mt-1 text-muted-foreground">
              已放弃方向：{node.alternatives_rejected.join("；")}
            </div>
          ) : null}
          {node.evidence_refs?.length ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {node.evidence_refs.map((ref) => (
                <Chip key={ref} mono>
                  {ref}
                </Chip>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function EvidenceTable({ evidence }: { evidence: EvidenceResponse | null }) {
  if (!evidence || evidence.refs.length === 0) {
    return (
      <EmptyView
        icon={Link2Icon}
        title="还没有证据引用"
        hint="Claim、Hypothesis、Finding 的 evidence_refs，以及 report_finding 绑定的流量都会出现在这里。"
      />
    );
  }
  return (
    <div className="overflow-hidden rounded-lg border">
      <div className="text-muted-foreground grid grid-cols-[minmax(0,1.2fr)_70px_90px_minmax(0,1fr)] gap-2 border-b bg-muted/40 px-3 py-2 text-[11px] font-medium">
        <span>引用</span>
        <span>类型</span>
        <span>可用性</span>
        <span>来源节点</span>
      </div>
      <div className="divide-y">
        {evidence.refs.map((ref) => (
          <div
            key={ref.ref}
            className="grid grid-cols-[minmax(0,1.2fr)_70px_90px_minmax(0,1fr)] items-center gap-2 px-3 py-2 text-xs"
          >
            <span className="truncate font-mono text-[11px]" title={ref.ref}>
              {ref.ref}
              {ref.evidence_versions?.length ? (
                <span className="text-muted-foreground"> · v{ref.evidence_versions.join(",")}</span>
              ) : null}
            </span>
            <Chip>{ref.kind}</Chip>
            <Availability ref_={ref} />
            <span className="text-muted-foreground truncate">
              {ref.source_kinds?.join("、") || "—"}
              {ref.source_node_ids.length > 0 ? ` · ${ref.source_node_ids.map((id) => `#${id}`).join(" ")}` : ""}
            </span>
          </div>
        ))}
      </div>
      {!evidence.traffic_enabled ? (
        <div className="text-muted-foreground border-t px-3 py-2 text-[11px]">
          流量记录未启用，traffic 引用只会显示为不可用。
        </div>
      ) : null}
    </div>
  );
}

function Availability({ ref_ }: { ref_: EvidenceRef }) {
  if (ref_.available === undefined) return <span className="text-muted-foreground">未校验</span>;
  return ref_.available ? (
    <span className="text-emerald-600 dark:text-emerald-400">可用</span>
  ) : (
    <span className="text-rose-600 dark:text-rose-400">缺失</span>
  );
}

export function IntelligenceTab({ taskId }: { taskId: string }) {
  const [routes, setRoutes] = React.useState<TaskRoute[]>([]);
  const [information, setInformation] = React.useState<InformationResponse | null>(null);
  const [summary, setSummary] = React.useState<InformationResponse | null>(null);
  const [evidence, setEvidence] = React.useState<EvidenceResponse | null>(null);
  const [selectedRouteID, setSelectedRouteID] = React.useState<number | null>(null);
  // Route-tab detail selection and the information-graph route filter are two
  // different states: defaulting the filter to the first route hid every other
  // route (and disabled include_sources, which is skipped when route_id > 0).
  const [infoRouteID, setInfoRouteID] = React.useState<number | null>(null);
  const [typeFilter, setTypeFilter] = React.useState("all");
  const [openNodeID, setOpenNodeID] = React.useState<string | null>(null);
  const [view, setView] = React.useState("routes");
  const [loading, setLoading] = React.useState(true);
  const [informationLoading, setInformationLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [reloadTick, setReloadTick] = React.useState(0);

  // A response from a previous task/filter must never overwrite the current
  // view. currentTaskRef flips during render; infoSeq invalidates older
  // information requests when the route/type filter changes quickly.
  const currentTaskRef = React.useRef(taskId);
  currentTaskRef.current = taskId;
  const infoSeqRef = React.useRef(0);
  const endpointErrors = React.useRef<Record<string, string>>({});
  const syncError = React.useCallback(() => {
    setError(Object.values(endpointErrors.current).join("；"));
  }, []);
  const markError = React.useCallback((key: string, err: unknown) => {
    endpointErrors.current[key] = err instanceof Error ? err.message : "情报数据加载失败";
    syncError();
  }, [syncError]);
  const clearEndpointError = React.useCallback((key: string) => {
    if (!endpointErrors.current[key]) return;
    delete endpointErrors.current[key];
    syncError();
  }, [syncError]);

  // Switching task must not keep the previous task's selected route/filter or
  // stale data; reset before the new load.
  React.useEffect(() => {
    infoSeqRef.current++;
    endpointErrors.current = {};
    setRoutes([]);
    setInformation(null);
    setSummary(null);
    setEvidence(null);
    setSelectedRouteID(null);
    setInfoRouteID(null);
    setOpenNodeID(null);
    setTypeFilter("all");
    setError("");
    setLoading(true);
    setInformationLoading(true);
  }, [taskId]);

  const loadRoutes = React.useCallback(async () => {
    try {
      const r = await api.taskRoutes(taskId);
      if (currentTaskRef.current !== taskId) return;
      setRoutes(r.routes ?? []);
      // Only the route-tab detail selection defaults to the first route.
      setSelectedRouteID((current) => current ?? r.routes?.[0]?.route_id ?? null);
      clearEndpointError("routes");
    } catch (err) {
      if (currentTaskRef.current === taskId) markError("routes", err);
    }
  }, [taskId, markError, clearEndpointError]);

  const loadInformation = React.useCallback(async () => {
    const seq = ++infoSeqRef.current;
    setInformationLoading(true);
    try {
      const i = await api.taskInformation(taskId, {
        type: typeFilter === "all" ? undefined : typeFilter,
        routeId: infoRouteID ?? undefined,
        includeSources: true,
      });
      if (currentTaskRef.current !== taskId || seq !== infoSeqRef.current) return;
      setInformation(i);
      clearEndpointError("information");
    } catch (err) {
      if (currentTaskRef.current === taskId && seq === infoSeqRef.current) {
        markError("information", err);
      }
    } finally {
      if (currentTaskRef.current === taskId && seq === infoSeqRef.current) {
        setInformationLoading(false);
      }
    }
  }, [taskId, typeFilter, infoRouteID, markError, clearEndpointError]);

  const loadEvidence = React.useCallback(async () => {
    try {
      const e = await api.taskEvidence(taskId, { includeSources: true });
      if (currentTaskRef.current !== taskId) return;
      setEvidence(e);
      clearEndpointError("evidence");
    } catch (err) {
      if (currentTaskRef.current === taskId) markError("evidence", err);
    }
  }, [taskId, markError, clearEndpointError]);

  // Top stat cards stay task-wide even when the information list is filtered to
  // one route. limit=1 keeps this cheap: the response still carries exact counts.
  const loadSummary = React.useCallback(async () => {
    try {
      const s = await api.taskInformation(taskId, { includeSources: true, limit: 1 });
      if (currentTaskRef.current !== taskId) return;
      setSummary(s);
      clearEndpointError("summary");
    } catch (err) {
      if (currentTaskRef.current === taskId) markError("summary", err);
    }
  }, [taskId, markError, clearEndpointError]);

  // Base snapshot (routes + evidence + task-wide totals) loads only on task/retry
  // changes; type and route filters never re-fetch these.
  React.useEffect(() => {
    endpointErrors.current = {};
    setError("");
    setLoading(true);
    void Promise.allSettled([loadRoutes(), loadEvidence(), loadSummary()]).finally(() => setLoading(false));
  }, [loadRoutes, loadEvidence, loadSummary, reloadTick]);

  // Information Graph reloads only when its own filters change.
  React.useEffect(() => {
    void loadInformation();
  }, [loadInformation, reloadTick]);

  // Poll only the visible tab.
  React.useEffect(() => {
    const timer = setInterval(() => {
      void loadSummary();
      if (view === "routes") void loadRoutes();
      else if (view === "information") void loadInformation();
      else void loadEvidence();
    }, 10000);
    return () => clearInterval(timer);
  }, [view, loadRoutes, loadInformation, loadEvidence, loadSummary]);

  const selected = routes.find((route) => route.route_id === selectedRouteID) ?? routes[0] ?? null;
  const nodes = information?.nodes ?? [];
  // Top cards always use task-wide totals; the Information card's filter chips
  // use the response's route-scoped counts so labels match the visible list.
  const summaryCounts = (summary ?? information)?.counts ?? {};
  const filterCounts = information?.counts ?? {};
  const filterTotal = information?.total ?? 0;
  const totalEvidence = evidence?.refs.length ?? 0;
  const missingEvidence = evidence?.refs.filter((ref) => ref.available === false).length ?? 0;

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>
            {error}
            <Button variant="outline" size="sm" onClick={() => setReloadTick((v) => v + 1)}>
              重试
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <IntelStatCard
          icon={RouteIcon}
          label="攻击路线"
          value={String(routes.length)}
          hint={`${routes.filter((r) => r.active_intents > 0).length} 条进行中`}
        />
        <IntelStatCard
          icon={CheckCircle2Icon}
          label="Claim"
          value={String(summaryCounts.claim ?? 0)}
          hint={`观察 ${summaryCounts.observation ?? 0} · 假设 ${summaryCounts.hypothesis ?? 0}`}
        />
        <IntelStatCard
          icon={AlertTriangleIcon}
          label="候选 / 确认漏洞"
          value={`${summaryCounts.finding_candidate ?? 0} / ${summaryCounts.finding ?? 0}`}
          hint="Candidate 需人工或 Planner 复核"
        />
        <IntelStatCard
          icon={CoinsIcon}
          label="证据引用"
          value={String(totalEvidence)}
          hint={missingEvidence > 0 ? `${missingEvidence} 条引用不可用` : "原始材料指针可回查"}
        />
      </div>

      <Tabs value={view} onValueChange={setView}>
        <TabsList>
          <TabsTrigger value="routes">路线</TabsTrigger>
          <TabsTrigger value="information">信息图</TabsTrigger>
          <TabsTrigger value="evidence">证据</TabsTrigger>
        </TabsList>

        <TabsContent value="routes" className="mt-3">
          {loading && routes.length === 0 ? (
            <Skeleton className="h-44 w-full" />
          ) : routes.length === 0 ? (
            <EmptyView
              icon={RouteIcon}
              title="还没有路线"
              hint="Planner 派发意图后，系统会按 route_id 聚合意图、checkpoint 和漏洞；旧意图按自身 id 读取为一条历史路线。"
            />
          ) : (
            <div className="grid gap-4 xl:grid-cols-[minmax(280px,0.9fr)_minmax(0,1.6fr)]">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <RouteIcon className="size-4" /> 路线列表
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col gap-2 p-3 pt-0">
                  {routes.map((route) => (
                    <RouteCard
                      key={route.route_id}
                      route={route}
                      selected={route.route_id === selected?.route_id}
                      onSelect={() => setSelectedRouteID(route.route_id)}
                    />
                  ))}
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <NetworkIcon className="size-4" /> 路线详情
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-3 pt-0">
                  <ScrollArea className="max-h-[68vh] pr-3">
                    {selected ? (
                      <RouteDetail route={selected} />
                    ) : (
                      <EmptyView
                        icon={RouteIcon}
                        title="选择一条路线"
                        hint="左侧列表展示当前任务的路线、阶段和最近 checkpoint。"
                      />
                    )}
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        <TabsContent value="information" className="mt-3">
          <Card>
            <CardHeader className="gap-3 pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                <FileSearchIcon className="size-4" /> Information Graph
              </CardTitle>
              <div className="flex flex-nowrap items-center gap-1.5 overflow-x-auto pb-1">
                <span className="text-muted-foreground shrink-0 text-[11px]">路线</span>
                <FilterChip active={infoRouteID === null} onClick={() => setInfoRouteID(null)} label="全部" />
                {routes.map((route) => (
                  <FilterChip
                    key={route.route_id}
                    active={infoRouteID === route.route_id}
                    onClick={() => setInfoRouteID(route.route_id)}
                    label={`route #${route.route_id}`}
                  />
                ))}
              </div>
              <div className="flex flex-wrap gap-1.5">
                <FilterChip
                  active={typeFilter === "all"}
                  onClick={() => setTypeFilter("all")}
                  label={`全部 ${filterTotal}`}
                />
                {TYPE_ORDER.filter((type) => (filterCounts[type] ?? 0) > 0 || typeFilter === type).map((type) => (
                  <FilterChip
                    key={type}
                    active={typeFilter === type}
                    onClick={() => setTypeFilter(type)}
                    label={`${typeMeta(type).label} ${filterCounts[type] ?? 0}`}
                  />
                ))}
              </div>
            </CardHeader>
            <CardContent className="p-3 pt-0">
              {informationLoading && !information ? (
                <div className="flex flex-col gap-2">
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              ) : nodes.length === 0 ? (
                <EmptyView
                  icon={FileSearchIcon}
                  title="这个视图没有节点"
                  hint="Observation、Claim、Hypothesis、Decision 和 Finding Candidate 都以 fact 节点保存；确认漏洞来自 findings 表。"
                />
              ) : (
                <div className="flex flex-col gap-2">
                  {nodes.map((node) => (
                    <InformationRow
                      key={`${node.kind}-${node.id}`}
                      node={node}
                      open={openNodeID === `${node.kind}-${node.id}`}
                      onToggle={() =>
                        setOpenNodeID((current) =>
                          current === `${node.kind}-${node.id}` ? null : `${node.kind}-${node.id}`,
                        )
                      }
                    />
                  ))}
                </div>
              )}
              {information?.truncated ? (
                <div className="text-muted-foreground mt-2 text-[11px]">
                  当前只展示最新一页；可用上方路线与类型筛选缩小范围。
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="evidence" className="mt-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Link2Icon className="size-4" /> Evidence Layer
              </CardTitle>
            </CardHeader>
            <CardContent className="p-3 pt-0">
              {loading && !evidence ? <Skeleton className="h-44 w-full" /> : <EvidenceTable evidence={evidence} />}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function FilterChip({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <Button
      type="button"
      size="sm"
      variant={active ? "secondary" : "outline"}
      className="h-7 shrink-0 px-2 text-[11px]"
      onClick={onClick}
    >
      {label}
    </Button>
  );
}
