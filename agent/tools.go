package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func intentWorkerSeconds(n *db.Node) float64 {
	ms := n.WorkerMS
	if n.State == "running" && n.WorkerStartedAt != nil {
		ms += time.Since(*n.WorkerStartedAt).Milliseconds()
	}
	if ms < 0 {
		ms = 0
	}
	return float64(ms) / 1000
}

// compactIntents distills intents to {id, summary, state, asset_ids, parents,
// yields, worker_seconds, worker_runs} so the planner sees both the direction
// and its cost, plus LINEAGE — parents (upstream facts/intents/findings) and
// yields (facts/findings produced) — without pulling full payloads.
func compactIntents(ns []*db.Node, parentsOf, yieldsOf map[int64][]int64) []map[string]any {
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		route := db.ParseIntentRoute(n)
		m := map[string]any{
			"id": n.ID, "summary": p["summary"], "state": n.State,
			"origin": n.Origin, "priority": n.Priority,
			"worker_seconds": intentWorkerSeconds(n), "worker_runs": n.WorkerRuns,
			"route_id": route.RouteID, "route_kind": route.RouteKind,
			"phase": route.PathPhase, "objective": route.Objective,
			"success_condition":  route.SuccessCondition,
			"checkpoint_fact_id": route.CheckpointFactID,
		}
		if route.ExpectedEvidence != nil {
			m["expected_evidence"] = route.ExpectedEvidence
		}
		if !route.Budget.Empty() {
			m["budget"] = route.Budget
		}
		if route.BudgetUsed != (db.RouteBudgetUsed{}) {
			m["budget_used"] = route.BudgetUsed
		}
		if n.Inherited {
			m["source_task_id"] = n.SourceTaskID
			m["inherited"] = true
		}
		// asset_ids is the structured "which assets this direction covers" signal for
		// dedup; fall back to legacy payload keys (target_ids plural, then target_id
		// single) so intents stored before the rename still surface their anchors.
		if tg, ok := p["asset_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_id"]; ok && tg != nil && tg != "" {
			m["asset_ids"] = []any{tg}
		}
		if ps := parentsOf[n.ID]; len(ps) > 0 {
			m["parents"] = ps // 上游：本意图派生自哪些节点（多个事实可共同产生一个意图）
		}
		ys := yieldsOf[n.ID]
		m["yield_count"] = len(ys)
		if len(ys) > 0 {
			m["yields"] = ys // 下游：本意图产生了哪些事实/发现
		}
		out = append(out, m)
	}
	return out
}

// ToolSet exposes the PG-backed dual graph (asset + exploration) to an LLM agent.
// One ToolSet is created per planner/worker run; per-run signals live here.
type ToolSet struct {
	findingRecorder FindingRecorder
	as              *db.AssetStore   // asset store (optional; nil = asset tools not available)
	cs              *db.CompanyStore // company store (optional)
	ts              *db.ExplorationStore
	worker          string
	taskID          int64 // PG tasks.id; 0 when unknown (tests / orchestrator cross-task reads)
	artifactRoots   []string
	// coverageDisabled mirrors tasks.coverage_enabled=false. Stored inverted so the
	// zero value (all existing ToolSet constructions) means ENABLED — matching the
	// DB default (true). When true: graphOverviewData drops the coverage block, the
	// auto-scope hook (insertAssets) is skipped, and add_task_scope/list_untested_assets
	// are filtered out of the agent's tool list. The scope field stays regardless.
	coverageDisabled bool
	// ownerNode is the exploration node that writes attach to: assets this run
	// touches get anchored to it as lineage/provenance (NOT visibility — the asset
	// graph is global and shared). Worker = its claimed intent; planner = begin root.
	ownerNode int64
	GoalMet   bool
	Reason    string
	writes    WriteCounts
	// killWork, if set, terminates a running work by intent id (engine callback,
	// wired by the planner). nil = the kill_work tool reports unavailable.
	killWork func(intentID int64) error
	// steerWork, if set, queues a mid-run course-correction for the work running an
	// intent id (engine callback, wired by the planner): the worker injects it before
	// its next tool call and re-plans, without being killed. nil = tool unavailable.
	steerWork func(intentID int64, msg string) error
	// retryWork, if set, reopens a blocked intent for its next run (engine callback,
	// wired by the planner). It is intentionally narrower than the UI rerun path:
	// only external failures (blocked) qualify; exhausted/stopped need a human.
	retryWork func(intentID int64) (queued bool, err error)
	// openIntentCap bounds the Planner's open frontier (2 × task worker count).
	// Zero disables the check for non-planner tool sets and tests.
	openIntentCap int
	// peerOps is the engine-side registry for worker-to-worker resource requests.
	// nil = the peer tools report unavailable (non-worker agents, tests).
	peerOps PeerOps
	// enrich, if set, receives async auto-completion triggers (DNS resolve for a
	// domain, HTTP probe for a site). nil = no engine enrichment.
	enrich EnrichTrigger
	// notify, if set, wakes the task's planner after a graph change that should be
	// re-planned promptly (currently: a new hint). nil = no wake (the hint is still
	// stored and read on the next round triggered by other events). debounced.
	notify func()
	// notifyFinding, if set, wakes the task's planner when this run reports a finding,
	// carrying (intentID, summary) so the round can spell out which intent found what.
	// Wired for workers; nil elsewhere → falls back to notify (bare wake).
	notifyFinding func(intentID int64, summary string)
	// resumeTask, if set, revives the task after a graph change that should make a
	// stopped task run again (currently: set_goals adds a goal). It flips a terminal/
	// paused task back to running and (re)starts the engine loops — a plain notify()
	// can't, because the planner's terminal gate swallows wakes. Wired ONLY for the
	// main agent (human steering); nil for the goals decomposer and workers.
	resumeTask func()
	// notifyGoal, if set, wakes the planner AND records ONE "人新增了 N 个目标：…" trigger
	// for a whole set_goals call (batch-aware — one call, one trigger, not one per goal)
	// so the next round spells out the added goals (instead of the planner having to
	// spot new open goals in the overview). Wired ONLY for the main agent; nil for the
	// goals decomposer (round-0 has no running planner to inform) and workers → those
	// fall back to the bare notify.
	notifyGoal func(texts []string)
	// notifyHint, if set, wakes the planner AND records ONE "人新增了 N 条战略提示：…"
	// trigger for a whole add_hint call (batch-aware — one call, one trigger) so the next
	// round is told the round was fired by a new hint and spells the hint out, instead of
	// the planner having to spot it folded into the graph overview. Wired for the main
	// agent + cross-task orchestration; nil elsewhere → falls back to the bare notify.
	notifyHint func(texts []string)
}

// PeerOps is the engine-side registry for worker-to-worker resource requests.
// The agent package only sees this interface so it does not depend on server.
type PeerOps interface {
	CreatePeerRequest(fromIntentID, toIntentID int64, requestType, reason string) (string, error)
	AnswerPeerRequest(receiverIntentID int64, requestID, answer, reason string) error
	CancelPeerRequest(fromIntentID int64, requestID string) error
	ReleasePeerRequest(receiverIntentID int64, requestID string) error
	RequestPeerArbitration(fromIntentID int64, requestID, reason string) error
}

// SetPeerOps wires the per-task peer request registry. Workers set it on each
// run; other agents leave it nil so the tools stay unavailable.
func (t *ToolSet) SetPeerOps(ops PeerOps) { t.peerOps = ops }

// SetNotifyGoal wires the goal-add trigger callback (see ToolSet.notifyGoal). Set only
// by the main-agent chat, so runtime-added goals are announced to the planner by name.
func (t *ToolSet) SetNotifyGoal(fn func([]string)) { t.notifyGoal = fn }

// SetNotifyHint wires the hint-add trigger callback (see ToolSet.notifyHint). Set by
// the main-agent chat and cross-task orchestration, so a runtime-added hint fires a
// planner round announced by name instead of a bare wake.
func (t *ToolSet) SetNotifyHint(fn func([]string)) { t.notifyHint = fn }

// SetResumeTask wires the task-revive callback (see ToolSet.resumeTask). Set only by
// the main-agent chat, so runtime-added goals can pull a finished task back to running.
func (t *ToolSet) SetResumeTask(fn func()) { t.resumeTask = fn }

// SetNotify wires the planner-wake callback (see ToolSet.notify). Set by callers
// that hold the task handle (main-agent chat, cross-task orchestration).
func (t *ToolSet) SetNotify(fn func()) { t.notify = fn }

// SetNotifyFinding wires the finding-wake callback (see ToolSet.notifyFinding).
func (t *ToolSet) SetNotifyFinding(fn func(int64, string)) { t.notifyFinding = fn }

// EnrichTrigger is the enrichment engine seen from the tool layer (see package
// enrich). Kept as an interface here to avoid coupling agent → enrich.
type EnrichTrigger interface {
	ResolveDomain(id int64, host string)
	ProbeSite(id int64, url string)
}

// WriteCounts breaks down what a worker persisted this run, by node kind, so the
// engine can log an accurate "wrote back" summary instead of lumping assets and
// findings under "facts" (record_fact → Facts, insert_assets → Assets,
// report_finding → Findings; each element of a batch counts once).
type WriteCounts struct {
	Facts    int
	Assets   int
	Findings int
}

// Total is every node persisted this run, regardless of kind — the
// "explored but persisted nothing" signal (Total == 0).
func (w WriteCounts) Total() int { return w.Facts + w.Assets + w.Findings }

// String renders the per-kind breakdown for logs, e.g. "事实1 资产25 漏洞0".
func (w WriteCounts) String() string {
	return fmt.Sprintf("事实%d 资产%d 漏洞%d", w.Facts, w.Assets, w.Findings)
}

// Writes reports what this run wrote back, split by node kind (so the engine can
// tell "explored but persisted nothing" apart from a completed intent, and log an
// honest breakdown instead of calling assets/findings "facts").
func (t *ToolSet) Writes() WriteCounts { return t.writes }

func NewToolSet(ts *db.ExplorationStore, worker string) *ToolSet {
	return &ToolSet{ts: ts, worker: worker}
}

// SetTaskID sets the PG task id on this ToolSet so that report_finding can
// dual-write to the standalone findings table (which survives task deletion).
func (t *ToolSet) SetTaskID(id int64) { t.taskID = id }

// SetArtifactRoots configures the working directories allowed to satisfy
// artifact:<path> references in record_fact and report_finding. Empty leaves
// artifact validation structural-only (used by unit tests without disk files).
func (t *ToolSet) SetArtifactRoots(dirs ...string) {
	var clean []string
	for _, d := range dirs {
		if s := strings.TrimSpace(d); s != "" {
			clean = append(clean, s)
		}
	}
	t.artifactRoots = clean
}

// SetCoverageEnabled records whether this task has the asset-coverage feature on
// (default enabled). Passing false makes graphOverviewData omit the coverage block
// and DropCoverageTools filter the two coverage-only tools out of the agent's tool
// list. It does NOT stop scope accumulation: insertAssets' auto-scope hook runs
// either way, because task_scope is the task's range boundary (the filter basis for
// asset queries), not merely a coverage denominator.
func (t *ToolSet) SetCoverageEnabled(enabled bool) { t.coverageDisabled = !enabled }

// CoverageDisabled reports whether the coverage feature is off for this task.
func (t *ToolSet) CoverageDisabled() bool { return t.coverageDisabled }

// coverageOnlyTools are the LLM tools that only make sense when asset coverage is
// on. When the feature is off they are filtered out of the agent's tool list so
// they neither pollute the prompt nor let the model build a disabled denominator.
// add_task_scope is deliberately NOT here: task_scope is the task's range boundary
// (the filter basis for asset queries), not merely a coverage denominator, so the
// agents that own范围定义 keep it either way — in lockstep with insertAssets'
// auto-scope hook, which also runs regardless of the switch.
var coverageOnlyTools = map[string]bool{"list_untested_assets": true}

// DropCoverageTools returns tools with the coverage-only ones removed when this
// task has the feature disabled; otherwise it returns tools unchanged.
func (t *ToolSet) DropCoverageTools(tools []actool.CoreTool) []actool.CoreTool {
	if !t.coverageDisabled {
		return tools
	}
	out := tools[:0:0]
	for _, tool := range tools {
		if coverageOnlyTools[tool.Name()] {
			continue
		}
		out = append(out, tool)
	}
	return out
}

// Cross-task reuse: exported accessors returning the per-task tool logic bound to
// THIS ToolSet's store. Host-side orchestration tools build a ToolSet for an
// arbitrary task, then Call these — so cross-task reads/hint reuse the exact
// same logic as the in-task tools. (readTool ignores ToolContext, so Call(…,nil)
// is safe; add_hint is a writeTool but also doesn't deref the context here.)
func (t *ToolSet) GraphOverviewTool() actool.CoreTool      { return t.graphOverview() }
func (t *ToolSet) ListFindingsTool() actool.CoreTool       { return t.listFindings() }
func (t *ToolSet) GetWorkerTraceTool() actool.CoreTool     { return t.getWorkerTrace() }
func (t *ToolSet) ListWorkerTracesTool() actool.CoreTool   { return t.listWorkerTraces() }
func (t *ToolSet) SearchWorkerTracesTool() actool.CoreTool { return t.searchAllWorkerTraces() }
func (t *ToolSet) NodeDetailTool() actool.CoreTool         { return t.nodeDetail() }
func (t *ToolSet) AddHintTool() actool.CoreTool            { return t.addHint() }

// SetEnrich wires the async enrichment engine (DNS/HTTP auto-completion).
func (t *ToolSet) SetEnrich(e EnrichTrigger) { t.enrich = e }

// SetOwnerNode sets the exploration node that writes anchor to (worker: its
// intent node; planner/main: the begin root). Assets created/referenced while
// ownerNode is set are anchored to it as lineage (not visibility).
func (t *ToolSet) SetOwnerNode(id int64) { t.ownerNode = id }

// anchorOwner records a lineage edge from this run's owner node to an asset
// (no-op if unset). Provenance only — the asset graph is global and shared, so
// this no longer affects which assets a task can read.
func (t *ToolSet) anchorOwner(assetID int64) {
	if t.ts != nil && t.ownerNode > 0 && assetID > 0 {
		_ = t.ts.Anchor(t.ownerNode, assetID)
	}
}

// pid parses an id that may arrive as a JSON number or string ("" / 0 → 0).
func pid(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}
	return 0
}

// pidList parses a list of ids (number|string), dropping zeros/invalids.
func pidList(raw []json.RawMessage) []int64 {
	var out []int64
	for _, r := range raw {
		if v := pid(r); v > 0 {
			out = append(out, v)
		}
	}
	return out
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}
func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func intp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func idp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func readTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func writeTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// readExpTool / writeExpTool build a domain tool whose handler dereferences the
// task-bound ExplorationStore. Two ToolSets carry a nil store: the catalog's
// seed-only shell (never called) and the server-level one behind buildDomainReg,
// which the tools table can bind to ANY agent — including ones that never run
// inside a task (auto/pentest/reporter/自定义 agent/旁路提问). Refusing there
// keeps a mis-bound tool a bad tool call; without the guard it was a nil deref,
// and tool handlers run on the harness's own goroutine, so the panic is out of
// reach of every recover() in the server and kills the whole process.
func (t *ToolSet) readExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return readTool(name, desc, schema, t.needExploration(name, run))
}

func (t *ToolSet) writeExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return writeTool(name, desc, schema, t.needExploration(name, run))
}

// needExploration wraps a handler so it only runs with an exploration store.
// Tools that degrade more usefully than "unavailable" (report_finding points at
// add_task_hint, set_goals/set_constraints at the task itself) keep their own
// bespoke guard instead.
func (t *ToolSet) needExploration(name string, run func(context.Context, json.RawMessage) (actool.Result, error)) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if t.ts == nil {
			return actool.Errorf(name + " 需要任务上下文（探索图）：当前 agent 不在某个任务内运行，取不到任务的探索图，该工具不可用。请在任务内使用它，或改用带 task_id 的跨任务读取工具（get_task_node_detail / list_task_findings / get_task_graph 等）。"), nil
		}
		return run(ctx, in)
	}
}

func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// --- read tools (planner + worker) ---

func (t *ToolSet) graphOverview() actool.CoreTool {
	return t.readExpTool("graph_overview",
		"(探索链路图)探索态势蒸馏摘要：资产计数、无接口的站点、frontier、发现、hints(人类/主 agent 的战略提示，生成意图时须纳入)。规划时先调它。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.graphOverviewData())
		})
}

// graphOverviewData computes the distilled situational snapshot shared by the
// graph_overview tool and the planner's wake-up prompt (which pre-injects it so
// the model needn't spend a turn calling the tool — every plan round starts with
// an empty context and always needs this first).
func (t *ToolSet) graphOverviewData() map[string]any {
	out := map[string]any{}
	// goals summary folded in so the planner needn't call list_goals each round.
	goals, _ := t.ts.ListByKind(db.KindGoal, 100)
	gsum := make([]map[string]any, 0, len(goals))
	for _, g := range goals {
		var p map[string]any
		_ = json.Unmarshal(g.Payload, &p)
		gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
	}
	out["goals"] = gsum
	// hints: 人类/主 agent 通过 add_hint 挂上图的战略提示；folded in so the
	// planner reads them every round when generating intents (否则只写不读).
	hints, _ := t.ts.ListByKind(db.KindHint, 50)
	hsum := make([]map[string]any, 0, len(hints))
	for _, h := range hints {
		var p map[string]any
		_ = json.Unmarshal(h.Payload, &p)
		hint := map[string]any{"id": h.ID, "state": h.State, "text": p["text"]}
		if findingTrafficBindingEnabled() && p["traffic_refs"] != nil {
			hint["traffic_refs"] = p["traffic_refs"]
		}
		hsum = append(hsum, hint)
	}
	out["hints"] = hsum
	// lineage from the exploration edges: an intent's parents (what it
	// derived_from — possibly several facts combined) and its yields (the
	// facts/findings it produced). factFrom maps a fact → the intent that
	// produced it. This is the relationship layer the flat lists lacked.
	// Checkpoints are yielded facts too, but they are route bookkeeping. Load the
	// full id set so yield_count and the wake-up triggers only count real
	// exploration output (not just the recent 1000-fact window).
	factNodes, _ := t.ts.ListByKind(db.KindFact, 1000) // newest first
	checkpointIDs, _ := t.ts.CheckpointFactIDs()
	edges, _ := t.ts.Edges(5000)
	parentsOf := map[int64][]int64{}
	yieldsOf := map[int64][]int64{}
	factFrom := map[int64]int64{}
	for _, e := range edges {
		switch e.Rel {
		case db.RelDerivedFrom, db.RelSpawns: // upstream: derived_from (fact/finding/intent→intent) or spawns (origin fact→goal, legacy begin→intent)
			parentsOf[e.To] = append(parentsOf[e.To], e.From)
		case db.RelYields: // intent --yields--> fact/finding
			if checkpointIDs[e.To] {
				continue
			}
			yieldsOf[e.From] = append(yieldsOf[e.From], e.To)
			factFrom[e.To] = e.From
		}
	}
	// cold-digest §6: members folded into an active digest are shown via cold_digests
	// (below), not the flat recent_* lists. `covered` maps member id → its digest id.
	// §6 render-time revival check: a covered member that has become hot again (a new
	// intent derived from it) must reappear this round — so `hidden` folds a member out
	// only when it is covered AND still cold.
	covered, _ := t.ts.CoveredMembers()
	// Render-time hot set (ancestor of a live intent / fact under a live intent).
	// §6 revival check: a covered member that revived (now hot) must NOT stay folded
	// — hidden() only folds a member out when it is covered AND still cold. Computed
	// every round (cheap for real graph sizes); nil map degrades safely.
	var hotAtRender map[int64]bool
	if cg, _, err := loadColdGraph(t.ts); err == nil {
		hotAtRender = cg.hotSet()
	}
	hidden := func(id int64) bool { _, c := covered[id]; return c && !hotAtRender[id] }
	const openIntentsCap = 30
	fr, _ := t.ts.Frontier(openIntentsCap) // priority DESC, id ASC —— 优先级最高的前 N 条；真实总数见 frontier_open
	out["open_intents"] = compactIntents(fr, parentsOf, yieldsOf)
	all, _ := t.ts.ListByKind(db.KindIntent, 300)
	var running, recentDone []*db.Node
	for _, n := range all {
		switch n.State {
		case "running":
			running = append(running, n)
		case "done", "blocked", "exhausted", "stopped":
			if hidden(n.ID) {
				continue // in a cold_digest and still cold — shown via cold_digests (§6.2)
			}
			recentDone = append(recentDone, n) // 最新在前（all 按 id 降序）；折叠的已剔除，输出时截最新 N
		}
	}
	out["running_intents"] = compactIntents(running, parentsOf, yieldsOf)
	// done_intents_total：已结束意图（done/blocked/exhausted/stopped）总数，与
	// recent_done_intents 平行命名——后者只是它的最新窗口截断视图。stopped 包含
	// Planner 取消和人工终止，后续轮次必须能看到并据此去重。
	if dt, err := t.ts.CountFinishedIntents(); err == nil {
		out["done_intents_total"] = dt
	}
	// frontier_open：开放意图真实总数（open_intents 只是其中优先级最高的前 N 条截断视图）。
	frontierOpen := len(fr)
	if fo, err := t.ts.CountOpenIntents(); err == nil {
		frontierOpen = fo
	}
	out["frontier_open"] = frontierOpen
	if t.openIntentCap > 0 {
		remaining := t.openIntentCap - frontierOpen
		if remaining < 0 {
			remaining = 0
		}
		out["open_intent_cap"] = t.openIntentCap
		out["open_intent_remaining"] = remaining
		out["cap_reached"] = frontierOpen >= t.openIntentCap
	}
	// findings (confirmed vulns) and facts (worker exploration results) are
	// now distinct node kinds. recent_facts surfaces fact summaries (esp.
	// negative results) so the planner sees them in one call; full content
	// via node_detail(id).
	vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
	// Checkpoints are route bookkeeping and origin facts are the task root, not
	// exploration facts: keep both out of the planner's fact count and window
	// (the Route block shows checkpoints; origin is implicit).
	infoFacts := make([]*db.Node, 0, len(factNodes))
	for _, n := range factNodes {
		if n.FactType() == db.FactTypeCheckpoint || n.State == db.StateOrigin {
			continue
		}
		infoFacts = append(infoFacts, n)
	}
	out["findings_total"] = len(vulnNodes) // 确认漏洞总数（目标判定看它）；明细见 finding_list（最新一窗）
	out["facts"] = len(infoFacts)          // 探索事实/结论数（含否定结论，不含 checkpoint）
	// findings 是任务里最高价值的产物 → 概览带最新一窗（≤10 条，vulnNodes 已按 id 降序即最新在前），
	// 让 planner 每轮判目标时一眼看到最近确认的漏洞；全量/更早的用 list_findings 取。
	// 每条只留 {id, summary, from_intent?}：from_intent 是产生本漏洞的意图。
	// evidence/assets/vulnclass/severity/state 等仍可用 list_findings / node_detail(id) 取。
	const findingListCap = 10
	findingList := make([]map[string]any, 0, findingListCap)
	for _, n := range vulnNodes {
		if len(findingList) >= findingListCap {
			break
		}
		var fp map[string]any
		_ = json.Unmarshal(n.Payload, &fp)
		m := map[string]any{"id": n.ID, "summary": fp["summary"]}
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // 本漏洞由哪个意图产生
		}
		findingList = append(findingList, m)
	}
	out["finding_list"] = findingList
	// recent_facts：非折叠事实里最新的一窗（≤N，infoFacts 按 id 降序即最新在前）。已折进
	// digest 且仍冷的（hidden）走 cold_digests，不在此重复。每条 {id, summary, from_intent?,
	// confidence?}；evidence 等详情用 node_detail(id)。更早的用 list_facts 翻。
	const recentFactsCap = 20
	recentFacts := make([]map[string]any, 0, recentFactsCap)
	for _, n := range infoFacts {
		if len(recentFacts) >= recentFactsCap {
			break
		}
		if hidden(n.ID) {
			continue // 已折进 digest 且仍冷 —— 见 cold_digests
		}
		m := compactNode(n)
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // 本事实由哪个意图产生
		}
		// confidence 带进概览：让规划者一眼看出哪条结论只是 inferred（尤其否定结论
		// 别当铁案）；evidence 较长，留给 node_detail(id)。
		var fp map[string]any
		if json.Unmarshal(n.Payload, &fp) == nil {
			if c, ok := fp["confidence"].(string); ok && c != "" {
				m["confidence"] = c
			}
		}
		recentFacts = append(recentFacts, m)
	}
	out["recent_facts"] = recentFacts

	// Route Graph 摘要：当前路线的阶段、目标、预算、最近 checkpoint。这里只放
	// 引用和摘要，完整证据用 node_detail / expand_digest 取。
	type routeAgg struct {
		id         int64
		phase      string
		objective  string
		kind       string
		budget     db.RouteBudget
		used       db.RouteBudgetUsed
		intents    int
		active     int
		assets     []int64
		checkpoint *db.Node
	}
	routeMap := map[int64]*routeAgg{}
	for _, n := range all {
		r := db.ParseIntentRoute(n)
		if r.RouteID <= 0 {
			continue
		}
		agg := routeMap[r.RouteID]
		if agg == nil {
			agg = &routeAgg{id: r.RouteID, kind: r.RouteKind, budget: r.Budget}
			routeMap[r.RouteID] = agg
		}
		agg.intents++
		if n.State == "open" || n.State == "running" || n.State == "paused" {
			agg.active++
		}
		if agg.phase == "" {
			agg.phase = r.PathPhase
		}
		if agg.objective == "" {
			agg.objective = r.Objective
		}
		if agg.budget.Empty() && !r.Budget.Empty() {
			agg.budget = r.Budget
		}
		if agg.used == (db.RouteBudgetUsed{}) && r.BudgetUsed != (db.RouteBudgetUsed{}) {
			agg.used = r.BudgetUsed
		}
		var ip struct {
			AssetIDs []int64 `json:"asset_ids"`
		}
		if json.Unmarshal(n.Payload, &ip) == nil {
			agg.assets = appendUniqueInt64(agg.assets, ip.AssetIDs...)
		}
	}
	const checkpointListCap = 10
	checkpoints := make([]map[string]any, 0, checkpointListCap)
	candidates := make([]map[string]any, 0, 10)
	infoCounts := map[string]int{}
	for _, n := range factNodes {
		ft := n.FactType()
		if ft != db.FactTypeCheckpoint && n.State != db.StateOrigin {
			infoCounts[ft]++
		}
		switch ft {
		case db.FactTypeCheckpoint:
			p := db.ParseFactPayload(n.Payload)
			if agg := routeMap[p.RouteID]; agg != nil && agg.checkpoint == nil {
				agg.checkpoint = n
				if p.BudgetUsed != (db.RouteBudgetUsed{}) {
					agg.used = p.BudgetUsed
				}
			}
			if len(checkpoints) < checkpointListCap {
				checkpoints = append(checkpoints, compactCheckpoint(n, p))
			}
		case db.FactTypeFindingCandidate:
			if len(candidates) < 10 {
				p := db.ParseFactPayload(n.Payload)
				candidates = append(candidates, compactCandidate(n, p))
			}
		}
	}
	routes := make([]map[string]any, 0, len(routeMap))
	for _, agg := range routeMap {
		m := map[string]any{
			"route_id": agg.id, "route_kind": agg.kind, "phase": agg.phase,
			"objective": agg.objective, "intents": agg.intents, "active_intents": agg.active,
			"asset_ids": agg.assets,
		}
		if !agg.budget.Empty() {
			m["budget"] = agg.budget
		}
		if agg.used != (db.RouteBudgetUsed{}) {
			m["budget_used"] = agg.used
		}
		if agg.checkpoint != nil {
			p := db.ParseFactPayload(agg.checkpoint.Payload)
			m["checkpoint"] = compactCheckpoint(agg.checkpoint, p)
		}
		routes = append(routes, m)
	}
	sort.Slice(routes, func(i, j int) bool {
		ai, _ := routes[i]["active_intents"].(int)
		aj, _ := routes[j]["active_intents"].(int)
		if ai != aj {
			return ai > aj
		}
		return routes[i]["route_id"].(int64) > routes[j]["route_id"].(int64)
	})
	if len(routes) > 20 {
		routes = routes[:20]
	}
	out["routes"] = routes
	out["checkpoints"] = checkpoints
	out["finding_candidates"] = candidates
	out["information_counts"] = infoCounts

	// recent_done_intents：非折叠的已结束意图里最新的一窗（≤N，recentDone 已按 id 降序）。
	// 更早的看 done_intents_total 计数 + node_detail(id)。
	const recentDoneCap = 12
	if len(recentDone) > recentDoneCap {
		recentDone = recentDone[:recentDoneCap]
	}
	out["recent_done_intents"] = compactIntents(recentDone, parentsOf, yieldsOf)
	// cold-digest §6.1: 折叠冷区的 digest body，按最新成员时间降序取前 N；被截的更旧 digest
	// 只给裸 id（仍可 expand_digest 展开），避免冷区唯一出口被无限拉长。
	const coldDigestsCap = 15
	if cds, more := coldDigestsRecent(t.ts, coldDigestsCap); len(cds) > 0 {
		out["cold_digests"] = cds // [{id, body, member_count}] —— 直接读 body (§6.1)
		if len(more) > 0 {
			out["cold_digests_more"] = more // 被截断的更旧 digest 的 id；用 expand_digest(id) 展开
		}
	}
	// the original task (root) so the planner always has it, not just the
	// decomposed goals.
	if description, goal, err := t.ts.Root(); err == nil {
		out["task"] = map[string]any{"description": description, "goal": goal}
	}
	// Direct source tasks are a live, read-only blackboard view. Keep their
	// summaries in a separate field so their intents never enter this task's
	// frontier or get mistaken for locally claimable work.
	out["related_tasks"] = t.relatedTaskOverviews()
	// coverage：粗略的资产测试覆盖度参考——范围(task_scope)内的资产里，被 fact 碰过的
	// 占比 + by_type(按类型的 总数/已测)。要看未测的具体资产由 agent 按需调 list_untested_assets 自行判断。仅任务上下文有。
	// 资产覆盖度功能关闭时(coverageDisabled)：只保留 host_count(目标主机数的感知信息)，
	// 丢弃 denominator/tested/pct/by_type/note 等覆盖度度量，避免污染上下文、也不诱导
	// 已隐藏的 add_task_scope/list_untested_assets。
	if t.as != nil && t.ts != nil && t.taskID > 0 {
		{
			m := map[string]any{}
			if !t.coverageDisabled {
				if cov, err := t.as.TaskCoverageWithSources(t.taskID); err == nil {
					m["denominator"] = cov.Denominator
					m["tested"] = cov.Tested
					m["by_type"] = cov.ByType
					m["note"] = "coverage资产测试覆盖度（包括接口等各种相关资产），粗略估计、仅供参考：包含当前任务与直接关联任务的 scope、事实锚点；关联 scope 只读。容器型资产/大量枚举会让它偏低，勿据此认为已测完；可用 add_task_scope 增补本任务范围、list_untested_assets 看未测资产【通常不调用list_untested_assets，按照任务推进即可】；"
					if cov.Denominator == 0 {
						m["pct"] = nil
						m["status"] = "范围未锚定"
					} else {
						m["pct"] = cov.Pct
					}
				}
				if scope := compactTaskScope(t.as, t.taskID); len(scope) > 0 {
					m["scope"] = scope
					m["scope_count"] = len(scope)
				}
			}
			if hosts, err := t.as.HostsByTaskWithSources(t.taskID); err == nil {
				// 只给主机总数，不再把 host 列表平铺进 graph_overview（大范围任务里那是每轮
				// 都重复携带的大量字符串，对规划决策价值有限）；具体主机按需 list_assets 查。
				m["host_count"] = len(hosts)
			}
			if len(m) > 0 {
				out["coverage"] = m
			}
		}
	}
	return out
}

// compactTaskScope renders the task's own scope rows for the coverage block. A
// company reference is expanded into its company_scope rules and keywords so the
// planner sees the authorization boundary without a second tool call; the same
// keyword is also retained in the rule list, matching the company scope view.
func compactTaskScope(as *db.AssetStore, taskID int64) []map[string]any {
	if as == nil || taskID <= 0 {
		return nil
	}
	rows, err := as.ListTaskScope(taskID)
	if err != nil || len(rows) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		entry := map[string]any{"kind": row.Kind, "source": row.Source}
		if row.CompanyID != nil {
			entry["company_id"] = *row.CompanyID
		}
		if row.CompanyName != "" {
			entry["company_name"] = row.CompanyName
		}
		switch {
		case row.Domain != "":
			entry["value"] = row.Domain
		case row.Net != "":
			entry["value"] = row.Net
		case row.Value != "":
			entry["value"] = row.Value
		}
		if row.Reason != "" {
			entry["reason"] = row.Reason
		}
		if row.CompanyID != nil && as.Companies() != nil {
			if rules, err := as.Companies().GetScope(*row.CompanyID); err == nil && len(rules) > 0 {
				companyScope := make([]map[string]any, 0, len(rules))
				var keywords []string
				for _, rule := range rules {
					// Show the human-entered ICP/keyword text; domains and networks
					// use their normalized form. A single IP is stored as /32 or
					// /128 CIDR, but the scope view should read as the address.
					value := rule.Raw
					switch rule.Kind {
					case "domain":
						value = rule.Domain
					case "ip":
						value = strings.TrimSuffix(strings.TrimSuffix(rule.Net, "/128"), "/32")
					case "cidr":
						value = rule.Net
					}
					if value == "" {
						value = rule.Value
					}
					if value == "" {
						value = rule.Raw
					}
					companyScope = append(companyScope, map[string]any{"kind": rule.Kind, "value": value})
					if rule.Kind == "keyword" {
						keywords = append(keywords, value)
					}
				}
				entry["company_scope"] = companyScope
				entry["company_keywords"] = keywords
			}
		}
		out = append(out, entry)
	}
	return out
}

func inheritedMap(m map[string]any, sourceTaskID int64) map[string]any {
	m["source_task_id"] = sourceTaskID
	m["inherited"] = true
	return m
}

const (
	relatedOverviewTotalTextRunes      = 48_000
	relatedOverviewMaxTextPerSource    = 8_000
	relatedOverviewMaxGoalsPerSource   = 8
	relatedOverviewMaxHintsPerSource   = 6
	relatedOverviewMaxFactsPerSource   = 12
	relatedOverviewMaxFindingsPerTask  = 6
	relatedOverviewMaxIntentsPerTask   = 8
	relatedOverviewMaxScopePerSource   = 12
	relatedOverviewMaxDigestsPerSource = 6
)

// overviewTextBudget bounds inherited prompt text while preserving a fair slice
// for every direct source. Full evidence remains available through the on-demand
// read tools, so truncation here does not discard persisted blackboard data.
type overviewTextBudget struct {
	remaining int
	truncated bool
}

func relatedOverviewBudgetForSources(sourceCount int) int {
	if sourceCount <= 0 {
		return 0
	}
	if sourceCount > db.MaxTaskSourceCount {
		sourceCount = db.MaxTaskSourceCount
	}
	perSource := relatedOverviewTotalTextRunes / sourceCount
	if perSource > relatedOverviewMaxTextPerSource {
		perSource = relatedOverviewMaxTextPerSource
	}
	return perSource
}

func (b *overviewTextBudget) take(value any, fieldLimit int) string {
	var text string
	switch value := value.(type) {
	case string:
		text = strings.TrimSpace(value)
	case nil:
		return ""
	default:
		text = strings.TrimSpace(fmt.Sprint(value))
	}
	if text == "" {
		return ""
	}
	if b.remaining <= 0 || fieldLimit <= 0 {
		b.truncated = true
		return ""
	}
	runes := []rune(text)
	limit := fieldLimit
	if limit > b.remaining {
		limit = b.remaining
	}
	if len(runes) > limit {
		b.truncated = true
		if limit == 1 {
			text = "…"
		} else {
			text = string(runes[:limit-1]) + "…"
		}
		runes = []rune(text)
	}
	b.remaining -= len(runes)
	return text
}

func recentTerminalIntents(store *db.ExplorationStore, limit int) []*db.Node {
	if limit <= 0 {
		return []*db.Node{}
	}
	const batch = 300
	cursor := int64(0)
	out := make([]*db.Node, 0, limit)
	for len(out) < limit {
		page, more, err := store.ListByKindPage(db.KindIntent, cursor, batch)
		if err != nil || len(page) == 0 {
			break
		}
		for _, intent := range page {
			switch intent.State {
			case "done", "blocked", "exhausted", "stopped":
				out = append(out, intent)
			}
			if len(out) >= limit {
				break
			}
		}
		if !more {
			break
		}
		cursor = page[len(page)-1].ID
	}
	return out
}

// relatedTaskOverviews distills persistent blackboard state from direct source
// tasks. It intentionally reads each source's local store methods, never its own
// related sources, so inheritance is one level only.
func (t *ToolSet) relatedTaskOverviews() []map[string]any {
	sources, err := t.ts.DirectSourceStores()
	if err != nil {
		return []map[string]any{}
	}
	if len(sources) > db.MaxTaskSourceCount {
		sources = sources[:db.MaxTaskSourceCount]
	}
	perSourceTextBudget := relatedOverviewBudgetForSources(len(sources))
	out := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		ts := source.Store
		// §2 cross-task: render the source task's OWN folded view — fold out the
		// members it has already folded, and surface its cold_digests read-only.
		hidden := hiddenMembersFor(ts)
		budget := overviewTextBudget{remaining: perSourceTextBudget}
		item := map[string]any{
			"source_task_id": source.Task.TaskID,
			"inherited":      true,
			"task": map[string]any{
				"description": budget.take(source.Task.Description, 800),
				"goal":        budget.take(source.Task.Goal, 800),
				"status":      source.Task.Status,
			},
		}
		stats, statsErr := ts.Stats()

		edges, _ := ts.Edges(5000)
		parentsOf := map[int64][]int64{}
		yieldsOf := map[int64][]int64{}
		factFrom := map[int64]int64{}
		for _, edge := range edges {
			switch edge.Rel {
			case db.RelDerivedFrom, db.RelSpawns:
				parentsOf[edge.To] = append(parentsOf[edge.To], edge.From)
			case db.RelYields:
				yieldsOf[edge.From] = append(yieldsOf[edge.From], edge.To)
				factFrom[edge.To] = edge.From
			}
		}

		goals, _ := ts.ListByKind(db.KindGoal, relatedOverviewMaxGoalsPerSource)
		goalSummary := make([]map[string]any, 0, len(goals))
		for _, goal := range goals {
			var payload map[string]any
			_ = json.Unmarshal(goal.Payload, &payload)
			goalSummary = append(goalSummary, inheritedMap(map[string]any{
				"id": goal.ID, "state": goal.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["goals"] = goalSummary

		hints, _ := ts.ListByKind(db.KindHint, relatedOverviewMaxHintsPerSource)
		hintSummary := make([]map[string]any, 0, len(hints))
		for _, hint := range hints {
			var payload map[string]any
			_ = json.Unmarshal(hint.Payload, &payload)
			hintSummary = append(hintSummary, inheritedMap(map[string]any{
				"id": hint.ID, "state": hint.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["hints"] = hintSummary

		facts, _ := ts.ListByKind(db.KindFact, relatedOverviewMaxFactsPerSource)
		findings, _ := ts.ListByKind(db.KindFinding, relatedOverviewMaxFindingsPerTask)
		intentNodes, _ := ts.ListByKind(db.KindIntent, 300)
		terminalIntent := make(map[int64]bool, len(intentNodes))
		for _, intent := range intentNodes {
			terminalIntent[intent.ID] = db.IsTerminalIntentState(intent.State)
		}
		item["facts"] = len(facts)
		item["findings"] = len(findings)
		if statsErr == nil {
			item["facts"] = stats[db.KindFact]
			item["findings"] = stats[db.KindFinding]
			if stats[db.KindGoal] > len(goals) || stats[db.KindHint] > len(hints) ||
				stats[db.KindFact] > len(facts) || stats[db.KindFinding] > len(findings) {
				budget.truncated = true
			}
		}
		recentFindings := make([]map[string]any, 0, len(findings))
		for _, finding := range findings {
			entry := inheritedMap(compactFinding(finding), source.Task.TaskID)
			entry["summary"] = budget.take(entry["summary"], 400)
			recentFindings = append(recentFindings, entry)
		}
		item["recent_findings"] = recentFindings
		recentFacts := make([]map[string]any, 0, len(facts))
		now := time.Now()
		for _, fact := range facts {
			if ok, _ := db.CanInheritFact(fact, now); !ok {
				continue
			}
			if hidden(fact.ID) {
				continue // folded into this source's cold_digests — shown there (§2/§6.2)
			}
			m := inheritedMap(compactNode(fact), source.Task.TaskID)
			m["summary"] = budget.take(m["summary"], 400)
			if from := factFrom[fact.ID]; from > 0 && terminalIntent[from] {
				m["from_intent"] = from
			}
			var payload map[string]any
			if json.Unmarshal(fact.Payload, &payload) == nil {
				if confidence, ok := payload["confidence"].(string); ok && confidence != "" {
					m["confidence"] = confidence
				}
			}
			recentFacts = append(recentFacts, m)
		}
		item["recent_facts"] = recentFacts

		recentDoneRaw := recentTerminalIntents(ts, relatedOverviewMaxIntentsPerTask)
		recentDone := recentDoneRaw[:0] // in-place filter: drop this source's folded intents (§2)
		for _, intent := range recentDoneRaw {
			if hidden(intent.ID) {
				continue
			}
			recentDone = append(recentDone, intent)
		}
		for _, intent := range recentDone {
			intent.Inherited = true
			intent.SourceTaskID = source.Task.TaskID
		}
		intentResults := compactIntents(recentDone, parentsOf, yieldsOf)
		for i, intent := range recentDone {
			intentResults[i]["summary"] = budget.take(intentResults[i]["summary"], 400)
			acts, _, err := ts.ActivityPageForTerminalIntent(intent.ID, 0, 20)
			if err != nil {
				continue
			}
			var resultSummary, textFallback string
			for _, activity := range acts {
				switch activity.Kind {
				case "result":
					resultSummary = activity.Summary
				case "text":
					textFallback = activity.Summary
				}
			}
			if resultSummary == "" {
				resultSummary = textFallback
			}
			if resultSummary != "" {
				intentResults[i]["result_summary"] = budget.take(resultSummary, 800)
			}
		}
		item["recent_intent_results"] = intentResults
		// §2 cross-task: the source task's folded cold region, read-only, newest-member
		// first & capped like the current task's. Members (and overflow digests) are
		// resolvable via expand_digest(id)/node_detail(id), which search source tasks.
		if cds, more := coldDigestsRecent(ts, relatedOverviewMaxDigestsPerSource); len(cds) > 0 {
			for _, cd := range cds {
				cd["inherited"] = true
				cd["source_task_id"] = source.Task.TaskID
			}
			item["cold_digests"] = cds
			if len(more) > 0 {
				item["cold_digests_more"] = more // 被截断的更旧 digest 的 id；expand_digest(id) 展开
			}
		}
		if statsErr == nil {
			item["node_stats"] = stats
		}

		if t.as != nil {
			if scopeRows, err := t.as.ListTaskScope(source.Task.TaskID); err == nil && len(scopeRows) > 0 {
				scopeCount := len(scopeRows)
				if len(scopeRows) > relatedOverviewMaxScopePerSource {
					scopeRows = scopeRows[:relatedOverviewMaxScopePerSource]
					budget.truncated = true
				}
				scope := make([]map[string]any, 0, len(scopeRows))
				for _, row := range scopeRows {
					entry := map[string]any{"kind": row.Kind, "source": budget.take(row.Source, 300)}
					switch {
					case row.Domain != "":
						entry["value"] = budget.take(row.Domain, 400)
					case row.Net != "":
						entry["value"] = budget.take(row.Net, 400)
					case row.Value != "":
						entry["value"] = budget.take(row.Value, 400)
					case row.CompanyID != nil:
						entry["company_id"] = *row.CompanyID
					}
					scope = append(scope, entry)
				}
				item["asset_scope"] = scope
				item["asset_scope_count"] = scopeCount
			}
			if coverage, err := t.as.TaskCoverage(source.Task.TaskID, source.Task.ExplorationID); err == nil {
				item["asset_coverage"] = map[string]any{
					"denominator": coverage.Denominator,
					"tested":      coverage.Tested,
					"pct":         coverage.Pct,
					"by_type":     coverage.ByType,
				}
			}
		}
		if budget.truncated {
			item["summary_truncated"] = true
		}
		out = append(out, item)
	}
	return out
}

// compactNode distills any exploration node to id + summary + state, dropping the
// big detail/evidence (fetch that on demand via node_detail).
func compactNode(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if n.Kind == db.KindFact {
		m["fact_type"] = n.FactType()
	}
	if rid := n.RouteID(); rid > 0 {
		m["route_id"] = rid
	}
	if n.Inherited {
		inheritedMap(m, n.SourceTaskID)
	}
	return m
}

func compactCheckpoint(n *db.Node, p db.FactPayload) map[string]any {
	m := map[string]any{
		"id": n.ID, "fact_type": db.FactTypeCheckpoint,
		"route_id": p.RouteID, "path_phase": p.PathPhase,
		"phase": p.PathPhase, "summary": p.Summary,
		"intent_id": p.IntentID, "run_id": p.CreatedByRun,
		"budget_used": p.BudgetUsed,
	}
	if p.Objective != "" {
		m["objective"] = p.Objective
	}
	if len(p.NextActions) > 0 {
		m["next_actions"] = p.NextActions
	}
	if len(p.AttemptedActions) > 0 {
		m["attempted_actions"] = p.AttemptedActions
	}
	if len(p.EvidenceRefs) > 0 {
		m["evidence_refs"] = p.EvidenceRefs
	}
	if len(p.ConfirmedClaimIDs) > 0 {
		m["confirmed_claim_ids"] = p.ConfirmedClaimIDs
	}
	if len(p.OpenHypothesisIDs) > 0 {
		m["open_hypothesis_ids"] = p.OpenHypothesisIDs
	}
	if len(p.FindingIDs) > 0 {
		m["finding_ids"] = p.FindingIDs
	}
	if p.SettlementReason != "" {
		m["settlement_reason"] = p.SettlementReason
	}
	return m
}

func compactCandidate(n *db.Node, p db.FactPayload) map[string]any {
	m := map[string]any{
		"id": n.ID, "fact_type": db.FactTypeFindingCandidate,
		"route_id": p.RouteID, "summary": p.Summary,
		"validation_state": p.ValidationState,
	}
	if p.Confidence != "" {
		m["confidence"] = p.Confidence
	}
	if len(p.ClaimIDs) > 0 {
		m["claim_ids"] = p.ClaimIDs
	}
	if len(p.EvidenceRefs) > 0 {
		m["evidence_refs"] = p.EvidenceRefs
	}
	return m
}

func appendUniqueInt64(dst []int64, values ...int64) []int64 {
	seen := make(map[int64]bool, len(dst)+len(values))
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range values {
		if v > 0 && !seen[v] {
			seen[v] = true
			dst = append(dst, v)
		}
	}
	return dst
}

// compactFinding is compactNode plus the vuln-specific vulnclass/severity.
func compactFinding(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if n.Inherited {
		inheritedMap(m, n.SourceTaskID)
	}
	if vc, ok := p["vulnclass"]; ok && vc != nil && vc != "" {
		m["vulnclass"] = vc
	}
	if sv, ok := p["severity"]; ok && sv != nil && sv != "" {
		m["severity"] = sv
	}
	return m
}

func (t *ToolSet) listFindings() actool.CoreTool {
	return t.readExpTool("list_findings", "列本任务及直接关联任务的【确认漏洞】(紧凑：id+task_id+intent_id+vulnclass+severity+摘要+状态)。关联任务条目带 source_task_id/inherited=true 且只读。这里只含漏洞；普通探索事实用 list_facts，详情用 node_detail(id)。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKindWithSources(db.KindFinding, 500)
			if err := t.ts.PopulateFindingTrafficIDs(f); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			intentOf, _ := t.ts.FindingIntentsWithSources() // finding id -> 产生它的 intent id
			taskID := t.taskID
			if taskID <= 0 {
				taskID, _ = t.ts.TaskID()
			}
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				m := compactFinding(n)
				if n.FindingID > 0 {
					m["finding_id"], m["finding_node_id"], m["traffic_count"] = n.FindingID, n.ID, n.TrafficCount
				}
				if n.Inherited {
					m["task_id"] = n.SourceTaskID
				} else {
					m["task_id"] = taskID
				}
				if iid, ok := intentOf[n.ID]; ok {
					m["intent_id"] = iid
				}
				out = append(out, m)
			}
			return jsonResult(out)
		})
}

// factsPageSize is the default page size for list_facts. Facts pile up on long
// tasks; returning all of them at once (the old behaviour) could blow up the
// context, so default to the newest page and let the agent page/filter for more.
const factsPageSize = 20

func (t *ToolSet) listFacts() actool.CoreTool {
	return t.readExpTool("list_facts", "分页列本任务及直接关联任务的【探索事实/结论】，最新在前(紧凑：id+摘要+状态，摘要过长会截断，全文用 node_detail(id))。参数均可选：limit(默认 20，上限 100)、before(游标，传上一页返回的 next_before 取更旧的一页；省略/0=最新一页)、q(按摘要关键词过滤)。返回 {facts, total, has_more, next_before}：total 是过滤后的总数，has_more=true 时用 next_before 继续翻页。关联任务条目带 source_task_id/inherited=true 且只读。漏洞看 list_findings。",
		obj(map[string]any{
			"limit":  intp("返回条数，默认 20，上限 100"),
			"before": intp("分页游标：只返回 id 小于该值的更旧事实；省略或 0 = 最新一页"),
			"q":      str("按事实摘要关键词过滤（不区分大小写）；省略 = 不过滤"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit  int    `json:"limit"`
				Before int64  `json:"before"`
				Q      string `json:"q"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = factsPageSize
			}
			if limit > 100 {
				limit = 100
			}
			f, hasMore, total, err := t.ts.ListByKindPageWithSources(db.KindFact, a.Before, limit, strings.TrimSpace(a.Q))
			if err != nil {
				return actool.Result{}, err
			}
			out := make([]map[string]any, 0, len(f))
			now := time.Now()
			for _, n := range f {
				if n.Inherited && n.Kind == db.KindFact {
					if ok, _ := db.CanInheritFact(n, now); !ok {
						continue
					}
				}
				out = append(out, compactFact(n))
			}
			res := map[string]any{"facts": out, "total": total, "has_more": hasMore}
			if hasMore && len(f) > 0 {
				res["next_before"] = f[len(f)-1].ID // 传回它取下一页(更旧的)
			}
			return jsonResult(res)
		})
}

// factSummaryMax caps a fact summary in list_facts output. Facts carry one-line
// conclusions, but nothing enforces brevity; a runaway summary must not bloat a
// whole page. Full text stays available via node_detail(id).
const factSummaryMax = 160

// compactFact is compactNode with the summary rune-capped for list_facts, so a
// page of facts stays bounded regardless of how long any single summary grew.
func compactFact(n *db.Node) map[string]any {
	m := compactNode(n)
	if s, ok := m["summary"].(string); ok && len([]rune(s)) > factSummaryMax {
		m["summary"] = string([]rune(s)[:factSummaryMax]) + "…"
		m["summary_truncated"] = true
	}
	return m
}

func (t *ToolSet) nodeDetail() actool.CoreTool {
	return t.readExpTool("node_detail", "按 id 取本任务或直接关联任务的【探索图节点】完整内容。继承节点带 source_task_id/inherited=true 且只读。仅限 list_facts/list_findings/graph_overview 返回的探索节点 id；资产请用 list_assets/asset_neighbors。",
		obj(map[string]any{"id": idp("探索图节点 id(非资产 id)")}, "id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.ID)
			if id <= 0 {
				return actool.Errorf("id 必填"), nil
			}
			n, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == nil {
				return actool.Errorf(fmt.Sprintf("未找到探索节点 %d。若你想查的是资产，请用 list_assets / asset_neighbors（资产与探索节点是不同的 id 空间，资产 id 不能传给 node_detail）。", id)), nil
			}
			if n.Inherited && n.Kind == db.KindFact {
				if ok, why := db.CanInheritFact(n, time.Now()); !ok {
					return actool.Errorf(fmt.Sprintf("关联任务节点 #%d 受继承与有效期策略限制，不能跨任务读取（%s）", id, why)), nil
				}
			}
			if err := t.ts.PopulateFindingTrafficIDs([]*db.Node{n}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(n) // full payload incl. detail / evidence, plus explicit finding IDs
		})
}

// --- planner write tools ---

// intentItem 是 add_intent 批量/单条的一条探索方向。
type routeBudgetItem struct {
	MaxToolCalls   int `json:"max_tool_calls"`
	MaxInputTokens int `json:"max_input_tokens"`
	MaxWallSeconds int `json:"max_wall_seconds"`
}

type intentItem struct {
	Summary          string            `json:"summary"`
	AssetIDs         []json.RawMessage `json:"asset_ids"`
	ParentIDs        []json.RawMessage `json:"parent_ids"`
	Priority         int               `json:"priority"`
	ContinuationOf   int64             `json:"continuation_of"`
	RouteKind        string            `json:"route_kind"`
	Objective        string            `json:"objective"`
	Phase            string            `json:"phase"`
	ExpectedEvidence []string          `json:"expected_evidence"`
	SuccessCondition string            `json:"success_condition"`
	Budget           routeBudgetItem   `json:"budget"`
}

// addOneIntent 创建一条意图节点并连上游血缘，返回 id。
// 约束：意图只能锚在已确认知识上——每个 parent_id 必须是已存在的 fact/finding
// 节点（不能挂在别的意图/目标/提示上）。顶层全新方向留空 parent_ids，兜底连 origin fact。
// 这样"每个意图都连到 fact 节点、且是发现驱动而非凭空规划"从创建路径上被强制。
func (t *ToolSet) addOneIntent(it intentItem) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary 不能为空")
	}
	// 先校验锚点（建节点前，避免坏锚点留下孤儿意图）。
	parents := pidList(it.ParentIDs)
	for _, pidv := range parents {
		n, err := t.ts.GetNodeWithSources(pidv)
		if err != nil || n == nil {
			return 0, fmt.Errorf("parent_id %d 不存在于本任务或直接关联任务：parent_ids 必须是已存在的【事实(fact)/发现(finding)】节点 id；顶层全新方向请留空 parent_ids", pidv)
		}
		if n.Kind != db.KindFact && n.Kind != db.KindFinding {
			return 0, fmt.Errorf("parent_id %d 是 %q 节点，不能作为意图锚点：意图只能锚在已确认的【事实(fact)/发现(finding)】上，不能挂在意图/目标/提示上；顶层全新方向请留空 parent_ids", pidv, n.Kind)
		}
	}
	var continuation *db.Node
	if it.ContinuationOf > 0 {
		n, err := t.ts.GetNodeWithSources(it.ContinuationOf)
		if err != nil || n == nil || n.Kind != db.KindIntent {
			return 0, fmt.Errorf("continuation_of %d 不是本任务可用的意图 id", it.ContinuationOf)
		}
		if n.Inherited {
			return 0, fmt.Errorf("continuation_of %d 是关联任务的历史意图，只读，不能接续", it.ContinuationOf)
		}
		if n.State == db.StateIntentDeleted {
			return 0, fmt.Errorf("continuation_of %d 已被删除，不能接续", it.ContinuationOf)
		}
		if !db.IsTerminalIntentState(n.State) {
			return 0, fmt.Errorf("原意图 #%d 当前状态为 %s，仍在执行队列中，不能创建接续；运行中的意图请用 steer_work，外部失败结束后请用 retry_work", n.ID, n.State)
		}
		continuation = n
		routeID := db.ParseIntentRoute(n).RouteID
		if routeID > 0 {
			active, err := t.ts.ActiveIntentForRoute(routeID)
			if err != nil {
				return 0, fmt.Errorf("检查路线活动意图失败：%w", err)
			}
			if active != nil {
				return 0, fmt.Errorf("路线 #%d 已有活动意图 #%d（%s），不能并行接续；先等待/结束该意图，或为不同方向新建路线", routeID, active.ID, active.State)
			}
		}
	}
	priority := it.Priority
	if priority == 0 {
		priority = 5
	}
	anchors := pidList(it.AssetIDs)
	// 资产拦截：意图绑定的资产若命中系统资产拦截规则，则禁止下发该意图。
	if t.as != nil && len(anchors) > 0 {
		hits, err := t.as.CheckAssetsIntercept(t.taskID, anchors)
		if err != nil {
			return 0, fmt.Errorf("资产拦截校验失败：%w", err)
		}
		if len(hits) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "意图「%s」绑定的资产未通过测试范围校验，请停止对相关资产进行测试：", it.Summary)
			for _, h := range hits {
				fmt.Fprintf(&b, "\n - %s", h.Describe())
			}
			return 0, fmt.Errorf("%s", b.String())
		}
	}
	routeKind := strings.TrimSpace(it.RouteKind)
	if routeKind == "" {
		routeKind = "path_stage"
	}
	phase := strings.TrimSpace(it.Phase)
	if phase != "" && !db.IsRoutePhase(phase) {
		return 0, fmt.Errorf("phase 只能是 %s（留空表示尚未标注）", strings.Join(db.RoutePhases, " / "))
	}
	objective := strings.TrimSpace(it.Objective)
	successCondition := strings.TrimSpace(it.SuccessCondition)
	expectedEvidence := trimmedStrings(it.ExpectedEvidence)
	budget := db.RouteBudget{
		MaxToolCalls:   it.Budget.MaxToolCalls,
		MaxInputTokens: it.Budget.MaxInputTokens,
		MaxWallSeconds: it.Budget.MaxWallSeconds,
	}
	if budget.MaxToolCalls < 0 || budget.MaxInputTokens < 0 || budget.MaxWallSeconds < 0 {
		return 0, fmt.Errorf("route budget 不能为负数")
	}
	if budget.MaxToolCalls > 10000 || budget.MaxInputTokens > 10_000_000 || budget.MaxWallSeconds > 30*24*3600 {
		return 0, fmt.Errorf("route budget 超出合理范围")
	}
	if continuation == nil && budget.Empty() {
		// A new route gets a finite default so a run cannot rely solely on the
		// (default-off) Watchdog cycle for cost control. Explicit values win.
		budget = db.DefaultRouteBudget()
	}
	// A continuation inherits the route identity and the remaining cumulative
	// budget. The model cannot choose a different route id here; the source intent
	// is the authority.
	routeID := int64(0)
	checkpointID := int64(0)
	budgetUsed := db.RouteBudgetUsed{}
	routeStartedAt := ""
	if continuation != nil {
		cr := db.ParseIntentRoute(continuation)
		routeID = cr.RouteID
		if routeKind == "path_stage" && cr.RouteKind != "" {
			routeKind = cr.RouteKind
		}
		if objective == "" {
			objective = cr.Objective
		}
		if phase == "" {
			phase = cr.PathPhase
		}
		if len(expectedEvidence) == 0 {
			expectedEvidence = cr.ExpectedEvidence
		}
		if successCondition == "" {
			successCondition = cr.SuccessCondition
		}
		budget = mergeRouteBudget(budget, cr.Budget)
		checkpointID = cr.CheckpointFactID
		budgetUsed = cr.BudgetUsed
		routeStartedAt = cr.RouteStartedAt
		if latest, err := t.ts.LatestCheckpointForRoute(routeID); err != nil {
			return 0, fmt.Errorf("读取路线 checkpoint 失败：%w", err)
		} else if latest != nil {
			cp := db.ParseFactPayload(latest.Payload)
			checkpointID = latest.ID
			budgetUsed = cp.BudgetUsed
			if cp.RouteStartedAt != "" {
				routeStartedAt = cp.RouteStartedAt
			}
		}
		if msg := exhaustedBudgetMessage(routeID, budget, budgetUsed); msg != "" {
			return 0, fmt.Errorf("%s", msg)
		}
	}
	if routeStartedAt == "" {
		routeStartedAt = time.Now().UTC().Format(time.RFC3339)
	}
	payload := map[string]any{
		"summary":          it.Summary,
		"route_kind":       routeKind,
		"route_started_at": routeStartedAt,
	}
	if routeID > 0 {
		payload["route_id"] = routeID
	}
	if objective != "" {
		payload["objective"] = objective
	}
	if phase != "" {
		payload["phase"] = phase
		payload["path_phase"] = phase
	}
	if len(expectedEvidence) > 0 {
		payload["expected_evidence"] = expectedEvidence
	}
	if successCondition != "" {
		payload["success_condition"] = successCondition
	}
	if !budget.Empty() {
		payload["budget"] = budget
	}
	if checkpointID > 0 {
		payload["checkpoint_fact_id"] = checkpointID
	}
	if budgetUsed != (db.RouteBudgetUsed{}) {
		payload["route_budget_used"] = budgetUsed
	}
	if len(anchors) > 0 {
		payload["asset_ids"] = anchors
	}
	if continuation != nil {
		payload["continuation_of"] = continuation.ID
		payload["parent_intent_id"] = continuation.ID
	}
	// Build all lineage edges up front; AddIntentWithEdges commits them with the
	// node, so a failed link can no longer leave an intent without its parents.
	edges := make([]db.NewEdge, 0, len(parents)+1)
	for _, parent := range parents {
		edges = append(edges, db.NewEdge{From: parent, Rel: db.RelDerivedFrom})
	}
	if continuation != nil {
		edges = append(edges, db.NewEdge{From: continuation.ID, Rel: db.RelDerivedFrom})
	}
	if len(parents) == 0 {
		if origin, _ := t.ts.OriginFactID(); origin > 0 {
			edges = append(edges, db.NewEdge{From: origin, Rel: db.RelDerivedFrom})
		}
	}
	id, _, err := t.ts.AddIntentWithEdges(payload, priority, anchors, t.worker, routeID, edges)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// openIntentCapError returns a planner-facing capacity error, or "" when a new
// intent of extra size fits. Write tools run exclusively in the harness, so the
// count here and the insert by the caller form one serialized operation.
func (t *ToolSet) openIntentCapError(extra int) (string, error) {
	if t.worker != "planner" || t.openIntentCap <= 0 {
		return "", nil
	}
	openCount, err := t.ts.CountOpenIntents()
	if err != nil {
		return "", err
	}
	if openCount+extra <= t.openIntentCap {
		return "", nil
	}
	fr, err := t.ts.Frontier(openCount)
	if err != nil {
		return "", err
	}
	var cancelable []string
	for i := len(fr) - 1; i >= 0 && len(cancelable) < 6; i-- {
		if fr[i].Origin == t.worker {
			cancelable = append(cancelable, fmt.Sprintf("#%d(p%d)", fr[i].ID, fr[i].Priority))
		}
	}
	if len(cancelable) == 0 {
		cancelable = append(cancelable, "无可取消的 Planner open 意图（队列由其他来源占用）")
	}
	return fmt.Sprintf("open Intent 上限 %d，当前 %d，本次提交 %d；先取消低优先级方向：%s",
		t.openIntentCap, openCount, extra, strings.Join(cancelable, ", ")), nil
}

func (t *ToolSet) addIntent() actool.CoreTool {
	return t.writeExpTool("add_intent", "生成【探索方向】写入 frontier，并连入探索链路。意图是开放的探索方向，不是固定类型——用 summary 一句话自由描述要探索/验证/利用什么。\n"+
		"★优先批量：一轮筛出的多个新方向放进 intents 数组一次提交（比逐条调用省往返）。返回 ids 数组，与 intents 等长同序（失败项 id=0，详情见 errors）。单条则省略 intents 直接给顶层 summary。",
		obj(map[string]any{
			"intents":           map[string]any{"type": "array", "description": "【优先用这个】要新增的探索方向数组，按顺序处理。每个元素字段同下方顶层字段（summary/asset_ids/parent_ids/priority/continuation_of/objective/phase/expected_evidence/success_condition/budget）。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"summary":           str("[单条] 一句话描述这个探索方向：做什么+为什么。已写清方向即可，不依赖资产 id。"),
			"asset_ids":         map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "本方向要测试/攻击的【目标资产 id】（**尽量传**，0/1/多个；是 list_assets 返回的资产 id，不是探索节点 id）：这条探索方向针对哪些资产（站点/接口/参数/主机等）。只要方向围绕某些具体资产就务必传上——它是「这条探索打哪些目标」的结构化标记，用于覆盖去重、把意图连入资产链路。仅当纯全局侦察、确实没有具体目标资产时才留空。"},
			"parent_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "上游锚点 id（可选，0/1/多个）：本方向由哪些【已确认的事实(fact)/发现(finding)】综合得出。**只能填已存在的 fact/finding 节点 id,不能填意图/目标/提示**——意图必须锚在已确认知识上,发现驱动而非凭空规划。多个事实共同产生一个新意图就传多个;顶层全新侦察方向请留空（会自动挂到任务起点 origin fact）。"},
			"priority":          intp("优先级 0-10，默认5"),
			"continuation_of":   intp("接续的原意图 id（可选）：仅当原意图已经结束（done/blocked/exhausted/stopped）且你要换一种打法时填写。原意图仍 open/running/paused 会被拒绝；外部失败恢复请优先使用 retry_work。接续会自动继承原路线的 route_id、预算余额和最近 checkpoint；若原路线累计预算已耗尽，必须显式传入更大的 budget 才能继续。"),
			"objective":         str("本阶段要达成的路线目标（可选；新路线建议填写）。接续时留空则继承原意图。"),
			"phase":             map[string]any{"type": "string", "enum": db.RoutePhases, "description": "路线阶段（可选）：recon/validation/exploitation/privilege/lateral/objective/verification/evidence/cleanup。接续时留空则继承。"},
			"expected_evidence": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "预期证据（可选）：什么响应/差异才能证明本阶段成功或排除假设。"},
			"success_condition": str("本阶段成功条件（可选）：确认什么或排除什么。"),
			"budget": map[string]any{"type": "object", "description": "路线累计预算（可选；新路线省略时默认 max_tool_calls=240、max_input_tokens=1200000；接续默认继承剩余额度）。当某维度已耗尽再接续时，必须显式传高于已用量的上限，否则会被拒绝。", "properties": map[string]any{
				"max_tool_calls":   intp("整条路线允许的工具调用总数"),
				"max_input_tokens": intp("整条路线允许的输入 token 总数"),
				"max_wall_seconds": intp("整条路线允许的墙钟秒数"),
			}},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Intents    []intentItem `json:"intents"`
				intentItem              // 单条模式：顶层 summary/asset_ids/parent_ids/priority
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Intents) > 0
			items := a.Intents
			if !batch {
				items = []intentItem{a.intentItem}
			}
			msg, err := t.openIntentCapError(len(items))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if msg != "" {
				return actool.Errorf(msg), nil
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			createdAny := false
			for i, it := range items {
				id, err := t.addOneIntent(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				createdAny = true
			}

			// 人经主 agent 直投意图 → 若任务已 done（无 open 目标的 goalless 分支），把它
			// 拉回 running，worker 才能领这条意图执行。resumeTask 仅由主 agent 的 Chat 接入
			// (SetResumeTask)；planner 的 ToolSet 为 nil，故 planner 自己调 add_intent 时此段
			// no-op，不影响其正常产意图。意图节点已在上面建好(open)，复活时不会被误判抽干。
			if createdAny && t.resumeTask != nil {
				t.resumeTask()
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("intent created: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) listGoals() actool.CoreTool {
	return t.readExpTool("list_goals", "列出本任务的目标节点及其状态（open/met），用于判断是否达成。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			g, _ := t.ts.ListByKind(db.KindGoal, 100)
			return jsonResult(g)
		})
}

func (t *ToolSet) proveGoal() actool.CoreTool {
	return t.writeExpTool("prove_goal", "当你判断某个发现/事实证明了某个目标达成时调用：把证据节点连到目标节点，并标记目标 met。",
		obj(map[string]any{
			"goal_id":     idp("目标节点 id"),
			"evidence_id": idp("证明它的发现/事实节点 id"),
			"reason":      str("为什么这个证据满足该目标"),
		}, "goal_id", "evidence_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				GoalID     json.RawMessage `json:"goal_id"`
				EvidenceID json.RawMessage `json:"evidence_id"`
				Reason     string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			goal, ev := pid(a.GoalID), pid(a.EvidenceID)
			if goal == 0 || ev == 0 {
				return actool.Errorf("goal_id 和 evidence_id 必填"), nil
			}
			goalNode, err := t.ts.GetNode(goal)
			if err != nil || goalNode == nil || goalNode.Kind != db.KindGoal {
				return actool.Errorf("goal_id 必须是本任务的目标节点（关联任务目标只读）"), nil
			}
			evidenceNode, err := t.ts.GetNodeWithSources(ev)
			if err != nil || evidenceNode == nil || (evidenceNode.Kind != db.KindFact && evidenceNode.Kind != db.KindFinding) {
				return actool.Errorf("evidence_id 必须是本任务或直接关联任务的事实/漏洞节点"), nil
			}
			_ = t.ts.Link(ev, db.RelProves, goal)
			_ = t.ts.SetNodeState(goal, "met")
			// 每标记一个目标 met，就检查本任务是否【所有目标】都已 met；若是，自动判定
			// 任务完成（置 GoalMet），无需再依赖模型显式调 goal_met。
			if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil && len(goals) > 0 {
				allMet := true
				for _, g := range goals {
					if g.State != "met" {
						allMet = false
						break
					}
				}
				if allMet {
					t.GoalMet = true
					t.Reason = fmt.Sprintf("所有 %d 个目标均已 met（最后由 goal %d 触发）", len(goals), goal)
					return actool.Text(fmt.Sprintf("goal %d marked met；本任务所有目标均已达成，任务自动判定完成", goal)), nil
				}
			}
			return actool.Text(fmt.Sprintf("goal %d marked met", goal)), nil
		})
}

func (t *ToolSet) goalMet() actool.CoreTool {
	return writeTool("goal_met", "【立即结束整个任务】——仅当你确认任务的【全部目标都已真正达成、整体收官】时才调（注意是任务【整体】完成；仅仅达成了其中某一个目标/某一个 flag/某一个漏洞【不算】——那种情况用 prove_goal 标记该目标即可）。⚠️它不是用来“结束本轮规划”的：本轮没有新意图要派、或在等 worker 产出，都【直接结束本轮即可，不要调本工具】（0 个意图是完全正常的）。正常判定优先用 prove_goal 逐个证明目标；goal_met 只是绕过逐个证明、直接从全局收官的手段。",
		obj(map[string]any{"reason": str("达成理由（必须是目标真正达成的证据，不能是“本轮无新方向”这类结束本轮的理由）")}, "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Reason string }
			_ = json.Unmarshal(in, &a)
			t.GoalMet = true
			t.Reason = a.Reason
			return actool.Text("acknowledged: goal marked met"), nil
		})
}

// --- worker write tools ---

func (t *ToolSet) addFinding() actool.CoreTool {
	return writeTool("report_finding", "记录确认的漏洞，用 evidence 提供命令输出、日志等可验证证据。任务上下文传当前 intent_id。返回的 finding_id 是独立漏洞记录 ID，finding_node_id 是探索节点 ID（第一行保留该节点编号）。", obj(map[string]any{
		"vulnclass": str("漏洞类别"), "name": str("漏洞名称"), "severity": str("critical|high|medium|low"), "summary": str("发现摘要"),
		"intent_id": idp("当前任务的意图 id"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "受影响资产 id"},
		"evidence":         str("证据/PoC 文本（必填：命令输出、日志或可复现步骤；不能只写结论）"),
		"evidence_refs":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：可回查证据引用 traffic:<id> / artifact:<path> / activity:<id> / node:<id>；没有流量时用命令输出文本并在 evidence 说明"},
		"evidence_hint_id": idp("可选：本任务中对应此漏洞的提示节点 ID，自动携带其结构化 traffic_refs；不能引用继承提示或其他漏洞的提示"),
		"traffic_refs": map[string]any{"type": "array", "description": "可选；HTTP/HTTPS 漏洞先检索并逐条核实请求/响应确实支持漏洞结论，再按复现顺序填写真实 ID。TCP 等非 HTTP 漏洞、未采集或找不到确切记录时省略或传 []，不阻止上报；可在 evidence 说明原因并提供其他可验证证据。不要猜测 ID、按域名/时间推定关联或仅为补包重复探测。用途 baseline 正常对照 / proof 漏洞证明 / verification 补充验证 / supporting 辅助证据。",
			"items": obj(map[string]any{"traffic_id": str("traffic_search 返回的真实流量 ID"), "role": map[string]any{"type": "string", "enum": []string{"baseline", "proof", "verification", "supporting"}}, "note": str("该流量如何支持漏洞结论")}, "traffic_id")},
	}, "vulnclass", "severity", "summary", "evidence"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			VulnClass, Name, Severity, Summary, Evidence string
			IntentID                                     json.RawMessage   `json:"intent_id"`
			AssetIDs                                     []json.RawMessage `json:"asset_ids"`
			TrafficRefs                                  []db.TrafficRef   `json:"traffic_refs"`
			EvidenceHintID                               json.RawMessage   `json:"evidence_hint_id"`
			EvidenceRefs                                 []string          `json:"evidence_refs"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.ts == nil {
			return actool.Errorf("report_finding 需要任务上下文；平台对话请通过 add_task_hint 向对应任务交接漏洞，并在提示中携带已有的 traffic_refs，由任务 Agent 登记。已登记漏洞可用 bind_finding_traffic 补绑。"), nil
		}
		// Auto-binding off: ignore the evidence params instead of rejecting the call.
		// stripTrafficParameters already removes them from the advertised schema, but
		// models routinely emit fields anyway — failing here would discard a confirmed
		// finding over a stray parameter. The success path below reports evidence_status
		// "not_bound" with the "已关闭，可在页面人工关联" note, which is what the caller needs.
		if !findingTrafficBindingEnabled() {
			a.TrafficRefs, a.EvidenceHintID = nil, nil
		}
		evidenceRefs, err := db.NormalizeEvidenceRefs(a.EvidenceRefs)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		for _, ref := range evidenceRefs {
			parsed, _ := db.ParseEvidenceRef(ref)
			if err := t.validateEvidenceRef(ctx, parsed); err != nil {
				return actool.Errorf(err.Error()), nil
			}
		}
		if len(a.EvidenceHintID) > 0 && pid(a.EvidenceHintID) <= 0 {
			return actool.Errorf("evidence_hint_id 必须为有效的提示节点 ID；无交接提示时省略"), nil
		}
		refs, err := t.findingRefsFromHint(pid(a.EvidenceHintID), a.TrafficRefs)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		// A confirmed finding needs reviewable evidence: non-empty command output,
		// validated evidence_refs, or real traffic bindings. Reject empty arrays/strings
		// or empty hints so a model claim cannot masquerade as a confirmed finding.
		if strings.TrimSpace(a.Evidence) == "" && len(refs) == 0 && len(evidenceRefs) == 0 {
			return actool.Errorf("report_finding 必须提供非空 evidence（命令输出/日志/复现步骤）、有效 traffic_refs（或含流量的 evidence_hint_id）或 evidence_refs；没有证据的推测用 record_fact 记 hypothesis 或 finding_candidate"), nil
		}
		intentID := pid(a.IntentID)
		routeID := int64(0)
		if intentID <= 0 && t.ownerNode > 0 {
			// Planner anchors to the origin fact; only a real intent is a valid
			// finding owner. Main-agent direct findings may have no intent at all.
			if n, err := t.ts.GetNode(t.ownerNode); err == nil && n != nil && n.Kind == db.KindIntent {
				intentID = t.ownerNode
			}
		}
		if intentID > 0 {
			if n, err := t.ts.GetNode(intentID); err == nil && n != nil {
				routeID = db.ParseIntentRoute(n).RouteID
			}
		}
		runInfo := RunInfoFrom(ctx)
		input := db.RecordFindingInput{TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: intentID, VulnClass: a.VulnClass, Name: a.Name, Severity: a.Severity, Summary: a.Summary, Evidence: a.Evidence, Worker: t.worker, AssetIDs: pidList(a.AssetIDs), EvidenceRefs: evidenceRefs, RouteID: routeID, RunID: runInfo.RunID}
		var recorded *db.RecordedFinding
		if t.findingRecorder != nil {
			recorded, err = t.findingRecorder.Record(ctx, input, refs)
		} else if len(refs) > 0 {
			return actool.Errorf("流量证据存储不可用；未登记漏洞"), nil
		} else {
			recorded, err = t.ts.RecordFinding(ctx, input)
		}
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.notifyFinding != nil {
			iid := input.IntentID
			if iid <= 0 {
				iid = t.ownerNode
			}
			t.notifyFinding(iid, a.Summary)
		} else if t.notify != nil {
			t.notify()
		}
		t.writes.Findings++
		// Keep the first line's node-ID contract for existing reporter triggers.
		for i := range recorded.Traffic.Bindings {
			recorded.Traffic.Bindings[i].Snapshot.ReqHead = ""
			recorded.Traffic.Bindings[i].Snapshot.RespHead = ""
		}
		result := struct {
			*db.RecordedFinding
			EvidenceStatus string `json:"evidence_status"`
			EvidenceNote   string `json:"evidence_note,omitempty"`
		}{RecordedFinding: recorded, EvidenceStatus: "bound"}
		if len(recorded.Traffic.Bindings) == 0 {
			result.EvidenceStatus = "not_bound"
			result.EvidenceNote = "漏洞已保存，未绑定流量。TCP/无包情形可正常继续；若已有核实的 HTTP 流量，请用可用的 bind_finding_traffic 或漏洞页面补绑，再完成证据交接。不要重复创建漏洞。"
			if !findingTrafficBindingEnabled() {
				result.EvidenceNote = "漏洞已保存。Agent 自动绑定流量已关闭，可在页面人工关联流量。"
			}
		}
		raw, _ := json.Marshal(result)
		return actool.Text(fmt.Sprintf("finding recorded: %d\n%s", recorded.NodeID, raw)), nil
	})
}

// recordFact writes a general exploration RESULT/conclusion (not a vuln, not a
// new asset) into the EXPLORATION graph, chained to the intent that produced it.
// This is the home for observations and — importantly — negative results
// ("port closed", "param not injectable", "no login found"). Such conclusions
// must NOT be stuffed into the asset graph via upsert_asset.
// factItem 是 record_fact 批量/单条的一条事实。
type factItem struct {
	Summary    string            `json:"summary"`
	FactType   string            `json:"fact_type"`
	Detail     string            `json:"detail"`
	Evidence   string            `json:"evidence"`   // 一行关键证据（命令+关键输出行），支撑结论、便于事后核对
	Confidence string            `json:"confidence"` // observed（直接看到）| inferred（据现象推断）
	IntentID   json.RawMessage   `json:"intent_id"`
	AssetIDs   []json.RawMessage `json:"asset_ids"`

	EvidenceRefs      []string          `json:"evidence_refs"`
	SourceActivityIDs []json.RawMessage `json:"source_activity_ids"`
	ObservationIDs    []json.RawMessage `json:"observation_ids"`
	ClaimIDs          []json.RawMessage `json:"claim_ids"`
	HypothesisIDs     []json.RawMessage `json:"hypothesis_ids"`
	ValidationActions []string          `json:"validation_actions"`
	ValidationState   string            `json:"validation_state"`
	State             string            `json:"state"`
	ObservedAt        string            `json:"observed_at"`
	ValidUntil        string            `json:"valid_until"`
	Sensitivity       string            `json:"sensitivity"`
	InheritancePolicy string            `json:"inheritance_policy"`
	Alternatives      []string          `json:"alternatives_rejected"`
	NextActions       []string          `json:"next_actions"`
	ProgressEvent     string            `json:"progress_event"`
	NextIntentID      json.RawMessage   `json:"next_intent_id"`
	CheckpointFactID  json.RawMessage   `json:"checkpoint_fact_id"`
}

// recordOneFact validates the information type and writes one fact node with its
// intent→yields edge in the same transaction. defaultIntent is the batch default.
func (t *ToolSet) recordOneFact(ctx context.Context, it factItem, defaultIntent int64) (int64, error) {
	payload, intent, err := t.normalizeFactInput(ctx, it, defaultIntent)
	if err != nil {
		return 0, err
	}
	// a fact is its OWN node kind (distinct from a vuln finding). The edge and
	// anchors commit with the node so a lineage write can never be silently lost.
	id, err := t.ts.AddNodeLinked(db.KindFact, payload, 5, "confirmed", t.worker, pidList(it.AssetIDs), intent, db.RelYields)
	if err != nil {
		return 0, err
	}
	t.writes.Facts++
	return id, nil
}

func (t *ToolSet) recordFact() actool.CoreTool {
	return t.writeExpTool("record_fact", "把探索【事实/结论】写入探索图，连到产生它的意图（intent_id）。必须先选 fact_type：observation（环境观察）/ claim（带证据的归纳）/ hypothesis（待验证假设）/ decision（有支撑的选择）/ finding_candidate（待确认漏洞）。\n"+
		"⚠️一次探索的多个观察要【汇总成一条事实】，不要拆成多条；summary=总结性一句话，detail=相关细节（可含多个具体项）。例：指纹意图→一条 observation {summary:'识别了 X 站点的技术栈与响应特征', detail:'nginx 1.25 / Vue3 / 200 / title=..'}，而不是状态码、指纹、标题各记一条。一条意图通常只产出一条事实，拆太碎会让图谱无限膨胀。\n"+
		"★facts 数组用于一次写多条【彼此不同】的结论（每条可省略 intent_id，默认用顶层 intent_id）。返回 ids 数组，与 facts 等长同序。\n"+
		"⚠️只写你在工具输出里【真实看到】的结论，不要脑补。observation/claim/hypothesis 必须带可回查来源：省略 source_activity_ids/evidence_refs 时，系统会自动挂本次意图最近一条 tool_result；要精确引用某一步就传 source_activity_ids（step_id）。evidence_refs 里流量用 traffic:<id>，文件用 artifact:<path>。\n"+
		"  · evidence=一行关键证据（命令+最能证明的 1-2 行输出），**务必简洁**——细节放 detail。\n"+
		"  · confidence=observed（输出里直接看到）| inferred（据现象推断）。claim 必须标注。\n"+
		"  · hypothesis 的 state 用 open/supported/rejected/expired；finding_candidate 的 validation_state 只能是 pending/rejected，确认漏洞必须调用 report_finding。\n"+
		"  · **否定类结论**只陈述实际看到什么、手段是否穷尽；方向是否放弃由规划者综合全局定。",
		obj(map[string]any{
			"facts":               map[string]any{"type": "array", "description": "【有多条不同结论时用】事实数组，元素字段同下方顶层字段；省略 intent_id 则用顶层 intent_id。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"fact_type":           map[string]any{"type": "string", "enum": db.FactTypes, "description": "必填：observation | claim | hypothesis | decision | finding_candidate"},
			"summary":             str("对本次探索结论的【总结性一句话】（是对 detail 的概括）"),
			"intent_id":           idp("产生本事实的意图 id（你领到的意图；批量时作为各条默认）"),
			"detail":              str("本事实的相关细节：把这次探索的多个观察事实都写进这里"),
			"evidence":            str("【一行】关键证据：命令 + 最能证明结论的一两行输出。务必简洁，不要粘大段输出（细节放 detail）。"),
			"evidence_refs":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可回查证据引用：traffic:<id> / artifact:<path> / activity:<id> / node:<id> / finding:<id>"},
			"source_activity_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "支撑本结论的执行步骤 id（get_worker_trace 的 step_id）；省略时自动挂最近一条 tool_result"},
			"observation_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "claim 引用的 observation 节点 id"},
			"claim_ids":           map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "hypothesis/finding_candidate 引用的 claim 节点 id"},
			"hypothesis_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "decision 引用的 hypothesis 节点 id"},
			"validation_actions":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "hypothesis 必填：至少一步可执行验证动作"},
			"alternatives_rejected": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "decision 可选：被放弃的替代方向/原因，避免后续重复评估同一条死路",
			},
			"state":              map[string]any{"type": "string", "enum": []string{"open", "supported", "rejected", "expired"}, "description": "hypothesis 的语义状态"},
			"validation_state":   map[string]any{"type": "string", "enum": []string{"pending", "rejected"}, "description": "finding_candidate 的验证状态；confirmed 只能走 report_finding"},
			"observed_at":        str("观察时间 RFC3339（省略=当前时间）"),
			"valid_until":        str("有效期 RFC3339（可选）"),
			"sensitivity":        map[string]any{"type": "string", "enum": []string{"normal", "credential", "token", "secret", "internal_file", "user_data", "ephemeral_port", "task_auth"}, "description": "敏感性标签（可选）：凭据/token/内部文件/用户数据/临时端口等标上后默认不跨任务继承"},
			"inheritance_policy": map[string]any{"type": "string", "enum": []string{"auto", "inheritable", "local_only"}, "description": "跨任务继承策略（可选）：auto（默认按敏感性与类型判断）/ inheritable / local_only"},
			"next_actions":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "下一步动作（会写入 checkpoint）"},
			"progress_event":     map[string]any{"type": "string", "description": "可选进展事件：new_asset/new_claim/validated_weakness/privilege_change/lateral_progress/objective_milestone/finding_written 等"},
			"next_intent_id":     idp("decision 选择的下一条意图 id"),
			"checkpoint_fact_id": idp("decision 引用的 checkpoint fact id"),
			"confidence":         str("observed（输出里直接看到）| inferred（据现象推断）。claim 必填。"),
			"asset_ids":          map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "相关资产 id（可选，0/1/多个）：该事实涉及哪些资产"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Facts    []factItem `json:"facts"`
				factItem            // 单条模式 + 批量默认 intent_id
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Facts) > 0
			items := a.Facts
			if !batch {
				items = []factItem{a.factItem}
			}
			defaultIntent := pid(a.factItem.IntentID) // 顶层 intent_id = 批量默认
			defaultFactType := strings.TrimSpace(a.factItem.FactType)
			for i := range items {
				if strings.TrimSpace(items[i].FactType) == "" {
					items[i].FactType = defaultFactType
				}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.recordOneFact(ctx, it, defaultIntent)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("fact recorded: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

type hintItem struct {
	Text        string            `json:"text"`
	AssetIDs    []json.RawMessage `json:"asset_ids"`
	TrafficRefs []db.TrafficRef   `json:"traffic_refs"`
}

// addOneHint 挂一条 hint 节点(active/human)到探索图,可锚定资产,返回 id。
func (t *ToolSet) addOneHint(it hintItem) (int64, error) {
	if len(it.TrafficRefs) > 0 && !findingTrafficBindingEnabled() {
		return 0, fmt.Errorf("Agent 自动绑定流量已关闭，未保存携带 traffic_refs 的提示；可在系统设置开启，或仅交接文字")
	}
	if strings.TrimSpace(it.Text) == "" {
		return 0, fmt.Errorf("text 不能为空")
	}
	var anchors []int64
	for _, raw := range it.AssetIDs {
		if tid := pid(raw); tid > 0 {
			anchors = append(anchors, tid)
		}
	}
	refs, err := db.NormalizeTrafficRefs(it.TrafficRefs)
	if err != nil {
		return 0, err
	}
	payload := map[string]any{"text": it.Text}
	if len(refs) > 0 {
		payload["traffic_refs"] = refs
	}
	// 唤醒 planner 不在此处逐条做——由 addHint 在整批写完后统一触发一次（带上提示文本），
	// 避免一次 add_hint 多条提示逐条刷屏 planner 的触发行。
	return t.ts.AddNode(db.KindHint, payload, 0, "active", "human", anchors)
}

type goalItem struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass"`
}

// addOneGoal 挂一条 goal 节点(open)到探索图:连到任务根(origin fact,rel spawns)。
// origin 取 t.worker(缺省 system):goals 拆解器写入的记 "goals"、主 agent 运行时记
// "human"。唤醒 planner 由 setGoals 在整批写完后统一做(见下),这里只负责落库。
func (t *ToolSet) addOneGoal(it goalItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text 不能为空")
	}
	payload := map[string]any{"text": text}
	if vc := strings.TrimSpace(it.VulnClass); vc != "" {
		payload["vulnclass"] = vc
	}
	origin := t.worker
	if origin == "" {
		origin = "system"
	}
	id, err := t.ts.AddNode(db.KindGoal, payload, 0, "open", origin, nil)
	if err != nil {
		return 0, err
	}
	if of, _ := t.ts.OriginFactID(); of > 0 && id > 0 {
		_ = t.ts.Link(of, db.RelSpawns, id) // goals descend from the task root (origin fact)
	}
	return id, nil
}

// setGoals 给【本任务】新增探索目标(goal 节点)。既是目标拆解器的提交工具,也是主
// agent 运行时补目标的工具——同一个受管工具,可在 web 端改描述/schema、按 agent 绑定。
func (t *ToolSet) setGoals() actool.CoreTool {
	return writeTool("set_goals",
		"给【本任务】新增探索目标(goal)。目标=最终可交付/可核验的结果,不是攻击步骤或侦察动作。\n"+
			"★优先批量:多个目标放进 goals 数组一次提交,返回 ids 与之等长同序(失败项 id=0,详情见 errors)。单条则省略 goals 直接给顶层 text。\n"+
			"vulnclass 可选:对应漏洞类(如 SQLi/IDOR),业务逻辑类目标留空。目标是否达成由系统判定标记 met,本工具只负责新增。",
		obj(map[string]any{
			"goals":     map[string]any{"type": "array", "description": "【优先用这个】要新增的目标数组,按顺序处理。每个元素:text(必填,一个独立可验证的最终目标)+ vulnclass(可选)。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"text":      str("[单条] 一个独立可验证的最终目标"),
			"vulnclass": str("[单条] 对应漏洞类(若明确),如 SQLi/IDOR;业务逻辑目标可留空"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_goals 未启用: ExplorationStore 未初始化"), nil
			}
			var a struct {
				Goals    []goalItem `json:"goals"`
				goalItem            // 单条模式:顶层 text/vulnclass
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Goals) > 0
			items := a.Goals
			if !batch {
				items = []goalItem{a.goalItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneGoal(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			if len(addedTexts) > 0 {
				// 唤醒 planner(整批一次)。优先 notifyGoal:一次 set_goals 记一条「人新增了
				// N 个目标:…」触发,不逐条刷屏;拆解器/worker 无此回调 → 退回纯 notify(拆解器
				// round-0 连 notify 也没接,即无操作,因为此时 planner 尚未启动)。
				switch {
				case t.notifyGoal != nil:
					t.notifyGoal(addedTexts)
				case t.notify != nil:
					t.notify()
				}
				// 主 agent 运行时新增目标 → 把已完成/暂停的任务拉回 running 继续跑(终态门会
				// 吞掉普通 notify,必须显式复活)。仅 mainagent 接了此回调;拆解器/worker 为 nil。
				if t.resumeTask != nil {
					t.resumeTask()
				}
			}

			if !batch { // 单条:保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("goal added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

type constraintItem struct {
	Text string `json:"text"`
	Type string `json:"type"` // allow | deny
}

// addOneConstraint 落一条操作约束到 task_constraints。origin 取 t.worker(缺省 system):
// 拆解器写 "goals"、主 agent 写 "human"。
func (t *ToolSet) addOneConstraint(it constraintItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text 不能为空")
	}
	kind := strings.TrimSpace(strings.ToLower(it.Type))
	if kind == "" {
		kind = "deny" // 默认按禁止处理:未标注类型时更保守
	}
	if kind != "allow" && kind != "deny" {
		return 0, fmt.Errorf("type 必须是 allow 或 deny")
	}
	return t.ts.AddConstraint(kind, text, t.worker)
}

// setConstraints 给【本任务】新增操作约束(allow=允许做什么 / deny=禁止做什么)。既是目标
// 拆解器 round-0 抽约束的提交工具,也是主 agent 运行时补约束的工具——同一受管工具,可在 web
// 端改描述/schema、按 agent 绑定。约束会被注入 planner/worker 的系统提示以约束探索边界。
func (t *ToolSet) setConstraints() actool.CoreTool {
	return writeTool("set_constraints",
		"给【本任务】新增操作约束,用来框定探索边界:type=allow(允许做的操作)或 deny(禁止做的操作)。\n"+
			"约束=对『可以/不可以做哪些操作』的规定(如『仅测当前端口,不扫其他端口』『禁止对生产库做写操作』『只允许被动侦察』),不是目标、也不是攻击步骤。\n"+
			"★优先批量:多条放进 constraints 数组一次提交,返回 ids 与之等长同序(失败项 id=0,详情见 errors)。单条则省略 constraints 直接给顶层 text/type。\n"+
			"只登记任务目标/描述里【明确写出】的约束,不要臆造;拿不准类型时用 deny(更保守)。",
		obj(map[string]any{
			"constraints": map[string]any{"type": "array", "description": "【优先用这个】要新增的约束数组,按顺序处理。每个元素:text(必填,一条约束)+ type(allow|deny)。返回 ids 与本数组等长、同序。", "items": map[string]any{"type": "object"}},
			"text":        str("[单条] 一条操作约束的内容"),
			"type":        str("[单条] allow(允许)或 deny(禁止);缺省按 deny 处理"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_constraints 未启用: ExplorationStore 未初始化"), nil
			}
			var a struct {
				Constraints    []constraintItem `json:"constraints"`
				constraintItem                  // 单条模式:顶层 text/type
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Constraints) > 0
			items := a.Constraints
			if !batch {
				items = []constraintItem{a.constraintItem}
			}
			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneConstraint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			if !batch { // 单条:保持简单返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("constraint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) addHint() actool.CoreTool {
	return t.writeExpTool("add_hint", "把人类/主 agent 的战略提示挂到探索图，规划者下次生成意图时会读到它。\n"+
		"★优先批量：多条提示放进 hints 数组一次提交（比逐条调用省往返）。返回 ids 数组，与 hints 等长同序（失败项 id=0，详情见 errors）。单条则省略 hints 直接给顶层 text。",
		obj(map[string]any{
			"hints":        map[string]any{"type": "array", "description": "【优先用这个】要新增的提示数组，按顺序处理。每个元素字段同下方顶层字段（text/asset_ids/traffic_refs）。返回 ids 与本数组等长、同序。", "items": obj(map[string]any{"text": str("提示内容"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": HintTrafficSchema()})},
			"text":         str("[单条] 提示内容，如'重点挖认证后接口'"),
			"traffic_refs": HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "锚定的资产 id（可选，0/1/多个）"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Hints    []hintItem `json:"hints"`
				hintItem            // 单条模式：顶层 text/asset_ids
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Hints) > 0
			items := a.Hints
			if !batch {
				items = []hintItem{a.hintItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneHint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			if len(addedTexts) > 0 {
				// 唤醒 planner（整批一次）。优先 notifyHint：一次 add_hint 记一条「人新增了
				// N 条战略提示：…」触发，让 planner 明确"本轮由新增 hint 触发"并看到提示内容；
				// 未接该回调时退回纯 notify（bare wake，hint 仍折在图里供其自行读取）。
				switch {
				case t.notifyHint != nil:
					t.notifyHint(addedTexts)
				case t.notify != nil:
					t.notify()
				}
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("hint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// killWorkTool lets the planner terminate a single running work (by intent id).
func (t *ToolSet) killWorkTool() actool.CoreTool {
	return t.writeExpTool("kill_work", "终止一条正在运行的意图(work)。用于叫停跑偏/无意义的探索；被终止的意图标记为 stopped，不再自动重领。先用 get_worker_output 看看它在干嘛再决定。",
		obj(map[string]any{"intent_id": idp("要终止的意图 id（= work 句柄）")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.killWork == nil {
				return actool.Errorf("kill_work 当前不可用"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）"), nil
			}
			if err := t.killWork(id); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("已向意图 %d 的 work 发送终止信号", id)), nil
		})
}

// steerWorkTool lets the planner inject a mid-run course-correction into a running
// work WITHOUT killing it: the message reaches the worker before its next tool call,
// which re-plans its next step (already-gathered context is kept). For in-intent
// nudges ("停做 X、聚焦 Y"); if the whole direction is wrong use kill_work + a new intent.
func (t *ToolSet) steerWorkTool() actool.CoreTool {
	return t.writeExpTool("steer_work", "给一条正在运行的意图(work)实时注入纠偏指令，不打断它、不丢已有进展：worker 会在下一步动作前收到你的指令并据此调整。用于'别再走 X、聚焦 Y'这类【意图内】纠偏；若方向整个错了应改用 kill_work 再下新意图。建议先用 get_worker_output 看它在干嘛。",
		obj(map[string]any{
			"intent_id": idp("要纠偏的意图 id（= work 句柄）"),
			"message":   str("给 worker 的纠偏指令，明确让它停止什么、转向什么"),
		}, "intent_id", "message"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.steerWork == nil {
				return actool.Errorf("steer_work 当前不可用"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Message  string          `json:"message"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）"), nil
			}
			if strings.TrimSpace(a.Message) == "" {
				return actool.Errorf("message 必填"), nil
			}
			if err := t.steerWork(id, a.Message); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("已向意图 %d 的 work 注入纠偏指令（下一步生效）", id)), nil
		})
}

// retryWorkTool reopens one blocked intent for another run. It deliberately
// excludes exhausted/stopped: those states can represent a Watchdog budget
// decision or a human stop, so only the UI rerun path may revive them.
func (t *ToolSet) retryWorkTool() actool.CoreTool {
	return t.writeExpTool("retry_work", "重开一条因外部模型或网络故障进入 blocked 的意图(work)，复用原转录和已写回产物继续执行。running/open/paused 不可重开；exhausted/stopped 需要人工在界面处理。",
		obj(map[string]any{"intent_id": idp("要重开的意图 id（= work 句柄）")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.retryWork == nil {
				return actool.Errorf("retry_work 当前不可用"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）"), nil
			}
			if node.State != "blocked" {
				return actool.Errorf(fmt.Sprintf("意图 #%d 当前状态为 %s，只有 blocked 可以自动重开；running 用 steer_work，open 可等待或 cancel_intent", id, node.State)), nil
			}
			msg, err := t.openIntentCapError(1)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if msg != "" {
				return actool.Errorf(msg), nil
			}
			queued, err := t.retryWork(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"intent_id": id, "state": "open", "queued": queued,
				"message": "意图已重开，worker 会复用原转录继续执行。",
			})
		})
}

// cancelIntentTool stops one queued intent owned by the Planner. It is a logical
// cancellation: the node, lineage and audit remain, and a human can still rerun it.
// Only open intents are eligible; running work uses steer_work or the terminate path.
func (t *ToolSet) cancelIntentTool() actool.CoreTool {
	return t.writeExpTool("cancel_intent", "取消一条排队中的 open 意图(work)：只修改状态为 stopped，保留节点、血缘和审计；不会停止运行中的 work。只能取消由 Planner 自己创建的 open 意图。",
		obj(map[string]any{
			"intent_id": idp("要取消的意图 id（= work 句柄）"),
			"reason":    str("取消原因，写明被新事实覆盖、方向过时或优先级过低等原因"),
		}, "intent_id", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Reason   string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return actool.Errorf("reason 必填"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）"), nil
			}
			if node.Origin != t.worker {
				return actool.Errorf(fmt.Sprintf("只能取消 Planner 自己创建的意图（当前来源 %q）", node.Origin)), nil
			}
			changed, err := t.ts.CompareAndSetIntentStateWithReason(id, "open", "stopped", "planner_cancelled: "+reason)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !changed {
				return actool.Errorf(fmt.Sprintf("意图 #%d 已不在 open 状态（可能刚被 worker 领取），未取消", id)), nil
			}
			return jsonResult(map[string]any{
				"intent_id": id, "state": "stopped",
				"reason": "planner_cancelled: " + reason,
			})
		})
}

// getWorkerOutput returns a work's final conclusion text by intent id. While the
// intent is still live, the same rows are only attempt-level output: return them
// as last_text with an explicit running state instead of presenting a retryable
// model_error as the work's final answer.
func (t *ToolSet) getWorkerOutput() actool.CoreTool {
	return t.readExpTool("get_worker_output", "取本任务或直接关联任务某条意图(work)的输出。关联任务结果带 source_task_id/inherited=true 且只读。意图已结束(done/blocked/exhausted/stopped)时返回 final_text；仍 open/running/paused 时只返回 state、running=true 和 last_text，last_text 不是最终结论。",
		obj(map[string]any{"intent_id": idp("意图 id（= work 句柄）")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			intentNode, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id 不属于本任务或其直接关联任务"), nil
			}
			acts, _, err := t.ts.ActivityListWithSources(id, 0, 1000)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var lastResult, lastText *db.Activity
			for i := range acts {
				switch acts[i].Kind {
				case "result":
					lastResult = &acts[i]
				case "text":
					lastText = &acts[i]
				}
			}
			activityText := func(pick *db.Activity) string {
				if pick == nil {
					return ""
				}
				detail, _ := t.ts.ActivityDetailWithSources(pick.ID)
				if detail == "" {
					detail = pick.Summary
				}
				return detail
			}
			if !db.IsTerminalIntentState(intentNode.State) {
				pick := lastText
				if pick == nil {
					pick = lastResult
				}
				result := map[string]any{
					"intent_id": id, "state": intentNode.State,
					"running": true, "final": false,
					"last_text": activityText(pick),
					"notice":    "该意图仍在运行或排队，当前输出不是最终结论；实时状态用 graph_overview，执行过程用 get_worker_trace。",
				}
				if pick != nil {
					result["summary"] = pick.Summary
					result["is_error"] = pick.IsError
				}
				result["worker_seconds"] = intentWorkerSeconds(intentNode)
				result["worker_runs"] = intentNode.WorkerRuns
				if intentNode.Inherited {
					inheritedMap(result, intentNode.SourceTaskID)
				}
				return jsonResult(result)
			}
			pick := lastResult
			if pick == nil {
				pick = lastText
			}
			if pick == nil {
				if intentNode.Inherited {
					return jsonResult(inheritedMap(map[string]any{
						"intent_id": id, "state": intentNode.State, "final": true,
						"final_text": "（该 work 尚无任何输出）",
					}, intentNode.SourceTaskID))
				}
				return jsonResult(map[string]any{
					"intent_id": id, "state": intentNode.State, "final": true,
					"final_text": "（该 work 尚无任何输出）",
				})
			}
			result := map[string]any{
				"intent_id": id, "state": intentNode.State, "final": true,
				"final_text": activityText(pick),
				"summary":    pick.Summary, "is_error": pick.IsError,
				"worker_seconds": intentWorkerSeconds(intentNode),
				"worker_runs":    intentNode.WorkerRuns,
			}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// traceSteps renders summary-only trace rows, re-truncating each summary to 100
// chars — the stored summary is capped at 200 for the UI transcript; the trace
// tools want it tighter since a whole work's step list is many rows.
func traceSteps(acts []db.Activity, intentState string) []map[string]any {
	steps := make([]map[string]any, 0, len(acts))
	provisional := !db.IsTerminalIntentState(intentState)
	for i := range acts {
		step := map[string]any{
			"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
			"is_error": acts[i].IsError, "summary": firstLine(acts[i].Summary, 100),
		}
		if provisional && acts[i].Kind == "result" {
			step["provisional"] = true
		}
		if acts[i].Inherited {
			inheritedMap(step, acts[i].SourceTaskID)
		}
		steps = append(steps, step)
	}
	return steps
}

// getWorkerTrace exposes a work's execution PROCESS (not just its final output):
// list step summaries, keyword-search within one work, or pull full detail of a
// few specific steps. Thinking steps are excluded everywhere.
func (t *ToolSet) getWorkerTrace() actool.CoreTool {
	return t.readExpTool("get_worker_trace",
		"查看某条意图(work)的【执行过程】（区别于 get_worker_output 只给终态结论）。三种用法：\n"+
			"① 只传 intent_id → 返回该 work 每一步的摘要流（summary≤100字，含 step_id；只是动作轮廓，不含完整输出）；\n"+
			"② intent_id + q → 只返回命中关键字的步骤摘要（在摘要和完整输出里都搜；仍只给 summary，要看内容用③）；\n"+
			"③ intent_id + step_ids → 返回这些步骤的完整内容(detail)；一次最多取 5 个，超出只返回前 5 个并在 notice/omitted_step_ids 里告知未取的。\n"+
			"典型流程：先①/②定位可疑步骤的 step_id，再用③取其完整输出。不含思考(thinking)步骤。支持直接关联任务的历史 trace；其结果带 source_task_id/inherited=true 且只读。",
		obj(map[string]any{
			"intent_id": idp("意图 id（= work 句柄）"),
			"q":         str("关键字：只返回摘要/完整输出命中它的步骤（可选；与 step_ids 互斥）"),
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要取完整内容的 step_id（来自①/②返回；一次最多取 5 个，多传只返回前 5 个，其余在 omitted_step_ids 里列出）"},
			"limit":     intp("摘要流/检索的返回上限（可选）"),
		}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage   `json:"intent_id"`
				Q        string            `json:"q"`
				StepIDs  []json.RawMessage `json:"step_ids"`
				Limit    int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id 必填"), nil
			}
			intentNode, nodeErr := t.ts.GetNodeWithSources(id)
			if nodeErr != nil {
				return actool.Errorf(nodeErr.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id 不属于本任务或其直接关联任务"), nil
			}
			// ③ detail drill-down by step ids, thinking excluded by the store.
			if len(a.StepIDs) > 0 {
				// Dedup + drop invalid ids first so garbage/duplicates don't eat into
				// the per-call cap. detail is returned in full (untruncated), so the
				// cap bounds one tool result; over the cap we serve the first N and
				// tell the model exactly which ids were deferred, instead of erroring
				// and forcing it to re-plan the call.
				const maxStepIDs = 5
				var ids []int64
				seen := make(map[int64]bool)
				for _, raw := range a.StepIDs {
					if v := pid(raw); v > 0 && !seen[v] {
						seen[v] = true
						ids = append(ids, v)
					}
				}
				var omitted []int64
				if len(ids) > maxStepIDs {
					omitted = append(omitted, ids[maxStepIDs:]...)
					ids = ids[:maxStepIDs]
				}
				acts, err := t.ts.ActivityByIDsWithSources(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				steps := make([]map[string]any, 0, len(acts))
				for i := range acts {
					if acts[i].NodeID == nil || *acts[i].NodeID != id || acts[i].Inherited != intentNode.Inherited ||
						(acts[i].Inherited && acts[i].SourceTaskID != intentNode.SourceTaskID) {
						continue
					}
					step := map[string]any{
						"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
						"is_error": acts[i].IsError, "detail": acts[i].Detail,
					}
					if acts[i].Kind == "result" && !db.IsTerminalIntentState(intentNode.State) {
						step["provisional"] = true
					}
					if acts[i].Inherited {
						inheritedMap(step, acts[i].SourceTaskID)
					}
					steps = append(steps, step)
				}
				result := map[string]any{"intent_id": id, "state": intentNode.State, "steps": steps, "returned_step_ids": ids,
					"worker_seconds": intentWorkerSeconds(intentNode), "worker_runs": intentNode.WorkerRuns}
				if len(omitted) > 0 {
					// returned_step_ids/omitted_step_ids let the model decide programmatically
					// whether another call is worth it; the notice states the same in prose.
					result["omitted_step_ids"] = omitted
					result["notice"] = fmt.Sprintf(
						"每次最多取 %d 个步骤的完整内容，本次已返回前 %d 个（%v），未取的 %d 个为 %v。"+
							"若这些内容已足够定位，则无需再取剩余步骤；确需继续时，用这些 step_id 再调一次。",
						maxStepIDs, len(ids), ids, len(omitted), omitted)
				}
				if intentNode.Inherited {
					inheritedMap(result, intentNode.SourceTaskID)
				}
				return jsonResult(result)
			}
			// ①/② summary stream, optionally keyword-filtered; 100-char summaries.
			var acts []db.Activity
			var err error
			if strings.TrimSpace(a.Q) != "" {
				acts, err = t.ts.ActivityTraceSearchWithSources(id, a.Q, a.Limit)
			} else {
				acts, err = t.ts.ActivityTraceWithSources(id, a.Limit)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			result := map[string]any{"intent_id": id, "state": intentNode.State, "steps": traceSteps(acts, intentNode.State),
				"worker_seconds": intentWorkerSeconds(intentNode), "worker_runs": intentNode.WorkerRuns}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// searchAllWorkerTraces keyword-searches EVERY work's process in this task — for
// finding what a worker saw but never wrote back as a fact. Returns only matching
// summaries (≤100 chars), each tagged with its intent_id for follow-up drill-down.
func (t *ToolSet) searchAllWorkerTraces() actool.CoreTool {
	return t.readExpTool("search_all_worker_traces",
		"【通常不推荐使用，因为系统中已经给了大部分信息了】在【本任务其他 work 的执行过程】里按关键字(q)检索——用于找回某个 worker 见过、却没写进 fact 的东西（某路径/token/报错等）。"+
			"已自动排除你自己这条意图的步骤（那些本就在你上下文里）。"+
			"只返回命中步骤的摘要(summary≤100字)，每条带 intent_id；据此再用 get_worker_trace(intent_id, step_ids=[...]) 取完整内容。",
		obj(map[string]any{
			"q":     str("关键字（在所有 work 步骤的摘要+完整输出里搜）"),
			"limit": intp("返回上限，默认 100（可选）"),
		}, "q"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Q) == "" {
				return actool.Errorf("q 必填"), nil
			}
			// 排除调用者自身这条意图的步骤（worker 的自有 trace 已在其上下文里）。
			acts, err := t.ts.ActivityTraceSearchAllWithSources(t.ownerNode, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits := make([]map[string]any, 0, len(acts))
			states := make(map[int64]string)
			for i := range acts {
				var intent int64
				if acts[i].NodeID != nil {
					intent = *acts[i].NodeID
				}
				hit := map[string]any{
					"intent_id": intent, "step_id": acts[i].ID, "worker": acts[i].Worker,
					"kind": acts[i].Kind, "tool": acts[i].Tool, "is_error": acts[i].IsError,
					"summary": firstLine(acts[i].Summary, 100),
				}
				if acts[i].Kind == "result" {
					state, ok := states[intent]
					if !ok {
						n, nodeErr := t.ts.GetNodeWithSources(intent)
						if nodeErr != nil {
							return actool.Errorf(nodeErr.Error()), nil
						}
						if n != nil {
							state = n.State
						}
						states[intent] = state
					}
					if !db.IsTerminalIntentState(state) {
						hit["provisional"] = true
					}
				}
				if acts[i].Inherited {
					inheritedMap(hit, acts[i].SourceTaskID)
				}
				hits = append(hits, hit)
			}
			return jsonResult(map[string]any{"query": a.Q, "hits": hits})
		})
}

// listWorkerTraces gives a worker (which has no graph_overview and can't see the
// intent graph) a lightweight index of the works in this task — intent_id +
// one-line summary + state — so it can DISCOVER which works to inspect via
// get_worker_trace. Without this a worker only knows intent_ids that come back
// from search_all_worker_traces hits. Excludes still-open intents (not yet run →
// no process to inspect).
func (t *ToolSet) listWorkerTraces() actool.CoreTool {
	return t.readExpTool("list_worker_traces",
		"【通常不推荐使用，因为系统中已经给了大部分信息了】列出本任务里【已跑过的 work（意图）】索引：intent_id + 一句话方向(summary) + 状态。"+
			"你(worker)看不到探索图，用它来发现有哪些 work 值得翻看——再用 get_worker_trace(intent_id) 看其步骤、get_worker_trace(intent_id, step_ids=[...]) 取详情。"+
			"只列已执行的(running/done/exhausted/blocked/stopped)，不含还没跑的 open。注意：你的任务边界仍是你领到的那条意图，看别的 work 只为复用观察/避免重复劳动。",
		obj(map[string]any{
			"q":     str("按 summary 关键字过滤（可选）"),
			"limit": intp("返回上限，默认 50（可选）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			all, err := t.ts.ListByKindWithSources(db.KindIntent, 500)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Q))
			out := make([]map[string]any, 0, limit)
			for _, n := range all {
				if n.Inherited && n.State == "running" {
					continue
				}
				switch n.State {
				case "running", "done", "exhausted", "blocked", "stopped": // has run → has a process
				default:
					continue
				}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				summary, _ := p["summary"].(string)
				if q != "" && !strings.Contains(strings.ToLower(summary), q) {
					continue
				}
				item := map[string]any{"intent_id": n.ID, "summary": summary, "state": n.State}
				if n.Inherited {
					inheritedMap(item, n.SourceTaskID)
				}
				out = append(out, item)
				if len(out) >= limit {
					break
				}
			}
			return jsonResult(map[string]any{"works": out})
		})
}

// PlannerTools is the read + intent-generation + goal-judgement tool set.
func (t *ToolSet) PlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		// cold-digest §6.1: restore folded cold nodes (digest body → members → detail).
		t.expandDigest(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.listGoals(), t.addIntent(), t.proveGoal(), t.goalMet(),
		t.killWorkTool(), t.steerWorkTool(), t.retryWorkTool(), t.cancelIntentTool(),
		// report_finding：规划态势研判时若自身已确证漏洞，可直接登记（与 worker 同工具）。
		t.addFinding(),
		// list_companies：查看企业列表 + scope + 资产数（拿 company_id / 理解归属范围）。
		t.listCompanies(),
		// list_assets：规划时按 DSL 检索全资产库（配合 list_untested_assets 的"范围内未测"视角，
		// 补上"按域名/指纹/端口/状态码等条件在整库里查"的能力）。
		t.listAssets(),
		// add_company_scope：规划时可把域名/IP/CIDR/ICP/关键词纳入某公司的资产范围（自动认领命中资产）。
		t.addCompanyScope(),
		// add_task_scope：主动把整根域/整公司/某子域/IP 纳入本任务测试范围(覆盖度分母)。
		t.addTaskScope(),
		// list_untested_assets：按需查本任务范围内未测资产(类型+分页)，自行决定补测。
		t.listUntestedAssets(),
	}
}
