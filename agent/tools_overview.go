package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// --- read tools (planner + worker) ---

func (t *ToolSet) graphOverview() actool.CoreTool {
	return t.readExpTool("graph_overview",
		"(探索链路图)规划者的战略索引：路线单行账本、未测目标样本、可复用凭据、同指纹候选资产，按 12KB 确定裁剪。规划时先调它；查看单个节点完整正文用 node_detail，翻页读取全部事实用 list_facts。",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.plannerOverviewData())
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
	// 产出分质的判定表：finding 恒为高价值；fact 只有带高价值 progress_event 才算。
	// 由本轮的 fact 窗口 + finding 窗口构建，供 compactIntents 区分
	// high_value_yields / observation_yields。
	yieldKinds := make(map[int64]string, len(factNodes))
	for _, n := range factNodes {
		yieldKinds[n.ID] = yieldClassOf(n)
	}
	findingNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
	for _, n := range findingNodes {
		yieldKinds[n.ID] = "high"
	}
	t.yieldClass = func(id int64) string { return yieldKinds[id] }
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
	out["open_intents"] = compactIntents(fr, parentsOf, yieldsOf, t.yieldClass)
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
	out["running_intents"] = compactIntents(running, parentsOf, yieldsOf, t.yieldClass)
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
	// G5 observer: WAF / 429 hits tell the planner a target is fighting back or
	// rate-limiting, so it can slow down or switch technique instead of hammering.
	// Omitted when the task has no guard wired (tests, chat sessions).
	if t.guardAttributions != nil {
		if attrs := t.guardAttributions(); len(attrs) > 0 {
			out["guard_attributions"] = attrs
		}
	}
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
		effort     string
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
		if agg.effort == "" && r.Effort != "" {
			agg.effort = db.NormalizeEffort(r.Effort)
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
	// 路线自治健康度：连续跑干次数 / 总棒数 / 是否有人工介入。规划者据此决定续派还是换线
	// （而非靠 yield_count 的笼统数字）。budget/budget_used 仍保留为历史统计，不再参与任何
	// 阻断；effort 才是运行档位。
	routeIDs := make([]int64, 0, len(routeMap))
	for id := range routeMap {
		routeIDs = append(routeIDs, id)
	}
	health, _ := t.ts.RouteHealthByID(routeIDs)
	routes := make([]map[string]any, 0, len(routeMap))
	for _, agg := range routeMap {
		m := map[string]any{
			"route_id": agg.id, "route_kind": agg.kind, "phase": agg.phase,
			"objective": agg.objective, "intents": agg.intents, "active_intents": agg.active,
			"asset_ids": agg.assets,
		}
		if h, ok := health[agg.id]; ok {
			m["total_runs"] = h.TotalRuns
			m["consecutive_dry_runs"] = h.ConsecutiveDryRuns
			m["runs_since_finding"] = h.RunsSinceLastFinding
			m["worker_seconds"] = h.WorkerSeconds
			m["autonomy_status"] = h.AutonomyStatus
			m["human_involved"] = h.HumanInvolved
		}
		if !agg.budget.Empty() {
			m["budget"] = agg.budget // 历史统计，不参与阻断
		}
		if agg.used != (db.RouteBudgetUsed{}) {
			m["budget_used"] = agg.used
		}
		if agg.checkpoint != nil {
			p := db.ParseFactPayload(agg.checkpoint.Payload)
			m["checkpoint"] = compactCheckpoint(agg.checkpoint, p)
		}
		if agg.effort != "" {
			m["effort"] = agg.effort
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
	out["recent_done_intents"] = compactIntents(recentDone, parentsOf, yieldsOf, t.yieldClass)
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
					m["note"] = "coverage资产测试覆盖度（包括接口等各种相关资产），粗略估计、仅供参考：包含当前任务与直接关联任务的 scope、事实锚点；关联 scope 只读。容器型资产/大量枚举会让它偏低，勿据此认为已测完；可用 add_task_scope 增补本任务范围、list_untested_assets 看未测资产。"
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

// plannerOverviewMaxBytes is the hard size bound for the planner's strategic
// projection. The planner wakes on every graph change; an unbounded snapshot
// would crowd out its reasoning prompt.
const plannerOverviewMaxBytes = 12288

// plannerOverviewData is the planner's macro strategic index. It keeps the whole
// decision surface (goals, hints, frontier, findings, credentials, route health)
// but renders routes as compact one-line ledgers and caps every list, then trims
// deterministically to plannerOverviewMaxBytes.
func (t *ToolSet) plannerOverviewData() map[string]any {
	base := t.graphOverviewData()
	out := map[string]any{}
	for _, key := range []string{
		"task", "goals", "hints", "frontier_open", "open_intent_cap",
		"open_intent_remaining", "cap_reached", "open_intents", "running_intents",
		"done_intents_total", "findings_total", "facts", "guard_attributions",
	} {
		if v, ok := base[key]; ok {
			out[key] = v
		}
	}
	// recent_done_intents: newest 10, each summary capped so one verbose intent
	// cannot dominate the index.
	if done, ok := base["recent_done_intents"].([]map[string]any); ok {
		out["recent_done_intents"] = capOverviewIntentSummaries(done, 10, 160)
	} else {
		out["recent_done_intents"] = []map[string]any{}
	}
	if list, ok := base["finding_list"].([]map[string]any); ok {
		if len(list) > 10 {
			list = list[:10]
		}
		out["finding_list"] = list
	} else {
		out["finding_list"] = []map[string]any{}
	}
	if facts, ok := base["recent_facts"].([]map[string]any); ok {
		capped := make([]map[string]any, 0, 10)
		for _, f := range facts {
			if len(capped) >= 10 {
				break
			}
			m := cloneStringAnyMap(f)
			m["summary"] = truncRunesValue(m["summary"], 160)
			capped = append(capped, m)
		}
		out["recent_facts"] = capped
	} else {
		out["recent_facts"] = []map[string]any{}
	}
	if candidates, ok := base["finding_candidates"].([]map[string]any); ok {
		if len(candidates) > 6 {
			candidates = candidates[:6]
		}
		out["finding_candidates"] = candidates
	} else {
		out["finding_candidates"] = []map[string]any{}
	}
	// Routes: compact ledger. Full checkpoints stay out of the top level; only
	// the newest checkpoint id and a 160-rune summary travel with the route.
	if routes, ok := base["routes"].([]map[string]any); ok {
		out["routes"] = compactPlannerRoutes(routes)
	} else {
		out["routes"] = []map[string]any{}
	}
	// Coverage keeps the untested backlog sample so the planner can steer toward
	// blank targets without a separate list_untested_assets call.
	cov := map[string]any{}
	if baseCov, ok := base["coverage"].(map[string]any); ok {
		cov = cloneStringAnyMap(baseCov)
	}
	if !t.coverageDisabled && t.as != nil && t.taskID > 0 {
		if untested, total, err := t.as.ListUntestedAssetsWithSources(t.taskID, "", 15, 0); err == nil {
			cov["untested_total"] = total
			sample := make([]map[string]any, 0, len(untested))
			for _, a := range untested {
				sample = append(sample, map[string]any{"id": a.ID, "type": a.Type, "label": a.Label})
			}
			cov["untested_targets_sample"] = sample
		}
	}
	if len(cov) > 0 {
		out["coverage"] = cov
	}
	out["reusable_credentials"] = t.reusableCredentialSummaries(10)
	out["variant_targets"] = t.variantTargets()
	if digests, ok := base["cold_digests"]; ok {
		out["cold_digests"] = digests
	}
	if more, ok := base["cold_digests_more"]; ok {
		out["cold_digests_more"] = more
	}
	if related, ok := base["related_tasks"]; ok {
		out["related_tasks"] = related
	}
	if counts, ok := base["information_counts"]; ok {
		out["information_counts"] = counts
	}
	trimPlannerOverviewToBudget(out, plannerOverviewMaxBytes)
	return out
}

func cloneStringAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func truncRunesValue(v any, n int) any {
	s, ok := v.(string)
	if !ok || n <= 0 {
		return v
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func capOverviewIntentSummaries(list []map[string]any, limit, summaryRunes int) []map[string]any {
	out := make([]map[string]any, 0, limit)
	for _, item := range list {
		if len(out) >= limit {
			break
		}
		m := cloneStringAnyMap(item)
		m["summary"] = truncRunesValue(m["summary"], summaryRunes)
		out = append(out, m)
	}
	return out
}

func compactPlannerRoutes(routes []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(routes))
	for _, r := range routes {
		m := map[string]any{
			"route_id":             r["route_id"],
			"phase":                r["phase"],
			"objective":            r["objective"],
			"effort":               r["effort"],
			"asset_ids":            r["asset_ids"],
			"active_intents":       r["active_intents"],
			"total_runs":           r["total_runs"],
			"consecutive_dry_runs": r["consecutive_dry_runs"],
			"runs_since_finding":   r["runs_since_finding"],
			"worker_seconds":       r["worker_seconds"],
			"autonomy_status":      r["autonomy_status"],
			"human_involved":       r["human_involved"],
			"last_checkpoint_id":   int64(0),
			"last_summary":         "",
		}
		if cp, ok := r["checkpoint"].(map[string]any); ok {
			if id, ok := cp["id"].(int64); ok {
				m["last_checkpoint_id"] = id
			}
			m["last_summary"] = truncRunesValue(cp["summary"], 160)
		}
		out = append(out, m)
	}
	return out
}

// reusableCredentialSummaries returns credential/token/secret facts visible to
// this task (own and direct-source inheritable facts), newest first.
func (t *ToolSet) reusableCredentialSummaries(limit int) []map[string]any {
	out := make([]map[string]any, 0, limit)
	if t.ts == nil || limit <= 0 {
		return out
	}
	facts, err := t.ts.ListByKindWithSources(db.KindFact, 1000)
	if err != nil {
		return out
	}
	now := time.Now()
	for _, n := range facts {
		if len(out) >= limit {
			break
		}
		if n.Inherited {
			if ok, _ := db.CanInheritFact(n, now); !ok {
				continue
			}
		}
		p := db.ParseFactPayload(n.Payload)
		sensitive := p.Sensitivity == "credential" || p.Sensitivity == "token" || p.Sensitivity == "secret"
		if !sensitive && p.ProgressEvent != "credential_obtained" {
			continue
		}
		out = append(out, map[string]any{
			"id": n.ID, "summary": truncRunesValue(p.Summary, 160), "route_id": n.RouteID(),
		})
	}
	return out
}

// variantTargets finds sibling assets that share a component fingerprint with an
// asset already anchored by a confirmed finding, excluding assets that already
// have a confirmed finding of their own. The planner uses them to push the same
// fingerprint's exploit to untested siblings.
func (t *ToolSet) variantTargets() []map[string]any {
	if t.as == nil || t.taskID <= 0 || t.ts == nil {
		return []map[string]any{}
	}
	findings, err := t.ts.ListByKindWithSources(db.KindFinding, 200)
	if err != nil || len(findings) == 0 {
		return []map[string]any{}
	}
	findingIDs := make([]int64, 0, len(findings))
	for _, f := range findings {
		findingIDs = append(findingIDs, f.ID)
	}
	anchors, err := t.ts.AssetIDsForNodes(findingIDs)
	if err != nil {
		return []map[string]any{}
	}
	findingAssets := map[int64]bool{}
	for _, ids := range anchors {
		for _, id := range ids {
			findingAssets[id] = true
		}
	}
	taskAssets, err := t.as.QueryByTask(t.taskID, "", 500, 0)
	if err != nil || len(taskAssets) == 0 {
		return []map[string]any{}
	}
	type component struct {
		service string
		techs   []string
	}
	componentOf := func(a *db.Asset) component {
		c := component{service: strings.ToLower(strings.TrimSpace(a.ServiceName))}
		for _, tch := range a.Technologies {
			tch = strings.ToLower(strings.TrimSpace(tch))
			if tch != "" {
				c.techs = append(c.techs, tch)
			}
		}
		return c
	}
	fingerprintOf := func(c component) string {
		if c.service != "" {
			return c.service
		}
		return strings.Join(c.techs, ",")
	}
	sharesFingerprint := func(c component, fp string) bool {
		if c.service != "" && c.service == fp {
			return true
		}
		for _, tch := range c.techs {
			if tch == fp {
				return true
			}
		}
		return false
	}
	sourceByID := map[int64]*db.Asset{}
	for _, r := range taskAssets {
		sourceByID[r.ID] = r
	}
	out := make([]map[string]any, 0, 8)
	seen := map[string]bool{}
	for _, f := range findings {
		if len(out) >= 8 {
			break
		}
		for _, assetID := range anchors[f.ID] {
			if findingAssets[assetID] == false {
				continue
			}
			src := sourceByID[assetID]
			if src == nil {
				loaded, e := t.as.GetByIDs([]int64{assetID})
				if e != nil || len(loaded) == 0 {
					continue
				}
				src = loaded[0]
			}
			fp := fingerprintOf(componentOf(src))
			if fp == "" {
				continue
			}
			key := fmt.Sprintf("%d|%s", f.ID, fp)
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates := make([]int64, 0, 8)
			for _, cand := range taskAssets {
				if cand.ID == assetID || findingAssets[cand.ID] {
					continue
				}
				if sharesFingerprint(componentOf(cand), fp) {
					candidates = append(candidates, cand.ID)
					if len(candidates) >= 8 {
						break
					}
				}
			}
			if len(candidates) == 0 {
				continue
			}
			out = append(out, map[string]any{
				"fingerprint": fp, "source_finding_id": f.ID, "candidate_asset_ids": candidates,
			})
			break
		}
	}
	return out
}

// trimPlannerOverviewToBudget deterministically shrinks a planner snapshot until
// it marshals within maxBytes. goals, hints, open_intents, running_intents,
// finding_list and reusable_credentials are never trimmed.
func trimPlannerOverviewToBudget(out map[string]any, maxBytes int) {
	fits := func() bool { return overviewJSONSize(out) <= maxBytes }

	if fits() {
		return
	}
	// 1) Fold cold-digest bodies to their first 80 runes.
	if digests, ok := out["cold_digests"].([]map[string]any); ok {
		for _, d := range digests {
			d["body"] = truncRunesValue(d["body"], 80)
		}
	}
	if fits() {
		return
	}
	// 2) Keep only digest ids once bodies still do not fit.
	if digests, ok := out["cold_digests"].([]map[string]any); ok {
		ids := make([]any, 0, len(digests))
		for _, d := range digests {
			ids = append(ids, d["id"])
		}
		delete(out, "cold_digests")
		delete(out, "cold_digests_more")
		out["cold_digest_ids"] = ids
	}
	if fits() {
		return
	}
	// 3) Shrink related_task lists, then drop sources from the tail.
	if related, ok := out["related_tasks"].([]map[string]any); ok {
		for _, item := range related {
			for _, key := range []string{"facts", "findings", "intents", "hints", "goals", "asset_scope", "cold_digests"} {
				if list, ok := item[key].([]map[string]any); ok && len(list) > 4 {
					item[key] = list[:4]
				}
				if list, ok := item[key].([]any); ok && len(list) > 4 {
					item[key] = list[:4]
				}
			}
		}
	}
	if fits() {
		return
	}
	if related, ok := out["related_tasks"].([]map[string]any); ok {
		for len(related) > 0 && !fits() {
			related = related[:len(related)-1]
			out["related_tasks"] = related
		}
	}
	if fits() {
		return
	}
	// 4) Reduce the fact / candidate / done windows, keeping the stated minima.
	shrinkOverviewList(out, "recent_facts", 3, maxBytes)
	shrinkOverviewList(out, "finding_candidates", 0, maxBytes)
	shrinkOverviewList(out, "recent_done_intents", 4, maxBytes)
	if fits() {
		return
	}
	// 5) Keep at most 12 inactive routes; active routes always stay.
	if routes, ok := out["routes"].([]map[string]any); ok {
		kept := make([]map[string]any, 0, len(routes))
		inactive := 0
		for _, r := range routes {
			if active, _ := r["active_intents"].(int); active == 0 {
				inactive++
				if inactive > 12 {
					continue
				}
			}
			kept = append(kept, r)
		}
		out["routes"] = kept
	}
	if cov, ok := out["coverage"].(map[string]any); ok {
		delete(cov, "scope")
		delete(cov, "by_type")
		delete(cov, "note")
		if sample, ok := cov["untested_targets_sample"].([]map[string]any); ok && len(sample) > 8 {
			cov["untested_targets_sample"] = sample[:8]
		}
	}
	if fits() {
		return
	}
	// 6) Last resort: shrink capped windows to one entry and drop optional blocks
	// in a fixed order. Required strategic keys stay present even when empty.
	shrinkOverviewList(out, "recent_facts", 1, maxBytes)
	shrinkOverviewList(out, "recent_done_intents", 1, maxBytes)
	shrinkOverviewList(out, "finding_candidates", 0, maxBytes)
	for _, key := range []string{
		"information_counts", "cold_digest_ids", "related_tasks", "guard_attributions", "coverage",
	} {
		if fits() {
			return
		}
		delete(out, key)
	}
	if fits() {
		return
	}
	if routes, ok := out["routes"].([]map[string]any); ok {
		for len(routes) > 1 && !fits() {
			routes = routes[:len(routes)-1]
			out["routes"] = routes
		}
	}
}

func overviewJSONSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 1 << 30
	}
	return len(b)
}

func shrinkOverviewList(out map[string]any, key string, min, maxBytes int) {
	for {
		if overviewJSONSize(out) <= maxBytes {
			return
		}
		list, ok := out[key].([]map[string]any)
		if !ok || len(list) <= min {
			return
		}
		out[key] = list[:len(list)-1]
	}
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
		checkpointIDs, _ := ts.CheckpointFactIDs()
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
				if checkpointIDs[edge.To] {
					continue
				}
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

		facts, _ := ts.ListFactsExcludingBookkeeping(relatedOverviewMaxFactsPerSource)
		factTotal := len(facts)
		findings, _ := ts.ListByKind(db.KindFinding, relatedOverviewMaxFindingsPerTask)
		intentNodes, _ := ts.ListByKind(db.KindIntent, 300)
		terminalIntent := make(map[int64]bool, len(intentNodes))
		for _, intent := range intentNodes {
			terminalIntent[intent.ID] = db.IsTerminalIntentState(intent.State)
		}
		item["facts"] = len(facts)
		item["findings"] = len(findings)
		if statsErr == nil {
			realFacts := stats[db.KindFact] - len(checkpointIDs)
			if realFacts > 0 {
				realFacts-- // task-root origin fact
			}
			if realFacts < 0 {
				realFacts = 0
			}
			factTotal = realFacts
			item["facts"] = factTotal
			item["findings"] = stats[db.KindFinding]
			if stats[db.KindGoal] > len(goals) || stats[db.KindHint] > len(hints) ||
				factTotal > len(facts) || stats[db.KindFinding] > len(findings) {
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
		// Classify with the SOURCE task's own facts/findings: local yieldClass ids
		// never match a source node, which would mark every inherited yield as a
		// plain observation.
		sourceKinds := make(map[int64]string, len(facts)+len(findings))
		for _, fact := range facts {
			sourceKinds[fact.ID] = yieldClassOf(fact)
		}
		for _, finding := range findings {
			sourceKinds[finding.ID] = "high"
		}
		intentResults := compactIntents(recentDone, parentsOf, yieldsOf, func(id int64) string {
			return sourceKinds[id]
		})
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
			// The digest body is withheld (it may cover non-inheritable members), so
			// without a hint the planner sees an opaque box and cannot tell whether
			// the folded region is worth expanding. Attach the covered assets' ids so
			// it can match a digest to a host it is already working on.
			digestIDs := make([]int64, 0, len(cds))
			for _, cd := range cds {
				if id, ok := cd["id"].(int64); ok && id > 0 {
					digestIDs = append(digestIDs, id)
				}
			}
			assetLabels := t.digestAssetLabels(ts, digestIDs)
			for _, cd := range cds {
				cd["inherited"] = true
				cd["source_task_id"] = source.Task.TaskID
				// A digest body may summarize members that are non-inheritable;
				// expose only its id/member_count, never the source prose.
				delete(cd, "body")
				cd["body_withheld"] = "关联任务摘要正文不跨任务展开"
				if id, ok := cd["id"].(int64); ok {
					if labels := assetLabels[id]; len(labels) > 0 {
						cd["asset_labels"] = labels
					}
				}
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
