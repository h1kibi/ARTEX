package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Fast Path 只做固定规则与计时：8 分钟压力提示、10 分钟创建 Slow Path 任务、
// 20 分钟按周期表推进或终止。语义判断全部交给 Slow Path；Fast Path 执行结果，
// 不调用模型。
const watchdogPressureText = "你到现在就做了这些工作？再没有有效进展将终止本次运行。请立即将已确认的有效进展、事实、资产或发现写回；不要编造未验证的内容。"

type cycleSignal string

const (
	cycleSignalGreen     cycleSignal = "green"
	cycleSignalTerminate cycleSignal = "terminate"
	cycleSignalAsk       cycleSignal = "ask"
	cycleSignalNone      cycleSignal = "none"
)

type cycleAnswer string

const (
	cycleAnswerNone cycleAnswer = "none"
	cycleAnswerYes  cycleAnswer = "yes"
	cycleAnswerNo   cycleAnswer = "no"
)

// watchdogDecisionPending is true while a card is open or answered but its
// action has not yet advanced/finished the run. Fast Path must not generate
// more pressure or Slow Path work in that window.
func watchdogDecisionPending(state string) bool {
	return state == db.WatchdogDecisionOpen || state == db.WatchdogDecisionAnswered
}

type cycleAction string

const (
	cycleActionNext      cycleAction = "next"
	cycleActionRequest   cycleAction = "request"
	cycleActionTerminate cycleAction = "terminate"
)

// cycleDecision is the pure result of one 20-minute boundary. Tests drive this
// table directly; the Fast Path only performs the requested I/O.
type cycleDecision struct {
	Action        cycleAction
	NextCycle     int
	RequestKind   string
	DefaultRule   string
	Reason        string
	TerminalState string
}

// decideCycle implements the autonomy budget table. autoUsed is the number of
// green-light advances already consumed by this run; cycleNo remains the current
// cycle label for user-default rules and audit messages.
func decideCycle(cycleNo, autoUsed, maxAutoCycles int, signal cycleSignal, answer cycleAnswer) cycleDecision {
	if maxAutoCycles < 1 {
		maxAutoCycles = 1
	}
	if maxAutoCycles > 4 {
		maxAutoCycles = 4
	}
	terminate := func(state, reason string) cycleDecision {
		return cycleDecision{Action: cycleActionTerminate, TerminalState: state, Reason: reason}
	}
	next := func(n int, reason string) cycleDecision {
		return cycleDecision{Action: cycleActionNext, NextCycle: n, Reason: reason}
	}
	request := func(n int, reason string) cycleDecision {
		rule := "c1_plus_terminate"
		if cycleNo == 0 {
			rule = "c0_continue"
		}
		return cycleDecision{
			Action: cycleActionRequest, NextCycle: n,
			RequestKind: db.WatchdogRequestAsk, DefaultRule: rule,
			Reason: reason,
		}
	}
	switch signal {
	case cycleSignalGreen:
		if autoUsed < maxAutoCycles {
			return next(cycleNo+1, fmt.Sprintf("C%d 慢速判断放绿灯，自主进入 C%d（预算 %d，已用 %d）",
				cycleNo, cycleNo+1, maxAutoCycles, autoUsed))
		}
		return request(cycleNo+1, fmt.Sprintf("已用完自主放行预算（%d），当前 C%d 生成下一周期用户请求",
			maxAutoCycles, cycleNo))
	case cycleSignalAsk:
		switch answer {
		case cycleAnswerYes:
			return next(cycleNo+1, fmt.Sprintf("用户明确同意进入 C%d", cycleNo+1))
		case cycleAnswerNo:
			return terminate("stopped", "用户明确拒绝继续，终止本运行")
		default:
			if cycleNo == 0 {
				return next(1, "C0 用户请求静默，默认同意进入 C1")
			}
			return terminate("exhausted", fmt.Sprintf("C%d 用户请求静默，按默认规则终止", cycleNo))
		}
	case cycleSignalTerminate:
		return terminate("stopped", "慢速判断要求终止")
	default:
		return terminate("exhausted", fmt.Sprintf("C%d 没有绿灯，也没有用户请求", cycleNo))
	}
}

// watchdogFast is the fixed-rule ticker. It never waits on the model: Slow Path
// work is enqueued and consumed by a separate goroutine, so a slow/unavailable
// Watchdog Agent cannot stall pressure delivery or cycle accounting.
type watchdogFast struct {
	s       *Server
	monitor *RunMonitor
	now     func() time.Time
}

func newWatchdogFast(s *Server, monitor *RunMonitor) *watchdogFast {
	return &watchdogFast{s: s, monitor: monitor, now: time.Now}
}

// Tick runs once per 5 seconds. Flush happens even while the watchdog is
// disabled, so worker_runs stays useful for the API and diagnostics.
func (f *watchdogFast) Tick(ctx context.Context) {
	if f == nil || f.s == nil || f.monitor == nil {
		return
	}
	f.monitor.Flush()
	if f.s.engine != nil {
		f.s.engine.SweepExpiredPeerRequests()
	}
	cfg := f.s.watchdogConfig()
	if !cfg.Enabled {
		return
	}
	now := f.now()
	for _, snap := range f.monitor.AllRunning() {
		if snap.State != db.WorkerRunStateRunning || snap.ProviderError != "" {
			continue
		}
		t, ok := f.s.m.Task(snap.TaskID)
		if !ok || !f.s.watchdogTaskActive(t) {
			continue
		}
		// 审批等待与供应商错误不属于停滞：一个在等人，一个由模型链处理。
		if snap.Phase == db.WorkerRunPhaseApproval || snap.Phase == db.WorkerRunPhasePaused ||
			snap.Phase == db.WorkerRunPhaseSettling {
			continue
		}
		cycleStart := snap.CycleStart
		if cycleStart.IsZero() {
			cycleStart = snap.HeartbeatAt
		}
		if cycleStart.IsZero() {
			continue
		}
		elapsed := now.Sub(cycleStart)
		// A user decision card owns this cycle. Do not inject another pressure
		// prompt or create another Slow Path job while it is open/answered but
		// not yet applied; the boundary still runs processCycle so silence
		// applies the documented default.
		decisionPending := watchdogDecisionPending(snap.DecisionState)

		if !decisionPending && !snap.PressureSent && elapsed >= cfg.PressureAfter {
			if err := f.s.engine.SteerWorkFrom(snap.IntentID, "watchdog", watchdogPressureText); err != nil {
				log.Printf("[watchdog] task %s 意图 #%d 压力提示未投递: %v", snap.TaskID, snap.IntentID, err)
			} else {
				f.monitor.SetPressureSent(snap.RunID)
				f.s.emitWatchdogActivity(t, "watchdog_pressure",
					fmt.Sprintf("已向意图 #%d 注入压力提示", snap.IntentID),
					watchdogPressureText, watchdogAudit{CycleNo: snap.CycleNo, Phase: snap.Phase})
				snap.PressureSent = true
			}
		}

		if !decisionPending && snap.SlowPathState == db.SlowPathNone && elapsed >= cfg.SlowPathAfter {
			snapshot, err := f.s.buildWatchdogSnapshot(t, snap)
			if err != nil {
				log.Printf("[watchdog] task %s 意图 #%d 组装慢速判断快照失败: %v", snap.TaskID, snap.IntentID, err)
			} else {
				job := &db.WatchdogJob{
					TaskID: snap.TaskID, IntentID: snap.IntentID, RunID: snap.RunID,
					CycleNo: snap.CycleNo, CycleStart: &cycleStart, Snapshot: snapshot,
				}
				if _, _, err := f.s.m.pg.EnqueueWatchdogJob(ctx, job); err != nil {
					log.Printf("[watchdog] task %s 意图 #%d 入队慢速判断失败: %v", snap.TaskID, snap.IntentID, err)
				} else {
					f.monitor.SetSlowPath(snap.RunID, db.SlowPathQueued, "", "", nil, snap.CycleNo)
					snap.SlowPathState = db.SlowPathQueued
					f.refreshUnavailableCard(ctx, t.ID)
				}
			}
		}

		if elapsed >= cfg.CycleAfter {
			f.processCycle(ctx, t, snap, cfg)
		}
	}
}

// refreshUnavailableCard updates an already-open task card with the current
// queue counts. It never creates a card: only a failed attempt to start the
// Watchdog Agent does that.
func (f *watchdogFast) refreshUnavailableCard(ctx context.Context, taskID string) {
	card, err := f.s.m.pg.OpenWatchdogUnavailable(ctx, taskID)
	if err != nil || card == nil {
		return
	}
	count, first, last, err := f.s.m.pg.WatchdogJobStats(ctx, taskID)
	if err != nil {
		return
	}
	_ = f.s.m.pg.RefreshOpenWatchdogUnavailable(ctx, taskID, count, first, last, card.NextRetryAt)
}

// processCycle reads the current card and Slow Path result, applies the pure
// cycle table, then performs exactly one action.
func (f *watchdogFast) processCycle(ctx context.Context, t *Task, snap RunSnapshot, cfg watchdogConfig) {
	ask, err := f.s.m.pg.LatestWatchdogAsk(ctx, snap.RunID, snap.CycleNo)
	if err != nil {
		log.Printf("[watchdog] task %s 意图 #%d 读取周期请求失败: %v", t.ID, snap.IntentID, err)
		return
	}
	signal, answer := cycleSignalNone, cycleAnswerNone
	if ask != nil {
		switch ask.Status {
		case db.WatchdogRequestOpen:
			signal = cycleSignalAsk
		case db.WatchdogRequestAnswered:
			signal = cycleSignalAsk
			switch ask.Answer {
			case "continue":
				answer = cycleAnswerYes
			case "stop":
				answer = cycleAnswerNo
			}
		default:
			// expired / superseded / cancelled: the card existed and was never
			// answered. Apply the cycle's silent default instead of falling back
			// to a later green light.
			signal = cycleSignalAsk
		}
	}
	if signal == cycleSignalNone && snap.SlowPathCycle == snap.CycleNo {
		switch snap.SlowPathClass {
		case "continue":
			signal = cycleSignalGreen
		case "terminate":
			signal = cycleSignalTerminate
		case "ask_user":
			signal = cycleSignalAsk
		case "provider_error":
			// 供应商错误由任务模型链处理，不进入周期判断，也不终止 worker。
			// 清空本轮 Slow Path 结果并重起计时，避免到点后每 5 秒空转重试。
			f.monitor.SetCycle(snap.RunID, snap.CycleNo, f.now(), false, db.SlowPathNone, db.WatchdogDecisionNone)
			return
		}
	}
	if signal == cycleSignalAsk && answer == cycleAnswerNone && ask == nil {
		// Slow Path 要求用户判断但卡片完全未创建（例如创建失败/服务重启）。
		// 在边界补一张卡，给它一个完整周期，而不是把"没有请求"当成静默终止。
		// 已经存在过期卡片时不补卡：周期表会按该周期的静默默认规则处理。
		result := f.createAsk(ctx, t, snap, cfg, true)
		if result == askCreated || result == askAlreadyExists {
			return
		}
		// Either the unavailable default card suppressed the worker ask or the
		// database write failed. The boundary still owns the rule: C0 silently
		// consents to C1, C1+ defaults to termination. Fall through and apply it
		// instead of leaving the Worker alive until the next tick.
	}
	decision := decideCycle(snap.CycleNo, snap.AutoCyclesUsed, cfg.MaxAutoCycles, signal, answer)
	switch decision.Action {
	case cycleActionNext:
		if ask != nil && ask.Status == db.WatchdogRequestOpen {
			answerText := "stop"
			if snap.CycleNo == 0 {
				answerText = "continue"
			}
			settled, err := f.s.m.pg.SettleWatchdogAsk(ctx, ask.ID, db.WatchdogRequestExpired, answerText, decision.Reason)
			if err != nil {
				log.Printf("[watchdog] task %s 结算周期请求失败: %v", t.ID, err)
				return
			}
			if !settled {
				return // 用户刚回答了同一张卡；由其选择路径推进
			}
		}
		f.advanceCycle(t, snap, decision.NextCycle, decision.Reason, signal == cycleSignalGreen)
	case cycleActionRequest:
		result := f.createAsk(ctx, t, snap, cfg, true)
		if result == askCreated || result == askAlreadyExists {
			return
		}
		// C2/C3+ green light needs a user card. The unavailable default card or a
		// database write failure prevented it; terminate at this boundary rather
		// than loop forever without a decision.
		reason := "Watchdog Agent 不可用，无法创建用户请求；按周期规则终止"
		if result == askCreateFailed {
			reason = "创建用户判断卡失败；按周期规则终止"
		}
		if _, err := f.terminate(ctx, t, snap, reason, "exhausted"); err != nil {
			log.Printf("[watchdog] task %s 意图 #%d 周期终止未生效: %v", t.ID, snap.IntentID, err)
		}
	case cycleActionTerminate:
		if ask != nil && ask.Status == db.WatchdogRequestOpen {
			answerText := "stop"
			if snap.CycleNo == 0 && decision.TerminalState == "exhausted" {
				answerText = "continue"
			}
			settled, err := f.s.m.pg.SettleWatchdogAsk(ctx, ask.ID, db.WatchdogRequestExpired, answerText, decision.Reason)
			if err != nil {
				log.Printf("[watchdog] task %s 结算周期请求失败: %v", t.ID, err)
				return
			}
			if !settled {
				return // 用户刚回答了同一张卡；由其选择路径处理
			}
		}
		reason := decision.Reason
		if snap.SlowPathClass == "terminate" && snap.SlowPathSummary != "" {
			reason = "慢速判断：" + snap.SlowPathSummary
			if snap.ProviderError == "" && len(snap.SlowPathEvidence) > 0 {
				reason += "（" + snap.SlowPathEvidence[0] + "）"
			}
		}
		if _, err := f.terminate(ctx, t, snap, reason, decision.TerminalState); err != nil {
			log.Printf("[watchdog] task %s 意图 #%d 周期终止未生效: %v", t.ID, snap.IntentID, err)
		}
	}
}

// advanceCycle grants the next cycle and restarts all three timers. The cycle
// number is monotonic for the run; effective output resets it to C0 separately.
func (f *watchdogFast) advanceCycle(t *Task, snap RunSnapshot, next int, reason string, autonomous bool) {
	if next <= snap.CycleNo {
		next = snap.CycleNo + 1
	}
	now := f.now()
	f.monitor.SetCycle(snap.RunID, next, now, false, db.SlowPathNone, db.WatchdogDecisionNone)
	if autonomous {
		f.monitor.RecordAutoAdvance(snap.RunID)
	}
	f.s.emitWatchdogActivity(t, "watchdog_cycle",
		fmt.Sprintf("意图 #%d 进入 C%d", snap.IntentID, next), reason,
		watchdogAudit{CycleNo: next, Phase: snap.Phase})
}

type askCreateResult int

const (
	askCreated askCreateResult = iota
	askAlreadyExists
	askBlockedUnavailable
	askCreateFailed
)

// createAsk opens the one user decision card for this run/cycle. C0 is created
// from a Slow Path ask; C2/C3+ are created by an automatic green light. The card
// deadline is the next cycle boundary, where silence applies the default rule.
// The result tells processCycle whether the unavailable default card prevented
// creation, so it can apply the cycle default instead of waiting forever.
func (f *watchdogFast) createAsk(ctx context.Context, t *Task, snap RunSnapshot, cfg watchdogConfig, resetCycle bool) askCreateResult {
	if unavailable, err := f.s.m.pg.OpenWatchdogUnavailable(ctx, t.ID); err == nil && unavailable != nil {
		// The task-level default card owns the screen while the judge is down.
		// Creating a worker ask here would reopen the exact card just closed.
		return askBlockedUnavailable
	}
	if existing, err := f.s.m.pg.OpenWatchdogAsk(ctx, snap.RunID, snap.CycleNo); err == nil && existing != nil {
		return askAlreadyExists
	}
	now := f.now()
	deadline := now.Add(cfg.CycleAfter)
	if !resetCycle {
		// Slow Path 在周期中途要求用户判断：默认截止时间仍是当前周期边界，
		// 不额外赠送一整个 20 分钟周期。边界已过（判断晚到）时改为从当前时刻
		// 起算一个完整周期，避免卡片没有对应的周期处理点。
		deadline = snap.CycleStart.Add(cfg.CycleAfter)
		if floor := now.Add(time.Minute); deadline.Before(floor) {
			resetCycle = true
			deadline = now.Add(cfg.CycleAfter)
		}
	}
	evidence, _ := json.Marshal(map[string]any{
		"phase": snap.Phase, "tool": snap.Tool,
		"last_output_at": optionalTime(snap.LastOutputAt),
		"cycle_no":       snap.CycleNo, "cycle_start": optionalTime(snap.CycleStart),
		"slow_path_class": snap.SlowPathClass, "slow_path_summary": snap.SlowPathSummary,
		"slow_path_evidence": snap.SlowPathEvidence,
		"facts":              snap.Facts, "assets": snap.Assets, "findings": snap.Findings,
	})
	options, _ := json.Marshal([]string{"continue", "stop"})
	window := fmt.Sprintf("%d 分钟", int(cfg.CycleAfter/time.Minute))
	if cfg.CycleAfter < time.Minute {
		window = fmt.Sprintf("%d 秒", int(cfg.CycleAfter/time.Second))
	}
	question := "是否申请额外 " + window + "？"
	card, created, err := f.s.m.pg.CreateWatchdogAsk(ctx, &db.WatchdogRequest{
		TaskID: t.ID, IntentID: &snap.IntentID, RunID: snap.RunID, CycleNo: snap.CycleNo,
		Kind: db.WatchdogRequestAsk, Question: question, Evidence: evidence, Options: options,
		DeadlineAt: &deadline, HardDeadlineAt: &deadline,
	})
	if err != nil {
		log.Printf("[watchdog] task %s 意图 #%d 创建用户请求失败: %v", t.ID, snap.IntentID, err)
		return askCreateFailed
	}
	if !created {
		if card != nil {
			return askAlreadyExists
		}
		return askCreateFailed
	}
	if card == nil {
		return askCreateFailed
	}
	if resetCycle {
		// The same run will start a new C0/current cycle at `now`; remove the old
		// (run, cycle) job so the next 10-minute enqueue is not suppressed by the
		// unique cycle key. The just-created ask is kept.
		if err := f.s.m.pg.DeleteWatchdogJobsForRun(ctx, snap.RunID); err != nil {
			log.Printf("[watchdog] task %s 意图 #%d 清理周期任务失败: %v", t.ID, snap.IntentID, err)
		}
		f.monitor.SetCycle(snap.RunID, snap.CycleNo, now, false, db.SlowPathNone, db.WatchdogDecisionOpen)
	} else {
		f.monitor.SetDecisionState(snap.RunID, db.WatchdogDecisionOpen)
	}
	f.s.emitWatchdogActivity(t, "watchdog_ask",
		fmt.Sprintf("意图 #%d 需要用户判断（C%d）", snap.IntentID, snap.CycleNo),
		question, watchdogAudit{CycleNo: snap.CycleNo, RequestID: card.ID, Phase: snap.Phase})
	return askCreated
}

// terminate is the only place Fast Path cancels a worker. The Engine validates
// the run id and waits until runIntent has committed the final state.
func (f *watchdogFast) terminate(ctx context.Context, t *Task, snap RunSnapshot, reason, terminalState string) (TerminationResult, error) {
	waitCtx, cancel := context.WithTimeout(ctx, watchdogSettlementWait+workControlWaitTimeout+5*time.Second)
	defer cancel()
	result, err := f.s.engine.TerminateWorkForCycle(waitCtx, snap.IntentID, snap.RunID, reason, terminalState, snap.CycleNo)
	if err != nil {
		return result, err
	}
	_ = f.s.m.pg.ExpireOpenWatchdogAsks(ctx, snap.RunID, snap.CycleNo, db.WatchdogRequestExpired,
		"stop", reason)
	return result, nil
}

// watchdogContinueCycle applies a user's "continue" answer immediately instead
// of waiting for the next 20-minute boundary: the granted cycle starts now.
func (s *Server) watchdogContinueCycle(t *Task, snap RunSnapshot, reason string) error {
	if s.watchdog == nil || s.watchdog.fast == nil {
		return fmt.Errorf("Watchdog 运行时未启动")
	}
	current := s.watchdog.monitor.LookupRun(snap.RunID)
	if current == nil || current.State != db.WorkerRunStateRunning || current.CycleNo != snap.CycleNo {
		return fmt.Errorf("该运行或周期已结束")
	}
	s.watchdog.fast.advanceCycle(t, *current, snap.CycleNo+1, reason, false)
	return nil
}

// watchdogTerminateCycle applies a user's "stop" answer immediately.
func (s *Server) watchdogTerminateCycle(t *Task, snap RunSnapshot, reason, terminalState string) (TerminationResult, error) {
	if s.watchdog == nil || s.watchdog.fast == nil {
		return TerminationResult{}, fmt.Errorf("Watchdog 运行时未启动")
	}
	current := s.watchdog.monitor.LookupRun(snap.RunID)
	if current == nil || current.State != db.WorkerRunStateRunning || current.CycleNo != snap.CycleNo {
		return TerminationResult{}, fmt.Errorf("该运行或周期已结束")
	}
	return s.watchdog.fast.terminate(s.ctx, t, *current, reason, terminalState)
}

// buildWatchdogSnapshot captures bounded evidence for the Slow Path. Details are
// fetched only for recent reasoning/tool-result rows; the trace itself is
// available to the agent through read-only tools.
func (s *Server) buildWatchdogSnapshot(t *Task, snap RunSnapshot) (json.RawMessage, error) {
	intent, err := t.Store.GetNode(snap.IntentID)
	if err != nil {
		return nil, err
	}
	acts, _, err := t.Store.ActivityList(&snap.IntentID, 0, 60)
	if err != nil {
		return nil, err
	}
	type step struct {
		Kind      string `json:"kind"`
		Tool      string `json:"tool,omitempty"`
		IsError   bool   `json:"is_error,omitempty"`
		Summary   string `json:"summary,omitempty"`
		Detail    string `json:"detail,omitempty"`
		CreatedAt string `json:"created_at"`
	}
	steps := make([]step, 0, 24)
	start := max(0, len(acts)-24)
	for _, a := range acts[start:] {
		item := step{Kind: a.Kind, Tool: a.Tool, IsError: a.IsError,
			Summary: preview(a.Summary, 300), CreatedAt: rfc3339(a.CreatedAt)}
		// 只取最近少量正文，避免慢速判断请求本身把上下文撑爆。
		if a.Kind == "thinking" || a.Kind == "tool_result" || a.Kind == "text" {
			if detail, err := t.Store.ActivityDetail(a.ID); err == nil && detail != "" {
				item.Detail = preview(detail, 4000)
			}
		}
		steps = append(steps, item)
	}
	snapshot := map[string]any{
		"task_id": t.ID, "goal": t.Goal, "description": t.Description,
		"intent_id": snap.IntentID, "intent": rawString(intent.Payload),
		"run_id": snap.RunID, "worker_name": snap.WorkerName,
		"phase": snap.Phase, "tool": snap.Tool,
		"phase_started_at": optionalTime(snap.PhaseStartedAt),
		"heartbeat_at":     optionalTime(snap.HeartbeatAt),
		"last_event_at":    optionalTime(snap.LastEventAt),
		"last_output_at":   optionalTime(snap.LastOutputAt),
		"cycle_no":         snap.CycleNo, "cycle_start": optionalTime(snap.CycleStart),
		"facts": snap.Facts, "assets": snap.Assets, "findings": snap.Findings,
		"recent_steps": steps,
	}
	return json.Marshal(snapshot)
}
