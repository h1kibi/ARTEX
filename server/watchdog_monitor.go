package server

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// RunMonitor keeps the hot-path state of every executing intent. It is the
// authoritative view while this process is alive: the activity stream is
// append-only and cannot answer "what phase is this worker in right now", and
// worker_runs alone would require a database write per tool event. The monitor
// updates memory on every event and flushes a snapshot on the Fast Path tick.
//
// All timestamps come from the injected clock so tests can drive the 8/10/20
// minute boundaries without sleeping.
type RunMonitor struct {
	pg *db.DB

	mu       sync.Mutex
	runs     map[string]*runState
	byIntent map[int64]string
	now      func() time.Time

	// onCycleReset runs after an effective write resets the cycle, outside the
	// monitor lock. The server uses it to supersede open asks and stale queued
	// jobs; tests can leave it nil.
	onCycleReset func(RunSnapshot)
	// onFinish runs exactly once per run, outside the monitor lock, after the
	// final state is persisted. It closes that run's control-plane leftovers.
	onFinish func(RunSnapshot)
}

type runState struct {
	TaskID           string
	IntentID         int64
	RunID            string
	WorkerName       string
	Phase            string
	PhaseStartedAt   time.Time
	HeartbeatAt      time.Time
	LastEventAt      time.Time
	LastOutputAt     time.Time
	LastHighValueAt  time.Time
	StartedAt        time.Time
	CycleStart       time.Time
	CycleNo          int
	AutoCyclesUsed   int
	PressureSent     bool
	SlowPathState    string
	DecisionState    string
	LeaseUntil       time.Time
	State            string
	Tool             string
	Facts            int
	Assets           int
	Findings         int
	ToolCalls        int
	InputTokens      int
	OutputTokens     int
	DuplicateActions int
	ProgressEvents   []string
	RouteID          int64
	RouteKind        string
	RoutePhase       string
	RouteObjective   string
	RouteBudget      db.RouteBudget
	RouteUsedBase    db.RouteBudgetUsed
	// EffortMaxAutoCycles is this run's autonomous green-light budget derived from
	// the intent's effort tier, and HasEffortMaxAutoCycles distinguishes "probe
	// allows 0 cycles" from "unset → use the global config".
	EffortMaxAutoCycles    int
	HasEffortMaxAutoCycles bool
	Effort                 string
	HumanInvolved          bool
	ProviderError          string
	SlowPathClass          string
	SlowPathSummary        string
	SlowPathEvidence       []string
	SlowPathCycle          int
	pendingTool            string
	pendingInput           string
	lastSignature          string
	lastSigCount           int
	lastPollSignature      string
	lastPollRepeat         int
	PollingRepeats         int
	dirty                  bool
	finishNotified         bool // the finish hook ran once for this run
}

// RunSnapshot is a copy of one run at a point in time. The Fast Path, API and
// termination result all read this shape instead of touching the live state.
type RunSnapshot struct {
	TaskID           string    `json:"task_id"`
	IntentID         int64     `json:"intent_id"`
	RunID            string    `json:"run_id"`
	WorkerName       string    `json:"worker_name"`
	Phase            string    `json:"phase"`
	PhaseStartedAt   time.Time `json:"phase_started_at"`
	HeartbeatAt      time.Time `json:"heartbeat_at"`
	LastEventAt      time.Time `json:"last_event_at"`
	LastOutputAt     time.Time `json:"last_output_at"`
	LastHighValueAt  time.Time `json:"last_high_value_at"`
	StartedAt        time.Time `json:"started_at"`
	CycleStart       time.Time `json:"cycle_start"`
	CycleNo          int       `json:"cycle_no"`
	AutoCyclesUsed   int       `json:"auto_cycles_used"`
	PressureSent     bool      `json:"pressure_sent"`
	SlowPathState    string    `json:"slow_path_state"`
	DecisionState    string    `json:"decision_state"`
	State            string    `json:"state"`
	Tool             string    `json:"tool,omitempty"`
	Facts            int       `json:"facts"`
	Assets           int       `json:"assets"`
	Findings         int       `json:"findings"`
	ToolCalls        int       `json:"tool_calls"`
	InputTokens      int       `json:"input_tokens"`
	OutputTokens     int       `json:"output_tokens"`
	DuplicateActions int       `json:"duplicate_actions"`
	// PollingRepeats counts consecutive normalized wait/poll actions (sleep N,
	// repeatedly reading slot_poll/slot_watch logs). >=2 is a zero-progress stall.
	PollingRepeats int                `json:"polling_repeats,omitempty"`
	ProgressEvents []string           `json:"progress_events,omitempty"`
	RouteID        int64              `json:"route_id,omitempty"`
	RouteKind      string             `json:"route_kind,omitempty"`
	RoutePhase     string             `json:"route_phase,omitempty"`
	RouteObjective string             `json:"route_objective,omitempty"`
	RouteBudget    db.RouteBudget     `json:"route_budget,omitempty"`
	RouteUsedBase  db.RouteBudgetUsed `json:"route_used_base,omitempty"`
	// Effort is the intent's run tier; EffortMaxAutoCycles its autonomous-cycle
	// budget (HasEffortMaxAutoCycles=false → fall back to config).
	Effort                 string `json:"effort,omitempty"`
	EffortMaxAutoCycles    int    `json:"effort_max_auto_cycles,omitempty"`
	HasEffortMaxAutoCycles bool   `json:"has_effort_max_auto_cycles,omitempty"`
	// HumanInvolved: the intent's route is human-owned (origin="human", a human
	// message, or a human "continue" decision). Such runs are exempt from
	// autonomous suspension and from silent cycle termination.
	HumanInvolved    bool      `json:"human_involved,omitempty"`
	ProviderError    string    `json:"provider_error,omitempty"`
	SlowPathClass    string    `json:"slow_path_class,omitempty"`
	SlowPathSummary  string    `json:"slow_path_summary,omitempty"`
	SlowPathEvidence []string  `json:"slow_path_evidence,omitempty"`
	SlowPathCycle    int       `json:"slow_path_cycle,omitempty"`
	LeaseUntil       time.Time `json:"lease_until,omitempty"`
}

func (r *runState) snapshot() RunSnapshot {
	evidence := append([]string(nil), r.SlowPathEvidence...)
	return RunSnapshot{
		TaskID: r.TaskID, IntentID: r.IntentID, RunID: r.RunID, WorkerName: r.WorkerName,
		Phase: r.Phase, PhaseStartedAt: r.PhaseStartedAt, HeartbeatAt: r.HeartbeatAt,
		LastEventAt: r.LastEventAt, LastOutputAt: r.LastOutputAt, LastHighValueAt: r.LastHighValueAt,
		StartedAt: r.StartedAt, CycleStart: r.CycleStart,
		CycleNo: r.CycleNo, AutoCyclesUsed: r.AutoCyclesUsed,
		PressureSent: r.PressureSent, SlowPathState: r.SlowPathState,
		DecisionState: r.DecisionState, State: r.State, Tool: r.Tool,
		Facts: r.Facts, Assets: r.Assets, Findings: r.Findings,
		ToolCalls: r.ToolCalls, InputTokens: r.InputTokens, OutputTokens: r.OutputTokens,
		DuplicateActions: r.DuplicateActions, PollingRepeats: r.PollingRepeats,
		ProgressEvents: append([]string(nil), r.ProgressEvents...),
		RouteID:        r.RouteID, RouteKind: r.RouteKind, RoutePhase: r.RoutePhase,
		RouteObjective: r.RouteObjective, RouteBudget: r.RouteBudget, RouteUsedBase: r.RouteUsedBase,
		Effort: r.Effort, EffortMaxAutoCycles: r.EffortMaxAutoCycles,
		HasEffortMaxAutoCycles: r.HasEffortMaxAutoCycles, HumanInvolved: r.HumanInvolved,
		ProviderError: r.ProviderError, SlowPathClass: r.SlowPathClass,
		SlowPathSummary: r.SlowPathSummary, SlowPathEvidence: evidence,
		SlowPathCycle: r.SlowPathCycle, LeaseUntil: r.LeaseUntil,
	}
}

// NewRunMonitor builds an empty monitor. now may be nil (wall clock); tests pass
// a controllable clock. pg may be nil in unit tests, in which case persistence is
// skipped and only the in-memory state matters.
func NewRunMonitor(pg *db.DB, now func() time.Time) *RunMonitor {
	if now == nil {
		now = time.Now
	}
	return &RunMonitor{
		pg:   pg,
		runs: map[string]*runState{}, byIntent: map[int64]string{},
		now: now,
	}
}

func (m *RunMonitor) writeCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

// Register starts one run and immediately persists its row. The lease is
// refreshed by Flush; it only marks the row as maintained by a live process.
func (m *RunMonitor) Register(taskID string, intentID int64, runID, workerName string) RunSnapshot {
	now := m.now()
	m.mu.Lock()
	state := &runState{
		TaskID: taskID, IntentID: intentID, RunID: runID, WorkerName: workerName,
		Phase: db.WorkerRunPhaseIdle, PhaseStartedAt: now, HeartbeatAt: now,
		LastEventAt: now, StartedAt: now, CycleStart: now, CycleNo: 0,
		SlowPathState: db.SlowPathNone, DecisionState: db.WatchdogDecisionNone,
		LeaseUntil: now.Add(runMonitorLease), State: db.WorkerRunStateRunning,
		dirty: true,
	}
	m.runs[runID] = state
	m.byIntent[intentID] = runID
	snap := state.snapshot()
	m.mu.Unlock()
	m.save(snap)
	return snap
}

const runMonitorLease = 30 * time.Second

// SetRoute attaches the intent's route identity and the cumulative budget already
// consumed by earlier runs on the same route. Fast Path reads this without a DB
// query every 5 seconds; the checkpoint remains the durable source.
func (m *RunMonitor) SetRoute(runID string, route db.IntentRoute) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.RouteID = route.RouteID
		r.RouteKind = route.RouteKind
		r.RoutePhase = route.PathPhase
		r.RouteObjective = route.Objective
		r.RouteBudget = route.Budget
		r.RouteUsedBase = route.BudgetUsed
		r.dirty = true
	}
	m.mu.Unlock()
}

// SetHumanInvolved refreshes a LIVE run's human-owned flag. Human ownership can
// start mid-run — the operator sends a guidance message to the running worker, or
// answers "continue" on its Watchdog card — and from that moment the run must be
// exempt from autonomous suspension and silent cycle termination. Reading the flag
// only at registration would let a run a human just took over be killed silently.
func (m *RunMonitor) SetHumanInvolved(runID string, humanInvolved bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil && r.HumanInvolved != humanInvolved {
		r.HumanInvolved = humanInvolved
		r.dirty = true
	}
	m.mu.Unlock()
}

// HumanInvolvedRun reports the current flag for one live run.
func (m *RunMonitor) HumanInvolvedRun(runID string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.runs[runID]; r != nil {
		return r.HumanInvolved
	}
	return false
}

// SetEffort attaches the intent's run tier and its autonomous-cycle budget to
// the run. probe passes 0 cycles explicitly: deciding not to grant any cycle is
// a decision, and collapsing it into "unset" would silently hand the run the
// global default. Called once at run registration, before any cycle boundary.
func (m *RunMonitor) SetEffort(runID, effort string, maxAutoCycles int, humanInvolved bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.Effort = effort
		r.EffortMaxAutoCycles = maxAutoCycles
		r.HasEffortMaxAutoCycles = true
		r.HumanInvolved = humanInvolved
		r.dirty = true
	}
	m.mu.Unlock()
}

// HeartbeatTask refreshes the heartbeat for every live run of a task. The worker
// loop calls it on each iteration, so a long tool call still proves the worker
// goroutine is alive; Fast Path also flushes it to the database.
func (m *RunMonitor) HeartbeatTask(taskID string) {
	if m == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	for _, r := range m.runs {
		if r.TaskID == taskID && r.State == db.WorkerRunStateRunning {
			r.HeartbeatAt = now
		}
	}
	m.mu.Unlock()
}

// Phase records a model/tool/approval phase transition. Changing into or out of
// the approval gate resets the cycle timer: waiting for a human is not a stall,
// and the worker should get a full interval afterwards.
func (m *RunMonitor) Phase(runID, phase, tool string) {
	if m == nil {
		return
	}
	now := m.now()
	var reset *RunSnapshot
	m.mu.Lock()
	r := m.runs[runID]
	if r == nil {
		m.mu.Unlock()
		return
	}
	wasApproval := r.Phase == db.WorkerRunPhaseApproval
	hadControl := r.SlowPathState != db.SlowPathNone || r.DecisionState != db.WatchdogDecisionNone
	if phase != r.Phase || tool != r.Tool {
		r.Phase = phase
		r.Tool = tool
		r.PhaseStartedAt = now
		r.dirty = true
	}
	r.LastEventAt = now
	if wasApproval && phase != db.WorkerRunPhaseApproval {
		m.resetCycleLocked(r, now)
		if hadControl {
			reset = m.cycleResetSnapshot(r)
		}
	}
	m.mu.Unlock()
	if reset != nil && m.onCycleReset != nil {
		m.onCycleReset(*reset)
	}
}

// Observe maps one activity record to phase/output bookkeeping. It is called
// from the same goroutine that writes activity, so ordering matches the trace.
func (m *RunMonitor) Observe(runID string, a db.Activity) {
	if m == nil {
		return
	}
	now := m.now()
	var reset *RunSnapshot
	m.mu.Lock()
	r := m.runs[runID]
	if r == nil {
		m.mu.Unlock()
		return
	}
	wasApproval := r.Phase == db.WorkerRunPhaseApproval
	hadControl := r.SlowPathState != db.SlowPathNone || r.DecisionState != db.WatchdogDecisionNone
	switch a.Kind {
	case "tool_use":
		r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseTool, a.Tool, now
		r.LastEventAt = now
		r.ToolCalls++
		r.pendingTool, r.pendingInput = a.Tool, a.Detail
		sig := a.Tool + "\x00" + firstLine(a.Detail, 4096)
		if sig == r.lastSignature {
			r.lastSigCount++
			r.DuplicateActions++
			m.appendProgressLocked(r, "duplicate_action")
		} else {
			r.lastSignature, r.lastSigCount = sig, 1
		}
		// 归一化的"长时等待/轮询"识别：sleep/Start-Sleep 的具体秒数不同、但都是空等；
		// 反复读 slot_poll/slot_watch/tail 日志也一样。把它们折算成同一个签名，否则
		// "sleep 30 / sleep 60 / sleep 90" 永远不算重复，worker 可以整周期空转不被发现。
		if wait := normalizePollingAction(a.Tool, a.Detail); wait != "" {
			pollSig := "polling\x00" + wait
			if pollSig == r.lastPollSignature {
				r.lastPollRepeat++
				r.DuplicateActions++
				m.appendProgressLocked(r, "duplicate_action")
			} else {
				r.lastPollSignature, r.lastPollRepeat = pollSig, 1
			}
			// 同一空等动作重复出现即"零实质推进"：Fast Path 的 terminate 判据直接读它。
			r.PollingRepeats = r.lastPollRepeat
		} else {
			// Real work between waits breaks the run of polling actions; otherwise a
			// worker alternating sleep/curl/sleep would never look like a loop.
			r.lastPollSignature, r.lastPollRepeat, r.PollingRepeats = "", 0, 0
		}
		r.dirty = true
	case "tool_result":
		r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseLLM, "", now
		r.LastEventAt = now
		if !a.IsError {
			switch a.Tool {
			case "record_fact":
				r.Facts++
				factType := agent.FactTypeFromInput(json.RawMessage(r.pendingInput))
				event := progressEventFromInput(json.RawMessage(r.pendingInput))
				if event == "" {
					switch factType {
					case db.FactTypeObservation:
						event = "observation"
					case db.FactTypeClaim:
						event = "new_claim"
					case db.FactTypeHypothesis:
						event = "hypothesis"
					case db.FactTypeFindingCandidate:
						event = "new_claim"
					}
				}
				m.markOutputLocked(r, now)
				if event != "" {
					m.appendProgressLocked(r, event)
				}
				if agent.IsHighValueProgress(event) {
					m.markHighValueLocked(r, now)
					if hadControl {
						reset = m.cycleResetSnapshot(r)
					}
				}
			case "insert_assets":
				// 一次调用可以批量登记多条资产；结果里的 results 数组长度才是
				// 本次实际写入量。解析失败时按一次调用计 1。
				count := 1
				var out struct {
					Results []json.RawMessage `json:"results"`
				}
				if json.Unmarshal([]byte(a.Detail), &out) == nil && len(out.Results) > 0 {
					count = len(out.Results)
				}
				r.Assets += count
				m.markOutputLocked(r, now)
				m.appendProgressLocked(r, "new_asset")
			case "report_finding":
				r.Findings++
				m.markOutputLocked(r, now)
				m.appendProgressLocked(r, "finding_written")
				m.markHighValueLocked(r, now)
				if hadControl {
					reset = m.cycleResetSnapshot(r)
				}
			}
		}
		r.pendingTool, r.pendingInput = "", ""
	case "thinking", "text":
		r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseLLM, "", now
		r.LastEventAt = now
		r.dirty = true
	case "usage", "result":
		// Usage frames are cumulative for the run; keep the latest frame instead of
		// summing them. A result frame also closes the current phase.
		if a.Kind == "result" {
			r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseSettling, "", now
		}
		if a.InputTokens != nil {
			r.InputTokens = *a.InputTokens
		}
		if a.OutputTokens != nil {
			r.OutputTokens = *a.OutputTokens
		}
		r.LastEventAt = now
		if !a.IsError {
			m.markOutputLocked(r, now)
		}
	case "intercept_request":
		r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseApproval, "", now
		r.LastEventAt = now
		r.dirty = true
	}
	if wasApproval && r.Phase != db.WorkerRunPhaseApproval {
		m.resetCycleLocked(r, now)
		if reset == nil && hadControl {
			reset = m.cycleResetSnapshot(r)
		}
	}
	m.mu.Unlock()
	if reset != nil && m.onCycleReset != nil {
		m.onCycleReset(*reset)
	}
}

// markOutputLocked records a write without restoring the observation timer.
// Ordinary facts and assets are useful output, but only a high-value ProgressEvent
// (validated weakness, privilege change, objective milestone, finding) resets the
// cycle. AutoCyclesUsed remains a run-wide budget and survives every reset.
func (m *RunMonitor) markOutputLocked(r *runState, now time.Time) {
	r.LastOutputAt = now
	r.dirty = true
}

func (m *RunMonitor) markHighValueLocked(r *runState, now time.Time) {
	r.LastOutputAt = now
	r.LastHighValueAt = now
	m.resetCycleLocked(r, now)
	r.dirty = true
}

func (m *RunMonitor) appendProgressLocked(r *runState, event string) {
	if event == "" {
		return
	}
	r.ProgressEvents = append(r.ProgressEvents, event)
	if len(r.ProgressEvents) > 20 {
		r.ProgressEvents = r.ProgressEvents[len(r.ProgressEvents)-20:]
	}
	r.dirty = true
}

// pollingSignature normalizes a wait/poll action so repeats are visible: the sleep
// duration is dropped (sleep 30 and sleep 600 are the same non-progress act), and
// log-tail/read probes are folded onto their target. Returns "" for actions that
// are real work.
func normalizePollingAction(tool, detail string) string {
	if tool != "Bash" && tool != "sleep" && tool != "Monitor" {
		return ""
	}
	// The SDK's dedicated sleep tool carries {"seconds":N}, not a command; it is a
	// wait by definition regardless of its argument shape.
	if tool == "sleep" {
		return "sleep"
	}
	trimmed := strings.TrimSpace(detail)
	// A tool_use activity carries the tool's RAW JSON input ("{""command"":""sleep
	// 300...""}"), not bare shell text. Matching against the JSON wrapper would make
	// every HasPrefix check false and hide exactly the sleeps/polls this gate exists for.
	if strings.HasPrefix(trimmed, "{") {
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal([]byte(trimmed), &in) == nil && strings.TrimSpace(in.Command) != "" {
			trimmed = strings.TrimSpace(in.Command)
		}
	}
	cmd := strings.ToLower(trimmed)
	if cmd == "" {
		return ""
	}
	if strings.HasPrefix(cmd, "start-sleep") || strings.Contains(cmd, "start-sleep ") ||
		strings.HasPrefix(cmd, "timeout /t") || strings.Contains(cmd, "ping -n") {
		return "sleep"
	}
	if strings.HasPrefix(cmd, "sleep ") || strings.Contains(cmd, "&& sleep ") || strings.Contains(cmd, "; sleep ") {
		return "sleep"
	}
	// waiting on another worker's slot / log instead of doing work
	for _, needle := range []string{"slot_poll", "slot_watch", "slot-", "worker.wait", "wait_for_slot"} {
		if strings.Contains(cmd, needle) {
			return "slot-wait"
		}
	}
	if strings.HasPrefix(cmd, "tail ") && strings.Contains(cmd, "log") {
		return "log-tail"
	}
	return ""
}

func progressEventFromInput(raw json.RawMessage) string {
	var a struct {
		ProgressEvent string `json:"progress_event"`
		Facts         []struct {
			ProgressEvent string `json:"progress_event"`
		} `json:"facts"`
	}
	if json.Unmarshal(raw, &a) != nil {
		return ""
	}
	if a.ProgressEvent != "" {
		return a.ProgressEvent
	}
	for _, f := range a.Facts {
		if f.ProgressEvent != "" {
			return f.ProgressEvent
		}
	}
	return ""
}

func (m *RunMonitor) resetCycleLocked(r *runState, now time.Time) {
	r.CycleNo = 0
	r.CycleStart = now
	r.PressureSent = false
	r.SlowPathState = db.SlowPathNone
	r.DecisionState = db.WatchdogDecisionNone
	r.SlowPathClass = ""
	r.SlowPathSummary = ""
	r.SlowPathEvidence = nil
	r.SlowPathCycle = 0
	r.ProviderError = ""
}

func (m *RunMonitor) cycleResetSnapshot(r *runState) *RunSnapshot {
	s := r.snapshot()
	return &s
}

// SetCycle persists an advanced/request cycle state. It is used by the Fast Path
// after it has already committed the corresponding request/job rows.
func (m *RunMonitor) SetCycle(runID string, cycleNo int, cycleStart time.Time, pressure bool, slowState, decisionState string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.CycleNo = cycleNo
		r.CycleStart = cycleStart
		r.PressureSent = pressure
		r.SlowPathState = slowState
		r.DecisionState = decisionState
		r.SlowPathClass = ""
		r.SlowPathSummary = ""
		r.SlowPathEvidence = nil
		r.SlowPathCycle = 0
		r.dirty = true
	}
	m.mu.Unlock()
}

// RecordAutoAdvance increments the run's count of cycles advanced by a green
// Watchdog judgment. User-approved cycles use SetCycle without this call, so
// the displayed remaining autonomy budget tracks real automatic advances.
func (m *RunMonitor) RecordAutoAdvance(runID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.AutoCyclesUsed++
		r.dirty = true
	}
	m.mu.Unlock()
}

// SetDecisionState records that a decision card is open without moving the
// cycle timer. Slow Path may ask for a user decision mid-cycle; the card must
// expire at the existing cycle boundary, not receive a fresh full interval.
func (m *RunMonitor) SetDecisionState(runID, state string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.DecisionState = state
		r.dirty = true
	}
	m.mu.Unlock()
}

// SetPressureSent marks the current cycle's one pressure prompt as delivered.
// It must not touch the slow-path result, which may already be queued/running.
func (m *RunMonitor) SetPressureSent(runID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.PressureSent = true
		r.dirty = true
	}
	m.mu.Unlock()
}

// SetSlowPath records a completed judgment. The cycle number and start are kept
// so a late result can be identified as stale.
func (m *RunMonitor) SetSlowPath(runID, state, class, summary string, evidence []string, cycleNo int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.SlowPathState = state
		r.SlowPathClass = class
		r.SlowPathSummary = summary
		r.SlowPathEvidence = append([]string(nil), evidence...)
		r.SlowPathCycle = cycleNo
		r.dirty = true
	}
	m.mu.Unlock()
}

// SetProviderError marks the run as failing in the provider path. Fast Path
// skips it: provider errors belong to the task model chain, not to Watchdog.
func (m *RunMonitor) SetProviderError(runID, message string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.ProviderError = message
		r.dirty = true
	}
	m.mu.Unlock()
}

// PauseTask marks live runs as paused. The timer still exists, but Fast Path
// reads the engine's pause flag and performs no actions.
func (m *RunMonitor) PauseTask(taskID string) {
	m.setTaskPhase(taskID, db.WorkerRunPhasePaused)
}

// SettlingTask marks live runs as settling before the task timeout drain.
func (m *RunMonitor) SettlingTask(taskID string) {
	m.setTaskPhase(taskID, db.WorkerRunPhaseSettling)
}

func (m *RunMonitor) setTaskPhase(taskID, phase string) {
	if m == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	for _, r := range m.runs {
		if r.TaskID == taskID && r.State == db.WorkerRunStateRunning {
			r.Phase = phase
			r.PhaseStartedAt = now
			r.dirty = true
		}
	}
	m.mu.Unlock()
}

// ResumeTask restarts the cycle timer on any run that survived a pause. The
// run-wide autonomous budget remains consumed; resuming does not award cycles.
func (m *RunMonitor) ResumeTask(taskID string) {
	if m == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	for _, r := range m.runs {
		if r.TaskID == taskID && r.State == db.WorkerRunStateRunning {
			r.Phase = db.WorkerRunPhaseLLM
			r.PhaseStartedAt = now
			r.CycleStart = now
			r.PressureSent = false
			r.SlowPathState = db.SlowPathNone
			r.DecisionState = db.WatchdogDecisionNone
			r.dirty = true
		}
	}
	m.mu.Unlock()
}

// Finish settles one run and makes Lookup stop returning it. The row is kept for
// diagnostics; the monitor map retains it until the task is removed or the
// process restarts.
func (m *RunMonitor) Finish(runID, state string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	r := m.runs[runID]
	if r == nil {
		m.mu.Unlock()
		return
	}
	if state == "" {
		state = db.WorkerRunStateFinished
	}
	r.State = state
	r.LeaseUntil = time.Time{}
	if m.byIntent[r.IntentID] == runID {
		delete(m.byIntent, r.IntentID)
	}
	notify := !r.finishNotified
	r.finishNotified = true
	snap := r.snapshot()
	m.mu.Unlock()
	m.save(snap)
	if notify && m.onFinish != nil {
		m.onFinish(snap)
	}
}

// FinishTask settles every live run for a task. Memory state changes atomically
// under one lock; persistence is one batch update and each once-only finish hook
// runs outside the lock with the final snapshot.
func (m *RunMonitor) FinishTask(taskID, state string) {
	if m == nil {
		return
	}
	if state == "" {
		state = db.WorkerRunStateFinished
	}
	var snapshots []RunSnapshot
	var runIDs []string
	m.mu.Lock()
	for id, r := range m.runs {
		if r.TaskID != taskID || r.State != db.WorkerRunStateRunning {
			continue
		}
		r.State = state
		r.LeaseUntil = time.Time{}
		if m.byIntent[r.IntentID] == id {
			delete(m.byIntent, r.IntentID)
		}
		if !r.finishNotified {
			r.finishNotified = true
			snapshots = append(snapshots, r.snapshot())
			runIDs = append(runIDs, id)
		}
	}
	m.mu.Unlock()

	if len(runIDs) == 0 {
		return
	}
	if m.pg != nil {
		ctx, cancel := m.writeCtx()
		if err := m.pg.FinishWorkerRuns(ctx, runIDs, state); err != nil {
			log.Printf("[watchdog] 批量结束任务运行失败 task=%s: %v", taskID, err)
		}
		cancel()
	}
	if m.onFinish != nil {
		for _, snap := range snapshots {
			m.onFinish(snap)
		}
	}
}

// RemoveTask drops all in-memory rows for a task. Database rows are removed by
// the caller in the same deletion/archive transaction.
func (m *RunMonitor) RemoveTask(taskID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	for id, r := range m.runs {
		if r.TaskID == taskID {
			delete(m.runs, id)
			if m.byIntent[r.IntentID] == id {
				delete(m.byIntent, r.IntentID)
			}
		}
	}
	m.mu.Unlock()
}

// Lookup returns the currently running snapshot for an intent, or nil.
func (m *RunMonitor) Lookup(intentID int64) *RunSnapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byIntent[intentID]
	if !ok {
		return nil
	}
	r := m.runs[id]
	if r == nil || r.State != db.WorkerRunStateRunning {
		return nil
	}
	s := r.snapshot()
	return &s
}

// LookupRun returns a snapshot by run id, including finished rows (history).
func (m *RunMonitor) LookupRun(runID string) *RunSnapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[runID]
	if r == nil {
		return nil
	}
	s := r.snapshot()
	return &s
}

// AllRunning returns every live run across tasks, ordered by task and intent.
func (m *RunMonitor) AllRunning() []RunSnapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RunSnapshot
	for _, r := range m.runs {
		if r.State == db.WorkerRunStateRunning {
			out = append(out, r.snapshot())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TaskID == out[j].TaskID {
			return out[i].IntentID < out[j].IntentID
		}
		return out[i].TaskID < out[j].TaskID
	})
	return out
}

// ListRunning returns every live run for a task, ordered by intent id.
func (m *RunMonitor) ListRunning(taskID string) []RunSnapshot {
	return m.list(taskID, true)
}

func (m *RunMonitor) list(taskID string, runningOnly bool) []RunSnapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RunSnapshot
	for _, r := range m.runs {
		if r.TaskID != taskID {
			continue
		}
		if runningOnly && r.State != db.WorkerRunStateRunning {
			continue
		}
		out = append(out, r.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IntentID < out[j].IntentID })
	return out
}

// Flush persists dirty snapshots and refreshes the heartbeat/lease of every live
// run. It is called from the Fast Path tick; errors are logged and retried on
// the next tick instead of failing the worker.
func (m *RunMonitor) Flush() {
	if m == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	var dirty []RunSnapshot
	var live []string
	for id, r := range m.runs {
		if r.State != db.WorkerRunStateRunning {
			continue
		}
		// Fast Path is the process's liveness tick: update the in-memory
		// heartbeat too, otherwise a long tool call leaves the API/agent snapshot
		// showing the time of the last activity event.
		r.HeartbeatAt = now
		r.LeaseUntil = now.Add(runMonitorLease)
		live = append(live, id)
		if r.dirty {
			dirty = append(dirty, r.snapshot())
			r.dirty = false
		}
	}
	m.mu.Unlock()
	if m.pg == nil {
		return
	}
	ctx, cancel := m.writeCtx()
	defer cancel()
	if err := m.pg.TouchWorkerRuns(ctx, live, now, now.Add(runMonitorLease)); err != nil {
		log.Printf("[watchdog] 刷新运行心跳失败: %v", err)
	} else if err := m.pg.PurgeExpiredWorkerRuns(ctx, now); err != nil {
		log.Printf("[watchdog] 清理过期运行记录失败: %v", err)
	}
	for i := range dirty {
		// Finish may have committed the final row while this snapshot was being
		// written. Never resurrect a finished run as "running"; the monitor state
		// is authoritative for liveness.
		m.mu.Lock()
		current := m.runs[dirty[i].RunID]
		stillRunning := current != nil && current.State == db.WorkerRunStateRunning
		m.mu.Unlock()
		if !stillRunning {
			continue
		}
		if err := m.pg.SaveWorkerRun(ctx, runRowFromSnapshot(dirty[i])); err != nil {
			log.Printf("[watchdog] 保存运行快照失败 run=%s: %v", dirty[i].RunID, err)
			m.markDirty(dirty[i].RunID)
			continue
		}
		// A Finish can land between the liveness check above and this write.
		// Re-read once and let the finished row win.
		m.mu.Lock()
		latest := m.runs[dirty[i].RunID]
		var final *RunSnapshot
		if latest != nil && latest.State != db.WorkerRunStateRunning {
			snap := latest.snapshot()
			final = &snap
		}
		m.mu.Unlock()
		if final != nil {
			m.save(*final)
		}
	}
}

func (m *RunMonitor) markDirty(runID string) {
	m.mu.Lock()
	if r := m.runs[runID]; r != nil {
		r.dirty = true
	}
	m.mu.Unlock()
}

func (m *RunMonitor) save(snap RunSnapshot) {
	if m == nil || m.pg == nil {
		return
	}
	ctx, cancel := m.writeCtx()
	defer cancel()
	if err := m.pg.SaveWorkerRun(ctx, runRowFromSnapshot(snap)); err != nil {
		log.Printf("[watchdog] 保存运行记录失败 run=%s: %v", snap.RunID, err)
	}
}

func runRowFromSnapshot(s RunSnapshot) *db.WorkerRun {
	row := &db.WorkerRun{
		TaskID: s.TaskID, IntentID: s.IntentID, RunID: s.RunID, WorkerName: s.WorkerName,
		Phase: s.Phase, CycleNo: s.CycleNo, AutoCyclesUsed: s.AutoCyclesUsed,
		PressureSent:  s.PressureSent,
		SlowPathState: s.SlowPathState, DecisionState: s.DecisionState, State: s.State,
	}
	set := func(dst **time.Time, value time.Time) {
		if !value.IsZero() {
			t := value
			*dst = &t
		}
	}
	set(&row.PhaseStartedAt, s.PhaseStartedAt)
	set(&row.HeartbeatAt, s.HeartbeatAt)
	set(&row.LastEventAt, s.LastEventAt)
	set(&row.LastOutputAt, s.LastOutputAt)
	set(&row.CycleStart, s.CycleStart)
	set(&row.LeaseUntil, s.LeaseUntil)
	return row
}

// SetCycleResetHook installs the post-output callback. It must be called before
// runs start (server construction); no locking is needed after that.
func (m *RunMonitor) SetCycleResetHook(fn func(RunSnapshot)) { m.onCycleReset = fn }

// SetFinishHook installs the once-per-run cleanup callback. It must be called
// before runs start (server construction).
func (m *RunMonitor) SetFinishHook(fn func(RunSnapshot)) { m.onFinish = fn }
