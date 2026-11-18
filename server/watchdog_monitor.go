package server

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"sync"
	"time"

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
	CycleStart       time.Time
	CycleNo          int
	PressureSent     bool
	SlowPathState    string
	DecisionState    string
	LeaseUntil       time.Time
	State            string
	Tool             string
	Facts            int
	Assets           int
	Findings         int
	ProviderError    string
	SlowPathClass    string
	SlowPathSummary  string
	SlowPathEvidence []string
	SlowPathCycle    int
	dirty            bool
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
	CycleStart       time.Time `json:"cycle_start"`
	CycleNo          int       `json:"cycle_no"`
	PressureSent     bool      `json:"pressure_sent"`
	SlowPathState    string    `json:"slow_path_state"`
	DecisionState    string    `json:"decision_state"`
	State            string    `json:"state"`
	Tool             string    `json:"tool,omitempty"`
	Facts            int       `json:"facts"`
	Assets           int       `json:"assets"`
	Findings         int       `json:"findings"`
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
		LastEventAt: r.LastEventAt, LastOutputAt: r.LastOutputAt, CycleStart: r.CycleStart,
		CycleNo: r.CycleNo, PressureSent: r.PressureSent, SlowPathState: r.SlowPathState,
		DecisionState: r.DecisionState, State: r.State, Tool: r.Tool,
		Facts: r.Facts, Assets: r.Assets, Findings: r.Findings,
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
		LastEventAt: now, CycleStart: now, CycleNo: 0,
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
		r.dirty = true
	case "tool_result":
		r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseLLM, "", now
		r.LastEventAt = now
		if !a.IsError {
			switch a.Tool {
			case "record_fact":
				r.Facts++
				m.markOutputLocked(r, now)
				if hadControl {
					reset = m.cycleResetSnapshot(r)
				}
			case "insert_assets":
				// 一次调用可以批量登记多条资产；结果里的 results 数组长度才是
				// 本次实际写入量。解析失败时按一次调用计 1，仍算有效写入。
				count := 1
				var out struct {
					Results []json.RawMessage `json:"results"`
				}
				if json.Unmarshal([]byte(a.Detail), &out) == nil && len(out.Results) > 0 {
					count = len(out.Results)
				}
				r.Assets += count
				m.markOutputLocked(r, now)
				if hadControl {
					reset = m.cycleResetSnapshot(r)
				}
			case "report_finding":
				r.Findings++
				m.markOutputLocked(r, now)
				if hadControl {
					reset = m.cycleResetSnapshot(r)
				}
			}
		}
	case "thinking", "text":
		r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseLLM, "", now
		r.LastEventAt = now
		r.dirty = true
	case "result":
		r.Phase, r.Tool, r.PhaseStartedAt = db.WorkerRunPhaseSettling, "", now
		r.LastEventAt = now
		if !a.IsError {
			m.markOutputLocked(r, now)
			if hadControl {
				reset = m.cycleResetSnapshot(r)
			}
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

// markOutputLocked records an effective write. It resets the cycle, so a worker
// that keeps producing facts/assets/findings gets a fresh 8/10/20 minute window
// instead of being terminated on cumulative runtime.
func (m *RunMonitor) markOutputLocked(r *runState, now time.Time) {
	r.LastOutputAt = now
	m.resetCycleLocked(r, now)
	r.dirty = true
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

// ResumeTask restarts the cycle timer on any run that survived a pause. In
// practice the pause cancels the run and it settles; this makes a fast resume
// safe without awarding a free cycle.
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
	snap := r.snapshot()
	m.mu.Unlock()
	m.save(snap)
}

// FinishTask settles every live run for a task (delete/shutdown path).
func (m *RunMonitor) FinishTask(taskID, state string) {
	if m == nil {
		return
	}
	var runIDs []string
	m.mu.Lock()
	for id, r := range m.runs {
		if r.TaskID == taskID && r.State == db.WorkerRunStateRunning {
			runIDs = append(runIDs, id)
		}
	}
	m.mu.Unlock()
	for _, id := range runIDs {
		m.Finish(id, state)
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
		Phase: s.Phase, CycleNo: s.CycleNo, PressureSent: s.PressureSent,
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
