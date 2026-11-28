package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// errWatchdogRunMismatch separates a stale termination (the intent now runs a
// different run id) from ordinary control contention. The HTTP layer maps both
// to 409, but the log and tests can tell them apart.
var errWatchdogRunMismatch = errors.New("watchdog termination run mismatch")

// watchdogAbortCause returns the named cause only when it came from a Watchdog
// control path. Planner kill, pause, delete and timeout keep their existing
// settlement branches.
func watchdogAbortCause(err error) *agent.AbortCause {
	var cause *agent.AbortCause
	if errors.As(err, &cause) &&
		(cause.Code == "killed_by_watchdog" || cause.Code == "watchdog_cycle_ended") {
		return cause
	}
	return nil
}

// TerminationResult is the settled explanation the Fast Path writes into the
// system audit and hands to the Planner trigger. Counts are captured before the
// run leaves the monitor, so they describe this run rather than the intent's
// whole history.
type TerminationResult struct {
	IntentID     int64     `json:"intent_id"`
	RunID        string    `json:"run_id"`
	State        string    `json:"state"`
	Reason       string    `json:"reason"`
	LastOutputAt time.Time `json:"last_output_at"`
	Phase        string    `json:"phase"`
	CycleNo      int       `json:"cycle_no"`
	Facts        int       `json:"facts"`
	Assets       int       `json:"assets"`
	Findings     int       `json:"findings"`
	ActivityID   int64     `json:"activity_id"`
}

// watchdogAudit is the metadata carried by watchdog_* activities and the
// provider_error activity. The frontend uses it to render structured cards
// without re-parsing the free-text summary.
type watchdogAudit struct {
	Classification string    `json:"classification,omitempty"`
	CycleNo        int       `json:"cycle_no,omitempty"`
	State          string    `json:"state,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	LastOutputAt   time.Time `json:"last_output_at,omitempty"`
	Phase          string    `json:"phase,omitempty"`
	Facts          int       `json:"facts,omitempty"`
	Assets         int       `json:"assets,omitempty"`
	Findings       int       `json:"findings,omitempty"`
	RequestID      int64     `json:"request_id,omitempty"`
	AlertCount     int       `json:"alert_count,omitempty"`
	ProviderKind   string    `json:"provider_kind,omitempty"`
	Evidence       []string  `json:"evidence,omitempty"`
}

type watchdogActivityMetadata struct {
	Watchdog *watchdogAudit `json:"watchdog,omitempty"`
}

func marshalWatchdogMetadata(a watchdogAudit) json.RawMessage {
	raw, _ := json.Marshal(watchdogActivityMetadata{Watchdog: &a})
	return raw
}

// TerminateOptions carries the authority behind one termination request.
type TerminateOptions struct {
	// CycleNo, when >= 0, requires the run's current cycle to match.
	CycleNo int
	// HumanStop marks an operator's explicit "stop". It is the one authority that
	// overrides human involvement: that IS the human's decision, not an autonomous
	// judgement.
	HumanStop bool
}

// TerminateWork stops exactly one live run. runID is matched before the cancel
// so a late result from an older run can never stop a newer one. The caller
// waits until runIntent has committed the final state and activity, not merely
// until the context is cancelled.
func (e *Engine) TerminateWork(ctx context.Context, intentID int64, runID, reason, terminalState string) (TerminationResult, error) {
	return e.terminateWork(ctx, intentID, runID, reason, terminalState, TerminateOptions{CycleNo: -1})
}

// TerminateWorkForCycle additionally requires the run's current cycle to match.
// A late Slow Path result must not terminate a cycle that has already advanced
// after an effective write. cycleNo < 0 skips the check (Planner/UI callers).
func (e *Engine) TerminateWorkForCycle(ctx context.Context, intentID int64, runID, reason, terminalState string, cycleNo int) (TerminationResult, error) {
	return e.terminateWork(ctx, intentID, runID, reason, terminalState, TerminateOptions{CycleNo: cycleNo})
}

// TerminateWorkGuarded is the Fast Path entry: like TerminateWorkForCycle, but also
// refusing an autonomous termination of a run a human now owns.
//
// The ownership check lives HERE, under workMu and immediately before the run's
// action slot is claimed, rather than in the caller. A caller-side check is a
// separate synchronization point: a human steer landing between the check and this
// commit would still be killed. Checking under the same lock that installs the
// termination makes the two decisions atomic.
func (e *Engine) TerminateWorkGuarded(ctx context.Context, intentID int64, runID, reason, terminalState string, cycleNo int, humanStop bool) (TerminationResult, error) {
	return e.terminateWork(ctx, intentID, runID, reason, terminalState, TerminateOptions{CycleNo: cycleNo, HumanStop: humanStop})
}

func (e *Engine) terminateWork(ctx context.Context, intentID int64, runID, reason, terminalState string, opts TerminateOptions) (TerminationResult, error) {
	cycleNo := opts.CycleNo
	var out TerminationResult
	if terminalState != "stopped" && terminalState != "exhausted" {
		terminalState = "stopped"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.workMu.Lock()
	run := e.work[intentID]
	if run == nil {
		e.workMu.Unlock()
		return out, fmt.Errorf("%w: 意图 %d 当前没有运行中的 work", errWorkControlConflict, intentID)
	}
	if run.runID != "" && runID != "" && run.runID != runID {
		e.workMu.Unlock()
		return out, fmt.Errorf("%w: 意图 %d 当前运行 %s，终止请求指向 %s",
			errWatchdogRunMismatch, intentID, run.runID, runID)
	}
	if cycleNo >= 0 && e.monitor != nil {
		snap := e.monitor.LookupRun(runID)
		if snap == nil || snap.CycleNo != cycleNo {
			e.workMu.Unlock()
			return out, fmt.Errorf("%w: 意图 %d 的周期已变化（终止请求 C%d）",
				errWatchdogRunMismatch, intentID, cycleNo)
		}
	}
	if !opts.HumanStop && e.monitor != nil {
		// Re-read the LIVE ownership flag here, not from the decision snapshot: any
		// human steer or "continue" answer that landed after the tick must win. The
		// monitor takes its own lock; it is never held against workMu in the other
		// order, so this cannot deadlock.
		if e.monitor.HumanInvolvedRun(runID) {
			e.workMu.Unlock()
			return out, fmt.Errorf("%w: 意图 %d 已转为人工介入，拒绝自动终止", errWatchdogRunMismatch, intentID)
		}
	}
	if run.settling {
		e.workMu.Unlock()
		return out, fmt.Errorf("%w: 意图 %d 已进入终态提交，终止请求不再生效", errWorkControlConflict, intentID)
	}
	if run.action != "" {
		e.workMu.Unlock()
		return out, fmt.Errorf("%w: 意图 %d 正在执行 %s 操作", errWorkControlConflict, intentID, run.action)
	}
	run.action = "watchdog"
	run.watchdogReason = reason
	run.watchdogState = terminalState
	run.humanStop = opts.HumanStop
	done := run.done
	settle := run.settle
	var cause error
	if terminalState == "exhausted" {
		cause = agent.WatchdogCycleEnded(reason)
	} else {
		cause = agent.WatchdogTermination(reason, terminalState)
	}
	e.workMu.Unlock()

	// Prefer the SDK settlement path: the worker gets its configured wrap-up
	// rounds and can checkpoint already-confirmed facts/assets/findings before
	// the intent is closed. Only a timeout falls back to cancelling the context.
	if settle != nil && settle(reason) {
		timer := time.NewTimer(watchdogSettlementWait)
		select {
		case err := <-done:
			timer.Stop()
			return e.terminationResult(intentID, run, err)
		case <-ctx.Done():
			timer.Stop()
			// The caller stopped waiting; still stop the run so it cannot keep
			// settling forever. A later read observes the settled state.
			run.cancel(cause)
			return out, fmt.Errorf("等待意图 %d 收尾: %w", intentID, ctx.Err())
		case <-timer.C:
			// Wrap-up window elapsed: force the hard-cancel path below.
		}
	}
	run.cancel(cause)

	timer := time.NewTimer(workControlWaitTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return e.terminationResult(intentID, run, err)
	case <-ctx.Done():
		e.releaseWorkControl(intentID, run, "watchdog")
		return out, fmt.Errorf("等待意图 %d 终止: %w", intentID, ctx.Err())
	case <-timer.C:
		e.releaseWorkControl(intentID, run, "watchdog")
		return out, fmt.Errorf("等待意图 %d 终止: %w", intentID, context.DeadlineExceeded)
	}
}

// terminationResult reads the settled outcome a runIntent stored before
// signalling done. The writer and this reader share workMu, so the pointer
// remains valid even after detachWork removed the map entry.
func (e *Engine) terminationResult(intentID int64, run *workExecution, err error) (TerminationResult, error) {
	if err != nil {
		return TerminationResult{}, err
	}
	var out TerminationResult
	e.workMu.Lock()
	if run.watchdogResult != nil {
		out = *run.watchdogResult
	}
	e.workMu.Unlock()
	if out.IntentID == 0 {
		return out, fmt.Errorf("意图 %d 已结束，但没有返回终止结果", intentID)
	}
	return out, nil
}

// setWatchdogResult stores the settled result on the live work handle before
// runIntent calls detachWork. The channel receive in TerminateWork happens
// after this write, so the result is visible without another lock in the caller.
func (e *Engine) setWatchdogResult(intentID int64, runID string, result TerminationResult) {
	e.workMu.Lock()
	if run := e.work[intentID]; run != nil && (runID == "" || run.runID == runID) {
		run.watchdogResult = &result
	}
	e.workMu.Unlock()
}

// watchdogRecentEvidence pulls the last meaningful activity summary and the last
// tool result summary for the planner event. The judge/UI already has the full
// trace; this is the bounded snapshot the planner can act on immediately.
func watchdogRecentEvidence(t *Task, intentID int64) (step, toolResult string) {
	if t == nil || t.Store == nil {
		return "", ""
	}
	acts, _, err := t.Store.ActivityList(&intentID, 0, 30)
	if err != nil {
		return "", ""
	}
	for i := len(acts) - 1; i >= 0; i-- {
		a := acts[i]
		if step == "" && a.Kind != "usage" && strings.TrimSpace(a.Summary) != "" {
			step = preview(a.Summary, 300)
		}
		if toolResult == "" && a.Kind == "tool_result" && strings.TrimSpace(a.Summary) != "" {
			toolResult = preview(a.Summary, 300)
		}
		if step != "" && toolResult != "" {
			break
		}
	}
	return step, toolResult
}

// settleWatchdogTermination is the runIntent branch for watchdog cancellation.
// It commits terminal_reason and the system audit record before detachWork, so
// the caller that is waiting on done can return a complete result.
func (e *Engine) settleWatchdogTermination(t *Task, name string, intent *db.Node, runID, reason, terminalState string) (TerminationResult, bool) {
	state := terminalState
	if state != "stopped" && state != "exhausted" {
		state = "stopped"
	}
	changed, err := t.Store.CompareAndSetIntentStateWithReason(intent.ID, "running", state, reason)
	if err != nil {
		log.Printf("[watchdog] task %s 意图 #%d 写入终止状态失败: %v", t.ID, intent.ID, err)
	}
	if !changed {
		log.Printf("[watchdog] task %s 意图 #%d 终止时状态已被其他路径修改", t.ID, intent.ID)
		return TerminationResult{IntentID: intent.ID, RunID: runID, State: state, Reason: reason}, false
	}
	result := TerminationResult{
		IntentID: intent.ID, RunID: runID, State: state, Reason: reason,
	}
	if e.monitor != nil {
		if snap := e.monitor.LookupRun(runID); snap != nil {
			result.LastOutputAt = snap.LastOutputAt
			result.Phase = snap.Phase
			result.CycleNo = snap.CycleNo
			result.Facts = snap.Facts
			result.Assets = snap.Assets
			result.Findings = snap.Findings
		}
	}
	recentStep, recentToolResult := watchdogRecentEvidence(t, intent.ID)
	summary := fmt.Sprintf("Watchdog 终止意图 #%d（%s）：%s", intent.ID, state, reason)
	activity := e.emitActivity(t, db.Activity{
		Worker: "system", Kind: "watchdog_terminated", NodeID: &intent.ID,
		Summary: summary, Detail: reason,
		Metadata: marshalWatchdogMetadata(watchdogAudit{
			State: state, Reason: reason, LastOutputAt: result.LastOutputAt,
			CycleNo: result.CycleNo, Phase: result.Phase,
			Facts: result.Facts, Assets: result.Assets, Findings: result.Findings,
		}),
	})
	result.ActivityID = activity.ID
	e.setWatchdogResult(intent.ID, runID, result)
	t.NotifyWatchdogTerminated(agent.TriggerEvent{
		Kind: "watchdog_terminated", IntentID: intent.ID, Detail: reason,
		Summary: state, Worker: name, CycleNo: result.CycleNo,
		LastOutputAt: result.LastOutputAt, Phase: result.Phase,
		Facts: result.Facts, Assets: result.Assets, Findings: result.Findings,
		RecentStep: recentStep, RecentToolResult: recentToolResult,
	})
	log.Printf("[watchdog] task %s 意图 #%d 已终止(%s)，写回 facts=%d assets=%d findings=%d",
		t.ID, intent.ID, state, result.Facts, result.Assets, result.Findings)
	return result, true
}

// claimWorkSettlement marks the run as committing its terminal state and reads any
// pending Watchdog termination in the SAME workMu critical section. Claiming via a
// separate peek left a window: a termination could set action=watchdog between the
// peek and detachWork, while the commit took the normal branch and never wrote the
// result the caller was waiting for.
func (e *Engine) claimWorkSettlement(intentID int64, runID string) (reason, state string, humanStop, hasWatchdog bool) {
	e.workMu.Lock()
	defer e.workMu.Unlock()
	run := e.work[intentID]
	if run == nil || (runID != "" && run.runID != runID) {
		return "", "", false, false
	}
	run.settling = true
	if run.watchdogReason == "" && run.watchdogState == "" {
		return "", "", false, false
	}
	return run.watchdogReason, run.watchdogState, run.humanStop, true
}

// peekWatchdogTermination reports the pending termination WITHOUT consuming it, so a
// settlement branch can decide precedence (an explicit human stop beats a need-human
// hand-off) before the normal settlement path takes it.
func (e *Engine) peekWatchdogTermination(intentID int64, runID string) (reason, state string, humanStop, ok bool) {
	e.workMu.Lock()
	defer e.workMu.Unlock()
	run := e.work[intentID]
	if run == nil || (runID != "" && run.runID != runID) {
		return "", "", false, false
	}
	if run.watchdogReason == "" && run.watchdogState == "" {
		return "", "", false, false
	}
	return run.watchdogReason, run.watchdogState, run.humanStop, true
}
