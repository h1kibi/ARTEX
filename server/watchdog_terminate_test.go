package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func testWatchdogTask(t *testing.T) (*Manager, *Task, *db.Node) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("watchdog termination fixture", "settle one worker", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "fixture intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	intent, err := task.Store.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatalf("intent=%+v err=%v", intent, err)
	}
	return m, task, intent
}

func TestWatchdogTerminationSettlesIntentAndNotifiesPlanner(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	monitor := NewRunMonitor(m.pg, func() time.Time { return now })
	s := newAdmissionTestServer(m, nil)
	s.engine.SetRunMonitor(monitor)
	s.watchdog = &watchdogRuntime{s: s, monitor: monitor}
	runID := "run-watchdog-test"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.Observe(runID, db.Activity{Kind: "tool_result", Tool: "record_fact", Detail: `{"id":1}`})
	monitor.Observe(runID, db.Activity{Kind: "tool_result", Tool: "insert_assets",
		Detail: `{"results":[{"id":1},{"id":2}]}`})
	monitor.Observe(runID, db.Activity{Kind: "tool_result", Tool: "report_finding", Detail: `{"finding_id":1}`})
	nodeID := intent.ID
	if _, err := task.Store.AppendActivity(db.Activity{NodeID: &nodeID, Worker: "work#1", Kind: "tool_result",
		Tool: "Bash", Summary: "nmap -sV 返回 80/open"}); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AppendActivity(db.Activity{NodeID: &nodeID, Worker: "work#1", Kind: "text",
		Summary: "分析：目标开放 80 端口"}); err != nil {
		t.Fatal(err)
	}

	workCtx, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	settled := make(chan struct{})
	go func() {
		defer close(settled)
		<-workCtx.Done()
		cause, ok := context.Cause(workCtx).(*agent.AbortCause)
		if !ok {
			t.Errorf("watchdog cancel lost its named cause: %v", context.Cause(workCtx))
			return
		}
		s.engine.settleWatchdogTermination(task, "work#1", intent, runID, cause.Text, cause.TerminalState)
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()

	result, err := s.engine.TerminateWork(context.Background(), intent.ID, runID, "同一命令反复空转", "stopped")
	if err != nil {
		t.Fatal(err)
	}
	<-settled
	if result.State != "stopped" || result.Reason != "同一命令反复空转" {
		t.Fatalf("result=%+v", result)
	}
	if result.Facts != 1 || result.Assets != 2 || result.Findings != 1 {
		t.Fatalf("write counts lost: %+v", result)
	}
	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil || node.State != "stopped" || node.TerminalReason != "同一命令反复空转" {
		t.Fatalf("intent=%+v err=%v", node, err)
	}
	acts, _, err := task.Store.ActivityList(&intent.ID, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range acts {
		if a.Kind == "watchdog_terminated" {
			found = true
			if len(a.Metadata) == 0 || a.Summary == "" {
				t.Fatalf("termination activity lacks audit payload: %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("watchdog_terminated activity not written")
	}
	events := task.drainTriggers()
	found = false
	for _, ev := range events {
		if ev.Kind == "watchdog_terminated" && ev.IntentID == intent.ID {
			found = true
			if ev.Summary != "stopped" || ev.Detail != "同一命令反复空转" || ev.Facts != 1 || ev.Assets != 2 {
				t.Fatalf("planner trigger=%+v", ev)
			}
			if ev.RecentStep == "" || ev.RecentToolResult == "" {
				t.Fatalf("planner trigger missing recent evidence: %+v", ev)
			}
		}
	}
	if !found {
		t.Fatalf("planner did not receive watchdog_terminated: %+v", events)
	}
}

func TestTerminateWorkRejectsStaleCycle(t *testing.T) {
	const (
		taskID   = "2"
		intentID = int64(42)
		runID    = "run-cycle"
	)
	e := NewEngine(nil)
	monitor := NewRunMonitor(nil, time.Now)
	e.SetRunMonitor(monitor)
	monitor.Register(taskID, intentID, runID, "work#1")
	ctx, cancel := context.WithCancelCause(context.Background())
	e.registerWorkRun(intentID, runID, cancel)
	if _, err := e.TerminateWorkForCycle(context.Background(), intentID, runID, "stale", "stopped", 1); !errors.Is(err, errWatchdogRunMismatch) {
		t.Fatalf("stale cycle termination error=%v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("stale cycle termination cancelled the current run")
	}
	_, complete := e.detachWork(intentID)
	complete(nil)
}

func TestWatchdogTerminationConcurrentOnlyOneWins(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	monitor := NewRunMonitor(m.pg, func() time.Time { return now })
	s := newAdmissionTestServer(m, nil)
	s.engine.SetRunMonitor(monitor)
	s.watchdog = &watchdogRuntime{s: s, monitor: monitor}
	runID := "run-concurrent"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	workCtx, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	settled := make(chan struct{})
	go func() {
		defer close(settled)
		<-workCtx.Done()
		cause, ok := context.Cause(workCtx).(*agent.AbortCause)
		if !ok {
			return
		}
		s.engine.settleWatchdogTermination(task, "work#1", intent, runID, cause.Text, cause.TerminalState)
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()
	type result struct {
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			_, err := s.engine.TerminateWorkForCycle(context.Background(), intent.ID, runID, "loop", "stopped", 0)
			results <- result{err: err}
		}()
	}
	var success, conflict int
	for range 2 {
		if res := <-results; res.err == nil {
			success++
		} else {
			conflict++
		}
	}
	<-settled
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent terminations success=%d conflict=%d, want 1/1", success, conflict)
	}
}

func TestTerminateWorkRejectsStaleRunAndSecondTermination(t *testing.T) {
	m, _, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	ctx, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, "new-run", cancel)
	_, err := s.engine.TerminateWork(context.Background(), intent.ID, "old-run", "stale", "stopped")
	if !errors.Is(err, errWatchdogRunMismatch) {
		t.Fatalf("stale termination error=%v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("stale termination cancelled the current run")
	}
	_, complete := s.engine.detachWork(intent.ID)
	complete(nil)
	if _, err := s.engine.TerminateWork(context.Background(), intent.ID, "new-run", "gone", "stopped"); !errors.Is(err, errWorkControlConflict) {
		t.Fatalf("termination after detach error=%v", err)
	}
}

func TestWatchdogSettlementCASConflictDoesNotEmitTerminationEvent(t *testing.T) {
	_, task, intent := testWatchdogTask(t)
	if err := task.Store.SetIntentState(intent.ID, "stopped"); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(nil)
	cause := agent.WatchdogTermination("late termination", "stopped")
	result, settled := e.settleWatchdogTermination(task, "work#1", intent, "run-late", cause.Text, cause.TerminalState)
	if settled || result.IntentID != intent.ID {
		t.Fatalf("late CAS settlement=%+v settled=%v, want conflict result", result, settled)
	}
	acts, _, err := task.Store.ActivityList(&intent.ID, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Kind == "watchdog_terminated" {
			t.Fatalf("late CAS emitted a second watchdog termination: %+v", a)
		}
	}
}

// Once runIntent has claimed the terminal commit, a late termination must be
// refused instead of claiming the run and waiting for a settlement result the
// commit's normal branch will never write.
func TestTerminateRefusedAfterSettlementClaim(t *testing.T) {
	_, task, intent := testWatchdogTask(t)
	e := NewEngine(nil)
	_, cancel := context.WithCancelCause(context.Background())
	e.registerWorkRun(intent.ID, "run-claim", cancel)
	defer func() {
		_, complete := e.detachWork(intent.ID)
		complete(nil)
	}()

	if _, _, _, ok := e.claimWorkSettlement(intent.ID, "run-claim"); ok {
		t.Fatal("claim reported a pending termination before one was requested")
	}
	_, err := e.TerminateWork(context.Background(), intent.ID, "run-claim", "用户明确拒绝继续", "stopped")
	if !errors.Is(err, errWorkControlConflict) {
		t.Fatalf("termination after the commit claim error=%v, want errWorkControlConflict", err)
	}
	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil {
		t.Fatalf("intent: %+v err=%v", node, err)
	}
	if node.State == "stopped" {
		t.Fatal("a refused termination still stopped the intent")
	}
}
