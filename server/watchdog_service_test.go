package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestCycleStartChanged(t *testing.T) {
	start := time.Now()
	if cycleStartChanged(nil, start) || cycleStartChanged(&start, time.Time{}) {
		t.Fatal("missing timestamps must not look stale")
	}
	close := start.Add(time.Second)
	if cycleStartChanged(&start, close) {
		t.Fatal("one-second claim skew should be tolerated")
	}
	far := start.Add(10 * time.Minute)
	if !cycleStartChanged(&start, far) {
		t.Fatal("a different cycle start must be stale")
	}
}

func TestWatchdogUnavailableErrorOnlyTaskRouter(t *testing.T) {
	if !isWatchdogUnavailableError(&taskLLMError{taskID: "1", chainExhausted: true}) {
		t.Fatal("task router failure should surface the unavailable card")
	}
	if !isWatchdogUnavailableError(context.DeadlineExceeded) {
		t.Fatal("judge wall-clock timeout should surface the unavailable card")
	}
	if !isWatchdogUnavailableError(errors.New("anthropic: status 429: rate limit")) {
		t.Fatal("provider rate-limit error should surface the unavailable card")
	}
	if isWatchdogUnavailableError(fmt.Errorf("%w: bad json", agent.ErrWatchdogReport)) {
		t.Fatal("a malformed model answer is a failed job, not unavailable")
	}
	if isWatchdogUnavailableError(errors.New("invalid json")) || isWatchdogUnavailableError(context.Canceled) {
		t.Fatal("generic model error/context cancellation must not surface the unavailable card")
	}
}

func TestWatchdogServiceMarksEndedRunStale(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	monitor := NewRunMonitor(m.pg, func() time.Time { return now })
	s := newAdmissionTestServer(m, nil)
	s.engine.SetRunMonitor(monitor)
	s.watchdog = &watchdogRuntime{s: s, monitor: monitor}
	svc := newWatchdogService(s, monitor)
	job := &db.WatchdogJob{TaskID: task.ID, IntentID: intent.ID, RunID: "run-ended", CycleNo: 0,
		CycleStart: &now, Snapshot: []byte(`{}`)}
	if _, _, err := m.pg.EnqueueWatchdogJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	stored, err := m.pg.WatchdogJobByCycle(context.Background(), "run-ended", 0)
	if err != nil || stored == nil {
		t.Fatalf("job=%+v err=%v", stored, err)
	}
	svc.runJob(context.Background(), stored, watchdogConfig{AgentRetry: time.Minute})
	got, err := m.pg.WatchdogJobByCycle(context.Background(), "run-ended", 0)
	if err != nil || got == nil || got.Status != db.WatchdogJobStale {
		t.Fatalf("ended-run job status=%+v err=%v", got, err)
	}
}

func TestWatchdogServiceSkipsOpenDecision(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	monitor := NewRunMonitor(m.pg, func() time.Time { return now })
	s := newAdmissionTestServer(m, nil)
	s.engine.SetRunMonitor(monitor)
	s.watchdog = &watchdogRuntime{s: s, monitor: monitor}
	runID := "run-open-ask"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetCycle(runID, 0, now, false, db.SlowPathNone, db.WatchdogDecisionOpen)
	job := &db.WatchdogJob{TaskID: task.ID, IntentID: intent.ID, RunID: runID, CycleNo: 0,
		CycleStart: &now, Snapshot: []byte(`{}`)}
	if _, _, err := m.pg.EnqueueWatchdogJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	stored, err := m.pg.WatchdogJobByCycle(context.Background(), runID, 0)
	if err != nil || stored == nil {
		t.Fatalf("job=%+v err=%v", stored, err)
	}
	svc := newWatchdogService(s, monitor)
	svc.now = func() time.Time { return now }
	svc.runJob(context.Background(), stored, watchdogConfig{AgentRetry: time.Minute})
	got, err := m.pg.WatchdogJobByCycle(context.Background(), runID, 0)
	if err != nil || got == nil || got.Status != db.WatchdogJobStale {
		t.Fatalf("open-decision job status=%+v err=%v", got, err)
	}
	if snap := monitor.Lookup(intent.ID); snap == nil || snap.State != db.WorkerRunStateRunning {
		t.Fatalf("worker was terminated while a decision was open: %+v", snap)
	}
}

func TestWatchdogUnavailableCardAggregatesReports(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	monitor := NewRunMonitor(m.pg, func() time.Time { return now })
	s := newAdmissionTestServer(m, nil)
	s.engine.SetRunMonitor(monitor)
	s.watchdog = &watchdogRuntime{s: s, monitor: monitor}
	runID := "run-unavailable"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	svc := newWatchdogService(s, monitor)
	svc.now = func() time.Time { return now }
	cfg := watchdogConfig{AgentRetry: time.Minute}
	ask, _, err := m.pg.CreateWatchdogAsk(context.Background(), &db.WatchdogRequest{
		TaskID: task.ID, IntentID: &intent.ID, RunID: runID, CycleNo: 0,
		Kind: db.WatchdogRequestAsk, Question: "continue?", DeadlineAt: &now,
	})
	if err != nil || ask == nil {
		t.Fatalf("create open ask: %+v err=%v", ask, err)
	}

	var cards []int64
	for cycle := 0; cycle < 2; cycle++ {
		start := now.Add(time.Duration(cycle) * time.Minute)
		job := &db.WatchdogJob{TaskID: task.ID, IntentID: intent.ID, RunID: runID, CycleNo: cycle,
			CycleStart: &start, Snapshot: []byte(`{"summary":"fixture"}`)}
		if _, _, err := m.pg.EnqueueWatchdogJob(context.Background(), job); err != nil {
			t.Fatal(err)
		}
		claimed, err := m.pg.WatchdogJobByCycle(context.Background(), runID, cycle)
		if err != nil || claimed == nil {
			t.Fatalf("load cycle %d: %+v err=%v", cycle, claimed, err)
		}
		svc.unavailable(context.Background(), task, claimed, cfg, context.DeadlineExceeded)
		card, err := m.pg.OpenWatchdogUnavailable(context.Background(), task.ID)
		if err != nil || card == nil {
			t.Fatalf("cycle %d unavailable card=%+v err=%v", cycle, card, err)
		}
		cards = append(cards, card.ID)
	}
	closedAsk, err := m.pg.WatchdogRequestByID(context.Background(), ask.ID)
	if err != nil || closedAsk == nil || closedAsk.Status != db.WatchdogRequestSuperseded {
		t.Fatalf("worker ask stayed actionable while unavailable: %+v err=%v", closedAsk, err)
	}
	if len(cards) != 2 || cards[0] != cards[1] {
		t.Fatalf("unavailable card was recreated instead of updated: %v", cards)
	}
	card, err := m.pg.OpenWatchdogUnavailable(context.Background(), task.ID)
	if err != nil || card == nil || card.AlertCount != 2 {
		t.Fatalf("card alert_count=%+v err=%v", card, err)
	}
	if card.FirstAlertAt == nil || card.LastAlertAt == nil || card.NextRetryAt == nil {
		t.Fatalf("card timestamps missing: %+v", card)
	}
}
