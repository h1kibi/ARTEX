package server

import (
	"context"
	"encoding/json"
	"iter"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// runtimeAcceptanceProvider drives the real Worker/SDK/Engine path without an
// external model. Calls 1 and 2 write facts; call 3 waits for a real pause; call
// 4 completes the resumed intent.
type runtimeAcceptanceProvider struct {
	intentID int64
	calls    atomic.Int32

	firstToolStarted  chan struct{}
	secondRelease     chan struct{}
	secondToolStarted chan struct{}
	thirdStarted      chan struct{}

	firstOnce   sync.Once
	secondOnce  sync.Once
	thirdOnce   sync.Once
	releaseOnce sync.Once
}

func (p *runtimeAcceptanceProvider) closeRelease() {
	p.releaseOnce.Do(func() { close(p.secondRelease) })
}

func (p *runtimeAcceptanceProvider) factInput(summary string) string {
	input, _ := json.Marshal(map[string]any{
		"summary":    summary,
		"intent_id":  p.intentID,
		"detail":     "deterministic runtime acceptance fixture",
		"evidence":   "fixture provider",
		"confidence": "observed",
	})
	return string(input)
}

func emitRuntimeText(yield func(llm.StreamEvent, error) bool, text string) {
	for _, event := range []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: text},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
		{Type: llm.SEMessageStop},
	} {
		if !yield(event, nil) {
			return
		}
	}
}

func emitRuntimeFact(yield func(llm.StreamEvent, error) bool, id, input string) {
	for _, event := range []llm.StreamEvent{
		{Type: llm.SEToolUseStart, ToolID: id, ToolName: "record_fact"},
		{Type: llm.SEToolInputJSON, Text: input},
		{Type: llm.SEMessageDelta, StopReason: "tool_use"},
		{Type: llm.SEMessageStop},
	} {
		if !yield(event, nil) {
			return
		}
	}
}

func (p *runtimeAcceptanceProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		switch p.calls.Add(1) {
		case 1:
			p.firstOnce.Do(func() { close(p.firstToolStarted) })
			emitRuntimeFact(yield, "runtime-fact-1", p.factInput("runtime fact one"))
		case 2:
			p.secondOnce.Do(func() { close(p.secondToolStarted) })
			select {
			case <-p.secondRelease:
				emitRuntimeFact(yield, "runtime-fact-2", p.factInput("runtime fact two"))
			case <-ctx.Done():
				yield(llm.StreamEvent{}, ctx.Err())
			}
		case 3:
			p.thirdOnce.Do(func() { close(p.thirdStarted) })
			<-ctx.Done()
			yield(llm.StreamEvent{}, ctx.Err())
		default:
			emitRuntimeText(yield, "resumed and complete")
		}
	}
}

func (p *runtimeAcceptanceProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for event, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(event)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func waitRuntimeSnapshot(t *testing.T, monitor *RunMonitor, intentID int64, want func(RunSnapshot) bool) RunSnapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if snap := monitor.Lookup(intentID); snap != nil && want(*snap) {
			return *snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	snap := monitor.Lookup(intentID)
	t.Fatalf("runtime snapshot did not reach expected state: %+v", snap)
	return RunSnapshot{}
}

func TestRealWorkerAutoAdvanceWriteAndResume(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	monitor := NewRunMonitor(m.pg, time.Now)
	s := newAdmissionTestServer(m, nil)
	s.watchdog = &watchdogRuntime{s: s, monitor: monitor, fast: newWatchdogFast(s, monitor)}
	s.engine.SetRunMonitor(monitor)

	provider := &runtimeAcceptanceProvider{
		intentID:          intent.ID,
		firstToolStarted:  make(chan struct{}),
		secondRelease:     make(chan struct{}),
		secondToolStarted: make(chan struct{}),
		thirdStarted:      make(chan struct{}),
	}
	t.Cleanup(provider.closeRelease)
	worker := agent.NewWorker(provider, "runtime-acceptance", m.dir,
		transcript.NewStore(filepath.Join(t.TempDir(), "transcripts")), 0, 0)

	runDone := make(chan bool, 1)
	go func() {
		runDone <- s.engine.runIntent(context.Background(), task, "work#1", worker, intent, "", "")
	}()
	select {
	case <-provider.firstToolStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("real Worker did not issue the first record_fact")
	}

	runID := ""
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		runs := monitor.ListRunning(task.ID)
		if len(runs) == 1 {
			runID = runs[0].RunID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if runID == "" {
		t.Fatal("real Worker run was not registered")
	}
	first := waitRuntimeSnapshot(t, monitor, intent.ID, func(snap RunSnapshot) bool { return snap.Facts == 1 })
	if first.CycleNo != 0 || first.AutoCyclesUsed != 0 {
		t.Fatalf("first effective write snapshot=%+v, want C0 and zero auto advances", first)
	}
	monitor.SetSlowPath(runID, db.SlowPathDone, "continue", "fixture progress", nil, 0)
	current := monitor.Lookup(intent.ID)
	if current == nil {
		t.Fatal("real Worker run disappeared before cycle processing")
	}
	if current.SlowPathClass != "continue" || current.SlowPathCycle != current.CycleNo {
		t.Fatalf("cycle fixture was not visible to Fast Path: %+v", current)
	}
	if ask, err := m.pg.LatestWatchdogAsk(context.Background(), current.RunID, current.CycleNo); err != nil {
		t.Fatal(err)
	} else if ask != nil {
		t.Fatalf("unexpected prior cycle ask=%+v", ask)
	}
	s.watchdog.fast.processCycle(context.Background(), task, *current, watchdogConfig{
		Enabled: true, CycleAfter: time.Minute, MaxAutoCycles: 2,
	})
	advanced := waitRuntimeSnapshot(t, monitor, intent.ID, func(snap RunSnapshot) bool {
		return snap.CycleNo == 1 && snap.AutoCyclesUsed == 1
	})
	if advanced.Facts != 1 {
		t.Fatalf("auto-advanced snapshot=%+v, first fact was lost", advanced)
	}

	provider.closeRelease()
	select {
	case <-provider.secondToolStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("real Worker did not reach the second record_fact")
	}
	writtenAgain := waitRuntimeSnapshot(t, monitor, intent.ID, func(snap RunSnapshot) bool { return snap.Facts == 2 })
	if writtenAgain.CycleNo != 0 || writtenAgain.AutoCyclesUsed != 1 {
		t.Fatalf("second effective write snapshot=%+v, want C0 with budget preserved", writtenAgain)
	}

	select {
	case <-provider.thirdStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("real Worker did not reach the pause/resume boundary")
	}
	s.engine.Pause(task.ID, agent.AbortPausedByUser)
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("real Worker did not stop on pause")
	}
	paused, err := task.Store.GetNode(intent.ID)
	if err != nil || paused == nil || paused.State != "open" {
		t.Fatalf("paused intent=%+v err=%v, want open for resume", paused, err)
	}

	s.engine.Resume(task)
	if err := task.Store.SetIntentState(intent.ID, "running"); err != nil {
		t.Fatal(err)
	}
	resumedDone := make(chan bool, 1)
	go func() {
		resumedDone <- s.engine.runIntent(context.Background(), task, "work#1", worker, intent, "", "")
	}()
	select {
	case <-resumedDone:
	case <-time.After(5 * time.Second):
		t.Fatal("resumed Worker did not complete")
	}
	resumed, err := task.Store.GetNode(intent.ID)
	if err != nil || resumed == nil || resumed.State != "done" {
		t.Fatalf("resumed intent=%+v err=%v, want done", resumed, err)
	}
}
