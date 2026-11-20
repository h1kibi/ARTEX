package server

import (
	"context"
	"encoding/json"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestWatchdogTerminationUsesSettlementBeforeCancel(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	e := NewEngine(m)
	workCtx, workCancel := context.WithCancelCause(context.Background())
	var gotReason string
	e.registerWorkRunFull(intent.ID, "run-settle", task.ID, "work#1", workCancel,
		func(reason string) bool {
			gotReason = reason
			go func() {
				time.Sleep(10 * time.Millisecond)
				if workCtx.Err() != nil {
					t.Errorf("settlement request cancelled the run context")
				}
				e.settleWatchdogTermination(task, "work#1", intent, "run-settle", reason, "stopped")
				_, done := e.detachWork(intent.ID)
				done(nil)
			}()
			return true
		})
	res, err := e.TerminateWork(context.Background(), intent.ID, "run-settle", "因为空转", "stopped")
	if err != nil {
		t.Fatal(err)
	}
	if gotReason != "因为空转" {
		t.Fatalf("settlement reason=%q", gotReason)
	}
	if res.IntentID != intent.ID || res.State != "stopped" || res.Reason != "因为空转" {
		t.Fatalf("termination result=%+v", res)
	}
	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil || node.State != "stopped" {
		t.Fatalf("intent state=%+v err=%v, want stopped", node, err)
	}
}

func TestWatchdogSettlementTimeoutFallsBackToCancel(t *testing.T) {
	old := watchdogSettlementWait
	watchdogSettlementWait = 40 * time.Millisecond
	t.Cleanup(func() { watchdogSettlementWait = old })

	m, task, intent := testWatchdogTask(t)
	e := NewEngine(m)
	workCtx, workCancel := context.WithCancelCause(context.Background())
	settled := false
	e.registerWorkRunFull(intent.ID, "run-timeout", task.ID, "work#1", workCancel,
		func(string) bool {
			settled = true
			return true // never produces done: the engine must force-cancel
		})
	go func() {
		<-workCtx.Done()
		cause, _ := context.Cause(workCtx).(*agent.AbortCause)
		if cause == nil {
			t.Errorf("fallback cancellation lost its named cause: %v", context.Cause(workCtx))
			return
		}
		e.settleWatchdogTermination(task, "work#1", intent, "run-timeout", cause.Text, cause.TerminalState)
		_, done := e.detachWork(intent.ID)
		done(nil)
	}()
	start := time.Now()
	res, err := e.TerminateWork(context.Background(), intent.ID, "run-timeout", "收尾超时", "stopped")
	if err != nil {
		t.Fatal(err)
	}
	if !settled {
		t.Fatal("settlement was never requested")
	}
	if elapsed := time.Since(start); elapsed < watchdogSettlementWait {
		t.Fatalf("returned after %v, before the settlement window %v", elapsed, watchdogSettlementWait)
	}
	if res.State != "stopped" {
		t.Fatalf("result=%+v", res)
	}
	if workCtx.Err() == nil {
		t.Fatal("fallback did not cancel the run context")
	}
}

// settlementProvider drives the real Worker -> SDK loop. The first call blocks
// until the test asks for termination, then returns a Read tool call. The
// post-tool settlement check consumes the request, and the second call sees the
// worker wrap-up prompt before returning ReasonWatchdog.
type settlementProvider struct {
	file                string
	started             chan struct{}
	release             chan struct{}
	settlementStarted   chan struct{}
	holdSettlement      chan struct{}
	startOnce           sync.Once
	releaseOnce         sync.Once
	settlementStartOnce sync.Once
	calls               atomic.Int64
	settled             atomic.Bool
}

func (p *settlementProvider) closeRelease() { p.releaseOnce.Do(func() { close(p.release) }) }

func (p *settlementProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if p.calls.Add(1) == 1 {
			p.startOnce.Do(func() { close(p.started) })
			select {
			case <-p.release:
			case <-ctx.Done():
				yield(llm.StreamEvent{}, ctx.Err())
				return
			}
			input, _ := json.Marshal(map[string]string{"file_path": p.file})
			if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "settle-read", ToolName: "Read"}, nil) {
				return
			}
			if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(input)}, nil) {
				return
			}
			if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "tool_use"}, nil) {
				return
			}
			yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
			return
		}
		for _, m := range req.Messages {
			for _, block := range m.Content {
				if strings.Contains(block.Text, "SETTLE_MARKER") {
					p.settled.Store(true)
				}
			}
		}
		if p.settlementStarted != nil {
			p.settlementStartOnce.Do(func() { close(p.settlementStarted) })
		}
		if p.holdSettlement != nil {
			select {
			case <-p.holdSettlement:
			case <-ctx.Done():
				yield(llm.StreamEvent{}, ctx.Err())
				return
			}
		}
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "settled"}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p *settlementProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for ev, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

type settlementRun struct {
	e          *Engine
	task       *Task
	intent     *db.Node
	prov       *settlementProvider
	runDone    chan struct{}
	termResult chan TerminationResult
	termErr    chan error
}

func startSettlementRun(t *testing.T, hold bool) *settlementRun {
	t.Helper()
	m, task, intent := testWatchdogTask(t)
	e := NewEngine(m)
	file := filepath.Join(t.TempDir(), "settlement.txt")
	if err := os.WriteFile(file, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldOverride := agent.WrapupOverride
	agent.WrapupOverride = func(key string) (string, bool) {
		if key == "worker" {
			return "SETTLE_MARKER 请写回", true
		}
		if oldOverride != nil {
			return oldOverride(key)
		}
		return "", false
	}
	t.Cleanup(func() { agent.WrapupOverride = oldOverride })
	prov := &settlementProvider{file: file, started: make(chan struct{}), release: make(chan struct{})}
	if hold {
		prov.settlementStarted = make(chan struct{})
		prov.holdSettlement = make(chan struct{})
		t.Cleanup(func() { close(prov.holdSettlement) })
	}
	t.Cleanup(prov.closeRelease)
	wk := agent.NewWorker(prov, "fixture", t.TempDir(), nil, 100000, 0)
	run := &settlementRun{
		e: e, task: task, intent: intent, prov: prov,
		runDone: make(chan struct{}), termResult: make(chan TerminationResult, 1), termErr: make(chan error, 1),
	}
	go func() {
		e.runIntent(context.Background(), task, "work#1", wk, intent, "", "")
		close(run.runDone)
	}()
	select {
	case <-prov.started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start its first model call")
	}
	go func() {
		res, err := e.TerminateWork(context.Background(), intent.ID, "", "integration settlement", "stopped")
		run.termResult <- res
		run.termErr <- err
	}()
	prov.closeRelease()
	if hold {
		select {
		case <-prov.settlementStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not enter the settlement model call")
		}
	}
	return run
}

func TestRunIntentConsumesSettlementRequest(t *testing.T) {
	r := startSettlementRun(t, false)
	if err := <-r.termErr; err != nil {
		t.Fatal(err)
	}
	res := <-r.termResult
	if res.State != "stopped" || res.Reason != "integration settlement" {
		t.Fatalf("termination result=%+v", res)
	}
	if !r.prov.settled.Load() {
		t.Fatal("settlement request did not reach the real SDK loop")
	}
	node, err := r.task.Store.GetNode(r.intent.ID)
	if err != nil || node == nil || node.State != "stopped" {
		t.Fatalf("intent state=%+v err=%v, want stopped", node, err)
	}
	<-r.runDone
	acts, _, err := r.task.Store.ActivityList(&r.intent.ID, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range acts {
		if a.Kind == "watchdog_terminated" {
			found = true
		}
	}
	if !found {
		t.Fatal("watchdog_terminated activity was not written")
	}
}

func TestSettlementStopsOnUserPause(t *testing.T) {
	r := startSettlementRun(t, true)
	r.e.Pause(r.task.ID, agent.AbortPausedByUser)
	select {
	case <-r.runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop after pause during settlement")
	}
	select {
	case <-r.termErr:
	case <-time.After(5 * time.Second):
		t.Fatal("termination waiter did not settle after pause")
	}
}

func TestSettlementStopsOnTaskDelete(t *testing.T) {
	r := startSettlementRun(t, true)
	if !r.e.BeginDelete(r.task.ID) {
		t.Fatal("delete barrier was not installed")
	}
	r.e.StopTask(r.task.ID)
	select {
	case <-r.runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop after delete during settlement")
	}
	select {
	case <-r.termErr:
	case <-time.After(5 * time.Second):
		t.Fatal("termination waiter did not settle after delete")
	}
}
