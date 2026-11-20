package server

import (
	"context"
	"errors"
	"iter"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// blockingWatchdogProvider keeps the real Worker/Engine path inside its model
// call until the test's TerminateWork cancels the run context.
type blockingWatchdogProvider struct {
	started chan struct{}
	once    sync.Once
}

func (p *blockingWatchdogProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.once.Do(func() { close(p.started) })
		<-ctx.Done()
		yield(llm.StreamEvent{}, ctx.Err())
	}
}

func (p *blockingWatchdogProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.once.Do(func() { close(p.started) })
	<-ctx.Done()
	return llm.Message{}, "", llm.Usage{}, ctx.Err()
}

func TestEngineRunIntentWatchdogTermination(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	monitor := NewRunMonitor(m.pg, time.Now)
	engine := NewEngine(m)
	engine.SetRunMonitor(monitor)
	provider := &blockingWatchdogProvider{started: make(chan struct{})}
	worker := agent.NewWorker(provider, "watchdog-integration", m.dir,
		transcript.NewStore(filepath.Join(t.TempDir(), "transcripts")), 0, 0)

	finished := make(chan bool, 1)
	go func() {
		finished <- engine.runIntent(context.Background(), task, "work#1", worker, intent, "", "")
	}()
	select {
	case <-provider.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Worker never entered the provider call")
	}

	var runID string
	for range 100 {
		engine.workMu.Lock()
		if run := engine.work[intent.ID]; run != nil {
			runID = run.runID
		}
		engine.workMu.Unlock()
		if runID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if runID == "" {
		t.Fatal("runIntent did not register a run identity")
	}
	result, err := engine.TerminateWork(context.Background(), intent.ID, runID, "同一工具反复空转", "stopped")
	if err != nil {
		t.Fatalf("TerminateWork: %v", err)
	}
	if result.State != "stopped" || result.Reason != "同一工具反复空转" {
		t.Fatalf("termination result=%+v", result)
	}
	if ok := <-finished; !ok {
		t.Fatal("runIntent did not settle successfully")
	}

	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil || node.State != "stopped" || node.TerminalReason != "同一工具反复空转" {
		t.Fatalf("intent=%+v err=%v", node, err)
	}
	activities, _, err := task.Store.ActivityList(&intent.ID, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var terminated int
	for _, activity := range activities {
		if activity.Kind == "watchdog_terminated" {
			terminated++
		}
	}
	if terminated != 1 {
		t.Fatalf("watchdog termination activity count=%d, want 1", terminated)
	}
}

type immediateProviderError struct{}

func (immediateProviderError) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("status 503: provider unavailable"))
	}
}

func (immediateProviderError) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, errors.New("status 503: provider unavailable")
}

func TestEngineRunIntentProviderErrorRunsFinishHook(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	previous := m.pg.LLMRetryPolicy()
	if err := m.pg.SetLLMRetryPolicy(db.LLMRetryPolicy{Intent: db.RetryRule{Attempts: -1}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetLLMRetryPolicy(previous) })

	monitor := NewRunMonitor(m.pg, time.Now)
	finished := make(chan RunSnapshot, 1)
	monitor.SetFinishHook(func(snap RunSnapshot) { finished <- snap })
	engine := NewEngine(m)
	engine.SetRunMonitor(monitor)
	worker := agent.NewWorker(immediateProviderError{}, "provider-error", m.dir,
		transcript.NewStore(filepath.Join(t.TempDir(), "transcripts")), 0, 0)
	done := make(chan struct{})
	go func() {
		engine.runIntent(context.Background(), task, "work#1", worker, intent, "", "")
		close(done)
	}()
	select {
	case snap := <-finished:
		if snap.ProviderError == "" || snap.State != db.WorkerRunStateFinished {
			t.Fatalf("finish hook snapshot=%+v", snap)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("provider-error run did not invoke finish hook")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("provider-error run did not return")
	}
}
