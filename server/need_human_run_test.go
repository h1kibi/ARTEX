package server

import (
	"context"
	"encoding/json"
	"iter"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// needHumanProvider drives a REAL Worker run: it asks the model for one
// record_fact(need_human=true) call, then (second turn) fails like a retryable
// provider error, and finally ends. That covers the two ways the hand-off used to
// be lost — a model_error retry overwriting WriteCounts, and a terminal reason
// outranking the flag.
type needHumanProvider struct {
	toolName string
	calls    atomic.Int32
	// failOnSecond makes the second completion return a retryable provider error.
	failOnSecond bool
	mu           sync.Mutex
	sawTool      bool
}

func (p *needHumanProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		n := p.calls.Add(1)
		if p.failOnSecond && n == 2 {
			yield(llm.StreamEvent{}, &providerTestError{"status 503: provider unavailable"})
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil)
		if n == 1 {
			// A fact must cite a real source: write the observation to the run's
			// artifact dir first, exactly as a worker would.
			args, _ := json.Marshal(map[string]any{
				"fact_type": "observation", "summary": "登录卡在短信验证码",
				"detail":        "/login 提交后要求手机验证码，需要人工提供",
				"evidence_refs": []string{"artifact:mfa.txt"},
				"need_human":    true,
			})
			for _, ev := range []llm.StreamEvent{
				{Type: llm.SEToolUseStart, ToolID: "call-1", ToolName: p.toolName},
				{Type: llm.SEToolInputJSON, Text: string(args)},
				{Type: llm.SEMessageDelta, StopReason: "tool_use"},
				{Type: llm.SEMessageStop},
			} {
				if !yield(ev, nil) {
					return
				}
			}
			return
		}
		for _, ev := range []llm.StreamEvent{
			{Type: llm.SETextDelta, Text: "已交接给人工"},
			{Type: llm.SEMessageDelta, StopReason: "end_turn"},
			{Type: llm.SEMessageStop},
		} {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

func (p *needHumanProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, &providerTestError{"not used"}
}

type providerTestError struct{ msg string }

func (e *providerTestError) Error() string { return e.msg }

// The full hand-off through a REAL worker run: the tool writes need_human, the run
// settles as paused (not done), and the human message endpoint accepts the resume.
func TestNeedHumanThroughRealWorkerRun(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.ctx = ctx
	s.watchdog = newWatchdogRuntime(s, time.Now)
	s.engine.SetRunMonitor(s.watchdog.monitor)

	prev := agent.FindingEvidenceHook
	t.Cleanup(func() { agent.FindingEvidenceHook = prev })

	writeRunArtifact(t, m.dir, task.ID, intent.ID, "mfa.txt", "blocked at /login: SMS code required")

	provider := &needHumanProvider{toolName: "record_fact"}
	worker := agent.NewWorker(provider, "handoff-run", m.dir,
		transcript.NewStore(filepath.Join(t.TempDir(), "transcripts")), 0, 0)

	done := make(chan bool, 1)
	go func() {
		done <- s.engine.runIntent(ctx, task, "work#1", worker, intent, "", "")
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("runIntent reported no settlement")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("runIntent did not finish")
	}

	acts, _, aerr := task.Store.ActivityList(&intent.ID, 0, 200)
	if aerr != nil {
		t.Fatal(aerr)
	}
	for _, a := range acts {
		t.Logf("activity %s/%s: %s | %s", a.Kind, a.Tool, a.Summary, preview(a.Detail, 200))
	}
	facts, _ := task.Store.ListByKind(db.KindFact, 20)
	t.Logf("facts recorded: %d (writes were not visible through the store?)", len(facts))

	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil {
		t.Fatalf("intent: %+v err=%v", node, err)
	}
	if node.State != "paused" {
		t.Fatalf("intent state = %q, want paused (hand-off lost)", node.State)
	}

	// The task must not close itself while the hand-off is pending.
	active, err := task.Store.HasActiveIntent()
	if err != nil || !active {
		t.Fatalf("HasActiveIntent = %v err=%v", active, err)
	}

	// The message endpoint's gates are: task not terminal, task not paused/queued,
	// node exists and is `paused`. All three must hold for the hand-off to be
	// resumable; the endpoint's own checks are asserted in
	// TestNeedHumanHandoffSurvivesGoallessTask, which drives the real route.
	if st := s.m.TaskStatus(task.ID); isTerminalStatus(st) {
		t.Fatalf("task status = %q; a pending hand-off must not be terminal", st)
	}
	if lc := task.lifecycleSnapshot(); lc.Paused || lc.Queued {
		t.Fatalf("task lifecycle paused=%v queued=%v; resume would be rejected", lc.Paused, lc.Queued)
	}
	if node.State != "paused" {
		t.Fatalf("intent state = %q; the message endpoint only accepts paused", node.State)
	}
}

// A retryable model error AFTER the hand-off must not drop the flag: the second
// attempt overwrites WriteCounts, and the run still has to settle as paused.
func TestNeedHumanSurvivesModelErrorRetry(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.ctx = ctx
	s.watchdog = newWatchdogRuntime(s, time.Now)
	s.engine.SetRunMonitor(s.watchdog.monitor)

	prevPolicy := m.pg.LLMRetryPolicy()
	if err := m.pg.SetLLMRetryPolicy(db.LLMRetryPolicy{Intent: db.RetryRule{Attempts: 2, IntervalMS: 10}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetLLMRetryPolicy(prevPolicy) })

	writeRunArtifact(t, m.dir, task.ID, intent.ID, "mfa.txt", "blocked at /login: SMS code required")

	provider := &needHumanProvider{toolName: "record_fact", failOnSecond: true}
	worker := agent.NewWorker(provider, "handoff-retry", m.dir,
		transcript.NewStore(filepath.Join(t.TempDir(), "transcripts")), 0, 0)

	done := make(chan bool, 1)
	go func() {
		done <- s.engine.runIntent(ctx, task, "work#1", worker, intent, "", "")
	}()
	select {
	case <-done:
	case <-time.After(120 * time.Second):
		t.Fatal("runIntent did not finish")
	}

	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil {
		t.Fatalf("intent: %+v err=%v", node, err)
	}
	if node.State != "paused" {
		t.Fatalf("intent state = %q after a retry, want paused", node.State)
	}
	if provider.calls.Load() < 2 {
		t.Fatalf("provider called %d times; the retry path was not exercised", provider.calls.Load())
	}
}

// writeRunArtifact places a file under the worker's per-intent run dir
// (<workDir>/tasks/<taskID>/i<intentID>), which is what ensureRunDir creates and
// what the worker's artifact: references resolve against.
func writeRunArtifact(t *testing.T, workDir, taskID string, intentID int64, name, body string) {
	t.Helper()
	dir := filepath.Join(workDir, "tasks", taskID, "i"+strconv.FormatInt(intentID, 10))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
