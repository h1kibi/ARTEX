package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// Human ownership can start MID-RUN: the operator sends guidance to the running
// worker, or answers "continue" on its Watchdog card. Registering the flag once
// would let a run the human just took over be silently terminated at the next
// cycle boundary, which is exactly what the Human Override Invariant forbids.
func TestHumanInvolvedRefreshesMidRun(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, time.Now)
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)

	runID := "run-human-refresh"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetEffort(runID, db.EffortStandard, 1, false)
	_, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	defer func() {
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()

	if monitor.HumanInvolvedRun(runID) {
		t.Fatal("run started human-involved")
	}
	// A planner steer must NOT make the run human-owned: the planner is an agent.
	if err := s.engine.SteerWorkFrom(intent.ID, "planner", "try the other parameter"); err != nil {
		t.Fatal(err)
	}
	if monitor.HumanInvolvedRun(runID) {
		t.Fatal("a planner steer marked the run human-involved")
	}
	// A human steer does.
	if err := s.engine.SteerWorkFrom(intent.ID, "mainagent", "here is the session cookie"); err != nil {
		t.Fatal(err)
	}
	if !monitor.HumanInvolvedRun(runID) {
		t.Fatal("a human steer did not mark the run human-involved")
	}
	if snap := monitor.LookupRun(runID); snap == nil || !snap.HumanInvolved {
		t.Fatalf("snapshot does not report human ownership: %+v", snap)
	}
}

// Answering "continue" on the card is the other way a human takes ownership, so
// the same refresh must happen on that path.
func TestWatchdogContinueMarksRunHumanOwned(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, time.Now)
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)

	runID := "run-continue"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetEffort(runID, db.EffortStandard, 1, false)
	snap := monitor.LookupRun(runID)
	if snap == nil {
		t.Fatal("run not registered")
	}
	if err := s.watchdogContinueCycle(task, *snap, "operator said continue"); err != nil {
		t.Fatal(err)
	}
	if !monitor.HumanInvolvedRun(runID) {
		t.Fatal("answering continue did not mark the run human-involved")
	}
}

// The termination decision is computed from a snapshot. A human steer that lands
// between that snapshot and the commit must cancel the kill: otherwise the run the
// operator just took over dies anyway.
func TestTerminateCancelledByLateHumanSteer(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, time.Now)
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)

	runID := "run-late-steer"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetEffort(runID, db.EffortStandard, 1, false)
	_, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	defer func() {
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()

	// Snapshot taken while the run is still autonomous.
	stale := *monitor.LookupRun(runID)
	if stale.HumanInvolved {
		t.Fatal("fixture already human-involved")
	}
	// The operator takes the wheel after the decision was computed.
	if err := s.engine.SteerWorkFrom(intent.ID, "mainagent", "hold on, try the SSO route"); err != nil {
		t.Fatal(err)
	}
	if !monitor.HumanInvolvedRun(runID) {
		t.Fatal("steer did not mark the run human-involved")
	}

	// Committing an autonomous termination must now be refused.
	if _, err := s.watchdog.fast.terminate(context.Background(), stale, "同一工具反复空转", "stopped", false); err == nil {
		t.Fatal("autonomous termination committed against a human-owned run")
	}
	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil {
		t.Fatalf("intent %d: %v", intent.ID, err)
	}
	if node.State == "stopped" {
		t.Fatal("run was terminated despite the late human steer")
	}

	// An explicit operator stop is NOT blocked by the human-involvement check. The
	// fixture has no live agent loop to settle, so the call blocks on the settlement
	// wait — what matters is that it got past the refusal gate above, i.e. it is not
	// rejected with errWatchdogRunMismatch ("运行中已转为人工介入").
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stopCancel()
	_, err = s.watchdog.fast.terminate(stopCtx, stale, "用户明确拒绝继续", "stopped", true)
	if err != nil && strings.Contains(err.Error(), "转为人工介入") {
		t.Fatalf("explicit human stop was refused by the human-involvement gate: %v", err)
	}
}

// The commit point itself must refuse an autonomous termination once the run is
// human-owned — including when the DECISION snapshot already said so. The earlier
// check skipped exactly that case (`&& !snap.HumanInvolved`), so a run the operator
// had already taken over still went through the terminate path.
func TestEngineRefusesAutoTerminateOnHumanOwnedRun(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, time.Now)
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)

	runID := "run-owned"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetEffort(runID, db.EffortStandard, 1, false)
	_, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	defer func() {
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()

	// The operator lifts the run out of autonomy.
	monitor.SetHumanInvolved(runID, true)

	// Autonomous termination: refused at the commit point, with the run untouched.
	_, err := s.engine.TerminateWorkGuarded(context.Background(), intent.ID, runID,
		"同一工具反复空转", "stopped", 0, false)
	if err == nil {
		t.Fatal("autonomous termination committed on a human-owned run")
	}
	if !errors.Is(err, errWatchdogRunMismatch) {
		t.Fatalf("refusal reason = %v, want errWatchdogRunMismatch", err)
	}
	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil {
		t.Fatalf("intent: %+v err=%v", node, err)
	}
	if node.State == "stopped" {
		t.Fatal("run was terminated despite human ownership")
	}

	// An explicit operator stop is authority, not an autonomous judgement.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stopCancel()
	_, err = s.engine.TerminateWorkGuarded(stopCtx, intent.ID, runID, "用户明确拒绝继续", "stopped", 0, true)
	if err != nil && errors.Is(err, errWatchdogRunMismatch) {
		t.Fatalf("explicit stop refused by the human-ownership gate: %v", err)
	}
}

// explicitStopProvider blocks the first model turn until the test releases it, so
// the termination request lands while the run is live. The first turn then either
// reports need_human or ends naturally; every later turn (wrap-up after a
// settlement request) just closes out with text.
type explicitStopProvider struct {
	needHuman bool
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (p *explicitStopProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		first := false
		p.once.Do(func() {
			first = true
			close(p.entered)
			<-p.release
		})
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if first && p.needHuman {
			args, _ := json.Marshal(map[string]any{
				"fact_type": "observation", "summary": "登录卡在短信验证码",
				"detail":        "/login 提交后要求手机验证码，需要人工提供",
				"evidence_refs": []string{"artifact:mfa.txt"},
				"need_human":    true,
			})
			for _, ev := range []llm.StreamEvent{
				{Type: llm.SEToolUseStart, ToolID: "call-1", ToolName: "record_fact"},
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
			{Type: llm.SETextDelta, Text: "本轮结束"},
			{Type: llm.SEMessageDelta, StopReason: "end_turn"},
			{Type: llm.SEMessageStop},
		} {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

func (p *explicitStopProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, &providerTestError{"not used"}
}

// An operator's explicit "stop" outranks a need-human hand-off and a natural
// completion. The run must settle as stopped with a filled-in result; a paused or
// done intent whose card was already answered leaves the UI and the API
// disagreeing (409 on the decision endpoint).
//
// The stop is issued while the real runIntent is inside its model turn and blocks
// until the pending termination is visible on the work handle, so the settlement
// claim and the stop request really intersect.
func TestExplicitStopOverridesHumanHandoff(t *testing.T) {
	for _, tc := range []struct {
		name      string
		needHuman bool
	}{
		{name: "worker_writes_need_human", needHuman: true},
		{name: "worker_completes", needHuman: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, task, intent := testWatchdogTask(t)
			s := newAdmissionTestServer(m, nil)
			s.watchdog = newWatchdogRuntime(s, time.Now)
			s.engine.SetRunMonitor(s.watchdog.monitor)
			if tc.needHuman {
				writeRunArtifact(t, m.dir, task.ID, intent.ID, "mfa.txt", "blocked at /login: SMS code required")
			}

			provider := &explicitStopProvider{
				needHuman: tc.needHuman,
				entered:   make(chan struct{}),
				release:   make(chan struct{}),
			}
			worker := agent.NewWorker(provider, "stop-run", m.dir,
				transcript.NewStore(filepath.Join(t.TempDir(), "transcripts")), 0, 0)

			runDone := make(chan bool, 1)
			go func() {
				runDone <- s.engine.runIntent(context.Background(), task, "work#1", worker, intent, "", "")
			}()
			select {
			case <-provider.entered:
			case <-time.After(60 * time.Second):
				t.Fatal("worker never started its first turn")
			}

			var runID string
			deadline := time.Now().Add(10 * time.Second)
			for runID == "" && time.Now().Before(deadline) {
				s.engine.workMu.Lock()
				if run := s.engine.work[intent.ID]; run != nil {
					runID = run.runID
				}
				s.engine.workMu.Unlock()
				if runID == "" {
					time.Sleep(5 * time.Millisecond)
				}
			}
			if runID == "" {
				t.Fatal("run identity was never registered")
			}

			type termination struct {
				result TerminationResult
				err    error
			}
			termDone := make(chan termination, 1)
			go func() {
				res, err := s.engine.TerminateWorkGuarded(context.Background(), intent.ID, runID,
					"用户明确拒绝继续", "stopped", -1, true)
				termDone <- termination{result: res, err: err}
			}()

			// Wait until the stop is installed on the live handle; that is the moment
			// the settlement claim races against.
			deadline = time.Now().Add(10 * time.Second)
			for {
				s.engine.workMu.Lock()
				run := s.engine.work[intent.ID]
				pending := run != nil && run.watchdogState != "" && run.humanStop
				s.engine.workMu.Unlock()
				if pending {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("stop request never reached the work handle")
				}
				time.Sleep(5 * time.Millisecond)
			}
			close(provider.release)

			select {
			case ok := <-runDone:
				if !ok {
					t.Fatal("runIntent reported no settlement")
				}
			case <-time.After(60 * time.Second):
				t.Fatal("runIntent did not finish")
			}
			var term termination
			select {
			case term = <-termDone:
			case <-time.After(60 * time.Second):
				t.Fatal("stop request did not return")
			}
			if term.err != nil {
				t.Fatalf("explicit stop returned an error: %v", term.err)
			}
			if term.result.State != "stopped" {
				t.Fatalf("termination state = %q, want stopped", term.result.State)
			}
			node, err := task.Store.GetNode(intent.ID)
			if err != nil || node == nil {
				t.Fatalf("intent: %+v err=%v", node, err)
			}
			if node.State != "stopped" {
				t.Fatalf("intent state = %q, want stopped", node.State)
			}
		})
	}
}
