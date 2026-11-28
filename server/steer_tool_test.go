package server

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// steerFixture registers a live work for one intent so SteerWorkFrom accepts the
// message (it refuses to queue for a non-running work).
func steerFixture(t *testing.T) (*Server, *RunMonitor, *Task, *db.Node, func()) {
	t.Helper()
	m, task, intent := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	monitor := NewRunMonitor(nil, nil)
	s.engine.SetRunMonitor(monitor)
	runID := "run-steer"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	_, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	cleanup := func() {
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}
	return s, monitor, task, intent, cleanup
}

// A watchdog pressure prompt must not block pure write-back tools: blocking
// record_fact/market writes cancels exactly the response the pressure asked for.
func TestDrainSteerForToolExemptsWriteBack(t *testing.T) {
	s, monitor, task, intent, cleanup := steerFixture(t)
	defer cleanup()
	if err := s.engine.SteerWorkFrom(intent.ID, "watchdog", watchdogPressureText); err != nil {
		t.Fatal(err)
	}
	monitor.SetPressureSent("run-steer")

	for _, tool := range []string{"record_fact", "insert_assets", "report_finding", "TodoWrite"} {
		if _, ok := s.engine.drainSteerForTool(intent.ID, tool); ok {
			t.Fatalf("%s was blocked by a watchdog pressure prompt", tool)
		}
	}
	// Still queued: the next probe call must receive it.
	msg, ok := s.engine.drainSteerForTool(intent.ID, "Bash")
	if !ok || msg.Source != "watchdog" || msg.Text != watchdogPressureText {
		t.Fatalf("probe call did not receive the pressure prompt: %+v ok=%v", msg, ok)
	}
	// Drained once only.
	if _, ok := s.engine.drainSteer(intent.ID); ok {
		t.Fatal("pressure prompt was delivered twice")
	}
	_ = task
}

// A planner correction (not watchdog pressure) always wins, even on write-back
// tools: it is a human/planner course change the worker must read before acting.
func TestDrainSteerForToolPlannerStillBlocksWrites(t *testing.T) {
	s, _, _, intent, cleanup := steerFixture(t)
	defer cleanup()
	if err := s.engine.SteerWorkFrom(intent.ID, "planner", "stop the brute force, pivot now"); err != nil {
		t.Fatal(err)
	}
	msg, ok := s.engine.drainSteerForTool(intent.ID, "record_fact")
	if !ok || msg.Source != "planner" {
		t.Fatalf("planner correction did not block record_fact: %+v ok=%v", msg, ok)
	}
}

// If a high-value write-back already reset the run's cycle (PressureSent cleared),
// the stale watchdog nag is dropped instead of nagging a run that complied.
func TestDrainSteerForToolDropsSatisfiedPressure(t *testing.T) {
	s, monitor, _, intent, cleanup := steerFixture(t)
	defer cleanup()
	if err := s.engine.SteerWorkFrom(intent.ID, "watchdog", watchdogPressureText); err != nil {
		t.Fatal(err)
	}
	runID := monitor.LookupRun("run-steer").RunID
	monitor.SetPressureSent(runID)
	// Simulate the compliance path: a high-value write drives a cycle reset, which
	// clears PressureSent (resetCycleLocked sets it false).
	monitor.Observe(runID, db.Activity{Kind: "tool_use", Tool: "record_fact",
		Detail: `{"fact_type":"claim","progress_event":"validated_weakness"}`})
	monitor.Observe(runID, db.Activity{Kind: "tool_result", Tool: "record_fact", Detail: `{"id":1}`})
	if snap := monitor.LookupRun(runID); snap.PressureSent {
		t.Fatal("fixture: cycle reset did not clear PressureSent")
	}
	if _, ok := s.engine.drainSteerForTool(intent.ID, "record_fact"); ok {
		t.Fatal("satisfied pressure prompt blocked a write-back call")
	}
	if _, ok := s.engine.drainSteer(intent.ID); ok {
		t.Fatal("satisfied pressure prompt survived for the next probe call")
	}
}

// Fast Path: normalized polling repeats with no slow-path verdict terminate a pure
// autonomous run at the boundary instead of granting another green cycle.
func TestPollingRepeatsTerminateAtCycleBoundary(t *testing.T) {
	cases := []struct {
		name          string
		human         bool
		wantAction    cycleAction
		wantRequestNo string
	}{
		{"autonomous route terminates", false, cycleActionTerminate, ""},
		{"human route asks instead", true, cycleActionRequest, db.WatchdogRequestAsk},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, task, intent := testWatchdogTask(t)
			now := time.Now()
			s := newAdmissionTestServer(m, nil)
			s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
			monitor := s.watchdog.monitor
			s.engine.SetRunMonitor(monitor)
			runID := "run-poll"
			monitor.Register(task.ID, intent.ID, runID, "work#1")
			monitor.SetEffort(runID, db.EffortStandard, 1, tc.human)
			_, cancel := context.WithCancelCause(context.Background())
			s.engine.registerWorkRun(intent.ID, runID, cancel)
			defer func() {
				_, complete := s.engine.detachWork(intent.ID)
				complete(nil)
			}()
			// Two normalized waits with different durations: still a stall.
			monitor.Observe(runID, db.Activity{Kind: "tool_use", Tool: "Bash", Detail: "sleep 30"})
			monitor.Observe(runID, db.Activity{Kind: "tool_use", Tool: "Bash", Detail: "sleep 600"})
			snap := monitor.LookupRun(runID)
			if snap.PollingRepeats < 2 {
				t.Fatalf("polling repeats=%d, fixture not detected", snap.PollingRepeats)
			}
			cycleStart := snap.CycleStart
			// The guard lives in processCycle. A terminated run must not be granted a
			// new cycle; a human route must instead get an ask card and keep running.
			s.watchdog.fast.processCycle(context.Background(), task, *snap, s.watchdogConfig())
			card, err := m.pg.LatestWatchdogAsk(context.Background(), runID, snap.CycleNo)
			if err != nil {
				t.Fatal(err)
			}
			if tc.human {
				if card == nil || card.Kind != db.WatchdogRequestAsk {
					t.Fatalf("human route did not get an ask card: %+v", card)
				}
				if after := monitor.LookupRun(runID); after == nil || after.State != db.WorkerRunStateRunning {
					t.Fatalf("human route run was stopped: %+v", after)
				}
				return
			}
			if card != nil && card.Kind == db.WatchdogRequestAsk {
				t.Fatalf("autonomous polling stall produced an ask card instead of terminating: %+v", card)
			}
			// Termination is dispatched on its own goroutine (the fixture has no live
			// SDK run to settle), so assert the two durable facts: no new cycle was
			// granted and no ask card was created. The terminate decision itself is
			// covered purely by TestPollingStallSignal.
			if after := monitor.LookupRun(runID); after != nil && after.CycleNo != snap.CycleNo &&
				!after.CycleStart.Equal(cycleStart) {
				t.Fatalf("polling stall was granted a new cycle: %+v", after)
			}
		})
	}
}

// normalizePollingAction must fold duration variants onto one signature and leave
// real work alone.
func TestNormalizePollingAction(t *testing.T) {
	cases := []struct {
		tool, detail, want string
	}{
		{"Bash", "sleep 30", "sleep"},
		{"Bash", "sleep 600", "sleep"},
		{"Bash", "sleep 5 && curl -s http://x", "sleep"},
		{"Bash", "Start-Sleep -Seconds 45", "sleep"},
		{"sleep", "{}", "sleep"},
		{"Bash", "cat slot_poll.log", "slot-wait"},
		{"Bash", "tail -f worker.log", "log-tail"},
		{"Bash", "curl -s http://target/", ""},
		{"Read", "sleep 3", ""},
		{"Bash", "", ""},
		// Real tool_use input is raw JSON, not bare shell text: the gate must read
		// the "command" field or every prefix check silently fails.
		{"Bash", `{"command":"sleep 300"}`, "sleep"},
		{"Bash", `{"command":"sleep 300; tail -n 5 app.log"}`, "sleep"},
		{"Bash", `{"command":"Start-Sleep -Seconds 60"}`, "sleep"},
		{"Bash", `{"command":"cat slot_poll.log"}`, "slot-wait"},
		{"Bash", `{"command":"tail -n 5 app.log"}`, "log-tail"},
		{"Bash", `{"command":"curl -s http://target/api"}`, ""},
		{"Bash", `{"command":"","timeout":3000}`, ""},
		{"sleep", `{"seconds":30}`, "sleep"},
	}
	for _, tc := range cases {
		if got := normalizePollingAction(tc.tool, tc.detail); got != tc.want {
			t.Fatalf("normalizePollingAction(%q,%q)=%q want %q", tc.tool, tc.detail, got, tc.want)
		}
	}
}

// pollingStallSignal is the pure gate extracted from processCycle: repeats at a
// boundary with no other verdict terminate an autonomous run and ask on a human
// route; a slow-path verdict for the same cycle always wins.
func TestPollingStallSignal(t *testing.T) {
	base := RunSnapshot{CycleNo: 2, PollingRepeats: 3}
	if got := pollingStallSignal(base, cycleSignalNone); got != cycleSignalTerminate {
		t.Fatalf("autonomous stall signal=%q want terminate", got)
	}
	human := base
	human.HumanInvolved = true
	if got := pollingStallSignal(human, cycleSignalNone); got != cycleSignalAsk {
		t.Fatalf("human stall signal=%q want ask", got)
	}
	judged := base
	judged.SlowPathCycle = judged.CycleNo
	if got := pollingStallSignal(judged, cycleSignalNone); got != cycleSignalNone {
		t.Fatal("a slow-path verdict for this cycle must win over the polling gate")
	}
	quiet := base
	quiet.PollingRepeats = 1
	if got := pollingStallSignal(quiet, cycleSignalNone); got != cycleSignalNone {
		t.Fatal("a single wait is not a stall")
	}
	if got := pollingStallSignal(base, cycleSignalGreen); got != cycleSignalGreen {
		t.Fatal("an existing signal must not be overridden")
	}
}

// The #14648 pattern: the worker loops on {"command":"sleep 300; tail ..."}. Raw
// JSON tool_use input must still normalize to the same polling signature.
func TestPollingRepeatsDetectsJSONSleepCommands(t *testing.T) {
	monitor := NewRunMonitor(nil, nil)
	monitor.Register("t1", 7, "run-json", "work#1")
	for _, cmd := range []string{
		`{"command":"sleep 300; tail -n 5 app.log"}`,
		`{"command":"sleep 600; tail -n 5 app.log"}`,
	} {
		monitor.Observe("run-json", db.Activity{Kind: "tool_use", Tool: "Bash", Detail: cmd})
	}
	snap := monitor.LookupRun("run-json")
	if snap.PollingRepeats < 2 {
		t.Fatalf("JSON sleep commands were not detected: polling_repeats=%d", snap.PollingRepeats)
	}
	// Past C0 the gate is the sole verdict (no slow-path result for this cycle).
	judged := *snap
	judged.CycleNo, judged.SlowPathCycle = 2, 1
	if got := pollingStallSignal(judged, cycleSignalNone); got != cycleSignalTerminate {
		t.Fatalf("stall signal=%q want terminate", got)
	}
}

// A real tool call between waits breaks the polling run: alternating sleep/curl
// must not be reported as a continuous stall.
func TestPollingRepeatsResetByRealWork(t *testing.T) {
	monitor := NewRunMonitor(nil, nil)
	monitor.Register("t1", 7, "run-x", "work#1")
	monitor.Observe("run-x", db.Activity{Kind: "tool_use", Tool: "Bash", Detail: "sleep 10"})
	monitor.Observe("run-x", db.Activity{Kind: "tool_use", Tool: "Bash", Detail: "sleep 20"})
	if got := monitor.LookupRun("run-x").PollingRepeats; got < 2 {
		t.Fatalf("polling repeats=%d want >=2", got)
	}
	monitor.Observe("run-x", db.Activity{Kind: "tool_use", Tool: "Bash", Detail: "curl -s http://target/api"})
	if got := monitor.LookupRun("run-x").PollingRepeats; got != 0 {
		t.Fatalf("real work did not reset polling repeats: %d", got)
	}
	monitor.Observe("run-x", db.Activity{Kind: "tool_use", Tool: "Bash", Detail: "slot_watch --wait"})
	if got := monitor.LookupRun("run-x").PollingRepeats; got != 1 {
		t.Fatalf("polling repeats after reset=%d want 1", got)
	}
}

// 人工路线最高优先级：周期边界本要终止时，human_involved 的 run 必须转为
// ask_user 卡片，run 继续存活；纯自治 run 则不产生卡片（走 terminate）。
func TestHumanInvolvedRouteConvertedToAsk(t *testing.T) {
	cases := []struct {
		name        string
		human       bool
		wantRunning bool
	}{
		{"autonomous terminates", false, false},
		{"human route asks and keeps running", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, task, intent := testWatchdogTask(t)
			now := time.Now()
			s := newAdmissionTestServer(m, nil)
			s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
			monitor := s.watchdog.monitor
			s.engine.SetRunMonitor(monitor)
			runID := "run-human"
			monitor.Register(task.ID, intent.ID, runID, "work#1")
			monitor.SetEffort(runID, db.EffortStandard, 1, tc.human)
			_, cancel := context.WithCancelCause(context.Background())
			s.engine.registerWorkRun(intent.ID, runID, cancel)
			defer func() {
				_, complete := s.engine.detachWork(intent.ID)
				complete(nil)
			}()
			// No slow-path verdict and no signal: the cycle table's default is terminate.
			snap := monitor.LookupRun(runID)
			s.watchdog.fast.processCycle(context.Background(), task, *snap, s.watchdogConfig())
			card, err := m.pg.LatestWatchdogAsk(context.Background(), runID, snap.CycleNo)
			if err != nil {
				t.Fatal(err)
			}
			if tc.human {
				if card == nil || card.Kind != db.WatchdogRequestAsk {
					t.Fatalf("human route did not get a decision card: %+v", card)
				}
				if after := monitor.LookupRun(runID); after == nil || after.State != db.WorkerRunStateRunning {
					t.Fatalf("human route run was silently killed: %+v", after)
				}
				return
			}
			if card != nil {
				t.Fatalf("autonomous termination produced a card instead of terminating: %+v", card)
			}
		})
	}
}

// 人工路线豁免【只针对自治止损】：用户在卡片上显式点 "stop" 时，人工意志就是
// 停止——必须照常终止，不能被 human_involved 覆盖回"再要一张卡"（否则永远停不下来）。
func TestHumanInvolvedRouteHonorsExplicitStop(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	runID := "run-human-stop"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetEffort(runID, db.EffortStandard, 1, true) // 人工路线
	_, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	defer func() {
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()

	// The card is answered "stop"; processCycle must apply the stop, not re-ask.
	card, created, err := m.pg.CreateWatchdogAsk(context.Background(), &db.WatchdogRequest{
		TaskID: task.ID, IntentID: &intent.ID, RunID: runID, CycleNo: 0,
		Kind: db.WatchdogRequestAsk, Question: "是否继续？",
		Options: []byte(`["continue","stop"]`),
	})
	if err != nil || !created || card == nil {
		t.Fatalf("fixture ask: card=%+v created=%v err=%v", card, created, err)
	}
	if _, err := m.pg.AnswerWatchdogRequest(context.Background(), card.ID, "stop", "人工明确拒绝"); err != nil {
		t.Fatal(err)
	}
	monitor.SetDecisionState(runID, db.WatchdogDecisionAnswered)

	snap := monitor.LookupRun(runID)
	s.watchdog.fast.processCycle(context.Background(), task, *snap, s.watchdogConfig())

	// An explicit stop must terminate, not re-ask. The answered card (status
	// "answered", answer "stop") proves the cycle processor consumed the user's
	// decision instead of overriding it back into another request card. The intent
	// itself stays untouched here because this fixture registers no live SDK run to
	// settle — the terminate dispatch is exercised end-to-end by
	// TestWatchdogProcessCycleTerminateDoesNotBlockTick.
	latest, err := m.pg.LatestWatchdogAsk(context.Background(), runID, snap.CycleNo)
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.Status != db.WatchdogRequestAnswered || latest.Answer != "stop" {
		t.Fatalf("explicit stop was not consumed as a stop: %+v", latest)
	}
	// No second card at all: the buggy override would have asked the same question
	// again (a fresh open row at the same run), leaving the operator unable to stop.
	var cards int
	if err := m.pg.QueryRow(`SELECT COUNT(*) FROM watchdog_requests WHERE run_id=$1 AND kind='watchdog_ask'`,
		runID).Scan(&cards); err != nil {
		t.Fatal(err)
	}
	if cards != 1 {
		t.Fatalf("explicit stop produced %d decision cards, want exactly the answered one", cards)
	}
}
