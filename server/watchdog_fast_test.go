package server

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestDecideCycleTable(t *testing.T) {
	cases := []struct {
		name         string
		cycle        int
		signal       cycleSignal
		answer       cycleAnswer
		action       cycleAction
		next         int
		terminal     string
		defaultRule  string
		requestCycle bool
	}{
		{"C0 绿灯进入 C1", 0, cycleSignalGreen, cycleAnswerNone, cycleActionNext, 1, "", "", false},
		{"C0 用户请求静默默认同意", 0, cycleSignalAsk, cycleAnswerNone, cycleActionNext, 1, "", "", false},
		{"C0 用户同意进入 C1", 0, cycleSignalAsk, cycleAnswerYes, cycleActionNext, 1, "", "", false},
		{"C0 用户拒绝终止", 0, cycleSignalAsk, cycleAnswerNo, cycleActionTerminate, 0, "stopped", "", false},
		{"C0 慢速终止", 0, cycleSignalTerminate, cycleAnswerNone, cycleActionTerminate, 0, "stopped", "", false},
		{"C0 无信号终止", 0, cycleSignalNone, cycleAnswerNone, cycleActionTerminate, 0, "exhausted", "", false},
		{"C1 绿灯进入 C2", 1, cycleSignalGreen, cycleAnswerNone, cycleActionNext, 2, "", "", false},
		{"C1 用户同意进入 C2", 1, cycleSignalAsk, cycleAnswerYes, cycleActionNext, 2, "", "", false},
		{"C1 用户静默终止", 1, cycleSignalAsk, cycleAnswerNone, cycleActionTerminate, 0, "exhausted", "", false},
		{"C1 用户拒绝终止", 1, cycleSignalAsk, cycleAnswerNo, cycleActionTerminate, 0, "stopped", "", false},
		{"C1 慢速终止", 1, cycleSignalTerminate, cycleAnswerNone, cycleActionTerminate, 0, "stopped", "", false},
		{"C1 无信号终止", 1, cycleSignalNone, cycleAnswerNone, cycleActionTerminate, 0, "exhausted", "", false},
		{"C2 绿灯止步生成 C3 请求", 2, cycleSignalGreen, cycleAnswerNone, cycleActionRequest, 3, "", "c1_plus_terminate", true},
		{"C2 用户同意进入 C3", 2, cycleSignalAsk, cycleAnswerYes, cycleActionNext, 3, "", "", false},
		{"C2 用户静默终止", 2, cycleSignalAsk, cycleAnswerNone, cycleActionTerminate, 0, "exhausted", "", false},
		{"C2 用户拒绝终止", 2, cycleSignalAsk, cycleAnswerNo, cycleActionTerminate, 0, "stopped", "", false},
		{"C2 慢速终止", 2, cycleSignalTerminate, cycleAnswerNone, cycleActionTerminate, 0, "stopped", "", false},
		{"C2 无信号终止", 2, cycleSignalNone, cycleAnswerNone, cycleActionTerminate, 0, "exhausted", "", false},
		{"C3 绿灯生成下一周期请求", 3, cycleSignalGreen, cycleAnswerNone, cycleActionRequest, 4, "", "c1_plus_terminate", true},
		{"C3 用户同意进入 C4", 3, cycleSignalAsk, cycleAnswerYes, cycleActionNext, 4, "", "", false},
		{"C3 用户静默终止", 3, cycleSignalAsk, cycleAnswerNone, cycleActionTerminate, 0, "exhausted", "", false},
		{"C3 用户拒绝终止", 3, cycleSignalAsk, cycleAnswerNo, cycleActionTerminate, 0, "stopped", "", false},
		{"C3 慢速终止", 3, cycleSignalTerminate, cycleAnswerNone, cycleActionTerminate, 0, "stopped", "", false},
		{"C3 无信号终止", 3, cycleSignalNone, cycleAnswerNone, cycleActionTerminate, 0, "exhausted", "", false},
		{"C5 绿灯生成下一周期请求", 5, cycleSignalGreen, cycleAnswerNone, cycleActionRequest, 6, "", "c1_plus_terminate", true},
		{"C5 用户同意进入 C6", 5, cycleSignalAsk, cycleAnswerYes, cycleActionNext, 6, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideCycle(tc.cycle, tc.cycle, defaultWatchdogMaxAuto, tc.signal, tc.answer)
			if got.Action != tc.action || got.NextCycle != tc.next || got.TerminalState != tc.terminal {
				t.Fatalf("decision=%+v want action=%s next=%d terminal=%s", got, tc.action, tc.next, tc.terminal)
			}
			if tc.defaultRule != "" && got.DefaultRule != tc.defaultRule {
				t.Fatalf("default rule=%q want %q", got.DefaultRule, tc.defaultRule)
			}
			if tc.requestCycle && got.RequestKind == "" {
				t.Fatal("request action missing request kind")
			}
		})
	}
}

func TestDecideCycleAutoBudget(t *testing.T) {
	cases := []struct {
		name    string
		maxAuto int
		cycle   int
		signal  cycleSignal
		answer  cycleAnswer
		action  cycleAction
		next    int
	}{
		{"N1 C0 green -> C1", 1, 0, cycleSignalGreen, cycleAnswerNone, cycleActionNext, 1},
		{"N1 C1 green -> ask", 1, 1, cycleSignalGreen, cycleAnswerNone, cycleActionRequest, 2},
		{"N2 C0 green -> C1", 2, 0, cycleSignalGreen, cycleAnswerNone, cycleActionNext, 1},
		{"N2 C1 green -> C2", 2, 1, cycleSignalGreen, cycleAnswerNone, cycleActionNext, 2},
		{"N2 C2 green -> ask", 2, 2, cycleSignalGreen, cycleAnswerNone, cycleActionRequest, 3},
		{"N3 C2 green -> C3", 3, 2, cycleSignalGreen, cycleAnswerNone, cycleActionNext, 3},
		{"N3 C3 green -> ask", 3, 3, cycleSignalGreen, cycleAnswerNone, cycleActionRequest, 4},
		{"N4 C3 green -> C4", 4, 3, cycleSignalGreen, cycleAnswerNone, cycleActionNext, 4},
		{"N4 C4 green -> ask", 4, 4, cycleSignalGreen, cycleAnswerNone, cycleActionRequest, 5},
		{"ask yes advances", 2, 1, cycleSignalAsk, cycleAnswerYes, cycleActionNext, 2},
		{"ask no stops", 2, 1, cycleSignalAsk, cycleAnswerNo, cycleActionTerminate, 0},
		{"ask silence exhausts", 2, 1, cycleSignalAsk, cycleAnswerNone, cycleActionTerminate, 0},
		{"C0 ask silence advances", 4, 0, cycleSignalAsk, cycleAnswerNone, cycleActionNext, 1},
		{"terminate stops", 4, 2, cycleSignalTerminate, cycleAnswerNone, cycleActionTerminate, 0},
		{"no signal exhausts", 4, 2, cycleSignalNone, cycleAnswerNone, cycleActionTerminate, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideCycle(tc.cycle, tc.cycle, tc.maxAuto, tc.signal, tc.answer)
			if got.Action != tc.action || got.NextCycle != tc.next {
				t.Fatalf("decision=%+v want action=%s next=%d", got, tc.action, tc.next)
			}
			if tc.action == cycleActionTerminate && got.TerminalState == "" {
				t.Fatal("terminate decision missing terminal state")
			}
		})
	}
}

func TestDecideCycleUsesCumulativeAutoBudget(t *testing.T) {
	if got := decideCycle(0, 2, 2, cycleSignalGreen, cycleAnswerNone); got.Action != cycleActionRequest {
		t.Fatalf("used budget was ignored: %+v", got)
	}
	if got := decideCycle(0, 0, 2, cycleSignalGreen, cycleAnswerNone); got.Action != cycleActionNext || got.NextCycle != 1 {
		t.Fatalf("unused budget did not advance: %+v", got)
	}
}

func TestWatchdogRunDTOAutoBudget(t *testing.T) {
	cases := []struct {
		maxAuto, inputUsed int
		used, remaining    int
	}{
		{2, 0, 0, 2},
		{2, 1, 1, 1},
		{2, 2, 2, 0},
		{2, 5, 2, 0},
		{1, 0, 0, 1},
		{4, 3, 3, 1},
	}
	for _, tc := range cases {
		var d watchdogRunDTO
		d.applyAutoBudget(tc.maxAuto, tc.inputUsed)
		if d.MaxAutoCycles != tc.maxAuto || d.AutoCyclesUsed != tc.used || d.AutoCyclesRemaining != tc.remaining {
			t.Fatalf("budget(%d,%d)=%+v", tc.maxAuto, tc.inputUsed, d)
		}
	}
}

func TestRunMonitorTracksOnlyAutonomousAdvances(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("auto budget", "count only green advances", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	monitor := NewRunMonitor(m.pg, nil)
	monitor.Register(task.ID, 1, "run-auto", "work#1")
	monitor.RecordAutoAdvance("run-auto")
	monitor.RecordAutoAdvance("run-auto")
	snap := monitor.Lookup(1)
	if snap == nil || snap.AutoCyclesUsed != 2 || snap.CycleNo != 0 {
		t.Fatalf("snapshot=%+v, want 2 autonomous advances at cycle 0", snap)
	}
	monitor.SetCycle("run-auto", 3, time.Now(), false, db.SlowPathNone, db.WatchdogDecisionNone)
	if snap := monitor.Lookup(1); snap.AutoCyclesUsed != 2 {
		t.Fatalf("user cycle advance changed auto count: %+v", snap)
	}
	monitor.Flush()
	row, err := m.pg.WorkerRunByID(t.Context(), "run-auto")
	if err != nil || row == nil || row.AutoCyclesUsed != 2 || row.CycleNo != 3 {
		t.Fatalf("persisted run=%+v err=%v", row, err)
	}
}

func TestWatchdogFastPressureOnceAndSlowPathQueue(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	keys := []string{settingWatchdogEnabled, settingWatchdogPressureSec, settingWatchdogSlowPathSec}
	previous := map[string]string{}
	present := map[string]bool{}
	for _, key := range keys {
		if old, ok, _ := m.pg.GetSetting(key); ok {
			previous[key], present[key] = old, true
		}
	}
	oldRun := agentRunSecs(t, m, "worker")
	t.Cleanup(func() {
		for _, key := range keys {
			if present[key] {
				_ = m.pg.SetSetting(key, previous[key])
			} else {
				_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, key)
			}
		}
		_ = m.pg.SetAgentRunSeconds("worker", oldRun)
	})
	for key, value := range map[string]string{
		settingWatchdogEnabled:     "true",
		settingWatchdogPressureSec: "1",
		settingWatchdogSlowPathSec: "2",
	} {
		if err := m.pg.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.pg.SetAgentRunSeconds("worker", 10); err != nil {
		t.Fatal(err)
	}
	runID := "run-fast-pressure"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	_, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	defer func() {
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()

	now = now.Add(2 * time.Second)
	if cfg := s.watchdogConfig(); !cfg.Enabled {
		t.Fatalf("watchdog config not enabled: %+v", cfg)
	}
	if snap := monitor.Lookup(intent.ID); snap == nil || !snap.CycleStart.Equal(now.Add(-2*time.Second)) {
		t.Fatalf("pre-tick snapshot=%+v", snap)
	}
	s.watchdog.fast.Tick(context.Background())
	msg, ok := s.engine.drainSteer(intent.ID)
	if !ok || msg.Source != "watchdog" || msg.Text != watchdogPressureText {
		t.Fatalf("pressure steer=%+v ok=%v snap=%+v", msg, ok, monitor.Lookup(intent.ID))
	}
	if snap := monitor.Lookup(intent.ID); snap == nil || !snap.PressureSent || snap.SlowPathState != db.SlowPathQueued {
		t.Fatalf("run after pressure=%+v", snap)
	}
	s.watchdog.fast.Tick(context.Background())
	if _, ok := s.engine.drainSteer(intent.ID); ok {
		t.Fatal("pressure prompt was delivered twice in one cycle")
	}
	job, err := m.pg.WatchdogJobByCycle(context.Background(), runID, 0)
	if err != nil || job == nil {
		t.Fatalf("slow path job=%+v err=%v", job, err)
	}
}

func TestWatchdogCycleResetReleasesJobKey(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	monitor.SetCycleResetHook(s.watchdogOnCycleReset)
	runID := "run-cycle-reset"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	start := now
	job := &db.WatchdogJob{TaskID: task.ID, IntentID: intent.ID, RunID: runID, CycleNo: 0,
		CycleStart: &start, Snapshot: []byte(`{"summary":"old cycle"}`)}
	if _, _, err := m.pg.EnqueueWatchdogJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	monitor.SetSlowPath(runID, db.SlowPathQueued, "", "", nil, 0)
	// An effective write resets the run to a fresh C0 at a new start. The old
	// (run, cycle) row must be removed, or the new 10-minute job is suppressed.
	now = now.Add(time.Minute)
	monitor.Observe(runID, db.Activity{Kind: "tool_use", Tool: "record_fact",
		Detail: `{"fact_type":"claim","progress_event":"validated_weakness"}`})
	monitor.Observe(runID, db.Activity{Kind: "tool_result", Tool: "record_fact", Detail: `{"id":1}`})
	if old, err := m.pg.WatchdogJobByCycle(context.Background(), runID, 0); err != nil || old != nil {
		t.Fatalf("old cycle job survived reset: %+v err=%v", old, err)
	}
	newStart := now
	newJob := &db.WatchdogJob{TaskID: task.ID, IntentID: intent.ID, RunID: runID, CycleNo: 0,
		CycleStart: &newStart, Snapshot: []byte(`{"summary":"new cycle"}`)}
	if _, created, err := m.pg.EnqueueWatchdogJob(context.Background(), newJob); err != nil || !created {
		t.Fatalf("new cycle job was suppressed: created=%v err=%v", created, err)
	}
}

func TestWatchdogFastSkipsPressureAndSlowPathWhileDecisionOpen(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	keys := []string{settingWatchdogEnabled, settingWatchdogPressureSec, settingWatchdogSlowPathSec}
	previous := map[string]string{}
	present := map[string]bool{}
	for _, key := range keys {
		if old, ok, _ := m.pg.GetSetting(key); ok {
			previous[key], present[key] = old, true
		}
	}
	oldRun := agentRunSecs(t, m, "worker")
	t.Cleanup(func() {
		for _, key := range keys {
			if present[key] {
				_ = m.pg.SetSetting(key, previous[key])
			} else {
				_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, key)
			}
		}
		_ = m.pg.SetAgentRunSeconds("worker", oldRun)
	})
	for key, value := range map[string]string{
		settingWatchdogEnabled:     "true",
		settingWatchdogPressureSec: "1",
		settingWatchdogSlowPathSec: "2",
	} {
		if err := m.pg.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.pg.SetAgentRunSeconds("worker", 10); err != nil {
		t.Fatal(err)
	}
	runID := "run-decision-open"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	_, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	defer func() {
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()
	monitor.SetCycle(runID, 0, now, false, db.SlowPathNone, db.WatchdogDecisionOpen)

	now = now.Add(3 * time.Second)
	s.watchdog.fast.Tick(context.Background())
	if _, ok := s.engine.drainSteer(intent.ID); ok {
		t.Fatal("pressure prompt was injected while a decision card was open")
	}
	if job, err := m.pg.WatchdogJobByCycle(context.Background(), runID, 0); err != nil || job != nil {
		t.Fatalf("slow path job was created while a decision card was open: %+v err=%v", job, err)
	}

	monitor.SetDecisionState(runID, db.WatchdogDecisionAnswered)
	now = now.Add(3 * time.Second)
	s.watchdog.fast.Tick(context.Background())
	if _, ok := s.engine.drainSteer(intent.ID); ok {
		t.Fatal("pressure prompt was injected while a decision was pending")
	}
	if job, err := m.pg.WatchdogJobByCycle(context.Background(), runID, 0); err != nil || job != nil {
		t.Fatalf("slow path job was created while a decision was pending: %+v err=%v", job, err)
	}

	for _, cycle := range []int{2, 3} {
		monitor.SetCycle(runID, cycle, now, false, db.SlowPathNone, db.WatchdogDecisionOpen)
		now = now.Add(3 * time.Second)
		s.watchdog.fast.Tick(context.Background())
		if _, ok := s.engine.drainSteer(intent.ID); ok {
			t.Fatalf("C%d pressure prompt was injected while a decision card was open", cycle)
		}
		if job, err := m.pg.WatchdogJobByCycle(context.Background(), runID, cycle); err != nil || job != nil {
			t.Fatalf("C%d slow path job was created while a decision card was open: %+v err=%v", cycle, job, err)
		}
	}
}

func TestWatchdogUnavailableAtCycleBoundaryAppliesDefault(t *testing.T) {
	cases := []struct {
		name       string
		cycle      int
		slowClass  string
		wantCycle  int
		terminated bool
	}{
		{"C0 ask_user silently enters C1", 0, "ask_user", 1, false},
		{"C1 ask_user terminates on silence", 1, "ask_user", 1, true},
		{"C2 green cannot ask, terminates", 2, "continue", 2, true},
		{"C3 green cannot ask, terminates", 3, "continue", 3, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, task, intent := testWatchdogTask(t)
			now := time.Now()
			s := newAdmissionTestServer(m, nil)
			s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
			monitor := s.watchdog.monitor
			s.engine.SetRunMonitor(monitor)
			runID := "run-unavailable-boundary"
			monitor.Register(task.ID, intent.ID, runID, "work#1")
			monitor.SetCycle(runID, tc.cycle, now, false, db.SlowPathNone, db.WatchdogDecisionNone)
			if tc.cycle >= 2 {
				// The fixture omits MaxAutoCycles, so the decision table clamps it to
				// the default budget of one. C2/C3 must model that budget as spent;
				// otherwise the current run-wide semantics correctly auto-advance.
				monitor.RecordAutoAdvance(runID)
			}
			monitor.SetSlowPath(runID, db.SlowPathDone, tc.slowClass, "fixture", nil, tc.cycle)
			if _, err := m.pg.CreateOrUpdateWatchdogUnavailable(t.Context(), task.ID,
				"Watchdog Agent 不可用", 1, &now, &now, &now); err != nil {
				t.Fatal(err)
			}
			workCtx, cancel := context.WithCancelCause(context.Background())
			s.engine.registerWorkRun(intent.ID, runID, cancel)
			done := make(chan struct{})
			if tc.terminated {
				go func() {
					defer close(done)
					<-workCtx.Done()
					cause, _ := context.Cause(workCtx).(*agent.AbortCause)
					if cause != nil {
						s.engine.settleWatchdogTermination(task, "work#1", intent, runID, cause.Text, cause.TerminalState)
					}
					_, complete := s.engine.detachWork(intent.ID)
					complete(nil)
				}()
			} else {
				defer func() {
					cancel(nil)
					_, complete := s.engine.detachWork(intent.ID)
					complete(nil)
				}()
			}

			snap := monitor.Lookup(intent.ID)
			if snap == nil {
				t.Fatal("run disappeared")
			}
			cfg := watchdogConfig{Enabled: true, CycleAfter: 20 * time.Minute, AgentRetry: time.Minute}
			s.watchdog.fast.processCycle(t.Context(), task, *snap, cfg)

			if tc.terminated {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("cycle boundary did not settle the worker")
				}
				node, err := task.Store.GetNode(intent.ID)
				if err != nil || node == nil || node.State != "exhausted" {
					t.Fatalf("terminated intent=%+v err=%v, want exhausted", node, err)
				}
			} else if got := monitor.Lookup(intent.ID); got == nil || got.CycleNo != tc.wantCycle {
				t.Fatalf("C0 silent consent cycle=%+v, want C%d", got, tc.wantCycle)
			}
			if ask, err := m.pg.OpenWatchdogAsk(t.Context(), runID, tc.cycle); err != nil || ask != nil {
				t.Fatalf("ask was created while unavailable: %+v err=%v", ask, err)
			}
		})
	}
}

func TestWatchdogAskWriteFailureTerminatesAtBoundary(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	runID := "run-ask-write-failure"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetCycle(runID, 1, now, false, db.SlowPathNone, db.WatchdogDecisionNone)
	monitor.SetSlowPath(runID, db.SlowPathDone, "ask_user", "needs a decision", nil, 1)

	funcName := "artex_test_fail_watchdog_ask"
	if _, err := m.pg.Exec(`CREATE OR REPLACE FUNCTION ` + funcName + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced watchdog request failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`CREATE TRIGGER ` + funcName + ` BEFORE INSERT ON watchdog_requests FOR EACH ROW WHEN (NEW.task_id = '` + task.ID + `') EXECUTE FUNCTION ` + funcName + `()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DROP TRIGGER IF EXISTS ` + funcName + ` ON watchdog_requests`)
		_, _ = m.pg.Exec(`DROP FUNCTION IF EXISTS ` + funcName + `()`)
	})

	workCtx, cancel := context.WithCancelCause(context.Background())
	s.engine.registerWorkRun(intent.ID, runID, cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-workCtx.Done()
		cause, _ := context.Cause(workCtx).(*agent.AbortCause)
		if cause != nil {
			s.engine.settleWatchdogTermination(task, "work#1", intent, runID, cause.Text, cause.TerminalState)
		}
		_, complete := s.engine.detachWork(intent.ID)
		complete(nil)
	}()

	snap := monitor.Lookup(intent.ID)
	if snap == nil {
		t.Fatal("run disappeared")
	}
	cfg := watchdogConfig{Enabled: true, CycleAfter: 20 * time.Minute, AgentRetry: time.Minute}
	s.watchdog.fast.processCycle(t.Context(), task, *snap, cfg)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ask write failure did not settle the worker at the boundary")
	}
	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil || node.State != "exhausted" {
		t.Fatalf("terminated intent=%+v err=%v, want exhausted", node, err)
	}
}

func TestWatchdogFastDoesNotCreateAskWhileUnavailable(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	runID := "run-unavailable-ask"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	if _, err := m.pg.CreateOrUpdateWatchdogUnavailable(t.Context(), task.ID,
		"Watchdog Agent 不可用", 1, &now, &now, &now); err != nil {
		t.Fatal(err)
	}
	cfg := watchdogConfig{Enabled: true, CycleAfter: 20 * time.Minute, AgentRetry: time.Minute}
	snap := monitor.Lookup(intent.ID)
	if snap == nil {
		t.Fatal("run disappeared")
	}
	s.watchdog.fast.createAsk(t.Context(), task, *snap, cfg, true)
	if card, err := m.pg.OpenWatchdogAsk(t.Context(), runID, 0); err != nil || card != nil {
		t.Fatalf("ask was created while the default card was open: %+v err=%v", card, err)
	}
}

func TestWatchdogFastCycleAdvanceThenAsk(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	cfg := watchdogConfig{
		Enabled: true, PressureAfter: time.Minute, SlowPathAfter: 2 * time.Minute,
		CycleAfter: 3 * time.Minute, AgentKey: "watchdog", AgentRetry: time.Minute,
		MaxAutoCycles: 2,
	}
	runID := "run-fast-cycle"
	monitor.Register(task.ID, intent.ID, runID, "work#1")

	for want := 1; want <= 2; want++ {
		monitor.SetSlowPath(runID, db.SlowPathDone, "continue", "still useful", nil, want-1)
		now = now.Add(3 * time.Minute)
		snap := monitor.Lookup(intent.ID)
		if snap == nil {
			t.Fatal("run disappeared")
		}
		s.watchdog.fast.processCycle(context.Background(), task, *snap, cfg)
		got := monitor.Lookup(intent.ID)
		if got == nil || got.CycleNo != want {
			t.Fatalf("after cycle %d snapshot=%+v", want, got)
		}
	}
	monitor.SetSlowPath(runID, db.SlowPathDone, "continue", "still useful", nil, 2)
	now = now.Add(3 * time.Minute)
	snap := monitor.Lookup(intent.ID)
	s.watchdog.fast.processCycle(context.Background(), task, *snap, cfg)
	card, err := m.pg.OpenWatchdogAsk(context.Background(), runID, 2)
	if err != nil || card == nil {
		t.Fatalf("C2 green did not create a C3 request: %+v err=%v", card, err)
	}
	if card.Question == "" || card.CycleNo != 2 {
		t.Fatalf("request shape=%+v", card)
	}
	if got := monitor.Lookup(intent.ID); got == nil || got.DecisionState != db.WatchdogDecisionOpen {
		t.Fatalf("decision state=%+v", got)
	}
}

func TestWatchdogFastMidCycleAskKeepsCycleBoundary(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	clock := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return clock })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	runID := "run-mid-ask"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	cycleStart := monitor.Lookup(intent.ID).CycleStart
	cfg := watchdogConfig{Enabled: true, CycleAfter: 20 * time.Minute, AgentRetry: time.Minute}
	clock = clock.Add(10 * time.Minute)
	snap := monitor.Lookup(intent.ID)
	s.watchdog.fast.createAsk(t.Context(), task, *snap, cfg, false)

	card, err := s.m.pg.OpenWatchdogAsk(t.Context(), runID, 0)
	if err != nil || card == nil {
		t.Fatalf("ask card=%+v err=%v", card, err)
	}
	wantDeadline := cycleStart.Add(cfg.CycleAfter)
	if card.DeadlineAt == nil || card.DeadlineAt.Sub(wantDeadline).Abs() > time.Millisecond {
		t.Fatalf("deadline=%v want %v", card.DeadlineAt, wantDeadline)
	}
	got := monitor.Lookup(intent.ID)
	if got == nil || got.CycleNo != 0 || !got.CycleStart.Equal(cycleStart) || got.DecisionState != db.WatchdogDecisionOpen {
		t.Fatalf("mid-cycle ask moved the cycle: %+v", got)
	}
}

func TestWatchdogFastProviderErrorDoesNotAsk(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	clock := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return clock })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	runID := "run-provider"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetSlowPath(runID, db.SlowPathDone, "provider_error", "quota exhausted", nil, 0)
	clock = clock.Add(2 * time.Minute)
	snap := monitor.Lookup(intent.ID)
	s.watchdog.fast.processCycle(t.Context(), task, *snap, watchdogConfig{Enabled: true, CycleAfter: time.Minute})
	if card, err := m.pg.OpenWatchdogAsk(t.Context(), runID, 0); err != nil || card != nil {
		t.Fatalf("provider error created a user request: %+v err=%v", card, err)
	}
	got := monitor.Lookup(intent.ID)
	if got == nil || got.State != db.WorkerRunStateRunning || !got.CycleStart.Equal(clock) {
		t.Fatalf("provider error did not reset the cycle: %+v", got)
	}
}

func TestWatchdogC0ConsentReasonIsNotSilentDefault(t *testing.T) {
	got := decideCycle(0, 0, defaultWatchdogMaxAuto, cycleSignalAsk, cycleAnswerYes)
	if got.Action != cycleActionNext || got.NextCycle != 1 {
		t.Fatalf("C0 consent decision=%+v", got)
	}
	if got.Reason != "用户明确同意进入 C1" {
		t.Fatalf("C0 consent reason=%q, want explicit user consent", got.Reason)
	}
}

func TestWatchdogDefaultRule(t *testing.T) {
	if got := watchdogDefaultRule(0); got != "c0_continue" {
		t.Fatalf("C0 rule=%q", got)
	}
	for _, cycle := range []int{1, 2, 3, 9} {
		if got := watchdogDefaultRule(cycle); got != "c1_plus_terminate" {
			t.Fatalf("C%d rule=%q", cycle, got)
		}
	}
}

// A termination can wait on a worker's settlement for up to
// watchdogSettlementWait plus the hard-cancel window. processCycle runs on the
// single shared Fast Path tick, so that wait must be dispatched in the
// background; otherwise every other task's pressure prompt, Slow Path enqueue
// and cycle accounting is delayed with it.
func TestWatchdogProcessCycleTerminateDoesNotBlockTick(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)

	runID := "run-async-terminate"
	_, workCancel := context.WithCancelCause(context.Background())
	settled := make(chan struct{}, 4)
	var dispatches atomic.Int32
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	finished := make(chan struct{})
	s.engine.registerWorkRunFull(intent.ID, runID, task.ID, "work#1", workCancel,
		func(reason string) bool {
			dispatches.Add(1)
			settled <- struct{}{}
			go func() {
				defer close(finished)
				<-release
				s.engine.settleWatchdogTermination(task, "work#1", intent, runID, reason, "stopped")
				_, done := s.engine.detachWork(intent.ID)
				done(nil)
			}()
			return true
		})
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetSlowPath(runID, db.SlowPathDone, "terminate", "no progress", nil, 0)
	snap := monitor.Lookup(intent.ID)
	if snap == nil {
		t.Fatal("run disappeared")
	}
	cfg := watchdogConfig{
		Enabled: true, PressureAfter: time.Minute, SlowPathAfter: 2 * time.Minute,
		CycleAfter: 3 * time.Minute, AgentKey: "watchdog", AgentRetry: time.Minute,
		MaxAutoCycles: 2,
	}

	returned := make(chan struct{})
	go func() {
		s.watchdog.fast.processCycle(context.Background(), task, *snap, cfg)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("processCycle blocked on the settlement window instead of dispatching it")
	}
	select {
	case <-settled:
	case <-time.After(5 * time.Second):
		t.Fatal("termination was not dispatched after the cycle decision")
	}
	if got := dispatches.Load(); got != 1 {
		t.Fatalf("settlement requested %d times, want 1", got)
	}
	// A second decision for the same run must not stack another attempt while
	// the first settlement is still pending.
	s.watchdog.fast.processCycle(context.Background(), task, *snap, cfg)
	if got := dispatches.Load(); got != 1 {
		t.Fatalf("duplicate decision stacked %d settlement requests, want 1", got)
	}
	close(release)
	released = true
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatched termination did not settle")
	}
	node, err := task.Store.GetNode(intent.ID)
	if err != nil || node == nil || node.State != "stopped" {
		t.Fatalf("intent=%+v err=%v, want stopped", node, err)
	}
}

func TestRouteBudgetExceeded(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	snap := RunSnapshot{
		RouteID: 7, StartedAt: now.Add(-2 * time.Second),
		RouteBudget:   db.RouteBudget{MaxToolCalls: 10, MaxInputTokens: 1000, MaxWallSeconds: 60},
		RouteUsedBase: db.RouteBudgetUsed{ToolCalls: 3, InputTokens: 200},
		ToolCalls:     2, InputTokens: 100,
	}
	if reason, exceeded := routeBudgetExceeded(snap, now); exceeded || reason != "" {
		t.Fatalf("budget tripped early: %s", reason)
	}
	snap.ToolCalls = 9
	if reason, exceeded := routeBudgetExceeded(snap, now); !exceeded || !strings.Contains(reason, "工具调用") {
		t.Fatalf("tool budget not enforced: %s", reason)
	}
	snap.ToolCalls = 0
	snap.InputTokens = 900
	if reason, exceeded := routeBudgetExceeded(snap, now); !exceeded || !strings.Contains(reason, "token") {
		t.Fatalf("token budget not enforced: %s", reason)
	}
	snap.InputTokens = 0
	snap.StartedAt = now.Add(-70 * time.Second)
	if reason, exceeded := routeBudgetExceeded(snap, now); !exceeded || !strings.Contains(reason, "墙钟") {
		t.Fatalf("wall budget not enforced: %s", reason)
	}
}
