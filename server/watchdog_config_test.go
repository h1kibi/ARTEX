package server

import (
	"testing"
	"time"
)

func TestWatchdogWorkerRunSeconds(t *testing.T) {
	cfg := watchdogConfig{Enabled: true, CycleAfter: 20 * time.Minute}
	if got := watchdogWorkerRunSeconds(1200, cfg); got != 0 {
		t.Fatalf("default worker timeout=%d, want unlimited (0) with Watchdog enabled", got)
	}
	cfg.WorkerRunSeconds = 6000
	if got := watchdogWorkerRunSeconds(1200, cfg); got != 6000 {
		t.Fatalf("explicit worker timeout=%d, want 6000", got)
	}
	cfg.WorkerRunSeconds = 0
	cfg.Enabled = false
	if got := watchdogWorkerRunSeconds(1200, cfg); got != 1200 {
		t.Fatalf("disabled watchdog changed the Agent timeout to %d", got)
	}
	cfg.Enabled = true
	if got := watchdogWorkerRunSeconds(0, cfg); got != 0 {
		t.Fatalf("unlimited Agent timeout was changed to %d", got)
	}
}

func TestWatchdogAgentsForTaskUsesUnlimitedWorkerTimeout(t *testing.T) {
	m, task, _ := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	s.taskAgents = map[string]*taskAgentBundle{}
	old, had, err := m.pg.GetSetting(settingWatchdogEnabled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = m.pg.SetSetting(settingWatchdogEnabled, old)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingWatchdogEnabled)
		}
	})
	if err := m.pg.SetSetting(settingWatchdogEnabled, "true"); err != nil {
		t.Fatal(err)
	}
	bundle := s.agentsForTask(task)
	if got := bundle.wk.RunTimeout(); got != 0 {
		t.Fatalf("constructed worker timeout=%v, want unlimited with worker_run_seconds=0", got)
	}
}

func TestWatchdogC3ApprovalCanContinueC4(t *testing.T) {
	// The two policies that used to truncate C4: the C3 decision table and the
	// automatic four-cycle wall clock. With user approval, C3 must advance to C4
	// and the effective Worker limit must stay unlimited (0) so the run survives.
	cfg := watchdogConfig{Enabled: true, CycleAfter: 20 * time.Minute}
	if got := watchdogWorkerRunSeconds(1200, cfg); got != 0 {
		t.Fatalf("watchdog worker timeout=%d, want unlimited", got)
	}
	decision := decideCycle(3, cycleSignalAsk, cycleAnswerYes)
	if decision.Action != cycleActionNext || decision.NextCycle != 4 {
		t.Fatalf("C3 approval decision=%+v, want next C4", decision)
	}
}

func TestWatchdogConfigDefaultsAndValidation(t *testing.T) {
	if cfg := (&Server{}).watchdogConfig(); cfg.Enabled || cfg.PressureAfter != 480*time.Second ||
		cfg.SlowPathAfter != 600*time.Second || cfg.CycleAfter != 1200*time.Second ||
		cfg.AgentKey != "watchdog" || cfg.AgentRetry != 300*time.Second {
		t.Fatalf("defaults=%+v", cfg)
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	s := &Server{m: m}
	keys := []string{settingWatchdogEnabled, settingWatchdogPressureSec, settingWatchdogSlowPathSec,
		settingWatchdogCycleSec, settingWatchdogAgentKey, settingWatchdogAgentRetry, settingWorkerRunSeconds}
	previous := map[string]string{}
	present := map[string]bool{}
	for _, key := range keys {
		if old, ok, _ := m.pg.GetSetting(key); ok {
			previous[key], present[key] = old, true
		}
	}
	t.Cleanup(func() {
		for _, key := range keys {
			if present[key] {
				_ = m.pg.SetSetting(key, previous[key])
			} else {
				_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, key)
			}
		}
	})
	for _, key := range keys {
		if _, err := m.pg.Exec(`DELETE FROM settings WHERE key=$1`, key); err != nil {
			t.Fatal(err)
		}
	}

	bad := 700 // > default slow-path 600
	if err := s.applyWatchdogSettings(watchdogSettingsPatch{PressureSec: &bad}); err == nil {
		t.Fatal("pressure >= slow was accepted")
	}
	if err := s.applyWatchdogSettings(watchdogSettingsPatch{
		Enabled: new(true), PressureSec: new(1), SlowPathSec: new(2), CycleSec: new(3),
		AgentKey: new("watchdog"), AgentRetry: new(5), WorkerRun: new(60),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := s.watchdogConfig()
	if !cfg.Enabled || cfg.PressureAfter != time.Second || cfg.SlowPathAfter != 2*time.Second ||
		cfg.CycleAfter != 3*time.Second || cfg.AgentRetry != 5*time.Second || cfg.WorkerRunSeconds != 60 {
		t.Fatalf("saved config=%+v", cfg)
	}
}
