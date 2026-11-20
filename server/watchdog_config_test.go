package server

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestWatchdogWorkerRunSeconds(t *testing.T) {
	cfg := watchdogConfig{Enabled: true, CycleAfter: 20 * time.Minute}
	if got := watchdogWorkerRunSeconds(1200, cfg); got != 0 {
		t.Fatalf("worker timeout=%d, want unlimited (0) with Watchdog enabled", got)
	}
	cfg.Enabled = false
	if got := watchdogWorkerRunSeconds(1200, cfg); got != 1200 {
		t.Fatalf("disabled watchdog changed the Agent timeout to %d", got)
	}
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
		t.Fatalf("constructed worker timeout=%v, want unlimited with Watchdog enabled", got)
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
	decision := decideCycle(3, 3, defaultWatchdogMaxAuto, cycleSignalAsk, cycleAnswerYes)
	if decision.Action != cycleActionNext || decision.NextCycle != 4 {
		t.Fatalf("C3 approval decision=%+v, want next C4", decision)
	}
}

func TestWatchdogConfigDefaultsAndValidation(t *testing.T) {
	if cfg := (&Server{}).watchdogConfig(); cfg.Enabled || cfg.PressureAfter != 480*time.Second ||
		cfg.SlowPathAfter != 600*time.Second || cfg.CycleAfter != 1200*time.Second ||
		cfg.AgentKey != "watchdog" || cfg.AgentRetry != 300*time.Second ||
		cfg.MaxAutoCycles != defaultWatchdogMaxAuto {
		t.Fatalf("defaults=%+v", cfg)
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	s := &Server{m: m}
	keys := []string{settingWatchdogEnabled, settingWatchdogPressureSec, settingWatchdogSlowPathSec,
		settingWatchdogAgentKey, settingWatchdogAgentRetry, settingWatchdogMaxAuto}
	restoreSettings(t, m, keys)
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
		Enabled: new(true), PressureSec: new(1), SlowPathSec: new(2),
		AgentKey: new("watchdog"), AgentRetry: new(5), MaxAutoCycles: new(3),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := s.watchdogConfig()
	if !cfg.Enabled || cfg.PressureAfter != time.Second || cfg.SlowPathAfter != 2*time.Second ||
		cfg.CycleAfter != 1200*time.Second || cfg.AgentRetry != 5*time.Second ||
		cfg.MaxAutoCycles != 3 {
		t.Fatalf("saved config=%+v", cfg)
	}
	if err := s.applyWatchdogSettings(watchdogSettingsPatch{MaxAutoCycles: new(5)}); err == nil {
		t.Fatal("max auto cycles 5 was accepted")
	}
	if err := s.applyWatchdogSettings(watchdogSettingsPatch{MaxAutoCycles: new(0)}); err == nil {
		t.Fatal("max auto cycles 0 was accepted")
	}
	slowTooBig := 5000 // > worker run_seconds (1200)
	if err := s.applyWatchdogSettings(watchdogSettingsPatch{SlowPathSec: &slowTooBig}); err == nil {
		t.Fatal("slow path >= cycle was accepted")
	}
}

func TestWatchdogConfigUsesWorkerRunSeconds(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	old := agentRunSecs(t, m, "worker")
	t.Cleanup(func() { _ = m.pg.SetAgentRunSeconds("worker", old) })
	s := &Server{m: m}
	if err := m.pg.SetAgentRunSeconds("worker", 1500); err != nil {
		t.Fatal(err)
	}
	if got := s.watchdogConfig().CycleAfter; got != 1500*time.Second {
		t.Fatalf("cycle=%v, want 1500s from worker run_seconds", got)
	}
	if err := m.pg.SetAgentRunSeconds("worker", 0); err != nil {
		t.Fatal(err)
	}
	if got := s.watchdogConfig().CycleAfter; got != defaultWatchdogCycleSec*time.Second {
		t.Fatalf("cycle=%v, want default %ds when run_seconds=0", got, defaultWatchdogCycleSec)
	}
}

func TestWatchdogSettingsPayload(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	s := &Server{m: m}
	p := s.watchdogSettingsPayload()
	if _, ok := p["watchdog_cycle_after_sec"]; ok {
		t.Fatal("payload still exposes removed watchdog_cycle_after_sec")
	}
	if _, ok := p["watchdog_max_auto_cycles"]; !ok {
		t.Fatal("payload missing watchdog_max_auto_cycles")
	}
	if _, ok := p["worker_run_seconds"]; !ok {
		t.Fatal("payload missing read-only worker_run_seconds")
	}
}

func TestWatchdogLegacySettingsMigration(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	oldAgent := agentRunSecs(t, m, "worker")
	restoreSettings(t, m, []string{
		legacySettingWorkerRunSeconds, legacySettingWatchdogCycleSec,
		settingWatchdogMigrated, settingWatchdogPressureSec, settingWatchdogSlowPathSec,
	})
	t.Cleanup(func() { _ = m.pg.SetAgentRunSeconds("worker", oldAgent) })
	s := &Server{m: m}

	cases := []struct {
		name      string
		legacyRun *int
		legacyCyc *int
		agentRun  int
		wantCycle int
		wantErr   bool
	}{
		{"legacy worker wins", new(6000), new(1200), 1200, 6000, false},
		{"legacy cycle when worker is 0", new(0), new(1800), 1200, 1800, false},
		{"agent run_seconds preserved when both absent/0", new(0), nil, 1500, 1500, false},
		{"agent run_seconds preserved when nothing configured", nil, nil, 1200, 1200, false},
		{"agent unlimited preserved", nil, nil, 0, 0, false},
		{"agent below slow path preserved", nil, nil, 500, 500, false},
		{"invalid legacy override does not rewrite", new(600), nil, 1200, 1200, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = m.pg.SetAgentRunSeconds("worker", tc.agentRun)
			_ = m.pg.SetSetting(settingWatchdogPressureSec, "480")
			_ = m.pg.SetSetting(settingWatchdogSlowPathSec, "600")
			for _, key := range []string{legacySettingWorkerRunSeconds, legacySettingWatchdogCycleSec, settingWatchdogMigrated} {
				_ = m.pg.DeleteSetting(key)
			}
			if tc.legacyRun != nil {
				_ = m.pg.SetSetting(legacySettingWorkerRunSeconds, strconv.Itoa(*tc.legacyRun))
			}
			if tc.legacyCyc != nil {
				_ = m.pg.SetSetting(legacySettingWatchdogCycleSec, strconv.Itoa(*tc.legacyCyc))
			}
			err := s.migrateWatchdogSettings()
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid legacy override was accepted")
				}
				if got := agentRunSecs(t, m, "worker"); got != tc.wantCycle {
					t.Fatalf("invalid migration changed run_seconds=%d, want %d", got, tc.wantCycle)
				}
				if _, ok, _ := m.pg.GetSetting(settingWatchdogMigrated); ok {
					t.Fatal("invalid migration wrote the completion marker")
				}
				if _, ok, _ := m.pg.GetSetting(legacySettingWorkerRunSeconds); !ok {
					t.Fatal("invalid migration deleted the legacy key")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := agentRunSecs(t, m, "worker"); got != tc.wantCycle {
				t.Fatalf("migrated run_seconds=%d, want %d", got, tc.wantCycle)
			}
			if v, ok, _ := m.pg.GetSetting(settingWatchdogMigrated); !ok || v != "true" {
				t.Fatalf("migration marker=%q ok=%v", v, ok)
			}
			for _, key := range []string{legacySettingWorkerRunSeconds, legacySettingWatchdogCycleSec} {
				if _, ok, _ := m.pg.GetSetting(key); ok {
					t.Fatalf("legacy key %s was not removed", key)
				}
			}
		})
	}
}

// A failed one-time migration must not brick startup: the Worker Agent keeps its
// current run_seconds, the completion marker stays absent so the next boot
// retries, and the server is still constructed.
func TestWatchdogMigrationFailureKeepsServerBooting(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	oldAgent := agentRunSecs(t, m, "worker")
	restoreSettings(t, m, []string{
		legacySettingWorkerRunSeconds, legacySettingWatchdogCycleSec,
		settingWatchdogMigrated, settingWatchdogPressureSec, settingWatchdogSlowPathSec,
	})
	t.Cleanup(func() { _ = m.pg.SetAgentRunSeconds("worker", oldAgent) })
	// Start from a clean migration state: the shared test DB may still carry the
	// marker from another test, which would skip the migration entirely.
	for _, key := range []string{
		settingWatchdogMigrated, legacySettingWatchdogCycleSec, legacySettingWorkerRunSeconds,
	} {
		if err := m.pg.DeleteSetting(key); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.pg.SetSetting(legacySettingWorkerRunSeconds, "not-an-integer"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	if s == nil {
		t.Fatal("New returned nil after a failed migration")
	}
	defer stopAllServerTasks(s, m)
	if got := agentRunSecs(t, m, "worker"); got != oldAgent {
		t.Fatalf("failed migration changed run_seconds=%d, want %d", got, oldAgent)
	}
	if _, ok, _ := m.pg.GetSetting(settingWatchdogMigrated); ok {
		t.Fatal("failed migration wrote the completion marker")
	}
	if _, ok, _ := m.pg.GetSetting(legacySettingWorkerRunSeconds); !ok {
		t.Fatal("failed migration deleted the legacy key")
	}
}

func restoreSettings(t *testing.T, m *Manager, keys []string) {
	t.Helper()
	type snapshot struct {
		value string
		ok    bool
	}
	prev := map[string]snapshot{}
	for _, key := range keys {
		v, ok, _ := m.pg.GetSetting(key)
		prev[key] = snapshot{value: v, ok: ok}
	}
	t.Cleanup(func() {
		for _, key := range keys {
			s := prev[key]
			if s.ok {
				_ = m.pg.SetSetting(key, s.value)
			} else {
				_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, key)
			}
		}
	})
}

func agentRunSecs(t *testing.T, m *Manager, key string) int {
	t.Helper()
	a, err := m.pg.GetAgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		return 0
	}
	return a.RunSecs
}
