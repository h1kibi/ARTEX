package server

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestWatchdogReadToolAllowlist(t *testing.T) {
	s := &Server{}
	tools := s.watchdogReadTools()
	got := map[string]bool{}
	for _, tool := range tools {
		got[tool.Name()] = true
		if !tool.IsReadOnly(nil) {
			t.Errorf("watchdog tool %s is not read-only", tool.Name())
		}
	}
	for _, name := range watchdogReadToolNames {
		if !got[name] {
			t.Errorf("watchdog tool %s missing", name)
		}
	}
	for _, forbidden := range []string{"Bash", "Write", "Edit", "MultiEdit", "Read", "LS", "Glob", "Grep"} {
		if got[forbidden] {
			t.Errorf("watchdog agent must not receive %s", forbidden)
		}
	}
	if len(got) != len(watchdogReadToolNames) {
		t.Fatalf("tool count=%d want %d: %v", len(got), len(watchdogReadToolNames), got)
	}
}

func TestWatchdogToolsAreScopedToRunTask(t *testing.T) {
	s := &Server{}
	scoped := scopeWatchdogTools([]actool.CoreTool{s.toolGetWorkerHealth()}, "2")[0]
	result, err := scoped.Call(t.Context(), []byte(`{"task_id":"3"}`), nil)
	if err != nil || !result.IsError {
		t.Fatalf("cross-task read result=%+v err=%v", result, err)
	}
	result, err = scoped.Call(t.Context(), []byte(`{}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("missing task_id should be pinned to the run task: %+v err=%v", result, err)
	}
}
