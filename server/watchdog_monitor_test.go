package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func newTestMonitor(t *testing.T, now *time.Time, pg *db.DB) *RunMonitor {
	t.Helper()
	return NewRunMonitor(pg, func() time.Time { return *now })
}

func TestRunMonitorPhasesAndEffectiveOutputResetCycle(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	m := newTestMonitor(t, &now, nil)
	snap := m.Register("2", 113, "run-a", "work#1")
	if snap.Phase != db.WorkerRunPhaseIdle || snap.CycleNo != 0 || snap.CycleStart.IsZero() {
		t.Fatalf("initial snapshot=%+v", snap)
	}

	m.Observe("run-a", db.Activity{Kind: "tool_use", Tool: "Bash"})
	snap = *m.Lookup(113)
	if snap.Phase != db.WorkerRunPhaseTool || snap.Tool != "Bash" {
		t.Fatalf("tool phase=%+v", snap)
	}
	m.Observe("run-a", db.Activity{Kind: "intercept_request"})
	snap = *m.Lookup(113)
	if snap.Phase != db.WorkerRunPhaseApproval {
		t.Fatalf("approval phase=%+v", snap)
	}

	// Autonomous advances belong to the run, not to the current cycle chain.
	m.RecordAutoAdvance("run-a")
	m.RecordAutoAdvance("run-a")
	// Leave approval and spend time in the old cycle; then a successful fact write
	// must reset the current cycle back to C0 and update last_output_at.
	now = now.Add(10 * time.Minute)
	m.SetCycle("run-a", 2, now.Add(-10*time.Minute), true, db.SlowPathDone, db.WatchdogDecisionOpen)
	m.Observe("run-a", db.Activity{Kind: "thinking"})
	now = now.Add(5 * time.Minute)
	m.Observe("run-a", db.Activity{Kind: "tool_use", Tool: "record_fact", Detail: `{"fact_type":"claim","progress_event":"validated_weakness"}`})
	m.Observe("run-a", db.Activity{Kind: "tool_result", Tool: "record_fact", Detail: `{"id":1}`})
	snap = *m.Lookup(113)
	if snap.CycleNo != 0 || snap.AutoCyclesUsed != 2 || snap.PressureSent || snap.SlowPathState != db.SlowPathNone ||
		snap.DecisionState != db.WatchdogDecisionNone || snap.Facts != 1 {
		t.Fatalf("high-value output did not reset cycle without resetting budget: %+v", snap)
	}
	if !snap.LastOutputAt.Equal(now) || !snap.LastHighValueAt.Equal(now) {
		t.Fatalf("output timestamps=%v/%v want %v", snap.LastOutputAt, snap.LastHighValueAt, now)
	}
	if len(snap.ProgressEvents) == 0 || snap.ProgressEvents[len(snap.ProgressEvents)-1] != "validated_weakness" {
		t.Fatalf("progress events=%v", snap.ProgressEvents)
	}
}

func TestRunMonitorLowValueWritesDoNotResetCycle(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	m := newTestMonitor(t, &now, nil)
	m.Register("2", 15, "run-low", "work#1")
	now = now.Add(5 * time.Minute)
	m.SetCycle("run-low", 2, now.Add(-5*time.Minute), true, db.SlowPathDone, db.WatchdogDecisionOpen)
	m.Observe("run-low", db.Activity{Kind: "tool_use", Tool: "record_fact", Detail: `{"fact_type":"observation"}`})
	m.Observe("run-low", db.Activity{Kind: "tool_result", Tool: "record_fact", Detail: `{"id":2}`})
	snap := *m.Lookup(15)
	if snap.CycleNo != 2 || snap.Facts != 1 || !snap.LastHighValueAt.IsZero() {
		t.Fatalf("low-value write changed cycle/high-value marker: %+v", snap)
	}
	m.Observe("run-low", db.Activity{Kind: "tool_use", Tool: "Bash", Detail: `{"command":"id"}`})
	m.Observe("run-low", db.Activity{Kind: "tool_result", Tool: "Bash", Detail: `uid=0`})
	m.Observe("run-low", db.Activity{Kind: "tool_use", Tool: "Bash", Detail: `{"command":"id"}`})
	snap = *m.Lookup(15)
	if snap.DuplicateActions != 1 || snap.ToolCalls != 3 {
		t.Fatalf("duplicate/tool counters=%+v", snap)
	}
}

func TestRunMonitorCountsBatchAssets(t *testing.T) {
	now := time.Now()
	m := newTestMonitor(t, &now, nil)
	m.Register("2", 7, "run-assets", "work#1")
	detail, _ := json.Marshal(map[string]any{
		"results": []any{map[string]any{"id": 1}, map[string]any{"id": 2}, map[string]any{"id": 3}},
	})
	m.Observe("run-assets", db.Activity{Kind: "tool_result", Tool: "insert_assets", Detail: string(detail)})
	if snap := m.Lookup(7); snap == nil || snap.Assets != 3 {
		t.Fatalf("asset count=%+v", snap)
	}
	m.Observe("run-assets", db.Activity{Kind: "tool_result", Tool: "insert_assets", IsError: true, Detail: "denied"})
	if snap := m.Lookup(7); snap == nil || snap.Assets != 3 {
		t.Fatalf("failed insert changed count: %+v", snap)
	}
}

func TestRunMonitorPauseResumeAndFinish(t *testing.T) {
	now := time.Now()
	m := newTestMonitor(t, &now, nil)
	m.Register("2", 11, "run-p", "work#1")
	m.RecordAutoAdvance("run-p")
	m.RecordAutoAdvance("run-p")
	m.PauseTask("2")
	if snap := m.Lookup(11); snap == nil || snap.Phase != db.WorkerRunPhasePaused {
		t.Fatalf("pause=%+v", snap)
	}
	now = now.Add(time.Minute)
	m.ResumeTask("2")
	if snap := m.Lookup(11); snap == nil || snap.Phase != db.WorkerRunPhaseLLM || !snap.CycleStart.Equal(now) || snap.AutoCyclesUsed != 2 {
		t.Fatalf("resume changed run budget=%+v", snap)
	}
	m.Finish("run-p", db.WorkerRunStateFinished)
	if snap := m.Lookup(11); snap != nil {
		t.Fatalf("finished run still lookup-able: %+v", snap)
	}
	if snap := m.LookupRun("run-p"); snap == nil || snap.State != db.WorkerRunStateFinished || snap.AutoCyclesUsed != 2 {
		t.Fatalf("finished history=%+v", snap)
	}
	m.RemoveTask("2")
	if snap := m.LookupRun("run-p"); snap != nil {
		t.Fatalf("removed run still present: %+v", snap)
	}

}

func TestRunMonitorApprovalExitResetsCycleAndRunsHook(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	m := newTestMonitor(t, &now, nil)
	m.Register("2", 14, "run-approval", "work#1")
	m.RecordAutoAdvance("run-approval")
	m.SetSlowPath("run-approval", db.SlowPathQueued, "", "", nil, 0)
	calls := 0
	m.SetCycleResetHook(func(snap RunSnapshot) {
		calls++
		if snap.CycleNo != 0 || snap.AutoCyclesUsed != 1 {
			t.Errorf("hook cycle/budget=%d/%d want 0/1", snap.CycleNo, snap.AutoCyclesUsed)
		}
	})
	m.Phase("run-approval", db.WorkerRunPhaseApproval, "")
	now = now.Add(5 * time.Minute)
	m.Phase("run-approval", db.WorkerRunPhaseTool, "Bash")
	if calls != 1 {
		t.Fatalf("cycle reset hook calls=%d, want 1", calls)
	}
	if snap := m.LookupRun("run-approval"); snap == nil || !snap.CycleStart.Equal(now) || snap.AutoCyclesUsed != 1 {
		t.Fatalf("approval exit changed run budget=%+v", snap)
	}
}

func TestRunMonitorFlushRefreshesHeartbeat(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	m := newTestMonitor(t, &now, nil)
	m.Register("2", 13, "run-heartbeat", "work#1")
	start := m.LookupRun("run-heartbeat").HeartbeatAt
	now = now.Add(10 * time.Minute)
	m.Flush()
	snap := m.LookupRun("run-heartbeat")
	if snap == nil || !snap.HeartbeatAt.Equal(now) {
		t.Fatalf("heartbeat=%v want %v (start %v)", snap, now, start)
	}
}

func TestRunMonitorSlowPathAndProviderError(t *testing.T) {
	now := time.Now()
	m := newTestMonitor(t, &now, nil)
	m.Register("2", 12, "run-s", "work#1")
	m.SetSlowPath("run-s", db.SlowPathDone, "terminate", "loop", []string{"same call twice"}, 3)
	snap := m.Lookup(12)
	if snap == nil || snap.SlowPathClass != "terminate" || snap.SlowPathCycle != 3 || len(snap.SlowPathEvidence) != 1 {
		t.Fatalf("slow path=%+v", snap)
	}
	m.SetProviderError("run-s", "quota")
	if snap = m.Lookup(12); snap == nil || snap.ProviderError != "quota" {
		t.Fatalf("provider error=%+v", snap)
	}
	m.Observe("run-s", db.Activity{Kind: "tool_result", Tool: "report_finding", Detail: `{"finding_id":1}`})
	if snap = m.Lookup(12); snap == nil || snap.ProviderError != "" || snap.Findings != 1 {
		t.Fatalf("output did not clear provider error: %+v", snap)
	}
}
