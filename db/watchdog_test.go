package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func watchdogTestTaskID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("wd-test-%d", time.Now().UnixNano())
}

func TestWatchdogSchemaAndWorkerRuns(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	ctx := context.Background()
	taskID := watchdogTestTaskID(t)
	defer d.DeleteWatchdogTaskData(ctx, taskID)

	var hasTerminal bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM information_schema.columns
WHERE table_name='exploration_nodes' AND column_name='terminal_reason')`).Scan(&hasTerminal); err != nil {
		t.Fatal(err)
	}
	if !hasTerminal {
		t.Fatal("exploration_nodes.terminal_reason 未创建")
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	run := &WorkerRun{
		TaskID: taskID, IntentID: 42, RunID: "run-1", WorkerName: "work#1",
		Phase: WorkerRunPhaseTool, PhaseStartedAt: &now, HeartbeatAt: &now,
		LastEventAt: &now, CycleStart: &now, CycleNo: 0,
		SlowPathState: SlowPathNone, DecisionState: WatchdogDecisionNone,
		State: WorkerRunStateRunning,
	}
	if err := d.SaveWorkerRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	runs, err := d.ListWorkerRuns(ctx, taskID, true)
	if err != nil || len(runs) != 1 || runs[0].RunID != "run-1" {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	lease := now.Add(time.Minute)
	if err := d.TouchWorkerRuns(ctx, []string{"run-1"}, now.Add(time.Second), lease); err != nil {
		t.Fatal(err)
	}
	got, err := d.WorkerRunByID(ctx, "run-1")
	if err != nil || got == nil || got.HeartbeatAt == nil || !got.HeartbeatAt.Equal(now.Add(time.Second)) {
		t.Fatalf("heartbeat=%+v err=%v", got, err)
	}
	if err := d.FinishWorkerRun(ctx, "run-1", WorkerRunStateFinished); err != nil {
		t.Fatal(err)
	}
	if runs, err = d.ListWorkerRuns(ctx, taskID, true); err != nil || len(runs) != 0 {
		t.Fatalf("finished run still listed: %+v err=%v", runs, err)
	}
	past := now.Add(-time.Minute)
	if err := d.SaveWorkerRun(ctx, &WorkerRun{
		TaskID: taskID, IntentID: 43, RunID: "run-expired", WorkerName: "work#2",
		Phase: WorkerRunPhaseTool, LeaseUntil: &past, State: WorkerRunStateRunning,
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.PurgeExpiredWorkerRuns(ctx, now); err != nil {
		t.Fatal(err)
	}
	if got, err := d.WorkerRunByID(ctx, "run-expired"); err != nil || got != nil {
		t.Fatalf("expired run survived: %+v err=%v", got, err)
	}
}

func TestWatchdogJobsQueueAndRetry(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	ctx := context.Background()
	taskID := watchdogTestTaskID(t)
	defer d.DeleteWatchdogTaskData(ctx, taskID)
	now := time.Now().UTC()
	start := now.Add(-time.Minute)
	snapshot := json.RawMessage(`{"summary":"fixture"}`)

	job := &WatchdogJob{TaskID: taskID, IntentID: 7, RunID: "run-job", CycleNo: 1,
		CycleStart: &start, Snapshot: snapshot}
	id, created, err := d.EnqueueWatchdogJob(ctx, job)
	if err != nil || !created || id == 0 {
		t.Fatalf("enqueue id=%d created=%v err=%v", id, created, err)
	}
	if id2, created2, err := d.EnqueueWatchdogJob(ctx, job); err != nil || created2 || id2 != id {
		t.Fatalf("duplicate enqueue id=%d created=%v err=%v", id2, created2, err)
	}
	claimed, err := d.ClaimWatchdogJob(ctx, now)
	if err != nil || claimed == nil || claimed.ID != id || claimed.Status != WatchdogJobRunning {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if again, err := d.ClaimWatchdogJob(ctx, now); err != nil || again != nil {
		t.Fatalf("same job claimed twice: %+v err=%v", again, err)
	}
	retryAt := now.Add(5 * time.Minute)
	if err := d.FinishWatchdogJob(ctx, id, WatchdogJobFailed, "temporary", &retryAt); err != nil {
		t.Fatal(err)
	}
	if claimed, err = d.ClaimWatchdogJob(ctx, now.Add(time.Minute)); err != nil || claimed != nil {
		t.Fatalf("retry claimed before due: %+v err=%v", claimed, err)
	}
	if claimed, err = d.ClaimWatchdogJob(ctx, retryAt.Add(time.Second)); err != nil || claimed == nil || claimed.Attempts != 2 {
		t.Fatalf("retry claim=%+v err=%v", claimed, err)
	}
	count, first, last, err := d.WatchdogJobStats(ctx, taskID)
	if err != nil || count != 1 || first == nil || last == nil {
		t.Fatalf("stats count=%d first=%v last=%v err=%v", count, first, last, err)
	}
	if err := d.ResetRunningWatchdogJobs(ctx); err != nil {
		t.Fatal(err)
	}
	if job, err := d.WatchdogJobByCycle(ctx, "run-job", 1); err != nil || job == nil || job.Status != WatchdogJobQueued {
		t.Fatalf("reset job=%+v err=%v", job, err)
	}
}

func TestWatchdogRequestsConditionalAndUnavailable(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	ctx := context.Background()
	taskID := watchdogTestTaskID(t)
	defer d.DeleteWatchdogTaskData(ctx, taskID)
	now := time.Now().UTC()
	intentID := int64(9)

	card, created, err := d.CreateWatchdogAsk(ctx, &WatchdogRequest{
		TaskID: taskID, IntentID: &intentID, RunID: "run-ask", CycleNo: 1,
		Kind: WatchdogRequestAsk, Question: "continue?", Evidence: json.RawMessage(`{"phase":"tool"}`),
		Options: json.RawMessage(`["continue","stop"]`), DeadlineAt: &now, HardDeadlineAt: &now,
	})
	if err != nil || !created || card == nil {
		t.Fatalf("create ask card=%+v created=%v err=%v", card, created, err)
	}
	dup, created, err := d.CreateWatchdogAsk(ctx, &WatchdogRequest{
		TaskID: taskID, IntentID: &intentID, RunID: "run-ask", CycleNo: 1,
		Kind: WatchdogRequestAsk, Question: "continue?",
	})
	if err != nil || created || dup == nil || dup.ID != card.ID {
		t.Fatalf("duplicate ask=%+v created=%v err=%v", dup, created, err)
	}
	answered, err := d.AnswerWatchdogRequest(ctx, card.ID, "continue", "ok")
	if err != nil || answered == nil || answered.Status != WatchdogRequestAnswered {
		t.Fatalf("answer=%+v err=%v", answered, err)
	}
	if second, err := d.AnswerWatchdogRequest(ctx, card.ID, "stop", ""); err != nil || second != nil {
		t.Fatalf("second answer=%+v err=%v", second, err)
	}
	if err := d.SupersedeOpenWatchdogAsks(ctx, "run-ask"); err != nil {
		t.Fatal(err)
	}

	firstAt, lastAt := now.Add(-time.Minute), now
	unavailable, err := d.CreateOrUpdateWatchdogUnavailable(ctx, taskID, "unavailable", 2, &firstAt, &lastAt, &now)
	if err != nil || unavailable == nil || unavailable.AlertCount != 2 {
		t.Fatalf("unavailable=%+v err=%v", unavailable, err)
	}
	updated, err := d.CreateOrUpdateWatchdogUnavailable(ctx, taskID, "unavailable", 3, &firstAt, &now, &now)
	if err != nil || updated == nil || updated.ID != unavailable.ID || updated.AlertCount != 3 {
		t.Fatalf("updated unavailable=%+v err=%v", updated, err)
	}
	if err := d.CloseWatchdogUnavailable(ctx, taskID); err != nil {
		t.Fatal(err)
	}
	if open, err := d.OpenWatchdogUnavailable(ctx, taskID); err != nil || open != nil {
		t.Fatalf("closed unavailable still open: %+v err=%v", open, err)
	}
}

func TestWatchdogDeleteTaskData(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	ctx := context.Background()
	taskID := watchdogTestTaskID(t)
	now := time.Now().UTC()
	if err := d.SaveWorkerRun(ctx, &WorkerRun{TaskID: taskID, IntentID: 1, RunID: "run-delete",
		WorkerName: "work#1", Phase: WorkerRunPhaseTool, LeaseUntil: &now, State: WorkerRunStateRunning}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.EnqueueWatchdogJob(ctx, &WatchdogJob{TaskID: taskID, IntentID: 1, RunID: "run-delete",
		CycleNo: 0, CycleStart: &now, Snapshot: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CreateWatchdogAsk(ctx, &WatchdogRequest{TaskID: taskID, RunID: "run-delete",
		CycleNo: 0, Kind: WatchdogRequestAsk, Question: "q"}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteWatchdogTaskData(ctx, taskID); err != nil {
		t.Fatal(err)
	}
	if rows, err := d.ListWorkerRuns(ctx, taskID, false); err != nil || len(rows) != 0 {
		t.Fatalf("runs=%+v err=%v", rows, err)
	}
	if job, err := d.WatchdogJobByCycle(ctx, "run-delete", 0); err != nil || job != nil {
		t.Fatalf("job=%+v err=%v", job, err)
	}
	if rows, err := d.ListWatchdogRequests(ctx, taskID, ""); err != nil || len(rows) != 0 {
		t.Fatalf("requests=%+v err=%v", rows, err)
	}
}

func TestWatchdogRecoverOnStartup(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	ctx := context.Background()
	taskID := watchdogTestTaskID(t)
	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	if err := d.SaveWorkerRun(ctx, &WorkerRun{TaskID: taskID, IntentID: 2, RunID: "run-recover",
		WorkerName: "work#1", Phase: WorkerRunPhaseTool, LeaseUntil: &past, State: WorkerRunStateRunning}); err != nil {
		t.Fatal(err)
	}
	job := &WatchdogJob{TaskID: taskID, IntentID: 2, RunID: "run-recover", CycleNo: 1,
		CycleStart: &now, Snapshot: []byte(`{}`)}
	if _, _, err := d.EnqueueWatchdogJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if claimed, err := d.ClaimWatchdogJob(ctx, now); err != nil || claimed == nil {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	ask, _, err := d.CreateWatchdogAsk(ctx, &WatchdogRequest{TaskID: taskID, RunID: "run-recover",
		CycleNo: 1, Kind: WatchdogRequestAsk, Question: "q"})
	if err != nil {
		t.Fatal(err)
	}
	unavailable, err := d.CreateOrUpdateWatchdogUnavailable(ctx, taskID, "unavailable", 1, &past, &now, &now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RecoverWatchdogOnStartup(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, err := d.ListWorkerRuns(ctx, taskID, false); err != nil || len(rows) != 0 {
		t.Fatalf("runs after recovery=%+v err=%v", rows, err)
	}
	if got, err := d.WatchdogJobByCycle(ctx, "run-recover", 1); err != nil || got == nil || got.Status != WatchdogJobQueued {
		t.Fatalf("job after recovery=%+v err=%v", got, err)
	}
	if got, err := d.WatchdogRequestByID(ctx, ask.ID); err != nil || got == nil || got.Status != WatchdogRequestExpired {
		t.Fatalf("ask after recovery=%+v err=%v", got, err)
	}
	if got, err := d.WatchdogRequestByID(ctx, unavailable.ID); err != nil || got == nil || got.Status != WatchdogRequestExpired {
		t.Fatalf("unavailable after recovery=%+v err=%v", got, err)
	}
	_ = d.DeleteWatchdogTaskData(ctx, taskID)
}

func TestIntentTerminalReasonLifecycle(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	expID, err := d.CreateExploration("watchdog reason", "test terminal reason")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	id, err := store.AddIntent(map[string]any{"summary": "fixture"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(id, "running"); err != nil {
		t.Fatal(err)
	}
	changed, err := store.CompareAndSetIntentStateWithReason(id, "running", "stopped", "watchdog loop")
	if err != nil || !changed {
		t.Fatalf("CAS changed=%v err=%v", changed, err)
	}
	node, err := store.GetNode(id)
	if err != nil || node == nil || node.TerminalReason != "watchdog loop" || node.State != "stopped" {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	if reopened, err := store.ReopenIntent(id); err != nil || !reopened {
		t.Fatalf("reopen=%v err=%v", reopened, err)
	}
	node, err = store.GetNode(id)
	if err != nil || node == nil || node.TerminalReason != "" || node.State != "open" {
		t.Fatalf("after reopen node=%+v err=%v", node, err)
	}
}
