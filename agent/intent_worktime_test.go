package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestIntentWorkerTimingAccumulatesAndReachesOverview(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("intent timing", "test intent timing", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "timed direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimIntent(intentID, "work#1")
	if err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}
	node, err := store.GetNode(intentID)
	if err != nil || node.WorkerStartedAt == nil {
		t.Fatalf("claim did not record worker start: node=%+v err=%v", node, err)
	}
	if err := store.AddIntentWorkTime(intentID, 2500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := store.AddIntentWorkTime(intentID, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	node, err = store.GetNode(intentID)
	if err != nil || node.WorkerMS != 3000 || node.WorkerRuns != 2 || node.WorkerStartedAt != nil {
		t.Fatalf("timing after two runs: node=%+v err=%v", node, err)
	}
	if err := store.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}

	overview := NewToolSet(store, "planner").graphOverviewData()
	recent := overview["recent_done_intents"].([]map[string]any)
	if len(recent) != 1 {
		t.Fatalf("recent intents: %#v", recent)
	}
	if recent[0]["worker_seconds"] != 3.0 || recent[0]["worker_runs"] != 2 {
		t.Fatalf("timing in overview: %#v", recent[0])
	}
}

func TestCompactIntentExposesYieldCountAndWorkerTime(t *testing.T) {
	nodes := []*db.Node{{
		ID: 1, Kind: db.KindIntent, State: "done", WorkerMS: 1500, WorkerRuns: 2,
		Payload: json.RawMessage(`{"summary":"timed direction"}`),
	}}
	out := compactIntents(nodes, nil, map[int64][]int64{1: {10, 11}}, func(int64) string { return "observation" })
	if len(out) != 1 {
		t.Fatalf("compact intents: %#v", out)
	}
	got := out[0]
	if got["worker_seconds"] != 1.5 || got["worker_runs"] != 2 || got["yield_count"] != 2 {
		t.Fatalf("compact ROI fields: %#v", got)
	}
}
