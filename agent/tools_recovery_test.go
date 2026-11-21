package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestGetWorkerOutputKeepsLiveAttemptProvisional(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("recovery output", "test output finality", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "retry target"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "work#1", Kind: "result", IsError: true,
		Summary: "attempt 1 failed", Detail: "attempt 1 failed detail",
	}); err != nil {
		t.Fatal(err)
	}

	tools := NewToolSet(store, "planner")
	input := fmt.Sprintf(`{"intent_id":%d}`, intentID)
	output := callReadJSON(t, tools.getWorkerOutput(), input).(map[string]any)
	if output["state"] != "running" || output["running"] != true || output["final"] != false {
		t.Fatalf("live output was not marked provisional: %#v", output)
	}
	if _, ok := output["final_text"]; ok {
		t.Fatalf("live output exposed final_text: %#v", output)
	}
	if output["last_text"] != "attempt 1 failed detail" {
		t.Fatalf("live output last_text: %#v", output)
	}

	trace := callReadJSON(t, tools.getWorkerTrace(), input).(map[string]any)
	steps := trace["steps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("trace steps: %#v", steps)
	}
	if steps[0].(map[string]any)["provisional"] != true {
		t.Fatalf("live result step was not provisional: %#v", steps[0])
	}

	search := callReadJSON(t, tools.searchAllWorkerTraces(), `{"q":"attempt 1 failed"}`).(map[string]any)
	hits := search["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["provisional"] != true {
		t.Fatalf("live search hit was not provisional: %#v", hits)
	}

	if err := store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}
	output = callReadJSON(t, tools.getWorkerOutput(), input).(map[string]any)
	if output["state"] != "blocked" || output["final"] != true || output["final_text"] != "attempt 1 failed detail" {
		t.Fatalf("terminal output: %#v", output)
	}
	if err := store.SetIntentState(intentID, db.StateIntentDeleted); err != nil {
		t.Fatal(err)
	}
	output = callReadJSON(t, tools.getWorkerOutput(), input).(map[string]any)
	if output["state"] != db.StateIntentDeleted || output["final"] != true {
		t.Fatalf("deleted output: %#v", output)
	}
}

func TestAddIntentRejectsLiveContinuation(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("continuation guard", "test continuation finality", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	original, err := store.AddIntent(map[string]any{"summary": "original intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(store, "planner")
	add := tools.addIntent()
	liveInput := fmt.Sprintf(`{"summary":"continue the original","continuation_of":%d}`, original)
	for _, state := range []string{"open", "running", "paused"} {
		if err := store.SetIntentState(original, state); err != nil {
			t.Fatal(err)
		}
		result, err := add.Call(context.Background(), json.RawMessage(liveInput), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(result.Flatten(), "不能创建接续") {
			t.Fatalf("%s continuation was accepted: %s", state, result.Flatten())
		}
	}

	if err := store.SetIntentState(original, "blocked"); err != nil {
		t.Fatal(err)
	}
	result, err := add.Call(context.Background(), json.RawMessage(liveInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimPrefix(result.Flatten(), "intent created: ")
	createdID, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil || createdID <= 0 {
		t.Fatalf("created id: %v raw=%s", err, result.Flatten())
	}
	created, err := store.GetNode(createdID)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(created.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if int64(payload["continuation_of"].(float64)) != original {
		t.Fatalf("continuation payload: %#v", payload)
	}
	var edgeCount int
	if err := d.QueryRow(`SELECT COUNT(*) FROM exploration_edges
WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4`,
		task.ExplorationID, original, db.RelDerivedFrom, createdID).Scan(&edgeCount); err != nil {
		t.Fatal(err)
	}
	if edgeCount != 1 {
		t.Fatalf("continuation lineage edge count=%d, want 1", edgeCount)
	}
}

func TestReopenBlockedIntentForRetryLimit(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("retry limit", "test retry limit", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "bounded retry"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}

	retry, changed, err := store.ReopenBlockedIntentForRetry(intentID, 2)
	if err != nil || !changed || retry != 1 {
		t.Fatalf("first retry: retry=%d changed=%v err=%v", retry, changed, err)
	}
	if err := store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}
	retry, changed, err = store.ReopenBlockedIntentForRetry(intentID, 2)
	if err != nil || !changed || retry != 2 {
		t.Fatalf("second retry: retry=%d changed=%v err=%v", retry, changed, err)
	}
	if err := store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}
	if _, changed, err = store.ReopenBlockedIntentForRetry(intentID, 2); err != nil || changed {
		t.Fatalf("limit should reject the third retry: changed=%v err=%v", changed, err)
	}
	node, err := store.GetNode(intentID)
	if err != nil || node.State != "blocked" {
		t.Fatalf("intent state after rejected retry: node=%+v err=%v", node, err)
	}

	reopened, err := store.ReopenIntent(intentID)
	if err != nil || !reopened {
		t.Fatalf("human rerun: reopened=%v err=%v", reopened, err)
	}
	if err := store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}
	retry, changed, err = store.ReopenBlockedIntentForRetry(intentID, 2)
	if err != nil || !changed || retry != 1 {
		t.Fatalf("human rerun should reset retry budget: retry=%d changed=%v err=%v", retry, changed, err)
	}
}

func TestReopenBlockedIntentForRetrySingleWinner(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("retry race", "test retry race", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "concurrent retry"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		retry   int
		changed bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			<-start
			retry, changed, err := store.ReopenBlockedIntentForRetry(intentID, 2)
			results <- outcome{retry: retry, changed: changed, err: err}
		}()
	}
	close(start)

	winners := 0
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.changed {
			winners++
			if got.retry != 1 {
				t.Fatalf("winner retry count=%d, want 1", got.retry)
			}
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent reopen winners=%d, want 1", winners)
	}
	node, err := store.GetNode(intentID)
	if err != nil || node.State != "open" {
		t.Fatalf("intent after concurrent reopen: node=%+v err=%v", node, err)
	}
}

func TestRestoreIntentStateDoesNotClobberClaim(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("retry rollback", "test retry rollback", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "claimed retry"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}
	if _, reopened, err := store.ReopenBlockedIntentForRetry(intentID, 2); err != nil || !reopened {
		t.Fatalf("reopen: reopened=%v err=%v", reopened, err)
	}
	if err := store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	changed, err := store.RestoreIntentState(&db.Node{ID: intentID, State: "blocked"})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("rollback overwrote a claimed intent")
	}
	node, err := store.GetNode(intentID)
	if err != nil || node.State != "running" {
		t.Fatalf("intent after rejected rollback: node=%+v err=%v", node, err)
	}
}
