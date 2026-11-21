package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestPlannerOpenIntentCapAndCancel(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("planner cap", "test planner open cap", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	ids := make([]int64, 0, 2)
	for _, summary := range []string{"low priority direction", "current direction"} {
		id, err := store.AddIntent(map[string]any{"summary": summary}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	tools := NewToolSet(store, "planner")
	tools.openIntentCap = 2
	overview := tools.graphOverviewData()
	if overview["frontier_open"] != 2 || overview["open_intent_cap"] != 2 || overview["open_intent_remaining"] != 0 || overview["cap_reached"] != true {
		t.Fatalf("graph cap fields: %#v", overview)
	}
	openIntents := overview["open_intents"].([]map[string]any)
	if len(openIntents) != 2 || openIntents[0]["origin"] != "planner" || openIntents[0]["priority"] != 5 {
		t.Fatalf("compact intent metadata: %#v", openIntents)
	}
	add := tools.addIntent()
	result, err := add.Call(context.Background(), json.RawMessage(`{"summary":"over cap"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Flatten(), "上限") {
		t.Fatalf("over-cap add was accepted: %s", result.Flatten())
	}
	open, err := store.CountOpenIntents()
	if err != nil || open != 2 {
		t.Fatalf("open count after rejected add=%d err=%v", open, err)
	}

	cancel := tools.cancelIntentTool()
	cancelInput := fmt.Sprintf(`{"intent_id":%d,"reason":"方向已被新事实覆盖"}`, ids[0])
	result, err = cancel.Call(context.Background(), json.RawMessage(cancelInput), nil)
	if err != nil || !strings.Contains(result.Flatten(), "stopped") {
		t.Fatalf("cancel result=%s err=%v", result.Flatten(), err)
	}
	node, err := store.GetNode(ids[0])
	if err != nil || node.State != "stopped" {
		t.Fatalf("cancelled intent: node=%+v err=%v", node, err)
	}
	overview = tools.graphOverviewData()
	recent := overview["recent_done_intents"].([]map[string]any)
	if len(recent) != 1 || recent[0]["state"] != "stopped" {
		t.Fatalf("cancelled intent missing from recent history: %#v", recent)
	}

	result, err = add.Call(context.Background(), json.RawMessage(`{"summary":"replacement direction"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "intent created:") {
		t.Fatalf("replacement add result=%s err=%v", result.Flatten(), err)
	}
}

func TestPlannerCancelRequiresPlannerOpenIntent(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("planner cancel guard", "test planner cancel guard", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	humanID, err := store.AddIntent(map[string]any{"summary": "human direction"}, 5, nil, "human")
	if err != nil {
		t.Fatal(err)
	}
	planner := NewToolSet(store, "planner")
	cancel := planner.cancelIntentTool()
	input := fmt.Sprintf(`{"intent_id":%d,"reason":"planner cleanup"}`, humanID)
	result, err := cancel.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil || !strings.Contains(result.Flatten(), "只能取消") {
		t.Fatalf("human intent cancel result=%s err=%v", result.Flatten(), err)
	}
	node, err := store.GetNode(humanID)
	if err != nil || node.State != "open" {
		t.Fatalf("human intent was changed: node=%+v err=%v", node, err)
	}

	runningID, err := store.AddIntent(map[string]any{"summary": "running direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(runningID, "running"); err != nil {
		t.Fatal(err)
	}
	input = fmt.Sprintf(`{"intent_id":%d,"reason":"planner cleanup"}`, runningID)
	result, err = cancel.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil || !strings.Contains(result.Flatten(), "未取消") {
		t.Fatalf("running intent cancel result=%s err=%v", result.Flatten(), err)
	}
	node, err = store.GetNode(runningID)
	if err != nil || node.State != "running" {
		t.Fatalf("running intent was changed: node=%+v err=%v", node, err)
	}
}

func TestPlannerBatchCapDoesNotPartiallyInsert(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("planner batch cap", "test planner batch cap", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	if _, err := store.AddIntent(map[string]any{"summary": "existing"}, 5, nil, "planner"); err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(store, "planner")
	tools.openIntentCap = 2
	batch := `{"intents":[{"summary":"batch one"},{"summary":"batch two"}]}`
	result, err := tools.addIntent().Call(context.Background(), json.RawMessage(batch), nil)
	if err != nil || !strings.Contains(result.Flatten(), "上限") {
		t.Fatalf("over-cap batch result=%s err=%v", result.Flatten(), err)
	}
	open, err := store.CountOpenIntents()
	if err != nil || open != 1 {
		t.Fatalf("batch partially inserted: open=%d err=%v", open, err)
	}
}

func TestAddIntentUsesToolOrigin(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("intent origin", "test intent origin", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	humanID, err := NewToolSet(store, "human").addOneIntent(intentItem{Summary: "human direction"})
	if err != nil {
		t.Fatal(err)
	}
	humanNode, err := store.GetNode(humanID)
	if err != nil || humanNode.Origin != "human" {
		t.Fatalf("human origin: node=%+v err=%v", humanNode, err)
	}

	plannerID, err := NewToolSet(store, "planner").addOneIntent(intentItem{Summary: "planner direction"})
	if err != nil {
		t.Fatal(err)
	}
	plannerNode, err := store.GetNode(plannerID)
	if err != nil || plannerNode.Origin != "planner" {
		t.Fatalf("planner origin: node=%+v err=%v", plannerNode, err)
	}
}

func TestHumanAddIntentBypassesPlannerCap(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("human cap bypass", "test human cap bypass", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "human")
	tools.openIntentCap = 1
	if _, err := tools.addOneIntent(intentItem{Summary: "human one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.addOneIntent(intentItem{Summary: "human two"}); err != nil {
		t.Fatalf("human add was capped: %v", err)
	}
	open, err := store.CountOpenIntents()
	if err != nil || open != 2 {
		t.Fatalf("human open count=%d err=%v", open, err)
	}
}

func TestCancelIntentAndWorkerClaimRace(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("cancel race", "test cancel race", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "race target"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(store, "planner")
	cancel := tools.cancelIntentTool()
	input := fmt.Sprintf(`{"intent_id":%d,"reason":"race test"}`, intentID)

	start := make(chan struct{})
	done := make(chan struct{}, 2)
	var cancelWon bool
	go func() {
		<-start
		result, _ := cancel.Call(context.Background(), json.RawMessage(input), nil)
		cancelWon = strings.Contains(result.Flatten(), "stopped")
		done <- struct{}{}
	}()
	go func() {
		<-start
		_, _ = store.ClaimIntent(intentID, "work#1")
		done <- struct{}{}
	}()
	close(start)
	<-done
	<-done

	node, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelWon && node.State != "stopped" {
		t.Fatalf("cancel won but state=%s", node.State)
	}
	if !cancelWon && node.State != "running" {
		t.Fatalf("claim won but state=%s", node.State)
	}
}

func TestPlannerRetryWorkRespectsCap(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("retry cap", "test retry cap", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	blockedID, err := store.AddIntent(map[string]any{"summary": "blocked retry"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(blockedID, "blocked"); err != nil {
		t.Fatal(err)
	}
	openID, err := store.AddIntent(map[string]any{"summary": "queued direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	tools := NewToolSet(store, "planner")
	tools.openIntentCap = 1
	tools.retryWork = func(id int64) (bool, error) {
		_, changed, err := store.ReopenBlockedIntentForRetry(id, 2)
		return changed, err
	}
	retry := tools.retryWorkTool()
	input := fmt.Sprintf(`{"intent_id":%d}`, blockedID)
	result, err := retry.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil || !strings.Contains(result.Flatten(), "上限") {
		t.Fatalf("retry over cap result=%s err=%v", result.Flatten(), err)
	}
	cancelResult, err := tools.cancelIntentTool().Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"intent_id":%d,"reason":"free slot"}`, openID)), nil)
	if err != nil || !strings.Contains(cancelResult.Flatten(), "stopped") {
		t.Fatalf("cancel before retry result=%s err=%v", cancelResult.Flatten(), err)
	}
	result, err = retry.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil || !strings.Contains(result.Flatten(), `"state":"open"`) {
		t.Fatalf("retry after cancel result=%s err=%v", result.Flatten(), err)
	}
}

func TestAddIntentRejectsDeletedContinuation(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("deleted continuation", "test deleted continuation", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	store := d.Exploration(task.ExplorationID)
	original, err := store.AddIntent(map[string]any{"summary": "deleted direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(original, db.StateIntentDeleted); err != nil {
		t.Fatal(err)
	}
	input := fmt.Sprintf(`{"summary":"recreate deleted direction","continuation_of":%d}`, original)
	result, err := NewToolSet(store, "planner").addIntent().Call(context.Background(), json.RawMessage(input), nil)
	if err != nil || !strings.Contains(result.Flatten(), "已被删除") {
		t.Fatalf("deleted continuation result=%s err=%v", result.Flatten(), err)
	}
}
