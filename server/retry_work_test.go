package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRetryBlockedIntentReopensBlocked(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	task, err := m.CreateTaskWithOptions("retry success", "test retry success", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	intentID, err := task.Store.AddIntent(map[string]any{"summary": "blocked retry target"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}

	s := newAdmissionTestServer(m, nil)
	if _, err := s.retryBlockedIntent(task, intentID); err != nil {
		t.Fatal(err)
	}
	node, err := task.Store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if node.State != "open" {
		t.Fatalf("retried intent state=%q, want open", node.State)
	}
}

// 新契约：blocked 意图的外部故障重试不再被旧路线数值预算拦截——预算已退化为统计。
func TestRetryBlockedIntentIgnoresSpentRouteBudget(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	task, err := m.CreateTaskWithOptions("retry budget", "test retry budget", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	intentID, _, err := task.Store.AddIntentWithEdges(map[string]any{
		"summary": "blocked on spent route", "budget": map[string]any{"max_tool_calls": 5},
	}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	used := db.RouteBudgetUsed{ToolCalls: 5}
	if _, err := task.Store.SaveRunCheckpoint(intentID, 0, 0, db.CheckpointPayload(
		"spent", "path_stage", "retry budget", "validation", "run-r", "completed",
		intentID, intentID, nil, nil, nil, nil, nil, nil, used,
	), used, ""); err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}

	s := newAdmissionTestServer(m, nil)
	if _, err := s.retryBlockedIntent(task, intentID); err != nil && strings.Contains(err.Error(), "预算已耗尽") {
		t.Fatalf("retry still blocked by the retired budget guard: %v", err)
	}
	node, err := task.Store.GetNode(intentID)
	if err != nil || node == nil {
		t.Fatalf("intent read: %v", err)
	}
	if node.State == "blocked" {
		t.Fatalf("blocked intent was not reopened: %+v", node)
	}
}

func TestRetryBlockedIntentRejectsLiveIntent(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	task, err := m.CreateTaskWithOptions("retry guard", "test retry guard", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	intentID, err := task.Store.AddIntent(map[string]any{"summary": "live retry target"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}

	s := newAdmissionTestServer(m, nil)
	_, err = s.retryBlockedIntent(task, intentID)
	if err == nil || !strings.Contains(err.Error(), "不是 blocked") {
		t.Fatalf("running intent retry error: %v", err)
	}
}
