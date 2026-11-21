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
