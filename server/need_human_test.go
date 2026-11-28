package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/harness"
)

// resolveIntentState is the whole precedence rule in one place.
func TestResolveIntentStatePrefersHumanHandoff(t *testing.T) {
	human := agent.WriteCounts{HumanNeeded: true}
	cases := []struct {
		name   string
		reason string
		err    error
		wrote  agent.WriteCounts
		want   string
	}{
		{"natural finish", "completed", nil, agent.WriteCounts{}, "done"},
		{"turn budget", "max_turns", nil, agent.WriteCounts{}, "exhausted"},
		{"wall clock", "timeout", nil, agent.WriteCounts{}, "exhausted"},
		{"error", "model_error", errFrom("boom"), agent.WriteCounts{}, "blocked"},
		// The hand-off wins over every one of them: a worker parked on an MFA prompt
		// that then hit its budget or errored downstream still needs the operator.
		{"handoff after turn budget", "max_turns", nil, human, "paused"},
		{"handoff after timeout", "timeout", nil, human, "paused"},
		{"handoff after error", "model_error", errFrom("boom"), human, "paused"},
		{"handoff on clean finish", "completed", nil, human, "paused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveIntentState(harnessReason(tc.reason), tc.err, tc.wrote)
			if got != tc.want {
				t.Fatalf("state = %q, want %q", got, tc.want)
			}
		})
	}
}

// The full hand-off, on a task with NO open goal (the goalless case): the intent
// must park in paused, the task must NOT be closed as done, and the human message
// endpoint must accept the resume. Before this, HasActiveIntent ignored `paused`,
// so the goalless sweep closed the task and the resume was rejected with
// "终态任务无法向 Worker 发送消息".
func TestNeedHumanHandoffSurvivesGoallessTask(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	if err := s.m.pg.SetBool(settingAgentTrafficBinding, false); err != nil {
		t.Fatal(err)
	}
	task, err := s.m.CreateTask("goalless handoff", "park on MFA", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	// No goals at all → the goalless branch, and no intents yet.
	if open, err := task.Store.HasOpenGoal(); err != nil || open {
		t.Fatalf("fixture has an open goal (open=%v err=%v)", open, err)
	}

	// The worker writes a need_human fact through the real tool.
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "log in and pull the admin list"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	artifact := t.TempDir()
	ts := agent.NewToolSet(task.Store, "worker")
	ts.SetOwnerNode(intentID)
	ts.SetArtifactRoots(artifact)
	writeArtifact(t, artifact, "mfa.txt", "blocked at /login: SMS code required")
	if r := workflowCall(t, context.Background(), ts.RecordFactTool(), map[string]any{
		"fact_type": "observation", "summary": "登录卡在短信验证码",
		"detail":        "/login 提交后要求输入手机验证码，需要人工提供",
		"evidence_refs": []string{"artifact:mfa.txt"}, "need_human": true,
	}, false); r == "" {
		t.Fatal("record_fact returned nothing")
	}
	if !ts.Writes().HumanNeeded {
		t.Fatal("need_human did not raise the run flag")
	}

	// The engine parks it (mirroring runIntent's settlement for this run).
	if err := transitionIntentState(task.Store, intentID, "running", resolveIntentState(harnessReason("max_turns"), nil, ts.Writes())); err != nil {
		t.Fatal(err)
	}
	node, err := task.Store.GetNode(intentID)
	if err != nil || node == nil || node.State != "paused" {
		t.Fatalf("intent state = %+v err=%v, want paused", node, err)
	}

	// The goalless sweep closes a task only when it has no open goal AND no active
	// intent. With a paused hand-off the second half must be false, or the task
	// closes itself and the resume below is rejected as a terminal task.
	open, err := task.Store.HasOpenGoal()
	if err != nil {
		t.Fatal(err)
	}
	active, err := task.Store.HasActiveIntent()
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("fixture unexpectedly has an open goal")
	}
	if !active {
		t.Fatal("HasActiveIntent = false; a paused hand-off must count as active")
	}

	// The human message endpoint must pass every lifecycle gate and reach the run.
	// This fixture has no LLM provider, so the run itself cannot start
	// ("worker 尚未就绪", a 500) — what matters is that the endpoint is NOT rejected
	// by the terminal-task / state gate that used to fire here. Compare against a
	// genuinely terminal task to prove the gate itself is still live.
	r := request("POST", "/api/tasks/"+task.ID+"/intents/"+itoa64(intentID)+"/messages",
		`{"message":"验证码是 123456","request_id":"req-handoff-1"}`)
	if r.Code == 409 && strings.Contains(r.Body.String(), "终态任务") {
		t.Fatalf("hand-off refused as a terminal task: %d %s", r.Code, r.Body)
	}
	if !strings.Contains(r.Body.String(), "worker 尚未就绪") {
		t.Fatalf("unexpected resume outcome: %d %s", r.Code, r.Body)
	}

	// Control: a terminal task IS refused, so the assertion above is meaningful.
	terminal, err := s.m.CreateTask("terminal control", "closed", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(terminal.ID, DeleteTaskOptions{}) })
	if err := s.m.SetTaskStatus(terminal.ID, "done"); err != nil {
		t.Fatal(err)
	}
	tid, err := terminal.Store.AddIntent(map[string]any{"summary": "closed lane"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := terminal.Store.SetIntentState(tid, "paused"); err != nil {
		t.Fatal(err)
	}
	if r := request("POST", "/api/tasks/"+terminal.ID+"/intents/"+itoa64(tid)+"/messages",
		`{"message":"x","request_id":"req-terminal-1"}`); r.Code != 409 {
		t.Fatalf("terminal task accepted a message: %d %s", r.Code, r.Body)
	}
}

func writeArtifact(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func harnessReason(s string) harness.TerminalReason { return harness.TerminalReason(s) }

type errString string

func (e errString) Error() string { return string(e) }

func errFrom(s string) error { return errString(s) }
