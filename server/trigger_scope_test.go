package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// latestConversation returns the newest conversation for an agent key.
func latestConversation(t *testing.T, s *Server, agentKey string) *db.Conversation {
	t.Helper()
	var id int64
	if err := s.m.pg.QueryRow(`SELECT id FROM conversations WHERE agent_key=$1 ORDER BY id DESC LIMIT 1`, agentKey).Scan(&id); err != nil {
		t.Fatalf("load latest conversation for %s: %v", agentKey, err)
	}
	c, err := s.m.pg.GetConversation(id)
	if err != nil || c == nil {
		t.Fatalf("read conversation %d: %v", id, err)
	}
	return c
}

func triggerFires(agentKey string, taskID int64, bodies ...string) []triggeredRun {
	items := make([]triggeredRun, len(bodies))
	for i, body := range bodies {
		items[i] = triggeredRun{agentKey: agentKey, taskID: taskID, taskDesc: "scope", message: body, mergeable: true}
	}
	return items
}

// Fires from one task merge into a run that keeps that task's authority, persists
// it on the conversation, and therefore keeps the same evidence write permission on
// every later turn (those rebuild their context from the server root).
func TestMergedTriggerScopePersistsSingleTask(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	row, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || row == nil || row.TaskID == nil {
		t.Fatalf("fixture finding has no task: %+v err=%v", row, err)
	}
	taskID := *row.TaskID

	merged := mergeAllRuns(triggerFires("reporter", taskID, "event one", "event two"))
	if merged.taskID != taskID {
		t.Fatalf("same-task merge lost the task scope: got %d want %d", merged.taskID, taskID)
	}
	if scope := s.triggerTaskScope(merged); scope == nil || *scope != taskID {
		t.Fatalf("merged run scope: %v", scope)
	}
	s.runTriggeredRun(merged)

	c := latestConversation(t, s, "reporter")
	if c.TaskID == nil || *c.TaskID != taskID {
		t.Fatalf("conversation task scope not persisted: %v", c.TaskID)
	}
	// Follow-up turns attach the PERSISTED scope, not the first message's claim.
	followUp := withConversationTaskScope(context.Background(), c)
	if ri := agent.RunInfoFrom(followUp); ri.TaskID != taskID {
		t.Fatalf("follow-up turn lost the task identity: %+v", ri)
	}
	out := workflowCall(t, followUp, s.toolUpdateFindingReport(), map[string]any{
		"finding_id": f.FindingID, "report": "## 合并触发后的报告",
	}, false)
	if !strings.Contains(out, "report updated") {
		t.Fatalf("follow-up write refused: %s", out)
	}
}

// A batch that mixes tasks names no single authorized task: the merged run must be
// unscoped, its conversation must not inherit the first event's task, and evidence
// writes from it must be refused.
func TestMergedTriggerScopeRejectsCrossTaskBatch(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	row, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || row == nil || row.TaskID == nil {
		t.Fatalf("fixture finding has no task: %+v err=%v", row, err)
	}
	ownerID := *row.TaskID
	other, err := s.m.CreateTask("trigger scope other", "must not inherit", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(other.ID, DeleteTaskOptions{}) })
	otherID, err := strconv.ParseInt(other.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	merged := mergeAllRuns([]triggeredRun{
		{agentKey: "reporter", taskID: ownerID, message: "owner event", mergeable: true},
		{agentKey: "reporter", taskID: otherID, message: "other event", mergeable: true},
	})
	if merged.taskID != 0 {
		t.Fatalf("cross-task merge kept a task identity: %d", merged.taskID)
	}
	if scope := s.triggerTaskScope(merged); scope != nil {
		t.Fatalf("cross-task merge authorized task %d", *scope)
	}
	s.runTriggeredRun(merged)

	c := latestConversation(t, s, "reporter")
	if c.TaskID != nil {
		t.Fatalf("cross-task conversation inherited task %d", *c.TaskID)
	}
	ctx := withConversationTaskScope(context.Background(), c)
	if ri := agent.RunInfoFrom(ctx); ri.TaskID != 0 {
		t.Fatalf("cross-task run attached task %d", ri.TaskID)
	}
	out := workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{
		"finding_id": f.FindingID, "report": "## 越权写入",
	}, true)
	if !strings.Contains(out, "未绑定任务") {
		t.Fatalf("unscoped conversation wrote a report: %s", out)
	}
	prev := s.m.pg.GetBool(settingAgentTrafficBinding, false)
	if err := s.m.pg.SetBool(settingAgentTrafficBinding, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.SetBool(settingAgentTrafficBinding, prev) })
	out = workflowCall(t, ctx, s.toolBindFindingTraffic(), map[string]any{
		"finding_id": f.FindingID, "traffic_refs": []db.TrafficRef{{TrafficID: "none"}},
	}, true)
	if !strings.Contains(out, "未绑定任务") {
		t.Fatalf("unscoped conversation bound traffic: %s", out)
	}
	// The refusal is a scope decision, not a broken lookup: the task-bound caller
	// still reaches the finding.
	ownerCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: ownerID})
	workflowCall(t, ownerCtx, s.toolUpdateFindingReport(), map[string]any{
		"finding_id": f.FindingID, "report": fmt.Sprintf("## task %d report", ownerID),
	}, false)
}
