package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// The stored reporter prompt that still says `update_finding_report(finding_id=<node_id>`
// must be replaced by the current default: that call now resolves finding_id as a
// RECORD id, so the old instruction steers the reporter onto the wrong row.
func TestReporterPromptMigratesOldNodeIDInstruction(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	a, err := pg.GetAgentByKey("reporter")
	if err != nil || a == nil {
		t.Fatalf("reporter agent: %+v err=%v", a, err)
	}
	old := "最后调用 update_finding_report(finding_id=<node_id>, report=..., evidence_version=...)。"
	if _, err := pg.SavePrompt(a.ID, old, "test", "system"); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetSetting("reporter_prompt_finding_node_id_v2", "false"); err != nil {
		t.Fatal(err)
	}
	s.reseedReporterPrompt()

	cur, err := pg.CurrentPrompt(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur != agent.ReporterDefaultPrompt {
		t.Fatalf("old built-in prompt was not upgraded:\n%s", cur)
	}
	if v, _, _ := pg.GetSetting("reporter_prompt_finding_node_id_v2"); v != "true" {
		t.Fatal("migration flag not recorded")
	}
}

// An operator-authored prompt that does not carry the old wording is authoritative.
func TestReporterPromptMigrationKeepsCustomPrompt(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	a, err := pg.GetAgentByKey("reporter")
	if err != nil || a == nil {
		t.Fatalf("reporter agent: %+v err=%v", a, err)
	}
	custom := "按本团队模板撰写报告，先核对流量证据，再用 update_finding_report 保存。"
	if _, err := pg.SavePrompt(a.ID, custom, "test", "user"); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetSetting("reporter_prompt_finding_node_id_v2", "false"); err != nil {
		t.Fatal(err)
	}
	s.reseedReporterPrompt()

	cur, err := pg.CurrentPrompt(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur != custom {
		t.Fatalf("custom prompt was overwritten:\n%s", cur)
	}
}

// Only the finding trigger (empty tool list, or one already watching report_finding)
// is repaired. A trigger the operator configured for other tools keeps its tool list,
// enabled flag and message.
func TestEnsureReporterTriggerLeavesOtherToolTriggersAlone(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	if err := pg.DeleteTriggersForAgent("reporter"); err != nil {
		t.Fatal(err)
	}
	other := &db.AgentTrigger{
		AgentKey: "reporter", Enabled: false, OnToolCall: true,
		ToolNames: []string{"list_task_findings"}, ToolCallMessage: "用户自定义的其他工具触发",
	}
	created, err := pg.CreateTrigger(other)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.ensureReporterTrigger(); err != nil {
		t.Fatal(err)
	}

	triggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	var repairedOther, installedFinding bool
	for _, tr := range triggers {
		switch {
		case tr.ID == created.ID:
			repairedOther = true
			if tr.Enabled || len(tr.ToolNames) != 1 || tr.ToolNames[0] != "list_task_findings" ||
				tr.ToolCallMessage != "用户自定义的其他工具触发" {
				t.Fatalf("user trigger was modified: %+v", tr)
			}
		case tr.OnToolCall && len(tr.ToolNames) == 1 && tr.ToolNames[0] == "report_finding":
			installedFinding = true
			if !tr.Enabled || tr.ToolCallMessage != reporterToolCallMessage {
				t.Fatalf("finding trigger not installed correctly: %+v", tr)
			}
		}
	}
	if !repairedOther {
		t.Fatal("user trigger disappeared")
	}
	if !installedFinding {
		t.Fatal("finding trigger was not installed next to the user's trigger")
	}
}

// Once the one-shot seed is recorded, an operator who deleted the reporter agent or
// disabled its trigger keeps that decision across restarts.
func TestReporterSeedDoesNotRekeyAfterCompletion(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	if err := pg.SetSetting("reporter_agent_seed_v1", "true"); err != nil {
		t.Fatal(err)
	}
	// Close the trigger but keep the agent: a completed seed must not re-enable it.
	triggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range triggers {
		if tr.OnToolCall {
			tr.Enabled = false
			if err := pg.UpdateTrigger(tr); err != nil {
				t.Fatal(err)
			}
		}
	}
	s.seedReporterAgent()
	for _, tr := range mustTriggers(t, pg) {
		if tr.OnToolCall && tr.Enabled {
			t.Fatalf("completed seed re-enabled the operator's disabled trigger: %+v", tr)
		}
	}
	if v, _, _ := pg.GetSetting("reporter_agent_seed_v1"); !strings.EqualFold(v, "true") {
		t.Fatal("seed flag lost")
	}
}

func mustTriggers(t *testing.T, pg *db.DB) []*db.AgentTrigger {
	t.Helper()
	triggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	return triggers
}
