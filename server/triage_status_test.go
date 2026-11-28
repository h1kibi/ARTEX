package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// findingNodePayload reads the exploration node's JSON payload for a finding.
func findingNodePayload(t *testing.T, store *db.ExplorationStore, nodeID int64) map[string]any {
	t.Helper()
	n, err := store.GetNode(nodeID)
	if err != nil || n == nil {
		t.Fatalf("read node %d: %v", nodeID, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// A human disposition is also a triage decision: confirming a verifying finding from
// the findings API must make it usable as goal proof, bound to the evidence version
// the operator saw; marking it a false positive must revoke that.
func TestFindingStatusSyncsTriageStateAndProvesGoal(t *testing.T) {
	s, seeded, request := trafficEvidenceServer(t)
	row, err := s.m.pg.GetFinding(seeded.FindingID)
	if err != nil || row == nil || row.TaskID == nil {
		t.Fatalf("fixture finding: %+v err=%v", row, err)
	}
	task := s.m.ResolveTask(strconv.FormatInt(*row.TaskID, 10))
	if task == nil {
		t.Fatal("fixture task missing")
	}
	store := s.m.pg.Exploration(task.ExpID)
	rec, err := store.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: *row.TaskID, ExplorationID: task.ExpID, Worker: "test",
		VulnClass: "SQL 注入", Name: "triage sync", Severity: "high",
		Summary: "text-only report awaiting corroboration", Evidence: "curl -> SQL error",
		TriageState: "verifying",
	})
	if err != nil {
		t.Fatal(err)
	}
	seedServerEvidenceFlow(t, s, "triage-sync-proof", []byte("uid=0(root)"))
	if _, err := s.evidenceStore().Bind(context.Background(), rec.FindingID, []db.TrafficRef{{TrafficID: "triage-sync-proof", Role: "proof"}}); err != nil {
		t.Fatal(err)
	}
	before, err := s.m.pg.GetFinding(rec.FindingID)
	if err != nil || before == nil {
		t.Fatal(err)
	}
	if before.TriageState != "verifying" || before.EvidenceVersion == 0 {
		t.Fatalf("setup: triage=%q version=%d", before.TriageState, before.EvidenceVersion)
	}

	w := request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", rec.FindingID), `{"status":"confirmed"}`)
	if w.Code != 200 {
		t.Fatalf("patch status: %d %s", w.Code, w.Body)
	}
	confirmed, err := s.m.pg.GetFinding(rec.FindingID)
	if err != nil || confirmed == nil {
		t.Fatal(err)
	}
	if confirmed.TriageState != "confirmed" {
		t.Fatalf("findings.triage_state not synced: %q", confirmed.TriageState)
	}
	payload := findingNodePayload(t, store, rec.NodeID)
	if payload["triage_state"] != "confirmed" {
		t.Fatalf("node triage_state not mirrored: %v", payload["triage_state"])
	}
	if v, _ := payload["triage_evidence_version"].(float64); int64(v) != confirmed.EvidenceVersion {
		t.Fatalf("confirmation bound to version %v, want %d", payload["triage_evidence_version"], confirmed.EvidenceVersion)
	}
	// The task detail list must expose the same triage verdict as the row.
	w = request("GET", "/api/exploration/findings?task="+task.ID, "")
	if w.Code != 200 {
		t.Fatalf("task findings list: %d %s", w.Code, w.Body)
	}
	var list []FindingDTO
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	findingID := strconv.FormatInt(rec.FindingID, 10)
	var listed *FindingDTO
	for i := range list {
		if list[i].FindingID == findingID {
			listed = &list[i]
			break
		}
	}
	if listed == nil {
		t.Fatalf("finding %s missing from the task list", findingID)
	}
	if listed.TriageState != "confirmed" {
		t.Fatalf("task list triage_state=%q, want confirmed", listed.TriageState)
	}
	// The finding can now prove a goal.
	goal, err := store.AddGoal(map[string]any{"text": "confirmed finding proves goal"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ProveGoalChecked(goal, rec.NodeID, agent.RevalidateProofEvidence); err != nil {
		t.Fatalf("confirmed finding cannot prove goal: %v", err)
	}

	// A false positive revokes the triage confirmation in both places.
	w = request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", rec.FindingID), `{"status":"false_positive"}`)
	if w.Code != 200 {
		t.Fatalf("patch false_positive: %d %s", w.Code, w.Body)
	}
	rejected, err := s.m.pg.GetFinding(rec.FindingID)
	if err != nil || rejected == nil {
		t.Fatal(err)
	}
	if rejected.TriageState != "rejected" {
		t.Fatalf("false positive did not reject triage: %q", rejected.TriageState)
	}
	if got := findingNodePayload(t, store, rec.NodeID)["triage_state"]; got != "rejected" {
		t.Fatalf("node triage_state not rejected: %v", got)
	}
	// An invalid verdict is refused instead of stored.
	if w := request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", rec.FindingID), `{"triage_state":"maybe"}`); w.Code != 400 {
		t.Fatalf("invalid triage_state accepted: %d %s", w.Code, w.Body)
	}
}
