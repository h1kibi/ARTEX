package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// proveGoalFixture builds an owner task with one direct source task and returns the
// handle, both stores and the owner tool set.
func proveGoalFixture(t *testing.T, name string) (*db.DB, *db.ExplorationStore, *db.ExplorationStore, *ToolSet) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	source, err := d.CreateTask(name+" source", "source goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(source.ID) })
	sourceID := source.ID
	owner, err := d.CreateTaskWithOptions(name+" owner", "owner goal", db.TaskCreateOptions{SourceTaskIDs: []int64{sourceID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(owner.ID) })
	ownerStore := d.Exploration(owner.ExplorationID)
	return d, d.Exploration(source.ExplorationID), ownerStore, NewToolSet(ownerStore, "worker")
}

func addSourceFact(t *testing.T, store *db.ExplorationStore, payload map[string]any) int64 {
	t.Helper()
	id, err := store.AddNode(db.KindFact, payload, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func proveGoal(t *testing.T, ts *ToolSet, goalID, evidenceID int64) string {
	t.Helper()
	res := callWrite(t, ts.proveGoal(), fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d,"reason":"fixture"}`, goalID, evidenceID))
	return res.Flatten()
}

// Evidence that lives in a live direct source task proves an owner goal: the
// pre-check accepts it, and the commit-time re-validation must too.
func TestProveGoalAcceptsDirectSourceEvidence(t *testing.T) {
	_, source, owner, ts := proveGoalFixture(t, "prove inherited")
	inheritableFact := addSourceFact(t, source, map[string]any{"fact_type": "claim", "summary": "source credential works"})
	recorded, err := source.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: mustTaskID(t, source), ExplorationID: source.ID(), Worker: "worker",
		VulnClass: "RCE", Name: "source finding", Severity: "high",
		Summary: "confirmed source vulnerability", Evidence: "curl -> uid=0",
	})
	if err != nil {
		t.Fatal(err)
	}

	factGoal, err := owner.AddGoal(map[string]any{"text": "source fact goal"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if out := proveGoal(t, ts, factGoal, inheritableFact); !strings.Contains(out, "marked met") {
		t.Fatalf("inheritable source fact rejected: %s", out)
	}
	findingGoal, err := owner.AddGoal(map[string]any{"text": "source finding goal"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if out := proveGoal(t, ts, findingGoal, recorded.NodeID); !strings.Contains(out, "marked met") {
		t.Fatalf("inheritable source finding rejected: %s", out)
	}
	for _, goal := range []int64{factGoal, findingGoal} {
		n, err := owner.GetNode(goal)
		if err != nil || n == nil || n.State != "met" {
			t.Fatalf("goal %d not met: %+v err=%v", goal, n, err)
		}
	}
	// The proves edges live in the OWNER exploration with src ids from the source
	// exploration, which the schema allows (node ids are global).
	edges, err := owner.EdgesTouching([]int64{factGoal, findingGoal})
	if err != nil {
		t.Fatal(err)
	}
	proves := map[int64]int64{}
	for _, e := range edges {
		if e.Rel == db.RelProves {
			proves[e.To] = e.From
		}
	}
	if proves[factGoal] != inheritableFact || proves[findingGoal] != recorded.NodeID {
		t.Fatalf("proves edges missing or mis-keyed: %+v", proves)
	}
}

// The in-transaction re-validation rejects source evidence the pre-check could not
// see change: a non-source node, a sensitive fact, a checkpoint, a verifying finding
// and a finding whose confirmation was bound to an older evidence version.
func TestProveGoalTxRejectsUnusableSourceEvidence(t *testing.T) {
	d, source, owner, _ := proveGoalFixture(t, "prove inherited reject")

	other, err := d.CreateTask("unrelated evidence", "no relation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(other.ID) })
	nonSourceFact, err := d.Exploration(other.ExplorationID).AddNode(db.KindFact,
		map[string]any{"fact_type": "claim", "summary": "unrelated"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	sensitive := addSourceFact(t, source, map[string]any{"fact_type": "claim", "summary": "token", "sensitivity": "token"})
	checkpoint := addSourceFact(t, source, map[string]any{"fact_type": "checkpoint", "summary": "bookkeeping"})
	verifying, err := source.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: mustTaskID(t, source), ExplorationID: source.ID(), Worker: "worker",
		VulnClass: "SSRF", Name: "verifying", Severity: "medium",
		Summary: "text only", Evidence: "screenshot", TriageState: "verifying",
	})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := source.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: mustTaskID(t, source), ExplorationID: source.ID(), Worker: "worker",
		VulnClass: "XXE", Name: "stale", Severity: "medium",
		Summary: "confirmed then evidence moved", Evidence: "curl -> file read",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Confirmation bound to version 1 while the evidence is at version 2: the verdict
	// judged evidence that no longer exists.
	if _, err := d.Exec(`UPDATE exploration_nodes SET payload = payload ||
'{"triage_state":"confirmed","triage_evidence_version":1,"evidence_version":2}'::jsonb WHERE id=$1`, stale.NodeID); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		id   int64
	}{
		{"non-source fact", nonSourceFact},
		{"sensitive source fact", sensitive},
		{"checkpoint source fact", checkpoint},
		{"verifying source finding", verifying.NodeID},
		{"stale-version source finding", stale.NodeID},
	}
	for _, tc := range cases {
		goal, err := owner.AddGoal(map[string]any{"text": "rejected " + tc.name}, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.ProveGoalCheckedWithInheritance(goal, tc.id, RevalidateProofEvidenceInTx); err == nil {
			t.Fatalf("%s was accepted inside the prove transaction", tc.name)
		}
		n, err := owner.GetNode(goal)
		if err != nil || n == nil {
			t.Fatalf("%s: read goal: %v", tc.name, err)
		}
		if n.State == "met" {
			t.Fatalf("%s marked the goal met without an evidence edge", tc.name)
		}
	}
}

// mustTaskID resolves the live task id bound to an exploration.
func mustTaskID(t *testing.T, store *db.ExplorationStore) int64 {
	t.Helper()
	id, err := store.TaskID()
	if err != nil || id <= 0 {
		t.Fatalf("task id for exploration %d: %d err=%v", store.ID(), id, err)
	}
	return id
}
