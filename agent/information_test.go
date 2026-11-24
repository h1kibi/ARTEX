package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func callWrite(t *testing.T, tool actool.CoreTool, input string) actool.Result {
	t.Helper()
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatalf("tool call: %v", err)
	}
	return res
}

func TestRecordFactValidatesInformationTypes(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("information types", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "collect evidence"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "worker")
	ts.SetOwnerNode(intentID)
	artifactDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(artifactDir, "out.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts.SetArtifactRoots(artifactDir)
	if err := ts.validateEvidenceRef(context.Background(), db.EvidenceRef{Kind: "artifact", ID: "missing.txt"}); err == nil {
		t.Fatal("missing artifact reference was accepted")
	}
	if err := ts.validateEvidenceRef(context.Background(), db.EvidenceRef{Kind: "artifact", ID: "../outside.txt"}); err == nil {
		t.Fatal("artifact path traversal was accepted")
	}
	if err := ts.validateEvidenceRef(context.Background(), db.EvidenceRef{Kind: "artifact", ID: "out.txt"}); err != nil {
		t.Fatalf("existing artifact rejected: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(artifactDir, "escape.txt")); err == nil {
		if err := ts.validateEvidenceRef(context.Background(), db.EvidenceRef{Kind: "artifact", ID: "escape.txt"}); err == nil {
			t.Fatal("symlink escaping the artifact root was accepted")
		}
	}
	ts.SetArtifactRoots()
	tool := ts.recordFact()

	if res := callWrite(t, tool, `{"summary":"no type"}`); !res.IsError || !strings.Contains(res.Flatten(), "fact_type") {
		t.Fatalf("missing fact_type accepted: %s", res.Flatten())
	}
	if res := callWrite(t, tool, `{"fact_type":"observation","summary":"no source"}`); !res.IsError || !strings.Contains(res.Flatten(), "source_activity_ids") {
		t.Fatalf("observation without source accepted: %s", res.Flatten())
	}
	res := callWrite(t, tool, `{"fact_type":"observation","summary":"HTTP 500 leaks DB error","evidence_refs":["artifact:out.txt"]}`)
	if res.IsError {
		t.Fatalf("observation rejected: %s", res.Flatten())
	}
	obsID := parseRecordedID(t, res.Flatten())

	if res = callWrite(t, tool, `{"fact_type":"claim","summary":"search is injectable","observation_ids":[`+itoa(obsID)+`],"confidence":"observed"}`); res.IsError {
		t.Fatalf("claim rejected: %s", res.Flatten())
	}
	claimID := parseRecordedID(t, res.Flatten())

	if res = callWrite(t, tool, `{"fact_type":"hypothesis","summary":"can read users","claim_ids":[`+itoa(claimID)+`]}`); !res.IsError || !strings.Contains(res.Flatten(), "validation_actions") {
		t.Fatalf("hypothesis without actions accepted: %s", res.Flatten())
	}
	if res = callWrite(t, tool, `{"fact_type":"hypothesis","summary":"can read users","claim_ids":[`+itoa(claimID)+`],"validation_actions":["UNION SELECT user()"]}`); res.IsError {
		t.Fatalf("hypothesis rejected: %s", res.Flatten())
	}
	if res = callWrite(t, tool, `{"fact_type":"finding_candidate","summary":"maybe SQLi","claim_ids":[`+itoa(claimID)+`],"validation_state":"confirmed"}`); !res.IsError || !strings.Contains(res.Flatten(), "report_finding") {
		t.Fatalf("candidate accepted as confirmed: %s", res.Flatten())
	}
	if res = callWrite(t, tool, `{"fact_type":"finding_candidate","summary":"maybe SQLi","claim_ids":[`+itoa(claimID)+`]}`); res.IsError {
		t.Fatalf("pending candidate rejected: %s", res.Flatten())
	}

	facts, err := store.ListByKind(db.KindFact, 20)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, n := range facts {
		types[n.FactType()]++
	}
	if types[db.FactTypeObservation] != 1 || types[db.FactTypeClaim] != 1 ||
		types[db.FactTypeHypothesis] != 1 || types[db.FactTypeFindingCandidate] != 1 {
		t.Fatalf("stored information types=%v", types)
	}
}

func TestAddIntentDefaultsRouteBudget(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("route defaults", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	first, err := ts.addOneIntent(intentItem{Summary: "default-budget route"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(first)
	if err != nil || node == nil {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	if b := db.ParseIntentRoute(node).Budget; b.MaxToolCalls != db.DefaultRouteMaxToolCalls || b.MaxInputTokens != db.DefaultRouteMaxInputTokens {
		t.Fatalf("default budget=%+v", b)
	}
	if err := store.SetIntentState(first, "done"); err != nil {
		t.Fatal(err)
	}
	cont, err := ts.addOneIntent(intentItem{Summary: "inherit defaults", ContinuationOf: first})
	if err != nil {
		t.Fatal(err)
	}
	if node, err = store.GetNode(cont); err != nil || node == nil {
		t.Fatalf("continuation=%+v err=%v", node, err)
	}
	if b := db.ParseIntentRoute(node).Budget; b.MaxToolCalls != db.DefaultRouteMaxToolCalls {
		t.Fatalf("continuation budget=%+v", b)
	}

	explicit, err := ts.addOneIntent(intentItem{Summary: "explicit route", Budget: routeBudgetItem{MaxToolCalls: 7}})
	if err != nil {
		t.Fatal(err)
	}
	if node, err = store.GetNode(explicit); err != nil || node == nil {
		t.Fatalf("explicit=%+v err=%v", node, err)
	}
	if b := db.ParseIntentRoute(node).Budget; b.MaxToolCalls != 7 || b.MaxInputTokens != 0 {
		t.Fatalf("explicit budget=%+v", b)
	}
}

func TestRenderPriorCheckpointHandoff(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("checkpoint handoff", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	first, err := store.AddIntent(map[string]any{"summary": "stage one", "path_phase": "validation"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	payload := db.CheckpointPayload(
		"confirmed the search endpoint is injectable; exact table read unproven",
		"path_stage", "verify the route", "validation", "run-1", "completed",
		first, first, nil, nil, nil,
		[]string{"traffic:123"}, []string{"GET /search?q=1'", "UNION SELECT version()"}, []string{"read users table with a bounded UNION"}, db.RouteBudgetUsed{ToolCalls: 12, InputTokens: 34000},
	)
	payload["attempted_actions"] = []string{"GET /search?q=1'", "UNION SELECT version()"}
	payload["next_actions"] = []string{"read users table with a bounded UNION"}
	cpID, err := store.AddNodeLinked(db.KindFact, payload, 0, "confirmed", "system", nil, first, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentRouteProgress(first, cpID, db.RouteBudgetUsed{ToolCalls: 12, InputTokens: 34000}, "2026-11-24T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(first)
	if err != nil || node == nil {
		t.Fatalf("intent=%+v err=%v", node, err)
	}
	block := renderPriorCheckpoint(store, node)
	for _, want := range []string{
		"前序 Run", "exact table read unproven", "GET /search?q=1'",
		"read users table", "traffic:123", "node_detail",
	} {
		if !strings.Contains(block, want) {
			t.Fatalf("checkpoint block missing %q:\n%s", want, block)
		}
	}
}

func TestGraphOverviewExcludesCheckpointsFromFacts(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("overview facts", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "overview fixture"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "one real fact",
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	payload := db.CheckpointPayload(
		"checkpoint should not count as a fact", "path_stage", "overview", "validation",
		"run-overview", "completed", intentID, intentID, nil, nil, nil,
		[]string{"traffic:1"}, []string{"GET /old"}, []string{"GET /next"}, db.RouteBudgetUsed{ToolCalls: 3},
	)
	if _, err := store.AddNodeLinked(db.KindFact, payload, 0, "confirmed", "system", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "planner")
	data := ts.graphOverviewData()
	if got := data["facts"].(int); got != 1 {
		t.Fatalf("facts=%d want 1 (checkpoint excluded)", got)
	}
	recent, _ := data["recent_facts"].([]map[string]any)
	if len(recent) != 1 || recent[0]["summary"] != "one real fact" {
		t.Fatalf("recent_facts=%v", recent)
	}
	checkpoints, _ := data["checkpoints"].([]map[string]any)
	if len(checkpoints) != 1 {
		t.Fatalf("checkpoints=%v", checkpoints)
	}
	attempted, _ := checkpoints[0]["attempted_actions"].([]string)
	if len(attempted) != 1 || attempted[0] != "GET /old" {
		t.Fatalf("checkpoint attempted_actions=%v", checkpoints[0]["attempted_actions"])
	}
}

func TestAddIntentInheritsRouteAndCheckpointBudget(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("route inheritance", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	first, err := ts.addOneIntent(intentItem{
		Summary: "validate IDOR", Objective: "verify object authorization",
		Phase: "validation", Budget: routeBudgetItem{MaxToolCalls: 20, MaxInputTokens: 5000},
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(first)
	if err != nil || node == nil {
		t.Fatalf("first intent=%+v err=%v", node, err)
	}
	route := db.ParseIntentRoute(node)
	if route.RouteID != first || route.PathPhase != "validation" || route.Budget.MaxToolCalls != 20 {
		t.Fatalf("first route=%+v", route)
	}

	checkpoint, err := store.AddNodeLinked(db.KindFact, db.CheckpointPayload(
		"checked baseline", "path_stage", "verify object authorization", "validation",
		"run-1", "completed", route.RouteID, first, nil, nil, nil,
		[]string{"traffic:x"}, nil, []string{"test id=1002"}, db.RouteBudgetUsed{ToolCalls: 8, InputTokens: 1200},
	), 0, "confirmed", "system", nil, first, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(first, "done"); err != nil {
		t.Fatal(err)
	}
	second, err := ts.addOneIntent(intentItem{
		Summary: "continue with a different object", ContinuationOf: first, Phase: "exploitation",
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err = store.GetNode(second)
	if err != nil || node == nil {
		t.Fatalf("second intent=%+v err=%v", node, err)
	}
	next := db.ParseIntentRoute(node)
	if next.RouteID != route.RouteID {
		t.Fatalf("continuation route=%d want %d", next.RouteID, route.RouteID)
	}
	if next.CheckpointFactID != checkpoint {
		t.Fatalf("continuation checkpoint=%d want %d", next.CheckpointFactID, checkpoint)
	}
	if next.BudgetUsed.ToolCalls != 8 || next.BudgetUsed.InputTokens != 1200 {
		t.Fatalf("continuation budget=%+v", next.BudgetUsed)
	}
	if next.Budget.MaxToolCalls != 20 {
		t.Fatalf("continuation lost route budget: %+v", next.Budget)
	}
	if _, err := ts.addOneIntent(intentItem{Summary: "parallel branch", ContinuationOf: first}); err == nil {
		t.Fatal("parallel continuation of the same route was accepted")
	}

	// Exhaust the route's cumulative tool-call budget. A bare continuation would
	// be killed again on the next Fast Path tick, so add_intent must reject it and
	// ask for an explicit larger budget.
	if err := store.SetIntentState(second, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveRunCheckpoint(second, 0, checkpoint, db.CheckpointPayload(
		"budget exhausted", "path_stage", "verify object authorization", "exploitation",
		"run-2", "exhausted", route.RouteID, second, nil, nil, nil,
		[]string{"traffic:y"}, nil, nil, db.RouteBudgetUsed{ToolCalls: 20, InputTokens: 5000},
	), db.RouteBudgetUsed{ToolCalls: 20, InputTokens: 5000}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.addOneIntent(intentItem{Summary: "keep going", ContinuationOf: second}); err == nil ||
		!strings.Contains(err.Error(), "预算已耗尽") {
		t.Fatalf("continuation on exhausted route err=%v", err)
	}
	expanded, err := ts.addOneIntent(intentItem{
		Summary: "keep going with more budget", ContinuationOf: second,
		Budget: routeBudgetItem{MaxToolCalls: 40, MaxInputTokens: 9000},
	})
	if err != nil {
		t.Fatalf("continuation with expanded budget: %v", err)
	}
	expandedNode, err := store.GetNode(expanded)
	if err != nil || expandedNode == nil {
		t.Fatalf("expanded intent=%+v err=%v", expandedNode, err)
	}
	if got := db.ParseIntentRoute(expandedNode).Budget; got.MaxToolCalls != 40 || got.MaxInputTokens != 9000 {
		t.Fatalf("expanded route budget=%+v", got)
	}
}

func parseRecordedID(t *testing.T, out string) int64 {
	t.Helper()
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "fact recorded: "))
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		t.Fatalf("parse recorded id from %q: %v", out, err)
	}
	return id
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
