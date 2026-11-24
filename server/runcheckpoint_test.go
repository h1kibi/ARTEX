package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestRunCheckpointAndCandidateReconciliation(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	task, err := m.CreateTask("checkpoint fixture", "verify route handoff", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	store := task.Store
	intentID, _, err := store.AddIntentWithEdges(map[string]any{
		"summary": "validate the candidate", "objective": "verify the route",
		"path_phase": "validation", "route_kind": "path_stage",
		"budget": map[string]any{"max_tool_calls": 20, "max_input_tokens": 5000},
	}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeClaim, "summary": "observed a candidate",
		"confidence": "observed", "evidence_refs": []string{"artifact:out.txt"},
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	hypID, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeHypothesis, "summary": "maybe exploitable",
		"state": "open", "claim_ids": []int64{claimID},
		"validation_actions": []string{"run the second request"},
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	start, _ := store.ActivityMaxID()
	now := time.Now()
	toolUse := "tool-use"
	if _, err := store.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "work#1", Kind: "tool_use", Tool: "Bash",
		ToolUseID: toolUse, Summary: "Bash curl", Detail: "curl https://example.test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "work#1", Kind: "tool_result", Tool: "Bash",
		ToolUseID: toolUse, Summary: "200 OK",
	}); err != nil {
		t.Fatal(err)
	}
	in, out := 1200, 300
	if _, err := store.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "work#1", Kind: "result",
		Summary: "validated the candidate", Detail: "the second request returned another user's object",
		InputTokens: &in, OutputTokens: &out,
	}); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(m)
	cpID, err := e.writeRunCheckpoint(task, node, "run-checkpoint", now.Add(-2*time.Second), start, "completed")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := store.GetNode(cpID)
	if err != nil || cp == nil {
		t.Fatalf("checkpoint=%+v err=%v", cp, err)
	}
	p := db.ParseFactPayload(cp.Payload)
	if p.FactType != db.FactTypeCheckpoint || p.RouteID != intentID || p.PathPhase != "validation" {
		t.Fatalf("checkpoint payload=%+v", p)
	}
	if len(p.ConfirmedClaimIDs) != 1 || p.ConfirmedClaimIDs[0] != claimID {
		t.Fatalf("checkpoint claims=%v", p.ConfirmedClaimIDs)
	}
	if len(p.OpenHypothesisIDs) != 1 || p.OpenHypothesisIDs[0] != hypID {
		t.Fatalf("checkpoint hypotheses=%v", p.OpenHypothesisIDs)
	}
	if p.BudgetUsed.ToolCalls != 1 || p.BudgetUsed.InputTokens != in || p.BudgetUsed.OutputTokens != out {
		t.Fatalf("checkpoint budget=%+v", p.BudgetUsed)
	}
	if len(p.EvidenceRefs) == 0 {
		t.Fatal("checkpoint lost evidence refs")
	}
	intentAfter, _ := store.GetNode(intentID)
	afterRoute := db.ParseIntentRoute(intentAfter)
	if afterRoute.CheckpointFactID != cpID {
		t.Fatalf("intent did not remember checkpoint: %+v", intentAfter)
	}
	if afterRoute.BudgetUsed.ToolCalls != 1 || afterRoute.BudgetUsed.InputTokens != in {
		t.Fatalf("intent did not remember route budget: %+v", afterRoute.BudgetUsed)
	}

	candidateID, err := e.reconcileFindingCandidate(task, intentAfter, "run-checkpoint")
	if err != nil || candidateID <= 0 {
		t.Fatalf("candidate id=%d err=%v", candidateID, err)
	}
	candidate, err := store.GetNode(candidateID)
	if err != nil || candidate == nil || candidate.FactType() != db.FactTypeFindingCandidate {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}
	cpPayload := db.ParseFactPayload(candidate.Payload)
	if cpPayload.ValidationState != "pending" || len(cpPayload.ClaimIDs) == 0 {
		t.Fatalf("candidate payload=%+v", cpPayload)
	}
	if _, err := e.reconcileFindingCandidate(task, intentAfter, "run-checkpoint"); err != nil {
		t.Fatal(err)
	}
	after, _ := store.ListByKind(db.KindFact, 50)
	candidates := 0
	for _, n := range after {
		if n.FactType() == db.FactTypeFindingCandidate {
			candidates++
		}
	}
	if candidates != 1 {
		t.Fatalf("candidate duplicated: %d", candidates)
	}
	// A rejected candidate is a decision, not a stale cache: re-extraction must
	// not reopen it to pending.
	var raw map[string]any
	_ = json.Unmarshal(candidate.Payload, &raw)
	raw["validation_state"] = "rejected"
	if err := store.UpdateFactPayload(candidateID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reconcileFindingCandidate(task, intentAfter, "run-checkpoint"); err != nil {
		t.Fatal(err)
	}
	rejected, err := store.GetNode(candidateID)
	if err != nil || db.ParseFactPayload(rejected.Payload).ValidationState != "rejected" {
		t.Fatalf("rejected candidate was reopened: %+v err=%v", rejected, err)
	}

	// A hypothesis-only run (no Claim) still yields a candidate; the old
	// claim-only guard silently dropped these runs.
	hypIntent, _, err := store.AddIntentWithEdges(map[string]any{
		"summary": "validate hypothesis only", "path_phase": "validation",
	}, 5, nil, "planner", intentID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeHypothesis, "summary": "maybe readable without auth",
		"state": "open", "evidence_refs": []string{"traffic:123"},
		"validation_actions": []string{"repeat the request without cookies"},
	}, 5, "confirmed", "worker", nil, hypIntent, db.RelYields); err != nil {
		t.Fatal(err)
	}
	hypNode, err := store.GetNode(hypIntent)
	if err != nil {
		t.Fatal(err)
	}
	hypCandidateID, err := e.reconcileFindingCandidate(task, hypNode, "run-hyp-only")
	if err != nil || hypCandidateID <= 0 {
		t.Fatalf("hypothesis-only candidate id=%d err=%v", hypCandidateID, err)
	}
	hypCandidate, _ := store.GetNode(hypCandidateID)
	hypPayload := db.ParseFactPayload(hypCandidate.Payload)
	if len(hypPayload.HypothesisIDs) == 0 || len(hypPayload.ClaimIDs) != 0 {
		t.Fatalf("hypothesis-only candidate payload=%+v", hypPayload)
	}
}

func TestRouteBudgetTerminalStateWithoutWatchdog(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	task, err := m.CreateTask("budget terminal", "no watchdog downgrade", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	store := task.Store
	intentID, _, err := store.AddIntentWithEdges(map[string]any{
		"summary": "spend budget exactly", "budget": map[string]any{"max_tool_calls": 1},
	}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	used := db.RouteBudgetUsed{ToolCalls: 1}
	if _, err := store.SaveRunCheckpoint(intentID, 0, 0, db.CheckpointPayload(
		"spent", "path_stage", "check budget", "validation", "run-b", "completed",
		intentID, intentID, nil, nil, nil, nil, nil, nil, used,
	), used, ""); err != nil {
		t.Fatal(err)
	}
	if got := routeBudgetTerminalState(store, intentID, "done"); got != "exhausted" {
		t.Fatalf("terminal state=%q want exhausted", got)
	}
	openID, _, err := store.AddIntentWithEdges(map[string]any{
		"summary": "still has budget", "budget": map[string]any{"max_tool_calls": 10},
	}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveRunCheckpoint(openID, 0, 0, db.CheckpointPayload(
		"one call", "path_stage", "check budget", "validation", "run-c", "completed",
		openID, openID, nil, nil, nil, nil, nil, nil, used,
	), used, ""); err != nil {
		t.Fatal(err)
	}
	if got := routeBudgetTerminalState(store, openID, "done"); got != "done" {
		t.Fatalf("terminal state=%q want done", got)
	}
}

func TestRouteInformationEvidenceViews(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	task, err := m.CreateTask("view fixture", "show route and information", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	store := task.Store
	assetID, err := m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: "view.example"})
	if err != nil {
		t.Fatal(err)
	}
	intentID, _, err := store.AddIntentWithEdges(map[string]any{
		"summary": "validate view", "objective": "show the route",
		"path_phase": "validation", "route_kind": "path_stage",
		"budget": map[string]any{"max_tool_calls": 10},
	}, 5, []int64{assetID}, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "observed response",
		"evidence_refs": []string{"artifact:view.txt"},
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeClaim, "summary": "observed response is repeatable",
		"confidence": "observed", "evidence_refs": []string{"artifact:view.txt"},
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(db.KindFact, db.CheckpointPayload(
		"view checkpoint", "path_stage", "show the route", "validation", "run-view", "completed",
		intentID, intentID, nil, nil, nil, []string{"artifact:view.txt"}, nil, []string{"next"}, db.RouteBudgetUsed{ToolCalls: 1},
	), 0, "confirmed", "system", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, engine: NewEngine(m), ctx: context.Background()}
	get := func(path string) map[string]any {
		r := httptest.NewRequest("GET", path, nil)
		r.SetPathValue("id", task.ID)
		w := httptest.NewRecorder()
		switch path {
		case "/routes":
			s.taskRoutes(w, r)
		case "/information":
			s.taskInformation(w, r)
		case "/evidence":
			s.taskEvidence(w, r)
		default:
			t.Fatalf("unknown path %s", path)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v (%s)", path, err, w.Body.String())
		}
		return out
	}
	routes := get("/routes")["routes"].([]any)
	if len(routes) != 1 {
		t.Fatalf("routes=%v", routes)
	}
	route := routes[0].(map[string]any)
	if int64(route["route_id"].(float64)) != intentID || route["phase"] != "validation" {
		t.Fatalf("route=%v", route)
	}
	if cps := route["checkpoints"].([]any); len(cps) != 1 {
		t.Fatalf("route checkpoints=%v", cps)
	}
	if route["intents"] == nil || route["findings"] == nil {
		t.Fatalf("route arrays must serialize as [] not null: %v", route)
	}
	// An open intent is queued, not running: the route must read "proposed"
	// until a worker actually claims it.
	if route["status"] != "proposed" {
		t.Fatalf("open intent route status=%v want proposed", route["status"])
	}
	if err := store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	route = get("/routes")["routes"].([]any)[0].(map[string]any)
	if route["status"] != "active" {
		t.Fatalf("running intent route status=%v want active", route["status"])
	}
	if err := store.SetIntentState(intentID, "open"); err != nil {
		t.Fatal(err)
	}
	ids := route["asset_ids"].([]any)
	if len(ids) != 1 || int64(ids[0].(float64)) != assetID {
		t.Fatalf("route assets=%v want %d", ids, assetID)
	}
	// Multi-stage route: I1 done, I2 exhausted. The earlier stage must not mask
	// the newer failure as "succeeded".
	if err := store.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	secondID, _, err := store.AddIntentWithEdges(map[string]any{
		"summary": "second stage", "path_phase": "exploitation",
	}, 5, nil, "planner", intentID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(secondID, "exhausted"); err != nil {
		t.Fatal(err)
	}
	route = get("/routes")["routes"].([]any)[0].(map[string]any)
	if route["status"] != "exhausted" {
		t.Fatalf("multi-stage route status=%v want exhausted", route["status"])
	}
	info := get("/information")
	if info["total"].(float64) != 2 || len(info["nodes"].([]any)) != 2 {
		t.Fatalf("information=%v", info)
	}
	for _, raw := range info["nodes"].([]any) {
		if raw.(map[string]any)["fact_type"] == db.FactTypeCheckpoint {
			t.Fatalf("information view leaked checkpoint: %v", raw)
		}
	}
	evidence := get("/evidence")
	if len(evidence["refs"].([]any)) == 0 {
		t.Fatalf("evidence=%v", evidence)
	}
}
