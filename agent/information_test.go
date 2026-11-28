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

	// fact_type is optional: omitting it records an observation. A claim with no
	// source at all (no tool result, no evidence) is still refused.
	if res := callWrite(t, tool, `{"summary":"no source"}`); !res.IsError || !strings.Contains(res.Flatten(), "source_activity_ids") {
		t.Fatalf("observation without source accepted: %s", res.Flatten())
	}
	res := callWrite(t, tool, `{"summary":"HTTP 500 leaks DB error","evidence_refs":["artifact:out.txt"]}`)
	if res.IsError {
		t.Fatalf("default observation rejected: %s", res.Flatten())
	}
	obsID := parseRecordedID(t, res.Flatten())
	if n, err := store.GetNode(obsID); err != nil || n == nil || n.FactType() != db.FactTypeObservation {
		t.Fatalf("omitted fact_type stored as %+v err=%v", n, err)
	}

	// claim without confidence defaults to inferred.
	if res = callWrite(t, tool, `{"fact_type":"claim","summary":"search is injectable","observation_ids":[`+itoa(obsID)+`]}`); res.IsError {
		t.Fatalf("claim rejected: %s", res.Flatten())
	}
	claimID := parseRecordedID(t, res.Flatten())
	claimNode, err := store.GetNode(claimID)
	if err != nil || claimNode == nil {
		t.Fatalf("claim %d: %+v err=%v", claimID, claimNode, err)
	}
	if got := db.ParseFactPayload(claimNode.Payload).Confidence; got != "inferred" {
		t.Fatalf("claim confidence=%q want inferred", got)
	}

	// A hypothesis without validation actions but with claim provenance is stored
	// as an observation instead of being rejected.
	if res = callWrite(t, tool, `{"fact_type":"hypothesis","summary":"can read users","claim_ids":[`+itoa(claimID)+`]}`); res.IsError {
		t.Fatalf("hypothesis downgrade rejected: %s", res.Flatten())
	}
	downgradedID := parseRecordedID(t, res.Flatten())
	if n, err := store.GetNode(downgradedID); err != nil || n == nil || n.FactType() != db.FactTypeObservation {
		t.Fatalf("hypothesis not downgraded to observation: %+v err=%v", n, err)
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

	// need_human is the run's hand-off to a human: it must land on the fact payload
	// (so it survives a restart and is visible to the planner) and raise the run's
	// HumanNeeded flag (so the engine parks the intent in paused instead of done).
	if ts.Writes().HumanNeeded {
		t.Fatal("HumanNeeded set before any need_human fact")
	}
	if res = callWrite(t, tool, `{"fact_type":"observation","summary":"blocked on SMS MFA","detail":"/login needs the SMS code","evidence_refs":["artifact:out.txt"],"need_human":true}`); res.IsError {
		t.Fatalf("need_human fact rejected: %s", res.Flatten())
	}
	if !ts.Writes().HumanNeeded {
		t.Fatal("need_human fact did not raise the run's HumanNeeded flag")
	}
	humanFactID := parseRecordedID(t, res.Flatten())
	humanFact, err := store.GetNode(humanFactID)
	if err != nil || humanFact == nil {
		t.Fatalf("need_human fact %d: %+v err=%v", humanFactID, humanFact, err)
	}
	var humanPayload db.FactPayload
	if err := json.Unmarshal(humanFact.Payload, &humanPayload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !humanPayload.NeedHuman {
		t.Fatalf("need_human not persisted on the payload: %s", humanFact.Payload)
	}
	// A fact without the flag must not raise it again (the flag is per report).
	ts2 := NewToolSet(store, "worker")
	ts2.SetOwnerNode(intentID)
	ts2.SetArtifactRoots(artifactDir)
	_ = callWrite(t, ts2.recordFact(), `{"fact_type":"observation","summary":"plain observation","evidence_refs":["artifact:out.txt"]}`)
	if ts2.Writes().HumanNeeded {
		t.Fatal("plain fact raised HumanNeeded")
	}

	facts, err := store.ListByKind(db.KindFact, 20)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, n := range facts {
		types[n.FactType()]++
	}
	// Four observations: the default one, the downgraded hypothesis, the need_human
	// hand-off and the plain one.
	if types[db.FactTypeObservation] != 4 || types[db.FactTypeClaim] != 1 ||
		types[db.FactTypeHypothesis] != 1 || types[db.FactTypeFindingCandidate] != 1 {
		t.Fatalf("stored information types=%v", types)
	}
}

func TestAddIntentEffortDefaultsAndHistory(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("route defaults", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	// effort 缺席 → standard；模型不再需要填任何数字预算。
	first, err := ts.addOneIntent(intentItem{Summary: "default-effort route"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(first)
	if err != nil || node == nil {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	if eff := db.ParseIntentRoute(node).Effort; db.NormalizeEffort(eff) != db.EffortStandard {
		t.Fatalf("default effort=%q want standard", eff)
	}
	if lim := db.EffortRuntimeLimits(db.NormalizeEffort("")); lim.MaxTurns != 80 || lim.MaxAutoCycles != 1 {
		t.Fatalf("standard limits=%+v", lim)
	}
	if err := store.SetIntentState(first, "done"); err != nil {
		t.Fatal(err)
	}
	cont, err := ts.addOneIntent(intentItem{Summary: "inherit effort", ContinuationOf: rawID(first)})
	if err != nil {
		t.Fatal(err)
	}
	if node, err = store.GetNode(cont); err != nil || node == nil {
		t.Fatalf("continuation=%+v err=%v", node, err)
	}

	// 旧库/旧提示词仍可能带 budget JSON：必须可解析、落库为历史统计，但不阻断。
	legacy, err := ts.addOneIntent(intentItem{Summary: "legacy budget route",
		Budget: routeBudgetItem{MaxToolCalls: 7}, Effort: db.EffortDeep})
	if err != nil {
		t.Fatalf("legacy budget JSON rejected: %v", err)
	}
	if node, err = store.GetNode(legacy); err != nil || node == nil {
		t.Fatalf("legacy=%+v err=%v", node, err)
	}
	r := db.ParseIntentRoute(node)
	if r.Budget.MaxToolCalls != 7 {
		t.Fatalf("legacy budget lost: %+v", r.Budget)
	}
	if r.Effort != db.EffortDeep {
		t.Fatalf("effort=%q want deep", r.Effort)
	}
	if lim := db.EffortRuntimeLimits(r.Effort); lim.MaxTurns != 130 || lim.MaxAutoCycles != 2 {
		t.Fatalf("deep limits=%+v", lim)
	}
	if lim := db.EffortRuntimeLimits(db.EffortProbe); lim.MaxTurns != 35 || lim.MaxAutoCycles != 0 {
		t.Fatalf("probe limits=%+v", lim)
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

func TestValidateProofAnchor(t *testing.T) {
	ts := &ToolSet{}
	fact := func(id int64, state, payload string) *db.Node {
		return &db.Node{ID: id, Kind: db.KindFact, State: state, Payload: []byte(payload)}
	}
	allowed := []*db.Node{
		fact(1, "confirmed", `{"fact_type":"observation","summary":"seen"}`),
		fact(2, "confirmed", `{"fact_type":"claim","summary":"proven"}`),
		fact(3, "confirmed", `{"summary":"legacy"}`),
		{ID: 4, Kind: db.KindFinding, State: "confirmed"},
	}
	for _, n := range allowed {
		if err := ts.validateProofAnchor(n); err != nil {
			t.Fatalf("node %d rejected: %v", n.ID, err)
		}
	}
	rejected := []*db.Node{
		fact(10, "confirmed", `{"fact_type":"hypothesis","summary":"maybe","validation_actions":["x"]}`),
		fact(11, "confirmed", `{"fact_type":"decision","summary":"choose"}`),
		fact(12, "confirmed", `{"fact_type":"finding_candidate","summary":"maybe vuln"}`),
		fact(13, "confirmed", `{"fact_type":"checkpoint","summary":"bookkeeping"}`),
		fact(14, db.StateOrigin, `{"summary":"task root"}`),
		{ID: 15, Kind: db.KindFinding, State: "dismissed"},
		fact(20, "confirmed", `{"fact_type":"claim","summary":"stale","valid_until":"2000-01-01T00:00:00Z"}`),
	}
	for _, n := range rejected {
		if err := ts.validateProofAnchor(n); err == nil {
			t.Fatalf("node %d (%s/%s) was accepted as proof", n.ID, n.Kind, n.FactType())
		}
	}
	inherited := &db.Node{ID: 30, Kind: db.KindFact, State: "confirmed", Inherited: true,
		Payload: []byte(`{"fact_type":"claim","summary":"source claim"}`)}
	if err := ts.validateProofAnchor(inherited); err != nil {
		t.Fatalf("inheritable source claim rejected: %v", err)
	}
	sensitiveInherited := &db.Node{ID: 31, Kind: db.KindFact, State: "confirmed", Inherited: true,
		Payload: []byte(`{"fact_type":"claim","summary":"source token","sensitivity":"token"}`)}
	if err := ts.validateProofAnchor(sensitiveInherited); err == nil {
		t.Fatal("inherited token claim accepted as proof")
	}
}

func TestValidateIntentAnchorAllowsTentativeKnowledge(t *testing.T) {
	ts := &ToolSet{}
	fact := func(id int64, state, payload string) *db.Node {
		return &db.Node{ID: id, Kind: db.KindFact, State: state, Payload: []byte(payload)}
	}
	allowed := []*db.Node{
		fact(1, "confirmed", `{"fact_type":"observation","summary":"seen"}`),
		fact(2, "confirmed", `{"fact_type":"claim","summary":"proven"}`),
		fact(3, "confirmed", `{"fact_type":"decision","summary":"chosen"}`),
		fact(4, "confirmed", `{"fact_type":"hypothesis","summary":"maybe","state":"open"}`),
		fact(5, "confirmed", `{"fact_type":"hypothesis","summary":"supported","state":"supported"}`),
		fact(6, "confirmed", `{"fact_type":"finding_candidate","summary":"pending","validation_state":"pending"}`),
		{ID: 7, Kind: db.KindFinding, State: "confirmed"},
	}
	for _, n := range allowed {
		if err := ts.validateIntentAnchor(n); err != nil {
			t.Fatalf("anchor %d rejected: %v", n.ID, err)
		}
	}
	rejected := []*db.Node{
		fact(10, "confirmed", `{"fact_type":"hypothesis","summary":"rejected","state":"rejected"}`),
		fact(11, "confirmed", `{"fact_type":"hypothesis","summary":"expired","state":"expired"}`),
		fact(12, "confirmed", `{"fact_type":"finding_candidate","summary":"no","validation_state":"rejected"}`),
		fact(13, "confirmed", `{"fact_type":"checkpoint","summary":"bookkeeping"}`),
		fact(14, db.StateOrigin, `{"summary":"root"}`),
		fact(15, "dismissed", `{"fact_type":"claim","summary":"denied"}`),
		fact(16, "confirmed", `{"fact_type":"claim","summary":"stale","valid_until":"2000-01-01T00:00:00Z"}`),
		{ID: 17, Kind: db.KindFinding, State: "dismissed"},
	}
	for _, n := range rejected {
		if err := ts.validateIntentAnchor(n); err == nil {
			t.Fatalf("anchor %d (%s) was accepted", n.ID, n.FactType())
		}
	}
	inheritedSecret := &db.Node{ID: 20, Kind: db.KindFact, State: "confirmed", Inherited: true,
		Payload: []byte(`{"fact_type":"claim","summary":"token","sensitivity":"token"}`)}
	if err := ts.validateIntentAnchor(inheritedSecret); err == nil {
		t.Fatal("non-inheritable source anchor accepted")
	}
}

func TestAddIntentAcceptsTentativeParentsButNotCheckpoint(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("intent anchors", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")
	parent := func(payload map[string]any) json.RawMessage {
		id, err := store.AddNode(db.KindFact, payload, 0, "confirmed", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		return json.RawMessage(itoa(id))
	}
	hyp := parent(map[string]any{"fact_type": db.FactTypeHypothesis, "summary": "open hypothesis", "state": "open"})
	if _, err := ts.addOneIntent(intentItem{Summary: "validate hypothesis", ParentIDs: []json.RawMessage{hyp}}); err != nil {
		t.Fatalf("open hypothesis parent rejected: %v", err)
	}
	candidate := parent(map[string]any{"fact_type": db.FactTypeFindingCandidate, "summary": "pending candidate", "validation_state": "pending"})
	if _, err := ts.addOneIntent(intentItem{Summary: "validate candidate", ParentIDs: []json.RawMessage{candidate}}); err != nil {
		t.Fatalf("pending candidate parent rejected: %v", err)
	}
	checkpoint := parent(db.CheckpointPayload(
		"bookkeeping", "path_stage", "fixture", "validation", "run-a", "completed",
		0, 0, nil, nil, nil, nil, nil, nil, db.RouteBudgetUsed{ToolCalls: 1},
	))
	if _, err := ts.addOneIntent(intentItem{Summary: "bad parent", ParentIDs: []json.RawMessage{checkpoint}}); err == nil {
		t.Fatal("checkpoint was accepted as intent parent")
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
		Summary: "continue with a different object", ContinuationOf: rawID(first), Phase: "exploitation",
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
	if _, err := ts.addOneIntent(intentItem{Summary: "parallel branch", ContinuationOf: rawID(first)}); err == nil {
		t.Fatal("parallel continuation of the same route was accepted")
	}

	// 数值预算不再阻断接续：即使 checkpoint 记录了"预算耗尽"的历史用量，接续也
	// 只受【两振挂起】约束（本 fixture 的两次运行都产出了高价值进展 → 不挂起）。
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
	// 该路线第二次运行确实产出了高价值进展 → 不满足两振挂起条件。
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeClaim, "summary": "object authorization bypassed",
		"confidence": "observed", "progress_event": "validated_weakness",
	}, 5, "confirmed", "worker", nil, second, db.RelYields); err != nil {
		t.Fatal(err)
	}
	third, err := ts.addOneIntent(intentItem{Summary: "keep going", ContinuationOf: rawID(second), Effort: db.EffortDeep})
	if err != nil {
		t.Fatalf("continuation must not be blocked by the legacy budget: %v", err)
	}
	thirdNode, err := store.GetNode(third)
	if err != nil || thirdNode == nil {
		t.Fatalf("third intent=%+v err=%v", thirdNode, err)
	}
	if got := db.ParseIntentRoute(thirdNode).Effort; got != db.EffortDeep {
		t.Fatalf("continuation effort=%q want deep", got)
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

// A continuation that omits effort inherits the source route's tier: a deep chain
// must not be silently demoted to standard by a bare continuation.
func TestAddIntentContinuationInheritsEffort(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("effort inheritance", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")
	first, err := ts.addOneIntent(intentItem{Summary: "deep chain", Effort: db.EffortDeep})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(first, "exhausted"); err != nil {
		t.Fatal(err)
	}
	// Every run of this fixture must be productive, or the two-dry-run rule (a
	// separate concern, covered in route_health_test.go) would reject the next one.
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeClaim, "summary": "stage progress",
		"progress_event": "validated_weakness",
	}, 5, "confirmed", "worker", nil, first, db.RelYields); err != nil {
		t.Fatal(err)
	}
	second, err := ts.addOneIntent(intentItem{Summary: "bare continuation", ContinuationOf: rawID(first)})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(second)
	if err != nil || node == nil {
		t.Fatalf("second intent: %v", err)
	}
	if got := db.ParseIntentRoute(node).Effort; got != db.EffortDeep {
		t.Fatalf("bare continuation effort=%q want deep (inherited)", got)
	}
	// An explicit tier still wins over the inherited one.
	if err := store.SetIntentState(second, "exhausted"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeClaim, "summary": "stage two progress",
		"progress_event": "objective_milestone",
	}, 5, "confirmed", "worker", nil, second, db.RelYields); err != nil {
		t.Fatal(err)
	}
	third, err := ts.addOneIntent(intentItem{Summary: "explicit probe", ContinuationOf: rawID(second), Effort: db.EffortProbe})
	if err != nil {
		t.Fatal(err)
	}
	node, err = store.GetNode(third)
	if err != nil || node == nil {
		t.Fatalf("third intent: %v", err)
	}
	if got := db.ParseIntentRoute(node).Effort; got != db.EffortProbe {
		t.Fatalf("explicit continuation effort=%q want probe", got)
	}
}

// 数值预算已废弃、永不强制执行，因此也永不拒绝：负数被吞成 0（不限），超限旧值
// 被原样落库做统计。add_intent 的预算校验报错率必须是 0%。
func TestAddIntentNeverRejectsLegacyBudget(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("legacy budget lenience", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	negative, err := ts.addOneIntent(intentItem{Summary: "negative legacy budget",
		Budget: routeBudgetItem{MaxToolCalls: -5, MaxInputTokens: -1, MaxWallSeconds: -30}})
	if err != nil {
		t.Fatalf("negative legacy budget rejected: %v", err)
	}
	if r := db.ParseIntentRoute(nodeByID(t, store, negative)); !r.Budget.Empty() {
		t.Fatalf("negative legacy budget not normalized to unlimited: %+v", r.Budget)
	}

	huge, err := ts.addOneIntent(intentItem{Summary: "oversized legacy budget",
		Budget: routeBudgetItem{MaxToolCalls: 999999, MaxInputTokens: 999_999_999, MaxWallSeconds: 999 * 24 * 3600}})
	if err != nil {
		t.Fatalf("oversized legacy budget rejected: %v", err)
	}
	if r := db.ParseIntentRoute(nodeByID(t, store, huge)); r.Budget.MaxToolCalls != 999999 {
		t.Fatalf("oversized legacy budget not persisted for statistics: %+v", r.Budget)
	}
}

// A worker that omits intent_id still writes a fully bound fact: the owner intent
// is inferred, route_id is copied, the intent→fact yields edge is created, and the
// latest tool_result is attached as the source activity.
func TestRecordFactAutoBindsWorkerIntent(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("auto lineage", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "worker")
	intentID, err := ts.addOneIntent(intentItem{Summary: "probe redis"})
	if err != nil {
		t.Fatal(err)
	}
	ts.SetOwnerNode(intentID)
	actID, err := store.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "worker", Kind: "tool_result", Tool: "Bash",
		Summary: "redis-cli INFO -> no auth",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := callWrite(t, ts.recordFact(), `{"summary":"port 6379 unauthenticated"}`)
	if res.IsError {
		t.Fatalf("record_fact rejected: %s", res.Flatten())
	}
	factID := parseRecordedID(t, res.Flatten())
	node, err := store.GetNode(factID)
	if err != nil || node == nil {
		t.Fatalf("fact %d: %+v err=%v", factID, node, err)
	}
	payload := db.ParseFactPayload(node.Payload)
	if payload.IntentID != intentID {
		t.Fatalf("intent_id=%d want %d", payload.IntentID, intentID)
	}
	if payload.RouteID != intentID {
		t.Fatalf("route_id=%d want %d", payload.RouteID, intentID)
	}
	if len(payload.SourceActivityIDs) != 1 || payload.SourceActivityIDs[0] != actID {
		t.Fatalf("source_activity_ids=%v want [%d]", payload.SourceActivityIDs, actID)
	}
	edges, err := store.EdgesTouching([]int64{factID})
	if err != nil {
		t.Fatal(err)
	}
	linked := false
	for _, e := range edges {
		if e.From == intentID && e.Rel == db.RelYields && e.To == factID {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("intent→fact yields edge missing: %+v", edges)
	}
}

// artifact: references written in either absolute spelling (Windows drive or the
// WSL /mnt/<drive> form) collapse to the root-relative path; paths outside every
// artifact root stay absolute and are rejected.
func TestArtifactPathNormalization(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("artifact paths", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "worker")
	intentID, err := ts.addOneIntent(intentItem{Summary: "artifact fixture"})
	if err != nil {
		t.Fatal(err)
	}
	ts.SetOwnerNode(intentID)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "i14846"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "i14846", "out.txt")
	if err := os.WriteFile(file, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts.SetArtifactRoots(root)
	tool := ts.recordFact()

	check := func(ref, want string) {
		t.Helper()
		input, _ := json.Marshal(map[string]any{"summary": "artifact form", "evidence_refs": []string{ref}})
		res := callWrite(t, tool, string(input))
		if res.IsError {
			t.Fatalf("%s rejected: %s", ref, res.Flatten())
		}
		id := parseRecordedID(t, res.Flatten())
		node, err := store.GetNode(id)
		if err != nil || node == nil {
			t.Fatalf("fact %d: %+v err=%v", id, node, err)
		}
		refs := db.ParseFactPayload(node.Payload).EvidenceRefs
		if len(refs) != 1 || refs[0] != "artifact:"+want {
			t.Fatalf("%s stored as %v want artifact:%s", ref, refs, want)
		}
	}
	check("artifact:"+file, "i14846/out.txt")
	if len(file) > 2 && file[1] == ':' {
		check("artifact:"+artifactCompareKey(file), "i14846/out.txt")
	}
	outside := filepath.Join(t.TempDir(), "win.ini")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideInput, _ := json.Marshal(map[string]any{"summary": "outside", "evidence_refs": []string{"artifact:" + outside}})
	if res := callWrite(t, tool, string(outsideInput)); !res.IsError {
		t.Fatalf("artifact outside the roots accepted: %s", res.Flatten())
	}
}

// add_intent accepts a stringified intents array, prefixed ids ("#12"), and a
// checkpoint echoed into parent_ids during continuation without failing.
func TestAddIntentNormalizesInputAndCheckpointParent(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("intent input norm", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	parent, err := store.AddNode(db.KindFact, map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "seen", "progress_event": "validated_weakness",
	}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	tool := ts.addIntent()
	first := callWrite(t, tool, `{"intents":"[{\"summary\":\"from parent\",\"parent_ids\":[\"#`+itoa(parent)+`\"]}]"}`)
	if first.IsError {
		t.Fatalf("stringified intents rejected: %s", first.Flatten())
	}
	var out struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.Unmarshal([]byte(first.Flatten()), &out); err != nil || len(out.IDs) != 1 || out.IDs[0] <= 0 {
		t.Fatalf("ids decode: %v %s", err, first.Flatten())
	}
	firstID := out.IDs[0]
	checkpoint, err := store.AddNodeLinked(db.KindFact, db.CheckpointPayload(
		"stage done", "path_stage", "route", "validation", "run-1", "completed",
		firstID, firstID, nil, nil, nil, nil, nil, nil, db.RouteBudgetUsed{ToolCalls: 2},
	), 0, "confirmed", "system", nil, firstID, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(firstID, "done"); err != nil {
		t.Fatal(err)
	}
	second := callWrite(t, tool, `{"summary":"continue","continuation_of":`+itoa(firstID)+`,"parent_ids":["#`+itoa(checkpoint)+`"]}`)
	if second.IsError {
		t.Fatalf("checkpoint parent in continuation rejected: %s", second.Flatten())
	}
}

// A continuation id sent as a display string ("#14825") must parse at the tool
// boundary and inherit the source route rather than failing the whole intent.
func TestAddIntentContinuationAcceptsStringID(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("string continuation", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	first, err := ts.addOneIntent(intentItem{Summary: "first lane"})
	if err != nil {
		t.Fatal(err)
	}
	firstNode, err := store.GetNode(first)
	if err != nil || firstNode == nil {
		t.Fatalf("first intent: %v", err)
	}
	wantRoute := db.ParseIntentRoute(firstNode).RouteID
	if err := store.SetIntentState(first, "done"); err != nil {
		t.Fatal(err)
	}

	res := callWrite(t, ts.addIntent(), `{"summary":"string continuation","continuation_of":"#`+itoa(first)+`"}`)
	if res.IsError {
		t.Fatalf("string continuation id rejected: %s", res.Flatten())
	}
	nextID, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(res.Flatten(), "intent created: ")), 10, 64)
	if err != nil || nextID <= 0 {
		t.Fatalf("continuation id decode: %v %q", err, res.Flatten())
	}
	next, err := store.GetNode(nextID)
	if err != nil || next == nil {
		t.Fatalf("continuation intent: %v", err)
	}
	if got := db.ParseIntentRoute(next).RouteID; got != wantRoute {
		t.Fatalf("continuation route=%d want %d", got, wantRoute)
	}
}
