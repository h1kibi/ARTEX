package db

import "testing"

func TestFactsYieldedExcludesCheckpoint(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("yield facts", "exclude checkpoints", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "yield fixture"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	factID, err := store.AddNodeLinked(KindFact, map[string]any{"fact_type": FactTypeClaim, "summary": "real yield"}, 0, "confirmed", "worker", nil, intentID, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(KindFact, CheckpointPayload(
		"bookkeeping", "path_stage", "yield fixture", "validation", "run-y", "completed",
		intentID, intentID, nil, nil, nil, nil, nil, nil, RouteBudgetUsed{ToolCalls: 1},
	), 0, "confirmed", "system", nil, intentID, RelYields); err != nil {
		t.Fatal(err)
	}
	got, err := store.FactsYielded(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != factID {
		t.Fatalf("FactsYielded=%v want only #%d", got, factID)
	}
}

func TestRouteIDsForAssetIncludesImplicitRouteID(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("asset route", "implicit route id", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	assetID, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: "legacy-route.example"})
	if err != nil {
		t.Fatal(err)
	}
	// Legacy/non-planner intent without an explicit payload.route_id.
	intentID, err := store.AddNode(KindIntent, map[string]any{"summary": "legacy intent"}, 5, "open", "seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Anchor(intentID, assetID); err != nil {
		t.Fatal(err)
	}
	ids, err := store.RouteIDsForAsset(assetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != intentID {
		t.Fatalf("RouteIDsForAsset=%v want [%d]", ids, intentID)
	}
	active, err := store.ActiveIntentForRoute(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.ID != intentID {
		t.Fatalf("ActiveIntentForRoute=%+v want #%d", active, intentID)
	}
}
