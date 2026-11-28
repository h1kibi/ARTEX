package db

import (
	"testing"
	"time"
)

// routeHealthFixture builds a route with N finished intents and controls whether
// each run produced a finding/high-value fact.
func TestRouteHealthDryRuns(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("route health", "dry run accounting", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)

	// Route A: run 1 productive (high-value fact), runs 2 and 3 dry.
	first, _, err := store.AddIntentWithEdges(map[string]any{"summary": "run one", "route_id": int64(1)}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	routeA := ParseIntentRoute(nodeByID(t, store, first)).RouteID
	if _, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeClaim, "summary": "credential obtained",
		"progress_event": "credential_obtained",
	}, 5, "confirmed", "worker", nil, first, RelYields); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(first, "done"); err != nil {
		t.Fatal(err)
	}
	second, _, err := store.AddIntentWithEdges(map[string]any{"summary": "run two"}, 5, nil, "planner", routeA, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Run 2: only an ordinary observation → dry.
	if _, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeObservation, "summary": "admin page returns 200",
	}, 5, "confirmed", "worker", nil, second, RelYields); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(second, "done"); err != nil {
		t.Fatal(err)
	}
	third, _, err := store.AddIntentWithEdges(map[string]any{"summary": "run three"}, 5, nil, "planner", routeA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(third, "exhausted"); err != nil {
		t.Fatal(err)
	}
	// A still-open run is not counted.
	if _, _, err := store.AddIntentWithEdges(map[string]any{"summary": "still open"}, 5, nil, "planner", routeA, nil); err != nil {
		t.Fatal(err)
	}

	health, err := store.RouteHealth(routeA)
	if err != nil {
		t.Fatal(err)
	}
	if health.TotalRuns != 3 {
		t.Fatalf("total_runs=%d want 3", health.TotalRuns)
	}
	if health.ConsecutiveDryRuns != 2 {
		t.Fatalf("consecutive_dry_runs=%d want 2", health.ConsecutiveDryRuns)
	}
	if health.HumanInvolved {
		t.Fatal("planner route reported as human-involved")
	}

	// A human-origin intent on the same route flips human_involved, which is what
	// exempts it from the autonomous suspension.
	if _, _, err := store.AddIntentWithEdges(map[string]any{"summary": "human nudge"}, 9, nil, "human", routeA, nil); err != nil {
		t.Fatal(err)
	}
	if health, err = store.RouteHealth(routeA); err != nil {
		t.Fatal(err)
	} else if !health.HumanInvolved {
		t.Fatal("origin=human intent did not mark the route human_involved")
	}
}

// RunsSinceLastFinding counts finished runs after the newest finding run, and
// worker time drives the parked_stagnant label once no finding has appeared.
func TestRouteHealthRunsSinceFindingAndAutonomy(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("route autonomy", "parked accounting", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)

	first, _, err := store.AddIntentWithEdges(map[string]any{"summary": "finding run", "route_id": int64(1)}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	routeID := ParseIntentRoute(nodeByID(t, store, first)).RouteID
	if _, err := store.AddNodeLinked(KindFinding, map[string]any{"summary": "confirmed RCE"}, 5, "confirmed", "worker", nil, first, RelYields); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(first, "done"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		id, _, err := store.AddIntentWithEdges(map[string]any{"summary": "credential run"}, 5, nil, "planner", routeID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AddNodeLinked(KindFact, map[string]any{
			"fact_type": FactTypeClaim, "summary": "token obtained", "progress_event": "credential_obtained",
		}, 5, "confirmed", "worker", nil, id, RelYields); err != nil {
			t.Fatal(err)
		}
		if err := store.AddIntentWorkTime(id, 1200*time.Second); err != nil {
			t.Fatal(err)
		}
		if err := store.SetIntentState(id, "done"); err != nil {
			t.Fatal(err)
		}
	}
	health, err := store.RouteHealth(routeID)
	if err != nil {
		t.Fatal(err)
	}
	if health.TotalRuns != 3 || health.RunsSinceLastFinding != 2 {
		t.Fatalf("health=%+v want 3 runs / 2 since finding", health)
	}
	if health.ConsecutiveDryRuns != 0 {
		t.Fatalf("credential runs counted as dry: %+v", health)
	}
	if health.WorkerSeconds != 2400 {
		t.Fatalf("worker_seconds=%d want 2400", health.WorkerSeconds)
	}
	if health.AutonomyStatus != RouteAutonomyParkedStagnant {
		t.Fatalf("autonomy=%q want parked_stagnant", health.AutonomyStatus)
	}
	// A human-owned route overrides the autonomous label.
	if _, _, err := store.AddIntentWithEdges(map[string]any{"summary": "human nudge"}, 5, nil, "human", routeID, nil); err != nil {
		t.Fatal(err)
	}
	if health, err = store.RouteHealth(routeID); err != nil {
		t.Fatal(err)
	} else if health.AutonomyStatus != RouteAutonomyActive {
		t.Fatalf("human route autonomy=%q want active", health.AutonomyStatus)
	}
}

// Only external evidence that is relevant (credential/privilege, a finding, or a
// fact on a shared target asset) unlocks a route. Ordinary observations of
// unrelated assets do not.
func TestHasRelevantOutsideEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("outside evidence", "relevance", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	assets := d.Assets()
	shared, err := assets.UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://shared-target.example.test/", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := assets.UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://other-target.example.net/", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}

	routeIntent, _, err := store.AddIntentWithEdges(map[string]any{"summary": "route A"}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	routeID := ParseIntentRoute(nodeByID(t, store, routeIntent)).RouteID
	otherIntent, _, err := store.AddIntentWithEdges(map[string]any{"summary": "route B"}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Own-route fact never counts, even on the shared asset.
	own, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeObservation, "summary": "own observation",
	}, 5, "confirmed", "worker", []int64{shared}, routeIntent, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasRelevantOutsideEvidence(routeID, []int64{shared}, []int64{own}); err != nil || ok {
		t.Fatalf("own-route fact counted as outside evidence: ok=%v err=%v", ok, err)
	}

	// Unrelated asset's ordinary observation is external but not relevant.
	plain, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeObservation, "summary": "unrelated host header",
	}, 5, "confirmed", "worker", []int64{unrelated}, otherIntent, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasRelevantOutsideEvidence(routeID, []int64{shared}, []int64{plain}); err != nil || ok {
		t.Fatalf("unrelated fact unlocked the route: ok=%v err=%v", ok, err)
	}

	// A fact on the shared target asset is relevant.
	sameAsset, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeObservation, "summary": "same target exposes new path",
	}, 5, "confirmed", "worker", []int64{shared}, otherIntent, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasRelevantOutsideEvidence(routeID, []int64{shared}, []int64{sameAsset}); err != nil || !ok {
		t.Fatalf("same-asset outside fact did not unlock: ok=%v err=%v", ok, err)
	}

	// Credential material is relevant regardless of anchors.
	cred, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeClaim, "summary": "domain admin password",
		"sensitivity": "credential",
	}, 5, "confirmed", "worker", nil, otherIntent, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasRelevantOutsideEvidence(routeID, []int64{shared}, []int64{cred}); err != nil || !ok {
		t.Fatalf("credential fact did not unlock: ok=%v err=%v", ok, err)
	}

	// Checkpoint bookkeeping never unlocks.
	checkpoint, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeCheckpoint, "summary": "checkpoint",
	}, 5, "confirmed", "worker", []int64{shared}, otherIntent, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasRelevantOutsideEvidence(routeID, []int64{shared}, []int64{checkpoint}); err != nil || ok {
		t.Fatalf("checkpoint unlocked the route: ok=%v err=%v", ok, err)
	}
}

func TestRouteHealthNewEvidenceReactivation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("route reactivation", "outside evidence", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)

	// Route A: one dry run.
	a1, _, err := store.AddIntentWithEdges(map[string]any{"summary": "lane A run"}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	routeA := ParseIntentRoute(nodeByID(t, store, a1)).RouteID
	if err := store.SetIntentState(a1, "exhausted"); err != nil {
		t.Fatal(err)
	}
	// Route B: a run that found a credential.
	b1, _, err := store.AddIntentWithEdges(map[string]any{"summary": "lane B run"}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeClaim, "summary": "domain admin creds",
		"progress_event": "credential_obtained",
	}, 5, "confirmed", "worker", nil, b1, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(b1, "done"); err != nil {
		t.Fatal(err)
	}

	// A fact of route A itself is not outside evidence.
	aFact, err := store.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeObservation, "summary": "own route observation",
	}, 5, "confirmed", "worker", nil, a1, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if outside, err := store.NodesOutsideRoute(routeA, []int64{aFact}); err != nil || outside {
		t.Fatalf("own route evidence counted as outside: outside=%v err=%v", outside, err)
	}
	if outside, err := store.NodesOutsideRoute(routeA, []int64{cred}); err != nil || !outside {
		t.Fatalf("cross-route credential not detected: outside=%v err=%v", outside, err)
	}
	// Unknown ids are not evidence at all (no fabrication loophole via 0/missing).
	if outside, err := store.NodesOutsideRoute(routeA, []int64{999999}); err != nil || outside {
		t.Fatalf("missing node counted as evidence: outside=%v err=%v", outside, err)
	}
}

func nodeByID(t *testing.T, store *ExplorationStore, id int64) *Node {
	t.Helper()
	n, err := store.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("node %d: %v", id, err)
	}
	return n
}

// A brand-new human-owned route has no finished run yet; it must still report
// human_involved from its very first (still running) intent, or the first run
// loses human protection entirely.
func TestRouteHealthHumanWhileFirstRunRunning(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("route health first run", "human protection", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)

	intentID, err := store.AddIntent(map[string]any{
		"summary": "human direct push", "objective": "confirm the injection",
	}, 9, nil, "human")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	routeID := ParseIntentRoute(nodeByID(t, store, intentID)).RouteID

	health, err := store.RouteHealth(routeID)
	if err != nil {
		t.Fatal(err)
	}
	if health.TotalRuns != 0 || health.ConsecutiveDryRuns != 0 {
		t.Fatalf("health=%+v want 0 runs / 0 dry (nothing finished yet)", health)
	}
	if !health.HumanInvolved {
		t.Fatal("a human-origin route lost human protection on its first running run")
	}
	// The same must hold when aggregated in bulk (graph_overview / routes API path).
	all, err := store.RouteHealthAll()
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := all[routeID]; !ok || !h.HumanInvolved {
		t.Fatalf("RouteHealthAll dropped the running-only human route: %+v", all)
	}
}

// 跨任务证据是"本路线之外"最强的一种：关联源任务继承来的凭据必须能重激活挂起路线。
func TestNodesOutsideRouteAcceptsCrossTaskEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	source, err := d.CreateTask("evidence source", "credential origin", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(source.ID)
	target, err := d.CreateTask("evidence target", "stale route", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(target.ID)
	srcStore := d.Exploration(source.ExplorationID)
	tgtStore := d.Exploration(target.ExplorationID)

	srcIntent, err := srcStore.AddIntent(map[string]any{"summary": "harvest creds"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := srcStore.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeClaim, "summary": "domain admin credential",
		"progress_event": "credential_obtained",
	}, 5, "confirmed", "worker", nil, srcIntent, RelYields)
	if err != nil {
		t.Fatal(err)
	}

	routeIntent, err := tgtStore.AddIntent(map[string]any{"summary": "stale lane"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	routeID := ParseIntentRoute(nodeByID(t, tgtStore, routeIntent)).RouteID

	// The credential lives in a DIFFERENT exploration; it is still valid outside
	// evidence for the suspended route (add_intent validated it via
	// GetNodeWithSources before asking).
	outside, err := tgtStore.NodesOutsideRoute(routeID, []int64{cred})
	if err != nil {
		t.Fatalf("cross-task evidence check failed: %v", err)
	}
	if !outside {
		t.Fatal("cross-task credential was not accepted as outside evidence")
	}
	// A node of the route itself never counts as outside evidence.
	own, err := tgtStore.AddNodeLinked(KindFact, map[string]any{
		"fact_type": FactTypeObservation, "summary": "own observation",
	}, 5, "confirmed", "worker", nil, routeIntent, RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if outside, err := tgtStore.NodesOutsideRoute(routeID, []int64{own}); err != nil || outside {
		t.Fatalf("own-route fact counted as outside evidence: outside=%v err=%v", outside, err)
	}
}
