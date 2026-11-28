package agent

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// suspendFixture builds a pure-autonomous route with two consecutive dry runs,
// which is exactly the state the two-dry-run rule blocks.
func suspendFixture(t *testing.T) (*ToolSet, *db.ExplorationStore, int64, int64) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("two dry runs", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	first, err := ts.addOneIntent(intentItem{Summary: "lane A stage one"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(first)
	if err != nil || node == nil {
		t.Fatalf("first intent: %v", err)
	}
	routeID := db.ParseIntentRoute(node).RouteID
	if err := store.SetIntentState(first, "exhausted"); err != nil {
		t.Fatal(err)
	}
	second, err := ts.addOneIntent(intentItem{Summary: "lane A stage two", ContinuationOf: rawID(first)})
	if err != nil {
		t.Fatalf("second run should be allowed (only one dry run so far): %v", err)
	}
	if err := store.SetIntentState(second, "exhausted"); err != nil {
		t.Fatal(err)
	}
	return ts, store, routeID, second
}

// Two consecutive dry runs on a pure-autonomous route must suspend a continuation
// that carries no outside evidence, with an actionable message (switch lanes /
// cite cross-route evidence / let a human resume it).
func TestTwoDryRunsSuspendAutonomousContinuation(t *testing.T) {
	ts, store, routeID, second := suspendFixture(t)

	health, err := store.RouteHealth(routeID)
	if err != nil {
		t.Fatal(err)
	}
	if health.ConsecutiveDryRuns != 2 || health.TotalRuns != 2 || health.HumanInvolved {
		t.Fatalf("health=%+v want 2 dry of 2 runs, not human", health)
	}

	_, err = ts.addOneIntent(intentItem{Summary: "lane A stage three", ContinuationOf: rawID(second)})
	if err == nil {
		t.Fatal("continuation without outside evidence was accepted despite two dry runs")
	}
	msg := err.Error()
	for _, want := range []string{"跑干", "parent_ids", "机理不同"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("suspension message missing %q: %s", want, msg)
		}
	}
}

// Citing a fact discovered on ANOTHER route re-activates the route: that is the
// credential-propagation path (a new domain-admin password justifies a new run).
func TestTwoDryRunsReactivatedByCrossRouteEvidence(t *testing.T) {
	ts, store, routeID, second := suspendFixture(t)

	// A different route discovers credentials.
	otherID, err := ts.addOneIntent(intentItem{Summary: "lane B credential hunt"})
	if err != nil {
		t.Fatal(err)
	}
	if otherNode, err := store.GetNode(otherID); err != nil || otherNode == nil {
		t.Fatalf("other intent: %v", err)
	} else if db.ParseIntentRoute(otherNode).RouteID == routeID {
		t.Fatal("fixture created the same route twice")
	}
	cred, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeClaim, "summary": "domain admin credential recovered",
		"progress_event": "credential_obtained",
	}, 5, "confirmed", "worker", nil, otherID, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ts.addOneIntent(intentItem{
		Summary: "lane A stage three with the new credential", ContinuationOf: rawID(second),
		ParentIDs: rawIDs(cred), Effort: db.EffortDeep,
	})
	if err != nil {
		t.Fatalf("cross-route evidence should re-activate the route: %v", err)
	}
	node, err := store.GetNode(next)
	if err != nil || node == nil {
		t.Fatalf("reactivated intent: %v", err)
	}
	if got := db.ParseIntentRoute(node).Effort; got != db.EffortDeep {
		t.Fatalf("effort=%q want deep", got)
	}
}

// A human-owned route is exempt unconditionally: no autonomous rule may suspend a
// line a person is watching.
func TestTwoDryRunsHumanRouteExempt(t *testing.T) {
	ts, store, routeID, second := suspendFixture(t)

	// A human message on one of the route's intents makes it human-involved.
	if _, err := store.AppendActivity(db.Activity{NodeID: &second, Worker: "user",
		Kind: "user", Summary: "continue, I am watching this lane"}); err != nil {
		t.Fatal(err)
	}
	health, err := store.RouteHealth(routeID)
	if err != nil {
		t.Fatal(err)
	}
	if !health.HumanInvolved {
		t.Fatal("human message did not mark the route human_involved")
	}
	if _, err := ts.addOneIntent(intentItem{Summary: "lane A stage three", ContinuationOf: rawID(second)}); err != nil {
		t.Fatalf("human route must be exempt from suspension: %v", err)
	}
}

// Ordinary outside facts on an unrelated asset do not unlock a suspended route;
// an outside fact on the route's own target asset does.
func TestTwoDryRunsNeedsRelevantOutsideEvidence(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("relevant outside evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	as := d.Assets()
	shared, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://relevant-shared.example.test/", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://relevant-other.example.net/", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "planner")
	ts.SetAssetStore(as, d.Companies())
	ts.SetTaskID(task.ID)

	first, err := ts.addOneIntent(intentItem{Summary: "lane A stage one", AssetIDs: rawIDs(shared)})
	if err != nil {
		t.Fatal(err)
	}
	routeID := db.ParseIntentRoute(nodeByID(t, store, first)).RouteID
	if err := store.SetIntentState(first, "exhausted"); err != nil {
		t.Fatal(err)
	}
	second, err := ts.addOneIntent(intentItem{Summary: "lane A stage two", ContinuationOf: rawID(first), AssetIDs: rawIDs(shared)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(second, "exhausted"); err != nil {
		t.Fatal(err)
	}
	health, err := store.RouteHealth(routeID)
	if err != nil {
		t.Fatal(err)
	}
	if health.ConsecutiveDryRuns < 2 {
		t.Fatalf("fixture not dry: %+v", health)
	}

	other, err := ts.addOneIntent(intentItem{Summary: "lane B unrelated discovery"})
	if err != nil {
		t.Fatal(err)
	}
	unrelatedFact, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "other host header",
	}, 5, "confirmed", "worker", []int64{unrelated}, other, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.addOneIntent(intentItem{
		Summary: "lane A retry without relevant evidence", ContinuationOf: rawID(second), ParentIDs: rawIDs(unrelatedFact),
	}); err == nil {
		t.Fatal("unrelated outside fact unlocked the suspended route")
	}

	sameAssetFact, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "shared target exposes a new path",
	}, 5, "confirmed", "worker", []int64{shared}, other, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.addOneIntent(intentItem{
		Summary: "lane A continues on shared-target evidence", ContinuationOf: rawID(second), ParentIDs: rawIDs(sameAssetFact),
	}); err != nil {
		t.Fatalf("same-asset outside fact should unlock the suspended route: %v", err)
	}
}

// parked_stagnant: four productive runs without a finding park the route while
// untested target assets remain; once the backlog is empty, or a human owns the
// route, continuations are allowed again.
func TestParkedStagnantBlocksWhileUntestedAssetsRemain(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("parked route", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	as := d.Assets()
	if _, err := as.AddAgentScope(task.ID, "keyword", "parked-target", "fixture", "agent"); err != nil {
		t.Fatal(err)
	}
	shared, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://parked-target-one.example.test/", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://parked-target-two.example.test/", TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "planner")
	ts.SetAssetStore(as, d.Companies())
	ts.SetTaskID(task.ID)

	first, err := ts.addOneIntent(intentItem{Summary: "stage one", AssetIDs: rawIDs(shared)})
	if err != nil {
		t.Fatal(err)
	}
	routeID := db.ParseIntentRoute(nodeByID(t, store, first)).RouteID
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeClaim, "summary": "token one", "progress_event": "credential_obtained",
	}, 5, "confirmed", "worker", nil, first, db.RelYields); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(first, "done"); err != nil {
		t.Fatal(err)
	}
	last := first
	for range 3 {
		next, err := ts.addOneIntent(intentItem{Summary: "credential stage", ContinuationOf: rawID(last), AssetIDs: rawIDs(shared)})
		if err != nil {
			t.Fatalf("productive continuation rejected before parking: %v", err)
		}
		if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
			"fact_type": db.FactTypeClaim, "summary": "token", "progress_event": "credential_obtained",
		}, 5, "confirmed", "worker", nil, next, db.RelYields); err != nil {
			t.Fatal(err)
		}
		if err := store.SetIntentState(next, "done"); err != nil {
			t.Fatal(err)
		}
		last = next
	}
	health, err := store.RouteHealth(routeID)
	if err != nil {
		t.Fatal(err)
	}
	if health.TotalRuns != 4 || health.RunsSinceLastFinding != 4 || health.ConsecutiveDryRuns != 0 {
		t.Fatalf("fixture health=%+v want 4 runs / 4 since finding / 0 dry", health)
	}
	if health.AutonomyStatus != db.RouteAutonomyParkedStagnant {
		t.Fatalf("autonomy=%q want parked_stagnant", health.AutonomyStatus)
	}
	_, err = ts.addOneIntent(intentItem{Summary: "fifth run", ContinuationOf: rawID(last)})
	if err == nil || !strings.Contains(err.Error(), "parked_stagnant") {
		t.Fatalf("untested backlog did not park the route: %v", err)
	}

	// Cover every target asset with an ordinary fact: the backlog is empty, so the
	// stale route may continue. The coverage query may expand a URL into separate
	// host/service rows, so anchor exactly the rows it reports as untested.
	backlog, total, err := as.ListUntestedAssetsWithSources(task.ID, "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total < 2 {
		t.Fatalf("fixture backlog=%d want at least 2", total)
	}
	for _, asset := range backlog {
		if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
			"fact_type": db.FactTypeObservation, "summary": "target touched",
		}, 5, "confirmed", "worker", []int64{asset.ID}, last, db.RelYields); err != nil {
			t.Fatal(err)
		}
	}
	fifth, err := ts.addOneIntent(intentItem{Summary: "fifth run after coverage", ContinuationOf: rawID(last)})
	if err != nil {
		t.Fatalf("empty backlog should release the parked route: %v", err)
	}
	if err := store.SetIntentState(fifth, "exhausted"); err != nil {
		t.Fatal(err)
	}

	// A new untested target appears, but a human now owns the route: exempt.
	if _, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://parked-target-three.example.test/", TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(db.Activity{NodeID: &fifth, Worker: "user",
		Kind: "user", Summary: "keep this lane, I am watching"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.addOneIntent(intentItem{Summary: "sixth run human watched", ContinuationOf: rawID(fifth)}); err != nil {
		t.Fatalf("human-owned route must bypass parked_stagnant: %v", err)
	}
}

// rawID renders one id in the json.RawMessage form intentItem uses.
func rawID(id int64) json.RawMessage {
	return json.RawMessage(strconv.FormatInt(id, 10))
}

// rawIDs converts explicit node ids into the json.RawMessage form intentItem uses.
func rawIDs(ids ...int64) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		out = append(out, json.RawMessage(strconv.FormatInt(id, 10)))
	}
	return out
}

// MainAgent acts on behalf of the human (ToolSet worker == "human"): its intents
// are human-pushed and must be exempt from the autonomous suspension even when the
// route itself has no human marker yet.
func TestTwoDryRunsMainAgentExempt(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("mainagent push", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	humanTS := NewToolSet(store, "human")

	// The route must be purely autonomous at the DB level (planner origin, no human
	// marker), so the fixture builds it with the planner tool set.
	plannerTS := NewToolSet(store, "planner")
	first, err := plannerTS.addOneIntent(intentItem{Summary: "planner lane stage one"})
	if err != nil {
		t.Fatal(err)
	}
	routeID := db.ParseIntentRoute(nodeByID(t, store, first)).RouteID
	if err := store.SetIntentState(first, "exhausted"); err != nil {
		t.Fatal(err)
	}
	second, err := plannerTS.addOneIntent(intentItem{Summary: "planner lane stage two", ContinuationOf: rawID(first)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(second, "exhausted"); err != nil {
		t.Fatal(err)
	}
	health, err := store.RouteHealth(routeID)
	if err != nil {
		t.Fatal(err)
	}
	if health.ConsecutiveDryRuns < 2 {
		t.Fatalf("fixture not dry: %+v", health)
	}
	if _, err := plannerTS.addOneIntent(intentItem{Summary: "planner retry", ContinuationOf: rawID(second)}); err == nil {
		t.Fatal("fixture: planner continuation should have been suspended")
	}
	if _, err := humanTS.addOneIntent(intentItem{Summary: "mainagent retry", ContinuationOf: rawID(second)}); err != nil {
		t.Fatalf("MainAgent (human) must be exempt from the suspension: %v", err)
	}
}
