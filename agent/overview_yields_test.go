package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// graph_overview must split yield_count into high-value vs observation counts
// while keeping the legacy total (frontend + old prompts read it), and expose the
// intent's effort tier.
func TestGraphOverviewYieldQualitySplit(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("yield split", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	ts := NewToolSet(store, "planner")

	intentID, err := ts.addOneIntent(intentItem{Summary: "deep lane", Effort: db.EffortDeep})
	if err != nil {
		t.Fatal(err)
	}
	// Two ordinary observations + one high-value fact + one finding.
	for _, f := range []map[string]any{
		{"fact_type": db.FactTypeObservation, "summary": "server header"},
		{"fact_type": db.FactTypeObservation, "summary": "port 8080 open"},
		{"fact_type": db.FactTypeClaim, "summary": "got domain admin",
			"progress_event": "credential_obtained"},
	} {
		if _, err := store.AddNodeLinked(db.KindFact, f, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AddNodeLinked(db.KindFinding, map[string]any{
		"summary": "unauthenticated RCE", "severity": "critical",
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}

	data := NewToolSet(store, "planner").graphOverviewData()
	recent, ok := data["recent_done_intents"].([]map[string]any)
	if !ok || len(recent) != 1 {
		t.Fatalf("recent_done_intents=%#v", data["recent_done_intents"])
	}
	got := recent[0]
	if got["yield_count"] != 4 {
		t.Fatalf("legacy yield_count=%v want 4 (split must not break it)", got["yield_count"])
	}
	if got["high_value_yields"] != 2 {
		t.Fatalf("high_value_yields=%v want 2 (credential + finding)", got["high_value_yields"])
	}
	if got["observation_yields"] != 2 {
		t.Fatalf("observation_yields=%v want 2", got["observation_yields"])
	}
	if got["effort"] != db.EffortDeep {
		t.Fatalf("effort=%v want deep", got["effort"])
	}

	// Route aggregation exposes autonomy health plus effort.
	routes, ok := data["routes"].([]map[string]any)
	if !ok || len(routes) == 0 {
		t.Fatalf("routes=%#v", data["routes"])
	}
	var matched map[string]any
	for _, r := range routes {
		if r["route_id"] == db.ParseIntentRoute(nodeByID(t, store, intentID)).RouteID {
			matched = r
		}
	}
	if matched == nil {
		t.Fatalf("route missing from overview: %#v", routes)
	}
	for _, key := range []string{"total_runs", "consecutive_dry_runs", "human_involved", "effort"} {
		if _, present := matched[key]; !present {
			t.Fatalf("route view missing %q: %#v", key, matched)
		}
	}
	if matched["total_runs"] != 1 || matched["consecutive_dry_runs"] != 0 || matched["human_involved"] != false {
		t.Fatalf("route health wrong: %#v", matched)
	}
	if matched["effort"] != db.EffortDeep {
		t.Fatalf("route effort=%v want deep", matched["effort"])
	}
}

// nodeByID is a small test helper shared by the agent-package fixtures.
func nodeByID(t *testing.T, store *db.ExplorationStore, id int64) *db.Node {
	t.Helper()
	n, err := store.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("node %d: %v", id, err)
	}
	return n
}

// A yield from another task's graph must be classified by THAT graph's node, not
// by a local map lookup that never matches inherited ids.
func TestYieldClassOfSourceGraph(t *testing.T) {
	if got := yieldClassOf(nil); got != "observation" {
		t.Fatalf("nil node class=%q", got)
	}
	// Findings are always high value; a plain observation fact never is.
	finding := &db.Node{ID: 1, Kind: db.KindFinding, Payload: []byte(`{"summary":"rce"}`)}
	if yieldClassOf(finding) != "high" {
		t.Fatal("a finding must classify as high value")
	}
	plain := &db.Node{ID: 2, Kind: db.KindFact, Payload: []byte(`{"fact_type":"observation","summary":"port open"}`)}
	if yieldClassOf(plain) != "observation" {
		t.Fatal("a plain observation must not classify as high value")
	}
	progress := &db.Node{ID: 3, Kind: db.KindFact, Payload: []byte(`{"fact_type":"claim","progress_event":"privilege_change"}`)}
	if yieldClassOf(progress) != "high" {
		t.Fatal("a high-value ProgressEvent fact must classify as high value")
	}
}
