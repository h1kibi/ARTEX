package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// The planner's strategic projection must stay inside 12,288 bytes while keeping
// the whole decision surface: every goal and hint, the frontier, findings and
// reusable credentials survive the deterministic trimming.
func TestPlannerOverviewRespects12KBBudget(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("planner budget", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)

	const goalCount = 3
	goalText := strings.Repeat("战略目标描述", 30)
	longText := strings.Repeat("战略目标与事实的长文本描述", 40)
	for i := range goalCount {
		if _, err := store.AddNode(db.KindGoal, map[string]any{"text": goalText, "index": i}, 5, "open", "human", nil); err != nil {
			t.Fatal(err)
		}
	}
	const hintCount = 12
	for range hintCount {
		if _, err := store.AddNode(db.KindHint, map[string]any{"text": strings.Repeat("人工提示", 12)}, 5, "active", "human", nil); err != nil {
			t.Fatal(err)
		}
	}

	var routes []int64
	var intents []int64
	for range 20 {
		id, _, err := store.AddIntentWithEdges(map[string]any{"summary": longText, "effort": "standard"}, 5, nil, "planner", 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		routeID := db.ParseIntentRoute(nodeByID(t, store, id)).RouteID
		routes = append(routes, routeID)
		intents = append(intents, id)
	}
	for i := range 30 {
		id, _, err := store.AddIntentWithEdges(map[string]any{"summary": longText}, 5, nil, "planner", routes[i%len(routes)], nil)
		if err != nil {
			t.Fatal(err)
		}
		intents = append(intents, id)
	}
	for _, id := range intents {
		if err := store.SetIntentState(id, "done"); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 100 {
		from := intents[i%len(intents)]
		if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
			"fact_type": db.FactTypeObservation, "summary": longText,
		}, 5, "confirmed", "worker", nil, from, db.RelYields); err != nil {
			t.Fatal(err)
		}
	}
	for i, routeID := range routes {
		from := intents[i]
		if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
			"fact_type": db.FactTypeCheckpoint, "route_id": routeID, "summary": longText,
			"path_phase": "recon", "objective": longText,
		}, 5, "confirmed", "worker", nil, from, db.RelYields); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
			"fact_type": db.FactTypeClaim, "summary": "reusable credential " + longText,
			"sensitivity": "credential", "progress_event": "credential_obtained",
		}, 5, "confirmed", "worker", nil, intents[i], db.RelYields); err != nil {
			t.Fatal(err)
		}
	}

	ts := NewToolSet(store, "planner")
	ts.SetTaskID(task.ID)
	out := ts.plannerOverviewData()
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > plannerOverviewMaxBytes {
		t.Fatalf("planner overview=%d bytes, budget=%d", len(raw), plannerOverviewMaxBytes)
	}
	goals, _ := out["goals"].([]map[string]any)
	if len(goals) != goalCount {
		t.Fatalf("goals=%d want %d (goals must never be trimmed)", len(goals), goalCount)
	}
	hints, _ := out["hints"].([]map[string]any)
	if len(hints) != hintCount {
		t.Fatalf("hints=%d want %d (hints must never be trimmed)", len(hints), hintCount)
	}
	creds, ok := out["reusable_credentials"].([]map[string]any)
	if !ok || len(creds) == 0 {
		t.Fatalf("reusable_credentials missing or empty: %#v", out["reusable_credentials"])
	}
	for _, key := range []string{"open_intents", "running_intents", "finding_list", "routes", "recent_facts"} {
		if _, ok := out[key]; !ok {
			t.Fatalf("planner overview lost required key %q", key)
		}
	}
}

func TestOverviewTextBudgetIsFairAndUTF8Safe(t *testing.T) {
	if got := relatedOverviewBudgetForSources(1); got != relatedOverviewMaxTextPerSource {
		t.Fatalf("single source budget=%d want=%d", got, relatedOverviewMaxTextPerSource)
	}
	perSource := relatedOverviewBudgetForSources(db.MaxTaskSourceCount)
	if perSource*db.MaxTaskSourceCount > relatedOverviewTotalTextRunes {
		t.Fatalf("aggregate budget exceeded: per_source=%d", perSource)
	}

	budget := overviewTextBudget{remaining: 5}
	got := budget.take(strings.Repeat("中", 10), 20)
	if !utf8.ValidString(got) {
		t.Fatalf("budget truncation produced invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 5 || !budget.truncated || budget.remaining != 0 {
		t.Fatalf("unexpected truncation: got=%q budget=%+v", got, budget)
	}
	if tail := budget.take("more", 20); tail != "" {
		t.Fatalf("exhausted budget returned more text: %q", tail)
	}
}
