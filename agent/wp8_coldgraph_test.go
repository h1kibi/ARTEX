package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// buildCompressionInput must keep the meat: internal hosts, credentials, paths and
// next actions recorded in detail/evidence/evidence_refs/next_actions. The old
// summary-only rendering threw exactly those away (docs §4.5).
func TestBuildCompressionInputKeepsDetailAndEvidence(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"fact_type":     db.FactTypeClaim,
		"summary":       "recovered a domain admin credential",
		"detail":        "svc_backup / Summer2024! works on 10.20.30.41:5985 (WinRM)",
		"evidence":      "crackmapexec winrm 10.20.30.41 -u svc_backup -p 'Summer2024!' -> [+]",
		"evidence_refs": []string{"traffic:991", "artifact:winrm.txt"},
		"next_actions":  []string{"psexec to 10.20.30.41 as svc_backup", "dump NTDS from dc01"},
	})
	if err != nil {
		t.Fatal(err)
	}
	node := &db.Node{ID: 7, Kind: db.KindFact, State: "confirmed", Payload: payload}
	g := newColdGraph([]cgNode{{ID: 7, Kind: db.KindFact, State: "confirmed"}}, nil)
	out := buildCompressionInput(g, block{Members: []int64{7}}, map[int64]*db.Node{7: node})

	for _, want := range []string{
		"svc_backup / Summer2024! works on 10.20.30.41:5985",
		"crackmapexec winrm 10.20.30.41",
		"traffic:991", "artifact:winrm.txt",
		"psexec to 10.20.30.41 as svc_backup",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("compression input dropped %q:\n%s", want, out)
		}
	}
}

// The detail/evidence budgets are enforced so N members still fit the summarizer.
func TestCompressionInputTruncatesLongFields(t *testing.T) {
	long := strings.Repeat("A", compressionDetailLimit*3)
	payload, _ := json.Marshal(map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "s",
		"detail": long, "evidence": strings.Repeat("B", compressionEvidenceLimit*3),
		"evidence_refs": []string{"e:1", "e:2", "e:3", "e:4", "e:5", "e:6", "e:7", "e:8", "e:9"},
	})
	node := &db.Node{ID: 3, Kind: db.KindFact, State: "confirmed", Payload: payload}
	g := newColdGraph([]cgNode{{ID: 3, Kind: db.KindFact, State: "confirmed"}}, nil)
	out := buildCompressionInput(g, block{Members: []int64{3}}, map[int64]*db.Node{3: node})

	if strings.Count(out, "A") > compressionDetailLimit+5 {
		t.Fatalf("detail not truncated: %d A's", strings.Count(out, "A"))
	}
	if !strings.Contains(out, "(+1 more)") {
		t.Fatalf("evidence_refs overflow marker missing:\n%s", out)
	}
	if strings.ContainsRune(out, '\uFFFD') {
		t.Fatalf("truncation split a rune: %q", out)
	}
}

// An idle heartbeat (no trigger) must NOT advance the cold round counter, so a
// lead being pursued during a long worker run is not folded away by mere waiting.
func TestIdleHeartbeatDoesNotAgeNodes(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("idle heartbeat", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	if _, err := ts.AddNode(db.KindIntent, map[string]any{"summary": "long running lane"}, 5, "running", "planner", nil); err != nil {
		t.Fatal(err)
	}
	before, err := ts.RoundNo()
	if err != nil {
		t.Fatal(err)
	}

	// Direct call: idle → round unchanged.
	roundIdle, _, _, err := (&Compactor{params: defaultColdParams()}).maintain(ts, false)
	if err != nil {
		t.Fatal(err)
	}
	if roundIdle != before {
		t.Fatalf("idle heartbeat advanced the round: %d → %d", before, roundIdle)
	}
	after, _ := ts.RoundNo()
	if after != before {
		t.Fatalf("round counter advanced on an idle round: %d → %d", before, after)
	}
	// A real trigger still advances it.
	roundActive, _, _, err := (&Compactor{params: defaultColdParams()}).maintain(ts, true)
	if err != nil {
		t.Fatal(err)
	}
	if roundActive != before+1 {
		t.Fatalf("active round did not advance: %d → %d", before, roundActive)
	}
	if got, _ := ts.RoundNo(); got != before+1 {
		t.Fatalf("round counter=%d want %d", got, before+1)
	}
}

// Inherited cold digests must carry the covered assets' labels, so a body-withheld
// digest is not an opaque box to the planner.
func TestInheritedColdDigestCarriesAssetLabels(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	current, err := d.CreateTask("label target", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(current.ID) })
	source, err := d.CreateTask("label source", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(source.ID) })
	if _, err := d.Exec(`INSERT INTO task_relations(task_id, source_task_id) VALUES ($1,$2)`, current.ID, source.ID); err != nil {
		t.Fatal(err)
	}

	srcStore := d.Exploration(source.ExplorationID)
	assets := d.Assets()
	host := fmt.Sprintf("labels-%d.invalid", source.ID)
	assetID, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{assetID}) })

	memberID, err := srcStore.AddNode(db.KindFact, map[string]any{"summary": "credential for the portal"}, 0, "confirmed", "worker", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}
	digestID, err := srcStore.AddNode(db.KindDigest, map[string]any{"body": "source secret body", "member_count": 1}, 0, "active", "system", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srcStore.Link(digestID, db.RelCovers, memberID); err != nil {
		t.Fatal(err)
	}

	tools := NewToolSet(d.Exploration(current.ExplorationID), "planner")
	tools.SetTaskID(current.ID)
	tools.SetAssetStore(assets, assets.Companies())
	overview := tools.graphOverviewData()
	related, ok := overview["related_tasks"].([]map[string]any)
	if !ok || len(related) != 1 {
		t.Fatalf("related_tasks=%#v", overview["related_tasks"])
	}
	digests, ok := related[0]["cold_digests"].([]map[string]any)
	if !ok || len(digests) == 0 {
		t.Fatalf("cold_digests missing: %#v", related[0]["cold_digests"])
	}
	var found bool
	for _, digest := range digests {
		if digest["id"] != digestID {
			continue
		}
		found = true
		if digest["body_withheld"] == nil {
			t.Fatalf("withheld marker missing: %#v", digest)
		}
		labels, ok := digest["asset_labels"].([]string)
		if !ok || len(labels) == 0 {
			t.Fatalf("asset_labels missing: %#v", digest)
		}
		if labels[0] != host {
			t.Fatalf("asset_labels=%v want first = %s", labels, host)
		}
	}
	if !found {
		t.Fatalf("digest %d missing from related overview: %#v", digestID, digests)
	}
}

// graph_overview must surface the guard's failure attribution (WAF / 429) so the
// planner can pace itself; with no guard wired the key is absent, not zeroed.
func TestGraphOverviewIncludesGuardAttributions(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("guard attributions", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	tools := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)

	if _, ok := tools.graphOverviewData()["guard_attributions"]; ok {
		t.Fatal("guard_attributions present without a guard")
	}
	tools.SetGuardAttributions(func() map[string]int {
		return map[string]int{"blocked": 3, "waf": 3, "rate_limited": 1}
	})
	got, ok := tools.graphOverviewData()["guard_attributions"].(map[string]int)
	if !ok || got["waf"] != 3 || got["rate_limited"] != 1 {
		t.Fatalf("guard_attributions=%#v", tools.graphOverviewData()["guard_attributions"])
	}
}

// next_actions and validation_actions are independent lists; a digest that renders
// one only as a fallback for the other loses the second whenever both are present.
func TestCompressionInputKeepsBothActionLists(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"fact_type": db.FactTypeHypothesis, "summary": "maybe IDOR on /api/orders",
		"state":              "open",
		"validation_actions": []string{"replay GET /api/orders/9001 as user B"},
		"next_actions":       []string{"pivot to the admin API once IDOR confirms"},
	})
	node := &db.Node{ID: 11, Kind: db.KindFact, State: "confirmed", Payload: payload}
	g := newColdGraph([]cgNode{{ID: 11, Kind: db.KindFact, State: "confirmed"}}, nil)
	out := buildCompressionInput(g, block{Members: []int64{11}}, map[int64]*db.Node{11: node})
	if !strings.Contains(out, "next_actions: pivot to the admin API") {
		t.Fatalf("next_actions missing:\n%s", out)
	}
	if !strings.Contains(out, "validation_actions: replay GET /api/orders/9001") {
		t.Fatalf("validation_actions missing when next_actions is present:\n%s", out)
	}
}
