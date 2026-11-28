package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/oast"
)

// The background triager promotes a `verifying` finding only when its evidence is
// genuinely re-checkable — an OAST callback or a bound traffic snapshot. A
// text-only report must stay verifying so it cannot prove a goal.
func TestBackgroundTriagePromotesOnlyWithRealEvidence(t *testing.T) {
	s, initial, taskID := findingFixture(t, "background triage")
	srv := oast.New(oast.Options{Addr: "127.0.0.1:0"})
	if err := srv.Start(); err != nil {
		t.Fatalf("start oast: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	s.m.oast = srv

	// Mark the finding verifying first (it was recorded with real text evidence).
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}
	s.wireFindingEvidenceVerification()
	// Save/restore the package-level hook so this test cannot leak into others.
	prev := agent.FindingEvidenceHook
	t.Cleanup(func() { agent.FindingEvidenceHook = prev })

	// Text-only evidence: nothing resolves → the state must stay verifying.
	agent.FindingEvidenceHook(taskID, 0, initial.FindingID, nil)
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageVerifying {
		t.Fatalf("text-only finding promoted to %q", st)
	}

	// A fabricated oast ref must not promote it either.
	agent.FindingEvidenceHook(taskID, 0, initial.FindingID, []string{"oast:999999999"})
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageVerifying {
		t.Fatalf("fabricated evidence promoted the finding to %q", st)
	}

	// A real callback does.
	tok := srv.Generate("proof", taskID, 0)
	if err := hitCallback(t, tok.CallbackURL); err != nil {
		t.Fatal(err)
	}
	events, _, known := srv.Poll(tok.Value)
	if !known || len(events) != 1 {
		t.Fatalf("callback not recorded: %v", events)
	}
	agent.FindingEvidenceHook(taskID, 0, initial.FindingID, []string{events[0].EvidenceRef})
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageConfirmed {
		t.Fatalf("resolvable oast evidence did not promote the finding: %q", st)
	}
}

// The node payload must mirror the state transition, because prove_goal reads the
// node (not the findings table) when it checks an anchor.
func TestTriageStateMirrorsIntoNodePayload(t *testing.T) {
	s, initial, _ := findingFixture(t, "triage mirror")
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}
	node := findingNodeOf(t, s, initial.NodeID)
	if st := agent.FindingTriageState(node); st != agent.TriageVerifying {
		t.Fatalf("node payload triage=%q want verifying", st)
	}
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageConfirmed); err != nil {
		t.Fatal(err)
	}
	node = findingNodeOf(t, s, initial.NodeID)
	if st := agent.FindingTriageState(node); st != agent.TriageConfirmed {
		t.Fatalf("node payload triage=%q want confirmed", st)
	}
	// Unknown states are rejected, not silently stored.
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, "bogus"); err == nil {
		t.Fatal("invalid triage state accepted")
	}
}

func findingTriageStateOf(t *testing.T, s *Server, findingID int64) string {
	t.Helper()
	var st string
	if err := s.m.pg.QueryRow(`SELECT triage_state FROM findings WHERE id=$1`, findingID).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func findingNodeOf(t *testing.T, s *Server, nodeID int64) *db.Node {
	t.Helper()
	// The finding's node lives in whichever exploration owns it; search the fixture
	// task's store directly.
	var expID int64
	if err := s.m.pg.QueryRow(`SELECT exploration_id FROM exploration_nodes WHERE id=$1`, nodeID).Scan(&expID); err != nil {
		t.Fatal(err)
	}
	n, err := s.m.pg.Exploration(expID).GetNode(nodeID)
	if err != nil || n == nil {
		t.Fatalf("node %d: %+v err=%v", nodeID, n, err)
	}
	return n
}

func hitCallback(t *testing.T, url string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/probe", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// A bound traffic snapshot used to be proof on its own. It is not: an access-control
// claim corroborated by a 200 that is really the login page is the most common AI
// false positive, so the response body decides. A refusal or an auth bounce must
// DEMOTE the finding instead of promoting it.
func TestTriageRefutesLoginPageEvidence(t *testing.T) {
	s, initial, taskID := findingFixture(t, "triage login page")
	s.wireFindingEvidenceVerification()
	prev := agent.FindingEvidenceHook
	t.Cleanup(func() { agent.FindingEvidenceHook = prev })

	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}

	// Judged on the snapshot alone: a 200 carrying a login form is a refusal.
	snap := db.TrafficEvidenceSnapshot{Status: 200, URL: "http://target/admin", Method: "GET"}
	body := []byte(`<html><form><input type="password" name="pwd"></form></html>`)
	if v := assessImpact(snap, body); !v.Refuted || v.Proven {
		t.Fatalf("login page not refuted: %+v", v)
	}
	// A 403 refusal is a refusal too.
	if v := assessImpact(db.TrafficEvidenceSnapshot{Status: 403}, nil); !v.Refuted {
		t.Fatalf("403 not refuted: %+v", v)
	}
	// Real affected content proves impact.
	if v := assessImpact(db.TrafficEvidenceSnapshot{Status: 200}, []byte(`{"users":[{"name":"admin","token":"abc"}]}`)); !v.Proven || v.Refuted {
		t.Fatalf("real content not accepted: %+v", v)
	}
	// A redirect is neither: it may be the exploit (open redirect) or a bounce.
	if v := assessImpact(db.TrafficEvidenceSnapshot{Status: 302}, nil); v.Proven || v.Refuted {
		t.Fatalf("redirect judged as proof or refutation: %+v", v)
	}

	// A fabricated ref must not promote (unchanged behaviour).
	agent.FindingEvidenceHook(taskID, 0, initial.FindingID, []string{"oast:999999999"})
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageVerifying {
		t.Fatalf("fabricated evidence changed the state to %q", st)
	}
}

// The real entry point must not confirm a traffic-backed report on its own: the
// write path cannot see whether the bound response is the login page. This drives
// report_finding end to end and asserts the finding lands as `verifying`, then lets
// the background triager read the bound bytes and refute it.
func TestReportFindingWithLoginPageTrafficStaysVerifyingThenRefuted(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	if err := s.m.pg.SetBool(settingAgentTrafficBinding, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.SetBool(settingAgentTrafficBinding, false) })

	s.wireFindingEvidenceVerification()
	prev := agent.FindingEvidenceHook
	t.Cleanup(func() { agent.FindingEvidenceHook = prev })

	task, err := s.m.CreateTask("login page traffic", "prove nothing", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID, ExplorationID: task.ExpID})

	// A 200 whose body is the login form — the canonical false positive.
	seedServerEvidenceFlow(t, s, "login-page-1", []byte(`<html><form action="/login"><input type="password" name="pwd"></form></html>`))

	ts := agent.NewToolSet(task.Store, "worker")
	ts.SetTaskID(taskID)
	ts.SetFindingRecorder(s.evidenceStore())
	report := ts.AddFindingTool()
	raw, _ := json.Marshal(map[string]any{
		"vulnclass": "越权访问", "severity": "high",
		"summary":      "未授权访问 /admin 管理接口",
		"evidence":     "GET /admin -> 200，返回了后台页面",
		"traffic_refs": []any{map[string]any{"traffic_id": "login-page-1", "role": "proof"}},
	})
	res, err := report.Call(ctx, raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("report_finding: %v %s", err, res.Flatten())
	}
	var recorded db.RecordedFinding
	if out := res.Flatten(); strings.Contains(out, "\n") {
		if uerr := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[1]), &recorded); uerr != nil {
			t.Fatalf("decode report result %q: %v", out, uerr)
		}
	}
	if recorded.FindingID == 0 {
		t.Fatalf("no finding recorded: %s", res.Flatten())
	}
	// The write path must NOT have confirmed it.
	if st := findingTriageStateOf(t, s, recorded.FindingID); st != agent.TriageVerifying {
		t.Fatalf("traffic-backed report landed as %q, want verifying", st)
	}
	// The background triager reads the bound body and refutes the claim.
	agent.FindingEvidenceHook(taskID, task.ExpID, recorded.FindingID, nil)
	if st := findingTriageStateOf(t, s, recorded.FindingID); st != agent.TriageRejected {
		t.Fatalf("login-page evidence settled as %q, want rejected", st)
	}
}

// A non-HTTP finding with no traffic or OAST reference is confirmed only when its
// cited evidence appears in a real successful tool_result of the producing intent.
func TestBackgroundTriagePromotesWithRealToolOutput(t *testing.T) {
	s, initial, taskID := findingFixture(t, "real tool output")
	const evidenceLine = `{"id":9001,"user":"alice","password_hash":"5f4dcc3b5aa765d61d8327deb882cf99"}`

	if _, err := s.m.pg.Exec(`UPDATE findings SET vulnclass=$2, summary=$3, evidence=$4 WHERE id=$1`,
		initial.FindingID, "Presto SQL 注入", "Presto 查询回显了其他用户口令哈希", evidenceLine); err != nil {
		t.Fatal(err)
	}
	var expID int64
	if err := s.m.pg.QueryRow(`SELECT exploration_id FROM exploration_nodes WHERE id=$1`, initial.NodeID).Scan(&expID); err != nil {
		t.Fatal(err)
	}
	store := s.m.pg.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "probe presto"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	// The finding node records which intent produced it, as the write path does.
	if _, err := s.m.pg.Exec(`UPDATE exploration_nodes SET payload = payload || jsonb_build_object('intent_id',$1::bigint) WHERE id=$2`,
		intentID, initial.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}

	s.wireFindingEvidenceVerification()
	prev := agent.FindingEvidenceHook
	t.Cleanup(func() { agent.FindingEvidenceHook = prev })

	// No activity yet: the cited line exists nowhere, so it must stay verifying.
	agent.FindingEvidenceHook(taskID, expID, initial.FindingID, nil)
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageVerifying {
		t.Fatalf("fabricated evidence promoted the finding to %q", st)
	}

	// A real Bash tool_result from the producing intent carries the cited bytes.
	if _, err := store.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "worker", Kind: "tool_result", Tool: "Bash",
		Summary: evidenceLine,
	}); err != nil {
		t.Fatal(err)
	}
	agent.FindingEvidenceHook(taskID, expID, initial.FindingID, nil)
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageConfirmed {
		t.Fatalf("real tool output did not promote the finding: %q", st)
	}
	if st := agent.FindingTriageState(findingNodeOf(t, s, initial.NodeID)); st != agent.TriageConfirmed {
		t.Fatalf("node payload triage_state = %q, want confirmed", st)
	}
}

// A body on a non-success status is an error page, not leaked data.
func TestAssessImpactRejectsNonSuccessStatuses(t *testing.T) {
	for _, status := range []int{404, 410, 429, 500} {
		v := assessImpact(db.TrafficEvidenceSnapshot{Status: status}, []byte(`{"detail":"some body"}`))
		if v.Proven {
			t.Fatalf("status %d judged as proven impact: %+v", status, v)
		}
		if status != 500 && !v.Refuted {
			t.Fatalf("status %d not refuted: %+v", status, v)
		}
	}
	// A real 200 with real content still proves.
	if v := assessImpact(db.TrafficEvidenceSnapshot{Status: 200}, []byte(`{"users":[{"id":1}]}`)); !v.Proven {
		t.Fatalf("200 with content not proven: %+v", v)
	}
}

// The runtime prefers the DB-stored tool schema, so an already-migrated database
// must receive record_fact's new `need_human` parameter. The refresh is guarded by
// a version flag, so the flag must have been bumped when the parameter was added.
func TestRecordFactSchemaRefreshCarriesNeedHuman(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	// Simulate a DB that ran the previous migration: the flag is set, and the stored
	// record_fact schema predates need_human.
	const flag = toolSchemaRefreshFlag
	prev, hadPrev, _ := pg.GetSetting(flag)
	t.Cleanup(func() {
		if hadPrev {
			_ = pg.SetSetting(flag, prev)
		}
	})
	if err := pg.SetSetting(flag, "false"); err != nil {
		t.Fatal(err)
	}
	stale := json.RawMessage(`{"type":"object","properties":{"summary":{"type":"string"}}}`)
	row, err := pg.GetTool("record_fact")
	if err != nil || row == nil {
		t.Fatalf("record_fact row: %v", err)
	}
	t.Cleanup(func() {
		bindings, _ := json.Marshal(row.Agents)
		_ = pg.UpdateTool(row.Key, row.Description, row.Schema, bindings, row.Enabled)
	})
	bindings, _ := json.Marshal(row.Agents)
	if err := pg.UpdateTool("record_fact", row.Description, stale, bindings, row.Enabled); err != nil {
		t.Fatal(err)
	}

	s.refreshBuiltinToolSchemas()

	updated, err := pg.GetTool("record_fact")
	if err != nil || updated == nil {
		t.Fatalf("record_fact after refresh: %v", err)
	}
	// The refresh must carry EVERY parameter added after the previous version: the
	// need_human flag (v14) and the explicit finding_node_id (v15).
	if !strings.Contains(string(updated.Schema), "need_human") {
		t.Fatalf("refreshed schema still lacks need_human: %s", updated.Schema)
	}
	if v, _, _ := pg.GetSetting(flag); v != "true" {
		t.Fatalf("migration flag not set after refresh: %q", v)
	}
}

// Roles are not interchangeable: a baseline 403 describes the authorised view, and
// a plain 200 may be a landing page. Only the impact-bearing snapshot decides.
//
// This drives the classification directly (no stored blobs needed): assessImpact
// judges on the status line when a snapshot carries no body, which is enough to
// pin the role precedence.
func TestJudgeBindingsRespectsRoles(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	binding := func(role string, status int) db.FindingTrafficBinding {
		return db.FindingTrafficBinding{Role: role, Snapshot: db.TrafficEvidenceSnapshot{Status: status}}
	}

	// A baseline refusal must NOT refute a finding: the 403 describes the
	// authorised view, not the claim. (No body on the proof snapshot, so it cannot
	// confirm either — but it must not be refuted.)
	confirmed, refuted, reason := s.judgeBindings(ctx, []db.FindingTrafficBinding{
		binding("baseline", 403),
		binding("proof", 200),
	})
	if refuted || confirmed {
		t.Fatalf("baseline 403 decided the finding: confirmed=%v refuted=%v reason=%q", confirmed, refuted, reason)
	}

	// A proven baseline does not confirm either: baseline is the control view.
	confirmed, refuted, reason = s.judgeBindings(ctx, []db.FindingTrafficBinding{
		binding("baseline", 200),
		binding("proof", 403),
	})
	if confirmed || !refuted {
		t.Fatalf("baseline 200 confirmed a refused claim: confirmed=%v refuted=%v reason=%q", confirmed, refuted, reason)
	}

	// Only controls: nothing demonstrates impact, and it must not be promoted.
	confirmed, refuted, reason = s.judgeBindings(ctx, []db.FindingTrafficBinding{binding("baseline", 200)})
	if confirmed || refuted {
		t.Fatalf("control-only evidence settled the finding: confirmed=%v refuted=%v reason=%q", confirmed, refuted, reason)
	}
	if reason == "" {
		t.Fatal("control-only verdict has no reason")
	}

	// verification is impact-bearing too: a refusal there refutes even when a
	// baseline was served a 200.
	if _, refuted, _ := s.judgeBindings(ctx, []db.FindingTrafficBinding{
		binding("baseline", 200), binding("verification", 403),
	}); !refuted {
		t.Fatal("verification refusal did not refute")
	}
}

// The same precedence through REAL bound snapshots: a login page as baseline and a
// genuine response as proof must confirm; the reverse must refute.
func TestJudgeBindingsWithStoredBodies(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	ctx := context.Background()

	seedServerEvidenceFlow(t, s, "role-baseline-login", []byte(`<html><input type="password" name="pwd"></html>`))
	seedServerEvidenceFlow(t, s, "role-proof-admin", []byte(`{"users":[{"name":"admin"}]}`))
	seedServerEvidenceFlow(t, s, "role-proof-login", []byte(`<html><input type="password" name="pwd"></html>`))

	task, err := s.m.CreateTask("role bodies", "judge", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)

	record := func(refs []db.TrafficRef) int64 {
		f, err := s.evidenceStore().Record(ctx, db.RecordFindingInput{
			TaskID: taskID, ExplorationID: task.ExpID, Worker: "test",
			VulnClass: "越权访问", Summary: "role fixture", Evidence: "fixture", Severity: "high",
		}, refs)
		if err != nil {
			t.Fatal(err)
		}
		return f.FindingID
	}

	// baseline = login page (the control), proof = real data → confirm.
	okID := record([]db.TrafficRef{
		{TrafficID: "role-baseline-login", Role: "baseline"},
		{TrafficID: "role-proof-admin", Role: "proof"},
	})
	bindings, err := s.m.pg.GetFindingTraffic(ctx, okID)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, refuted, reason := s.judgeBindings(ctx, bindings.Bindings)
	if !confirmed || refuted {
		t.Fatalf("proof data not confirmed: confirmed=%v refuted=%v reason=%q", confirmed, refuted, reason)
	}

	// baseline = login page, proof = login page → refute (the proof shows no impact).
	badID := record([]db.TrafficRef{
		{TrafficID: "role-baseline-login", Role: "baseline"},
		{TrafficID: "role-proof-login", Role: "proof"},
	})
	bindings, err = s.m.pg.GetFindingTraffic(ctx, badID)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, refuted, reason = s.judgeBindings(ctx, bindings.Bindings)
	if confirmed || !refuted {
		t.Fatalf("login-page proof not refuted: confirmed=%v refuted=%v reason=%q", confirmed, refuted, reason)
	}
}

// A bare traffic:/activity: pointer proves an exchange happened, not that it shows
// the claimed impact. It must leave the finding unconfirmed.
func TestActivityAndTrafficRefsAloneDoNotConfirm(t *testing.T) {
	s, initial, taskID := findingFixture(t, "refs alone")
	s.wireFindingEvidenceVerification()
	prev := agent.FindingEvidenceHook
	t.Cleanup(func() { agent.FindingEvidenceHook = prev })
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}
	agent.FindingEvidenceHook(taskID, 0, initial.FindingID, []string{"activity:1", "traffic:2"})
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageVerifying {
		t.Fatalf("existence-only refs settled the finding as %q", st)
	}
}

// A background verdict computed from stale evidence must not overwrite a decision
// that landed in the meantime — a human confirmation in particular.
func TestStaleTriageVerdictDoesNotOverwrite(t *testing.T) {
	s, initial, _ := findingFixture(t, "stale verdict")
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}
	traffic, err := s.m.pg.GetFindingTraffic(context.Background(), initial.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	staleVersion := traffic.Version

	// A human settles it while the background verdict is in flight.
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageConfirmed); err != nil {
		t.Fatal(err)
	}

	applied, err := s.m.pg.SetFindingTriageStateIfVersion(initial.FindingID, staleVersion, agent.TriageRejected)
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("stale verdict overwrote a human decision")
	}
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageConfirmed {
		t.Fatalf("state = %q, want confirmed (the human's verdict)", st)
	}
}

// The node mirror is part of the same transaction, so a committed verdict is
// visible through BOTH the findings table and the graph.
func TestTriageVerdictCommitsRowAndNodeTogether(t *testing.T) {
	s, initial, _ := findingFixture(t, "verdict atomic")
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}
	traffic, err := s.m.pg.GetFindingTraffic(context.Background(), initial.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.m.pg.SetFindingTriageStateIfVersion(initial.FindingID, traffic.Version, agent.TriageConfirmed)
	if err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	if st := findingTriageStateOf(t, s, initial.FindingID); st != agent.TriageConfirmed {
		t.Fatalf("row state = %q", st)
	}
	if st := agent.FindingTriageState(findingNodeOf(t, s, initial.NodeID)); st != agent.TriageConfirmed {
		t.Fatalf("node payload state = %q (row and graph disagree)", st)
	}
}

// A confirmation is bound to the evidence version it judged: both versions are
// mirrored onto the finding node, so a later evidence change is visible where the
// goal-proof gate reads it.
func TestTriageConfirmationBindsEvidenceVersion(t *testing.T) {
	s, initial, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	seedServerEvidenceFlow(t, s, "vb-proof", []byte(`{"users":[{"name":"admin"}]}`))

	if _, err := s.evidenceStore().Bind(ctx, initial.FindingID, []db.TrafficRef{{TrafficID: "vb-proof", Role: "proof"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}
	traffic, err := s.m.pg.GetFindingTraffic(ctx, initial.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.m.pg.SetFindingTriageStateIfVersion(initial.FindingID, traffic.Version, agent.TriageConfirmed)
	if err != nil || !applied {
		t.Fatalf("confirm: applied=%v err=%v", applied, err)
	}
	versions := nodeVersions(t, s, initial.NodeID)
	if versions.confirmed != traffic.Version || versions.evidence != traffic.Version {
		t.Fatalf("confirmation not bound to the evidence version: %+v (want %d)", versions, traffic.Version)
	}

	// The evidence changes: both versions move or diverge, and the gate sees it.
	seedServerEvidenceFlow(t, s, "vb-proof-2", []byte(`{"users":[{"name":"other"}]}`))
	if _, err := s.evidenceStore().Bind(ctx, initial.FindingID, []db.TrafficRef{{TrafficID: "vb-proof-2", Role: "supporting"}}); err != nil {
		t.Fatal(err)
	}
	after := nodeVersions(t, s, initial.NodeID)
	if after.evidence == versions.evidence {
		t.Fatalf("evidence version did not move on the node: %+v", after)
	}
	if after.confirmed != versions.confirmed {
		t.Fatalf("confirmation version moved with the evidence: %+v", after)
	}
	if !agent.ConfirmationIsStale(findingNodeOf(t, s, initial.NodeID)) {
		t.Fatal("goal-proof gate does not see the stale confirmation")
	}
}

type nodeVersionPair struct{ confirmed, evidence int64 }

func nodeVersions(t *testing.T, s *Server, nodeID int64) nodeVersionPair {
	t.Helper()
	n := findingNodeOf(t, s, nodeID)
	var p struct {
		Confirmed int64 `json:"triage_evidence_version"`
		Evidence  int64 `json:"evidence_version"`
	}
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return nodeVersionPair{confirmed: p.Confirmed, evidence: p.Evidence}
}

// The goal-proof transaction re-checks the evidence it is about to rely on. A
// confirmation invalidated between the caller's pre-check and the commit must stop
// the write, not slip through.
func TestProveGoalRevalidatesEvidenceInTransaction(t *testing.T) {
	s, initial, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	row, err := s.m.pg.GetFinding(initial.FindingID)
	if err != nil || row == nil || row.TaskID == nil {
		t.Fatalf("finding: %+v err=%v", row, err)
	}
	task, err := s.m.pg.GetTask(*row.TaskID)
	if err != nil || task == nil {
		t.Fatalf("task: %+v err=%v", task, err)
	}
	store := s.m.pg.Exploration(task.ExplorationID)
	goalID, err := store.AddNode(db.KindGoal, map[string]any{"text": "prove the finding"}, 1, "open", "human", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Evidence valid at the caller's pre-check.
	seedServerEvidenceFlow(t, s, "reval-proof", []byte(`{"users":[{"name":"admin"}]}`))
	if _, err := s.evidenceStore().Bind(ctx, initial.FindingID, []db.TrafficRef{{TrafficID: "reval-proof", Role: "proof"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.SetFindingTriageState(initial.FindingID, agent.TriageVerifying); err != nil {
		t.Fatal(err)
	}
	traffic, err := s.m.pg.GetFindingTraffic(ctx, initial.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := s.m.pg.SetFindingTriageStateIfVersion(initial.FindingID, traffic.Version, agent.TriageConfirmed); err != nil || !applied {
		t.Fatalf("confirm: applied=%v err=%v", applied, err)
	}
	// It is provable right now.
	if err := store.ProveGoalChecked(goalID, initial.NodeID, agent.RevalidateProofEvidence); err != nil {
		t.Fatalf("valid evidence rejected in-transaction: %v", err)
	}

	// Same goal, second evidence: invalidate it before the commit.
	other, err := s.m.pg.Exploration(task.ExplorationID).AddNode(db.KindFinding, map[string]any{
		"summary": "second", "triage_state": agent.TriageVerifying,
	}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ProveGoalChecked(goalID, other, agent.RevalidateProofEvidence); err == nil {
		t.Fatal("an unverified finding proved a goal inside the transaction")
	}

	// And the stale-confirmation case: evidence changed after the confirmation.
	seedServerEvidenceFlow(t, s, "reval-proof-2", []byte(`{"users":[]}`))
	if _, err := s.evidenceStore().Bind(ctx, initial.FindingID, []db.TrafficRef{{TrafficID: "reval-proof-2", Role: "supporting"}}); err != nil {
		t.Fatal(err)
	}
	goal2, err := store.AddNode(db.KindGoal, map[string]any{"text": "prove stale"}, 1, "open", "human", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ProveGoalChecked(goal2, initial.NodeID, agent.RevalidateProofEvidence); err == nil {
		t.Fatal("a confirmation bound to older evidence proved a goal")
	}
}

// "Not conclusive" must stay verifying, never become refuted.
func TestJudgeBindingsKeepsInconclusiveAsVerifying(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	binding := func(role string, status int) db.FindingTrafficBinding {
		return db.FindingTrafficBinding{Role: role, Snapshot: db.TrafficEvidenceSnapshot{Status: status}}
	}
	// A successful supporting response plus a redirect-only proof: nothing proved or
	// disproved the claim, so it must not be rejected.
	confirmed, refuted, reason := s.judgeBindings(ctx, []db.FindingTrafficBinding{
		binding("proof", 302),
		binding("supporting", 200),
	})
	if confirmed || refuted {
		t.Fatalf("inconclusive evidence settled the finding: confirmed=%v refuted=%v reason=%q", confirmed, refuted, reason)
	}
	if reason == "" {
		t.Fatal("inconclusive verdict has no reason")
	}
	// A supporting 200 alone must not confirm either.
	if confirmed, refuted, _ := s.judgeBindings(ctx, []db.FindingTrafficBinding{binding("supporting", 200)}); confirmed || refuted {
		t.Fatalf("supporting alone settled the finding: confirmed=%v refuted=%v", confirmed, refuted)
	}
}
