package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// reconcileFixture builds one task + intent and returns the engine and stores.
func reconcileFixture(t *testing.T, name string) (*Engine, *Task, *db.ExplorationStore, int64) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask(name, "reconcile fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	intentID, _, err := task.Store.AddIntentWithEdges(map[string]any{
		"summary": "probe the target", "path_phase": "validation",
	}, 5, nil, "planner", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(m), task, task.Store, intentID
}

// A real breakthrough written as a plain observation (the historical 70–80% loss
// case) must be captured; the high-value fact's evidence must survive into the
// candidate.
func TestReconcileCapturesHighValueObservation(t *testing.T) {
	e, task, store, intentID := reconcileFixture(t, "capture observation")
	obsID, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type":      db.FactTypeObservation,
		"summary":        "SQL injection confirmed on /api/search",
		"detail":         "parameter q returns 5 rows of /etc/passwd style output",
		"evidence":       "sqlmap -u http://10.0.0.5/api/search?q=1 -> DBMS: MySQL",
		"progress_event": "validated_weakness",
		"evidence_refs":  []string{"artifact:sqli.txt"},
		"next_actions":   []string{"dump the users table"},
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields)
	if err != nil {
		t.Fatal(err)
	}
	// An ordinary observation alongside it must not be promoted.
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "server header nginx/1.25",
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := e.reconcileFindingCandidate(task, intent, "run-1")
	if err != nil || id <= 0 {
		t.Fatalf("candidate id=%d err=%v", id, err)
	}
	n, err := store.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("candidate node: %v", err)
	}
	p := db.ParseFactPayload(n.Payload)
	if p.FactType != db.FactTypeFindingCandidate {
		t.Fatalf("fact_type=%q", p.FactType)
	}
	if !strings.Contains(p.Summary, "SQL injection") && !strings.Contains(p.Summary, "SQL 注入") {
		t.Fatalf("summary lost: %q", p.Summary)
	}
	if len(p.ObservationIDs) != 1 || p.ObservationIDs[0] != obsID {
		t.Fatalf("observation_ids=%v want [%d]", p.ObservationIDs, obsID)
	}
	if len(p.EvidenceRefs) != 1 || p.EvidenceRefs[0] != "artifact:sqli.txt" {
		t.Fatalf("evidence_refs=%v", p.EvidenceRefs)
	}
	if len(p.NextActions) != 1 || p.NextActions[0] != "dump the users table" {
		t.Fatalf("next_actions=%v", p.NextActions)
	}
}

// An offline inventory of claims ("ports open", "Apache 2.4.49") must stay
// inventory: the old rule turned these into candidates and drowned the real ones.
func TestReconcileIgnoresPlainInventoryClaim(t *testing.T) {
	e, task, store, intentID := reconcileFixture(t, "ignore inventory")
	for _, c := range []map[string]any{
		{"fact_type": db.FactTypeClaim, "summary": "ports 22/80/443 open on 10.0.0.9", "confidence": "observed",
			"evidence_refs": []string{"artifact:nmap.txt"}},
		{"fact_type": db.FactTypeClaim, "summary": "Apache 2.4.49 detected", "confidence": "observed",
			"evidence_refs": []string{"artifact:headers.txt"}},
	} {
		if _, err := store.AddNodeLinked(db.KindFact, c, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
			t.Fatal(err)
		}
	}
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := e.reconcileFindingCandidate(task, intent, "run-inv"); err != nil || id != 0 {
		t.Fatalf("inventory claim promoted: id=%d err=%v", id, err)
	}
}

// An explicit finding_candidate fact is captured even without a progress_event —
// the worker already made the judgement; reconciliation must not drop it.
func TestReconcileCapturesExplicitCandidate(t *testing.T) {
	e, task, store, intentID := reconcileFixture(t, "explicit candidate")
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeFindingCandidate, "summary": "possible IDOR on /api/users/2",
		"validation_state": "pending", "evidence_refs": []string{"artifact:idor.txt"},
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := e.reconcileFindingCandidate(task, intent, "run-cand")
	if err != nil || id <= 0 {
		t.Fatalf("explicit candidate dropped: id=%d err=%v", id, err)
	}
}

// A run that already reported a finding must not fabricate a second candidate.
func TestReconcileSkipsIntentWithFinding(t *testing.T) {
	e, task, store, intentID := reconcileFixture(t, "has finding")
	if _, err := store.AddNodeLinked(db.KindFact, map[string]any{
		"fact_type": db.FactTypeObservation, "summary": "rce worked",
		"progress_event": "validated_weakness", "evidence_refs": []string{"artifact:rce.txt"},
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNodeLinked(db.KindFinding, map[string]any{
		"summary": "unauthenticated RCE", "severity": "critical",
	}, 5, "confirmed", "worker", nil, intentID, db.RelYields); err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := e.reconcileFindingCandidate(task, intent, "run-f"); err != nil || id != 0 {
		t.Fatalf("candidate created despite a reported finding: id=%d", id)
	}
}

// findingFixture builds the smallest server surface the evidence tools need: a
// manager (PG + task) and one recorded finding with both ids resolved.
func findingFixture(t *testing.T, name string) (*Server, *db.RecordedFinding, int64) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask(name, "evidence tools", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	recorded, err := m.pg.Exploration(task.ExpID).RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: taskID, ExplorationID: task.ExpID, Worker: "test",
		VulnClass: "TEST", Name: "Evidence API", Severity: "low",
		Summary: "bound evidence", Evidence: "curl -i http://10.0.0.5/admin -> 200 with admin menu",
	})
	if err != nil {
		t.Fatal(err)
	}
	if recorded.FindingID == recorded.NodeID {
		t.Fatalf("fixture ids collide (%d); the test would not prove the fallback", recorded.FindingID)
	}
	// The two id spaces are independent sequences, so another task's row may share
	// either number. Resolution must therefore be task-scoped; the tests bind the
	// run to this task exactly as a worker does (see callers).
	return &Server{m: m}, recorded, taskID
}

// update_finding_report must accept either id report_finding prints. Passing the
// standalone record id (the JSON body's finding_id) is what models do; before this
// fix it returned "未找到" and the report was lost.
func TestUpdateFindingReportAcceptsBothIDs(t *testing.T) {
	s, initial, taskID := findingFixture(t, "report ids")
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})
	report := "# Report\nverified RCE"
	// Standalone record id (findings.id).
	if r := workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{
		"finding_id": initial.FindingID, "report": report,
	}, false); !strings.Contains(r, "report updated") {
		t.Fatalf("record id not accepted: %s", r)
	}
	f, err := s.m.pg.GetFinding(initial.FindingID)
	if err != nil || f == nil || !strings.Contains(f.Report, "verified RCE") {
		t.Fatalf("report not written via record id: %+v err=%v", f, err)
	}
	// Exploration node id — addressed explicitly as finding_node_id. Passing it as
	// finding_id means "the record with this number", which is a different row (or
	// none), so the two numberings are never interchanged.
	report2 := "# Report v2\nsecond pass"
	if r := workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{
		"finding_node_id": initial.NodeID, "report": report2,
	}, false); !strings.Contains(r, "report updated") {
		t.Fatalf("node id not accepted: %s", r)
	}
	if f, _ = s.m.pg.GetFinding(initial.FindingID); !strings.Contains(f.Report, "second pass") {
		t.Fatalf("report not written via node id: %+v", f)
	}
	// A number matching neither must still fail loudly.
	workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{
		"finding_id": int64(900000000000001), "report": "x",
	}, true)
}

func TestUpdateFindingReportRejectsCrossTaskWriteAndRealInterceptorCoversDeferredTools(t *testing.T) {
	s, initial, initialTaskID := findingFixture(t, "owner task")
	other, err := s.m.CreateTask("unrelated task", "must not overwrite owner report", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(other.ID, DeleteTaskOptions{}) })
	otherID, _ := strconv.ParseInt(other.ID, 10, 64)

	// A task-bound caller from another task must be refused when targeting owner's finding.
	otherCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: otherID})
	workflowCall(t, otherCtx, s.toolUpdateFindingReport(), map[string]any{
		"finding_id": initial.FindingID, "report": "# hijacked",
	}, true)

	// A session with no task (TaskID == 0) has no authority to write evidence: the
	// platform-level conversation must not be able to rewrite any finding's report.
	if out := workflowCall(t, context.Background(), s.toolUpdateFindingReport(), map[string]any{
		"finding_id": initial.FindingID, "report": "# hijacked by a task-less session",
	}, true); !strings.Contains(out, "未绑定任务") {
		t.Fatalf("task-less write was not refused with a scope error: %s", out)
	}
	if f, err := s.m.pg.GetFinding(initial.FindingID); err != nil || strings.Contains(f.Report, "hijacked") {
		t.Fatalf("task-less write changed the report: %+v err=%v", f, err)
	}
	// The finding's own task can write it.
	ownerCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: initialTaskID})
	if out := workflowCall(t, ownerCtx, s.toolUpdateFindingReport(), map[string]any{
		"finding_id": initial.FindingID, "report": "# legitimate reporter",
	}, false); !strings.Contains(out, "report updated") {
		t.Fatalf("owner task write failed: %s", out)
	}

	// Real DB-backed Interceptor (not stubInterceptor) must enable ExecuteExtraTool
	// by default AND migrate the legacy 8-tool saved setting once.
	if !s.m.interceptor.IsToolEnabled("ExecuteExtraTool") {
		t.Fatal("fresh DB interceptor does not enable ExecuteExtraTool by default")
	}
	_ = s.m.pg.SetSetting("intercept_enabled_tools", `["Bash","WebFetch","web_search","shell_open","shell_send","Write","Edit","MultiEdit"]`)
	// Server construction already ran the one-time migration, so clear its flag to
	// exercise the upgrade path against a legacy saved list.
	_ = s.m.pg.SetSetting("intercept_enabled_tools_execute_extra_v1", "false")
	s.m.interceptor.Invalidate()
	s.seedDeferredInterceptTool()
	if !s.m.interceptor.IsToolEnabled("ExecuteExtraTool") {
		t.Fatal("legacy 8-tool intercept_enabled_tools was not migrated to include ExecuteExtraTool")
	}
}

// get_finding_traffic addresses the same finding from both numberings: the record id
// through finding_id, the exploration node id through finding_node_id. The two id
// spaces are independent, so each is resolved in its own space rather than "either".
func TestFindingTrafficToolsAcceptNodeID(t *testing.T) {
	s, initial, taskID := findingFixture(t, "traffic ids")
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})
	byRecord := workflowCall(t, ctx, s.toolGetFindingTraffic(), map[string]any{
		"finding_id": initial.FindingID,
	}, false)
	byNode := workflowCall(t, ctx, s.toolGetFindingTraffic(), map[string]any{
		"finding_node_id": initial.NodeID,
	}, false)
	// The LEGACY read form still works: old prompts put the node id in finding_id, and
	// reads must keep resolving it (writes stay strict).
	legacy := workflowCall(t, ctx, s.toolGetFindingTraffic(), map[string]any{
		"finding_id": initial.NodeID,
	}, false)
	if legacy != byNode {
		t.Fatalf("legacy read form stopped resolving the node id:\nlegacy=%s\nnode=%s", legacy, byNode)
	}
	if byRecord != byNode {
		t.Fatalf("node id and record id disagree:\nrecord=%s\nnode=%s", byRecord, byNode)
	}
	if !strings.Contains(byNode, "binding") && !strings.Contains(byNode, "\"version\"") {
		t.Fatalf("unexpected traffic summary: %s", byNode)
	}
	// Neither id → the error must name both accepted forms, not send the model off
	// guessing a third number.
	out := workflowCall(t, ctx, s.toolGetFindingTraffic(), map[string]any{
		"finding_id": int64(900000000000002),
	}, true)
	if !strings.Contains(out, "finding_node_id") {
		t.Fatalf("error does not name the accepted ids: %s", out)
	}
}

// The deterministic gate: login-page bounce and banner guesses are refused; real
// traffic-backed evidence is confirmed; text-only evidence lands as verifying.
func TestReportFindingTriageGate(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("triage gate", "gate", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	ts := agent.NewToolSet(task.Store, "worker")
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	ts.SetTaskID(taskID)
	tool := ts.AddFindingTool()

	call := func(input map[string]any) (string, bool) {
		raw, _ := json.Marshal(input)
		res, err := tool.Call(context.Background(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten(), res.IsError
	}

	// 1) Login-page redirect reported as an access-control bug → rejected.
	if out, isErr := call(map[string]any{
		"vulnclass": "越权访问", "severity": "high",
		"summary":  "访问 /admin 跳转回登录页但返回 200 OK",
		"evidence": "curl -i http://10.0.0.5/admin -> 302 to /login, browser lands on 200 ok 登录页",
	}); !isErr {
		t.Fatalf("login-page bounce not rejected: %s", out)
	}
	// 2) Bare version banner → rejected as reconnaissance.
	if out, isErr := call(map[string]any{
		"vulnclass": "RCE", "severity": "critical",
		"summary":  "Apache 2.4.49 detected, 版本号判断存在 CVE-2021-41773",
		"evidence": "Server: Apache/2.4.49",
	}); !isErr {
		t.Fatalf("version-only guess not rejected: %s", out)
	}
	// 3) Hedge language with no evidence → rejected.
	if out, isErr := call(map[string]any{
		"vulnclass": "SSRF", "severity": "medium",
		"summary":  "可能可以 SSRF，疑似内网可达",
		"evidence": "响应时间略有差异",
	}); !isErr {
		t.Fatalf("guess language not rejected: %s", out)
	}
	// 4) Text-only but substantive evidence → stored as verifying (not proof).
	out, isErr := call(map[string]any{
		"vulnclass": "SQLi", "severity": "high",
		"summary":  "search 参数存在报错注入",
		"evidence": "GET /search?q=1' -> SQL syntax error near '' at line 1",
	})
	if isErr {
		t.Fatalf("substantive text evidence rejected: %s", out)
	}
	if !strings.Contains(out, `"triage_state":"verifying"`) {
		t.Fatalf("text-only finding should be verifying: %s", out)
	}
}
