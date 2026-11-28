package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// The deterministic gate's decision table. Each row pins one documented
// false-positive shape or one accepted shape, so a future prompt tweak cannot
// quietly widen it.
func TestClassifyFindingEvidence(t *testing.T) {
	cases := []struct {
		name       string
		vulnClass  string
		summary    string
		evidence   string
		refs       []string
		traffic    int
		wantState  string
		wantReject bool
	}{
		{
			name: "login bounce as access control", vulnClass: "越权访问",
			summary:   "未授权访问 /admin",
			evidence:  "curl -i /admin -> 302 to /login，最终返回 200 ok 登录页",
			wantState: TriageRejected, wantReject: true,
		},
		{
			// A traffic pointer proves an exchange happened, not that it shows impact.
			name: "traffic ref needs impact check", vulnClass: "IDOR",
			summary:  "读取了他人订单",
			evidence: "GET /api/orders/9001 returns another user's row",
			refs:     []string{"traffic:12"}, traffic: 0,
			wantState: TriageVerifying,
		},
		{
			name: "version banner", vulnClass: "RCE",
			summary:   "Apache 2.4.49 版本号判断存在路径穿越",
			evidence:  "Server: Apache/2.4.49",
			wantState: TriageRejected, wantReject: true,
		},
		{
			name: "hedged guess", vulnClass: "SSRF",
			summary:   "可能可以 SSRF",
			evidence:  "响应时间差异较大，疑似内网可达",
			wantState: TriageRejected, wantReject: true,
		},
		{
			name: "empty report", vulnClass: "XSS",
			summary: "", evidence: "",
			wantState: TriageRejected, wantReject: true,
		},
		{
			name: "substantive text only", vulnClass: "SQLi",
			summary:   "search 参数报错注入",
			evidence:  `GET /search?q=1' -> SQL syntax error near '' at line 1`,
			wantState: TriageVerifying,
		},
		{
			// A bound snapshot is not proof on its own: the write path cannot see
			// whether the response is the login page, so the background triager must
			// read the bytes before this may prove a goal.
			name: "bound traffic needs impact check", vulnClass: "SSRF",
			summary:   "服务端请求了内网地址",
			evidence:  "callback hit",
			traffic:   1,
			wantState: TriageVerifying,
		},
		{
			name: "oast ref is strong proof", vulnClass: "blind RCE",
			summary:   "无回显命令执行",
			evidence:  "callback received from the target",
			refs:      []string{"oast:3"},
			wantState: TriageConfirmed,
		},
		{
			// Same rule: an activity row is a command that ran, not proof of impact.
			name: "activity ref needs impact check", vulnClass: "cmd injection",
			summary:   "命令执行回显",
			evidence:  "id -> uid=0(root)",
			refs:      []string{"activity:42"},
			wantState: TriageVerifying,
		},
		{
			name: "artifact ref alone is weak", vulnClass: "info leak",
			summary:   "泄露了配置文件",
			evidence:  "见附件",
			refs:      []string{"artifact:leak.txt"},
			wantState: TriageVerifying,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyFindingEvidence(tc.vulnClass, tc.summary, tc.evidence, "", tc.refs, tc.traffic)
			if got.State != tc.wantState || got.Reject != tc.wantReject {
				t.Fatalf("gate=(%q reject=%v reason=%q) want (%q reject=%v)", got.State, got.Reject, got.Reason, tc.wantState, tc.wantReject)
			}
			if got.Reason == "" {
				t.Fatal("verdict without a reason")
			}
		})
	}
}

// A finding whose triage state is verifying/rejected cannot prove a goal: the
// whole point of the gate is that an unverified guess cannot end the task.
func TestVerifyingFindingCannotProveGoal(t *testing.T) {
	ts := NewToolSet(nil, "planner")
	payload, _ := json.Marshal(map[string]any{
		"summary": "maybe an RCE", "severity": "critical", "triage_state": TriageVerifying,
	})
	node := &db.Node{ID: 5, Kind: db.KindFinding, State: "confirmed", Payload: payload}
	err := ts.validateProofAnchor(node)
	if err == nil {
		t.Fatal("a verifying finding was accepted as goal proof")
	}
	if !strings.Contains(err.Error(), TriageVerifying) {
		t.Fatalf("error does not mention the triage state: %v", err)
	}

	// Confirmed (and legacy rows with no state at all) still prove goals.
	payload, _ = json.Marshal(map[string]any{"summary": "real RCE", "triage_state": TriageConfirmed})
	if err := ts.validateProofAnchor(&db.Node{ID: 6, Kind: db.KindFinding, State: "confirmed", Payload: payload}); err != nil {
		t.Fatalf("confirmed finding rejected: %v", err)
	}
	legacy, _ := json.Marshal(map[string]any{"summary": "legacy finding"})
	if err := ts.validateProofAnchor(&db.Node{ID: 7, Kind: db.KindFinding, State: "confirmed", Payload: legacy}); err != nil {
		t.Fatalf("legacy finding without triage_state rejected: %v", err)
	}
}

// The host can switch the gate off for a task type where its heuristics misfire;
// the disabled path must never reject.
func TestTriageGateCanBeDisabled(t *testing.T) {
	prev := TriageGateDisabled
	t.Cleanup(func() { TriageGateDisabled = prev })
	TriageGateDisabled = func() bool { return true }
	got := triageFinding("越权", "未授权访问", "跳转回登录页", "", nil, 0)
	if got.Reject || got.State != TriageConfirmed {
		t.Fatalf("disabled gate still rejected: %+v", got)
	}
}

// FindingTriageState defaults to confirmed for anything that is not a finding or
// carries no state, so historical rows keep working.
func TestFindingTriageStateDefaults(t *testing.T) {
	if st := FindingTriageState(nil); st != TriageConfirmed {
		t.Fatalf("nil=%q", st)
	}
	if st := FindingTriageState(&db.Node{ID: 1, Kind: db.KindFact}); st != TriageConfirmed {
		t.Fatalf("non-finding=%q", st)
	}
	if st := FindingTriageState(&db.Node{ID: 1, Kind: db.KindFinding, Payload: json.RawMessage(`{}`)}); st != TriageConfirmed {
		t.Fatalf("empty payload=%q", st)
	}
	if st := FindingTriageState(&db.Node{ID: 1, Kind: db.KindFinding, Payload: json.RawMessage(`{"triage_state":"  VERIFYING "}`)}); st != TriageVerifying {
		t.Fatalf("normalization failed: %q", st)
	}
}

// A hedged summary over SUBSTANTIAL evidence must not be rejected: non-HTTP
// findings have no traffic/oast pointer, and their honest conclusion reads
// "attackers can read the config, which may lead to lateral movement". Only a
// hedge that IS the whole report is refused.
func TestHedgedSummaryWithRealEvidenceIsVerifyingNotRejected(t *testing.T) {
	evidence := "objdump -d ./svc | grep -A4 'mmap' -> RWX segment at 0x405000; " +
		"printf 'AAAA...' | nc 10.9.9.9 9000 -> SIGSEGV, RIP=0x41414141 (attacker-controlled)"
	got := classifyFindingEvidence("memory corruption", "攻击者可控制 RIP，可能导致横向移动", evidence, "", nil, 0)
	if got.Reject {
		t.Fatalf("substantive non-HTTP evidence was rejected: %+v", got)
	}
	if got.State != TriageVerifying {
		t.Fatalf("state=%q want verifying (stored, cannot prove goal)", got.State)
	}

	// A hedge in the summary with thin evidence stays rejected.
	thin := classifyFindingEvidence("SSRF", "可能可以 SSRF", "响应略有差异", "", nil, 0)
	if !thin.Reject {
		t.Fatalf("thin hedged report was accepted: %+v", thin)
	}

	// A hedge word inside solid evidence but with a factual summary is accepted
	// too: the summary alone decides whether the claim itself is a guess.
	factual := classifyFindingEvidence("memory corruption", "RIP 可控导致命令执行",
		evidence+" (attackers may chain this)", "", nil, 0)
	if factual.Reject {
		t.Fatalf("factual summary with a hedged aside was rejected: %+v", factual)
	}

	// A PoC counts as substantial even when the evidence prose is short.
	withPoC := classifyFindingEvidence("RCE", "可能可以执行命令",
		"见 PoC", "GET /cgi?x=%3Bid", nil, 0)
	if withPoC.Reject && thinEvidence("见 PoC", "GET /cgi?x=%3Bid") {
		t.Fatalf("PoC text not counted as substance: %+v", withPoC)
	}
}

// An existence-only reference must not confirm a finding: this drives the real
// report_finding entry (no traffic binding) and asserts the stored state.
func TestReportFindingWithOnlyActivityRefStaysVerifying(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("refs only", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "probe"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "worker")
	ts.SetOwnerNode(intentID)
	report := ts.AddFindingTool()

	actID, err := store.AppendActivity(db.Activity{
		NodeID: &intentID, Worker: "worker", Kind: "tool_result", Tool: "Bash",
		Summary: "id -> uid=0(root)",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, callErr := report.Call(context.Background(), json.RawMessage(
		`{"vulnclass":"命令注入","severity":"high","summary":"/api/ping 存在命令注入","evidence":"id -> uid=0(root)","evidence_refs":["activity:`+itoa(actID)+`"]}`), nil)
	if callErr != nil || res.IsError {
		t.Fatalf("report_finding: %v %s", callErr, res.Flatten())
	}
	facts, err := store.ListByKind(db.KindFinding, 5)
	if err != nil || len(facts) != 1 {
		t.Fatalf("findings=%d err=%v", len(facts), err)
	}
	if st := FindingTriageState(facts[0]); st != TriageVerifying {
		t.Fatalf("existence-only ref produced triage=%q, want verifying", st)
	}
}

// Real command output contains the exact high-information line the report cites.
func TestTriageMatchEvidenceInOutputsAcceptsRealToolOutput(t *testing.T) {
	const apkLine = `const-string v3, "AKIAIOSFODNN7EXAMPLE"    # hardcoded AWS key`
	apkEvidence := "jadx 分析 com/example/Config.smali 得到如下内容\n" + apkLine
	matched, anchor := MatchEvidenceInOutputs(
		"信息泄露", "APK 内硬编码 AWS 密钥",
		apkEvidence,
		[]string{"cmd-output: " + apkLine + "\n12:38:51.120  I/artex: ready"},
	)
	if !matched || anchor != apkLine {
		t.Fatalf("APK hardcoded key not matched: matched=%v anchor=%q", matched, anchor)
	}

	const sqlLine = `{"id":9001,"user":"alice","password_hash":"5f4dcc3b5aa765d61d8327deb882cf99"}`
	sqlEvidence := "Presto 查询 mysql.orders 返回了其他用户的完整记录\n" + sqlLine
	matched, anchor = MatchEvidenceInOutputs(
		"SQL 注入", "Presto 查询回显了他人口令哈希",
		sqlEvidence,
		[]string{"Trino> SELECT * FROM mysql.orders WHERE id=9001;\n" + sqlLine},
	)
	if !matched || anchor != sqlLine {
		t.Fatalf("Presto SQL echo not matched: matched=%v anchor=%q", matched, anchor)
	}
}

// A fabricated report has no line that appeared in tool output.
func TestTriageMatchEvidenceInOutputsRejectsFabricatedNarrative(t *testing.T) {
	matched, anchor := MatchEvidenceInOutputs(
		"SSRF", "服务端请求了内网地址",
		"攻击者能够通过该接口读取任意用户的订单信息，这是一个严重的信息泄露问题",
		[]string{"命令执行完成，没有发现异常"},
	)
	if matched || anchor != "" {
		t.Fatalf("fabricated natural-language evidence matched: %v %q", matched, anchor)
	}

	// A long English narrative has letters but no machine-checkable data signal.
	anchors := ExtractEvidenceAnchors("the server returned a normal response with no sensitive content")
	if len(anchors) != 0 {
		t.Fatalf("natural-language line became an anchor: %#v", anchors)
	}
}

// Generic HTTP headers and command input are not evidence fingerprints.
func TestTriageExtractEvidenceAnchorsSkipsLowSignalLines(t *testing.T) {
	evidence := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: application/json\r\n" +
		"$ curl -i http://target/api/users\r\nok\r\n" +
		"用户信息读取成功，影响范围较大\r\n" +
		`{"users":[{"id":1,"name":"admin"}]}`
	anchors := ExtractEvidenceAnchors(evidence)
	if len(anchors) != 1 || anchors[0] != `{"users":[{"id":1,"name":"admin"}]}` {
		t.Fatalf("unexpected anchors: %#v", anchors)
	}
	if matched, _ := MatchEvidenceInOutputs("IDOR", "未授权读取用户列表",
		evidence, []string{"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: application/json"}); matched {
		t.Fatal("generic HTTP headers matched as evidence")
	}
}

// A login form is a common captured page that proves no impact; it must not
// promote a finding even when the cited markup appears in it.
func TestTriageMatchEvidenceInOutputsSkipsLoginForm(t *testing.T) {
	evidence := `<form action="/login" method="post">` + "\n" + `<input type="password" name="pwd">`
	page := `<html><body><form action="/login" method="post"><input type="password" name="pwd"></form></body></html>`
	if matched, anchor := MatchEvidenceInOutputs("越权访问", "未授权访问后台", evidence, []string{page}); matched {
		t.Fatalf("login form matched: %q", anchor)
	}
	// The same bytes carrying real business data are not a bare login page.
	if matched, _ := MatchEvidenceInOutputs("信息泄露", "后台泄露了用户令牌", evidence,
		[]string{page + `<script>var token="eyJhbGciOiJIUzI1NiJ9";</script>`}); !matched {
		t.Fatal("login page with business data was skipped")
	}
}

// Short lines can still be evidence when they carry a structured credential or
// identifier token; the rule is generic and matches no product or event name.
func TestTriageShortStructuredTokenIsEvidence(t *testing.T) {
	for _, line := range []string{"key=abc12345", "id={A1B2C3D4}", "token: abcd1234"} {
		anchors := ExtractEvidenceAnchors(line)
		if len(anchors) != 1 || anchors[0] != line {
			t.Fatalf("structured short line %q produced anchors %#v", line, anchors)
		}
	}
	if anchors := ExtractEvidenceAnchors("服务正常返回"); len(anchors) != 0 {
		t.Fatalf("natural-language short line became an anchor: %#v", anchors)
	}
	if anchors := ExtractEvidenceAnchors("key="); len(anchors) != 0 {
		t.Fatalf("empty structured value became an anchor: %#v", anchors)
	}
}
