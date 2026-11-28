package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// stubInterceptor is a minimal Interceptor: rules and the judge are injected
// directly so the guard's gating decisions can be asserted without a database.
type stubInterceptor struct {
	mu       sync.Mutex
	tools    []string
	rules    []db.InterceptRule // matched by substring on the tool input
	judge    intercept.Decision
	judgeOn  bool
	matched  string
	judged   string
	loggedIn string
}

func newStubInterceptor(t *testing.T) *stubInterceptor {
	t.Helper()
	return &stubInterceptor{tools: []string{"Bash", "WebFetch", "ExecuteExtraTool"}}
}

func (s *stubInterceptor) setRules(r []db.InterceptRule) { s.mu.Lock(); s.rules = r; s.mu.Unlock() }
func (s *stubInterceptor) setTools(t []string)           { s.mu.Lock(); s.tools = t; s.mu.Unlock() }
func (s *stubInterceptor) setJudgeDecision(action, msg string) {
	s.mu.Lock()
	s.judge, s.judgeOn = intercept.Decision{Action: action, Message: msg}, true
	s.mu.Unlock()
}
func (s *stubInterceptor) lastMatchedTool() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matched
}
func (s *stubInterceptor) lastJudgedTool() string { s.mu.Lock(); defer s.mu.Unlock(); return s.judged }

func (s *stubInterceptor) IsToolEnabled(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tools {
		if t == name {
			return true
		}
	}
	return false
}

func (s *stubInterceptor) Match(toolName string, input []byte) (intercept.Decision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rules {
		if !r.Enabled {
			continue
		}
		if strings.Contains(string(input), r.Pattern) {
			s.matched = toolName
			return intercept.Decision{Action: r.Action, Message: r.Message, RuleID: r.ID}, true
		}
	}
	return intercept.Decision{}, false
}

func (s *stubInterceptor) Judge(_ context.Context, tool string, _ json.RawMessage) (intercept.Decision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.judgeOn {
		return intercept.Decision{}, false
	}
	s.judged = tool
	return s.judge, true
}

func (s *stubInterceptor) Log(_ context.Context, _ int64, dec intercept.Decision, toolName string, _ []byte, _ string) {
	s.mu.Lock()
	s.loggedIn = toolName
	s.mu.Unlock()
}

func (s *stubInterceptor) HandleAsk(context.Context, int64, intercept.Decision, string, []byte) bool {
	return true
}

// A blocked target must be refused at the tool boundary — for a direct Bash/curl
// and, crucially, for a deferred MCP/custom tool dispatched through
// ExecuteExtraTool, which used to be a free bypass of every intercept rule.
func TestAssetGateBlocksGovDomain(t *testing.T) {
	g := New()
	rules := []db.AssetInterceptRule{
		{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true},
		{Kind: "fuzzy_domain", Pattern: ".edu", Enabled: true},
	}
	g.SetAssetIntercept(func() (block, allow []db.AssetInterceptRule, err error) { return rules, nil, nil })

	blocked := func(tool, input string) bool {
		b, _, _ := g.Hooks().PreToolUse(context.Background(), tool, json.RawMessage(input))
		return b
	}

	if !blocked("Bash", `{"command":"curl -s http://www.example.gov.cn/portal"}`) {
		t.Fatal("curl to a .gov.cn host was allowed")
	}
	if !blocked("Bash", `{"command":"nmap -p 443 ok.example.edu"}`) {
		t.Fatal("scan of an .edu host was allowed")
	}
	// A URL hidden inside a nested MCP call is still refused.
	if !blocked("ExecuteExtraTool", `{"tool_name":"mcp__fetch__get","params":{"url":"https://a.gov.cn/x"}}`) {
		t.Fatal("ExecuteExtraTool bypassed the .gov.cn block")
	}
	// In-scope work passes.
	if blocked("Bash", `{"command":"curl -s http://10.0.0.5:8080/health"}`) {
		t.Fatal("in-scope internal request was blocked")
	}
	if blocked("Bash", `{"command":"nmap -sV -p- acme-corp.example"}`) {
		t.Fatal("in-scope hostname scan was blocked")
	}
	// No rules configured → everything passes (unit tests / chat sessions).
	g2 := New()
	if b, _, _ := g2.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x.gov.cn/"}`)); b {
		t.Fatal("gate blocked without any configured rule")
	}
}

// A task allow-list must restrict the gate to its own targets.
func TestAssetGateAllowList(t *testing.T) {
	g := New()
	allow := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: "internal.lab", Enabled: true, Action: "allow"}}
	g.SetAssetIntercept(func() (block, a []db.AssetInterceptRule, err error) { return nil, allow, nil })
	blocked := func(input string) bool {
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(input))
		return b
	}
	if blocked(`{"command":"curl http://app.internal.lab:8080/"}`) {
		t.Fatal("in-allowlist target blocked")
	}
	if !blocked(`{"command":"curl http://public.other.example/"}`) {
		t.Fatal("out-of-allowlist target allowed")
	}
}

// The intercept rules and the LLM judge must see the DEFERRED tool's real name and
// parameters, not the ExecuteExtraTool envelope — otherwise every MCP tool escapes
// the whole rule system.
func TestExecuteExtraToolReviewedAsInnerTool(t *testing.T) {
	g := New()
	if got, rest, ok := innerCall("ExecuteExtraTool", json.RawMessage(`{"tool_name":"mcp__fs__write","params":{"path":"/etc/hosts"}}`)); !ok || got != "mcp__fs__write" || !strings.Contains(string(rest), "/etc/hosts") {
		t.Fatalf("innerCall=(%q,%s,%v)", got, rest, ok)
	}
	if got, _, ok := innerCall("Bash", json.RawMessage(`{"command":"ls"}`)); ok || got != "Bash" {
		t.Fatalf("non-wrapper was unwrapped: %q %v", got, ok)
	}
	// Missing params → empty object, never nil (the inner tool's schema check needs JSON).
	if _, rest, ok := innerCall("ExecuteExtraTool", json.RawMessage(`{"tool_name":"x"}`)); !ok || string(rest) != "{}" {
		t.Fatalf("missing params not defaulted: %s", rest)
	}

	// Audit records the wrapper→inner chain so a reviewer sees both.
	g.record("ExecuteExtraTool→mcp__fs__write", "allow", "", "")
	audit := g.Audit()
	if len(audit) == 0 || !strings.Contains(audit[len(audit)-1].Tool, "→") {
		t.Fatalf("audit does not preserve the wrapper chain: %+v", audit)
	}
}

// G5 counter: a WAF/429 answer is attributed so graph_overview can surface pacing
// pressure instead of the planner hammering a target that is fighting back.
func TestAttributionsCountWAFAndRateLimit(t *testing.T) {
	g := New()
	hook := g.Hooks()
	hook.PreToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x/"}`))
	hook.PostToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x/"}`), []byte("403 Forbidden (WAF)"), false)
	hook.PostToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x/"}`), []byte("429 Too Many Requests"), false)
	hook.PostToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x/"}`), []byte("connection refused"), true)
	hook.PostToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x/"}`), []byte("200 OK"), false)

	got := g.Attributions()
	if got["blocked"] != 1 || got["waf"] != 1 {
		t.Fatalf("blocked/waf=%d/%d want 1/1 (%v)", got["blocked"], got["waf"], got)
	}
	if got["rate_limited"] != 1 {
		t.Fatalf("rate_limited=%d want 1 (%v)", got["rate_limited"], got)
	}
	if got["error"] != 1 || got["ok"] != 1 {
		t.Fatalf("error/ok=%d/%d want 1/1 (%v)", got["error"], got["ok"], got)
	}
}

// ExtractTargets is the egress decision's input: it must find hosts in shell
// commands, WebFetch URLs and arbitrary tool JSON, without mistaking words for
// hosts, and it must be bounded.
func TestExtractTargets(t *testing.T) {
	domains, ips, urls := ExtractTargets("WebFetch", json.RawMessage(`{"url":"https://api.acme.example:8443/v1?x=1"}`))
	if len(domains) != 1 || domains[0] != "api.acme.example" || len(urls) != 1 {
		t.Fatalf("web fetch targets: %v %v %v", domains, ips, urls)
	}
	domains, ips, _ = ExtractTargets("Bash", json.RawMessage(`{"command":"curl -sS http://10.9.8.7:8080/x && ping example.org"}`))
	if len(ips) != 1 || ips[0] != "10.9.8.7" {
		t.Fatalf("ips=%v", ips)
	}
	foundOrg := false
	for _, d := range domains {
		if d == "example.org" {
			foundOrg = true
		}
	}
	if !foundOrg {
		t.Fatalf("bare host in a shell command not extracted: %v", domains)
	}
	// Words, flags and paths must not be read as hosts.
	domains, ips, urls = ExtractTargets("Bash", json.RawMessage(`{"command":"rm -rf ./build && ls -la /tmp/install"}`))
	if len(domains) != 0 || len(ips) != 0 || len(urls) != 0 {
		t.Fatalf("false positives: d=%v i=%v u=%v", domains, ips, urls)
	}
}

// An in-scope host must not vouch for an adjacent out-of-scope one: a task allow
// list of allowed.lab must refuse `nmap allowed.lab evil.example` as a whole.
// Evaluating the union of a command's targets (the old behaviour) let the allowed
// host satisfy the allow list for the entire command.
func TestAssetGatePerTargetNotUnion(t *testing.T) {
	g := New()
	allow := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: "allowed.lab", Enabled: true, Action: "allow"}}
	g.SetAssetIntercept(func() (block, a []db.AssetInterceptRule, err error) { return nil, allow, nil })

	blocked := func(input string) bool {
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(input))
		return b
	}
	if blocked(`{"command":"nmap -p 1-1000 allowed.lab"}`) {
		t.Fatal("in-allowlist single target blocked")
	}
	if !blocked(`{"command":"nmap -p 1-1000 allowed.lab evil.example"}`) {
		t.Fatal("out-of-allowlist neighbour rode along with an allowed host")
	}
	if !blocked(`{"command":"curl http://allowed.lab/ && curl http://evil.example/steal"}`) {
		t.Fatal("second URL in the same command escaped the allow list")
	}

	// Block rules behave the same way: one forbidden target fails the call even
	// when an allowed one precedes it.
	g2 := New()
	g2.SetAssetIntercept(func() (block, a []db.AssetInterceptRule, err error) {
		return []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true}}, nil, nil
	})
	if !blockedBy(g2, `{"command":"curl http://ok.example/ ; curl http://x.gov.cn/"}`) {
		t.Fatal("blocked host bypassed by pairing it with a clean one")
	}
}

func blockedBy(g *Guard, input string) bool {
	b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(input))
	return b
}

// Past the target cap the call is refused outright: truncating would let target
// 501 (a forbidden host) ride along inside a bulk scan list.
func TestAssetGateRefusesTruncatedTargetList(t *testing.T) {
	g := New()
	g.SetAssetIntercept(func() (block, allow []db.AssetInterceptRule, err error) {
		return []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true}}, nil, nil
	})
	var b strings.Builder
	b.WriteString(`{"command":"for h in`)
	for i := 0; i <= maxTargetsPerCall+5; i++ {
		fmt.Fprintf(&b, " host%d.example", i)
	}
	b.WriteString(`; do curl http://$h/; done"}`)
	blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(b.String()))
	if !blocked {
		t.Fatalf("a target list over %d entries was evaluated instead of refused", maxTargetsPerCall)
	}
	// The truncation flag is what the gate keys on; assert it directly too.
	if _, truncated := ExtractTargetGroups("Bash", json.RawMessage(b.String())); !truncated {
		t.Fatal("ExtractTargetGroups did not report truncation")
	}
}

// IPv6 literals must be extracted and gated: bare, bracketed and with a port.
// A missed IPv6 target is a silent bypass of every CIDR/block rule.
func TestAssetGateMatchesIPv6Literals(t *testing.T) {
	cases := []struct {
		name   string
		cmd    string
		blocks bool
	}{
		{"bare compressed", `{"command":"curl -g http://2001:db8::1/x"}`, true},
		{"bare bracketed", `{"command":"curl http://[2001:db8::1]/x"}`, true},
		{"bracketed with port", `{"command":"nmap -6 [2001:db8::1]:8080"}`, true},
		{"full form", `{"command":"curl http://2001:0db8:0000:0000:0000:0000:0000:0001/x"}`, true},
		{"outside the cidr", `{"command":"curl http://[2001:db9::1]/x"}`, false},
	}
	g := New()
	g.SetAssetIntercept(func() (block, allow []db.AssetInterceptRule, err error) {
		return []db.AssetInterceptRule{{Kind: "cidr", Pattern: "2001:db8::/32", Enabled: true}}, nil, nil
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(tc.cmd))
			if blocked != tc.blocks {
				t.Fatalf("blocked=%v want %v for %s", blocked, tc.blocks, tc.cmd)
			}
		})
	}
	// An out-of-CIDR address must NOT be blocked by a CIDR rule.
	g2 := New()
	g2.SetAssetIntercept(func() (block, allow []db.AssetInterceptRule, err error) {
		return []db.AssetInterceptRule{{Kind: "cidr", Pattern: "2001:db8::/32", Enabled: true}}, nil, nil
	})
	if blockedBy(g2, `{"command":"curl http://[2001:dba::1]/x"}`) {
		t.Fatal("address outside the CIDR was blocked")
	}
	// And the extractor must actually produce the IPv6 literal.
	_, ips, _ := ExtractTargets("Bash", json.RawMessage(`{"command":"curl http://[2001:db8::1]:8080/x"}`))
	found := false
	for _, ip := range ips {
		if ip == "2001:db8::1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("IPv6 literal not extracted: %v", ips)
	}
}

// Deferred MCP / custom tools dispatched through ExecuteExtraTool must reach the
// DB rules AND the LLM judge. The enabled-tools list only names eight built-ins, so
// gating on the INNER name silently dropped every deferred tool — the wrapper was
// reviewed, the payload that ran was not.
func TestExecuteExtraToolHitsRulesAndJudge(t *testing.T) {
	ic := newStubInterceptor(t)
	g := newGuard(ic)

	// Rule: any tool_input containing "rm -rf /" is denied.
	ic.setRules([]db.InterceptRule{{
		ID: 1, Name: "danger-delete", Enabled: true, Priority: 10,
		MatchTarget: "tool_input", MatchType: "string", Pattern: "rm -rf /", Action: "deny",
		Message: "禁止删除",
	}})
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "ExecuteExtraTool",
		json.RawMessage(`{"tool_name":"mcp__fs__exec","params":{"cmd":"rm -rf /"}}`))
	if !blocked {
		t.Fatal("deferred MCP tool bypassed the DB intercept rule")
	}
	if !strings.Contains(msg, "禁止删除") {
		t.Fatalf("block message lost the rule text: %q", msg)
	}
	// The judge must likewise see the inner name.
	if got := ic.lastMatchedTool(); got != "mcp__fs__exec" {
		t.Fatalf("rule was matched against %q, want the inner tool name", got)
	}

	// With only the judge enabled (no rule), the inner call must still be judged.
	ic.setRules(nil)
	ic.setJudgeDecision("deny", "模型拒绝")
	blocked, _, _ = g.Hooks().PreToolUse(context.Background(), "ExecuteExtraTool",
		json.RawMessage(`{"tool_name":"custom_http","params":{"url":"http://10.0.0.5/"}}`))
	if !blocked {
		t.Fatal("deferred custom tool bypassed the LLM judge")
	}
	if got := ic.lastJudgedTool(); got != "custom_http" {
		t.Fatalf("judge saw %q, want custom_http", got)
	}

	// Once the user disables ExecuteExtraTool itself, the deferred surface is off.
	ic.setTools([]string{"Bash"})
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "ExecuteExtraTool",
		json.RawMessage(`{"tool_name":"mcp__fs__exec","params":{"cmd":"rm -rf /"}}`)); blocked {
		t.Fatal("disabled deferred-tool surface still gated")
	}
}

// A platform refusal is not the target fighting back: it must not inflate the
// blocked/waf counters the planner reads to decide "the site is defending itself".
func TestPlatformBlockNotAttributedToTarget(t *testing.T) {
	g := New()
	hooks := g.Hooks()
	hooks.PreToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x.gov.cn/"}`))
	hooks.PostToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x.gov.cn/"}`),
		[]byte("【ARTEX 平台管控·非目标防御】此调用被平台拦截。原因：命中资产拦截规则。此操作被禁止。"), true)
	if got := g.Attributions(); len(got) != 0 {
		t.Fatalf("platform block was attributed to the target: %v", got)
	}
	// A genuine target 403 still counts.
	hooks.PostToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl http://x/"}`),
		[]byte("HTTP/1.1 403 Forbidden"), false)
	if got := g.Attributions(); got["waf"] != 1 {
		t.Fatalf("target WAF not counted: %v", got)
	}
}

// An unreadable rule table must not read as "no rules". The gate exists to stop
// out-of-scope targets, and a database error is precisely when a forbidden host
// would otherwise ride through — so the call is refused, not allowed.
func TestAssetGateFailsClosedOnRuleReadError(t *testing.T) {
	g := New()
	g.SetAssetIntercept(func() (block, allow []db.AssetInterceptRule, err error) {
		return nil, nil, errors.New("rule table unavailable")
	})
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl https://anything.example/"}`))
	if !blocked {
		t.Fatal("rule read error allowed the call")
	}
	if !strings.Contains(msg, "读取失败") {
		t.Fatalf("block message lost the cause: %q", msg)
	}
}

// A broken rule table must not block local write-back. A worker whose run is being
// cut short has to be able to hand its findings over; record_fact names no target,
// so scope is not a question about it.
func TestAssetGateAllowsLocalWriteBackOnRuleReadError(t *testing.T) {
	g := New()
	g.SetAssetIntercept(func() (block, allow []db.AssetInterceptRule, err error) {
		return nil, nil, errors.New("rule table unavailable")
	})
	for _, tool := range []string{"record_fact", "TodoWrite", "report_finding", "Read", "Edit"} {
		blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), tool, json.RawMessage(`{"summary":"x"}`))
		if blocked {
			t.Fatalf("%s was blocked by a rule read error: %s", tool, msg)
		}
	}
	// An outbound-capable call in the same state is still refused.
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(`{"command":"curl https://x.example/"}`)); !blocked {
		t.Fatal("outbound call allowed while the rules were unreadable")
	}
	// An unknown tool name defaults to the gated side.
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "some_mcp_fetcher", json.RawMessage(`{"url":"https://x.example/"}`)); !blocked {
		t.Fatal("unknown tool treated as local")
	}
}
