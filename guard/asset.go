package guard

import (
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// AssetInterceptHook supplies this task's asset block/allow rules to the guard.
// The server wires it to the asset store (global rules ∪ task rules); nil means
// no asset-level gating, which keeps unit tests and chat sessions unaffected.
//
// An error must NOT be read as "no rules": a rule table that cannot be read is
// exactly the moment a forbidden target would slip through, so the gate fails
// closed (see assetGateDecision).
type AssetInterceptHook func() (block, allow []db.AssetInterceptRule, err error)

// SetAssetIntercept installs the asset-rule source. It is read on every gated
// tool call, so a rule edit takes effect immediately without rebuilding the Guard.
func (g *Guard) SetAssetIntercept(fn AssetInterceptHook) {
	g.mu.Lock()
	g.assetRules = fn
	g.mu.Unlock()
}

// TargetGroup is ONE independently addressable target extracted from a tool call:
// the host, its IPs (an IP literal yields itself), and the full URLs that named it.
// Rules are evaluated per group, never over the union of a command's targets — a
// union lets one allowed host vouch for an adjacent forbidden one.
type TargetGroup struct {
	Domains []string
	IPs     []string
	URLs    []string
}

// Label renders the group for a block message.
func (tg TargetGroup) Label() string {
	switch {
	case len(tg.URLs) > 0:
		return tg.URLs[0]
	case len(tg.Domains) > 0:
		return tg.Domains[0]
	case len(tg.IPs) > 0:
		return tg.IPs[0]
	}
	return ""
}

// maxTargetsPerCall bounds how many distinct targets one tool call may name. Past
// the cap the call is REFUSED rather than truncated: silently ignoring target 501
// is exactly how a forbidden host rides along inside a bulk scan list.
const maxTargetsPerCall = 500

// assetGateDecision evaluates each target of one tool call against the asset rules.
// ok=false means the call must be blocked, with reason carrying the human-readable
// hit. EVERY extracted target must pass — one refusal fails the whole call.
func (g *Guard) assetGateDecision(tool string, input json.RawMessage) (bool, string) {
	g.mu.Lock()
	fn := g.assetRules
	g.mu.Unlock()
	if fn == nil {
		return true, ""
	}
	// Ask whether this call CAN leave the machine BEFORE reading the rules. A pure
	// write-back (record_fact, TodoWrite) or a local file edit names no outbound
	// target, so scope is not a question about it — and reading a broken rule table
	// there would block the very write-back a stalled worker must perform to hand
	// its findings over. Only calls that can reach a target are gated.
	if !canReachTarget(tool, input) {
		return true, ""
	}
	block, allow, err := fn()
	if err != nil {
		// Fail closed: an unreadable rule table says nothing about scope, and
		// treating it as "no rules" is the one direction that cannot be undone
		// after a request has left for a forbidden target.
		return false, "资产拦截规则读取失败，无法确认目标是否在授权范围内，本次调用已拒绝：" + err.Error()
	}
	if len(block) == 0 && !db.HasEnabledAssetRule(allow) {
		return true, ""
	}
	groups, truncated := ExtractTargetGroups(tool, input)
	if truncated {
		return false, "本次调用目标超过 " + itoa(maxTargetsPerCall) + " 个，已拒绝以阻止超范围目标混入；请分批在授权范围内执行"
	}
	for _, grp := range groups {
		if d := db.EvaluateAssetGate(block, allow, grp.Domains, grp.IPs, grp.URLs); !d.Allowed {
			label := grp.Label()
			if label != "" {
				return false, d.Reason + "（目标 " + label + "）"
			}
			return false, d.Reason
		}
	}
	return true, ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// reAbsoluteURL matches any absolute URL inside a free-form string (a shell
// command, a tool argument). Deliberately permissive: the goal is to catch the
// host being contacted, not to validate the URL.
var reAbsoluteURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s'"<>|;(){}\[\]]+`)

// reBracketedIPv6 matches an RFC 3986 bracketed IPv6 literal with an optional port
// (`[2001:db8::1]`, `[2001:db8::1]:8080`) as it appears outside a URL.
var reBracketedIPv6 = regexp.MustCompile(`\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?`)

// reHostLike matches a bare host, an IPv4 literal or a BARE IPv6 literal, each with
// an optional port. IPv6 is matched in two shapes: the compressed form with "::"
// and the full 8-group form, because a bare address would otherwise be chopped at
// the first colon (and every fragment would fail net.ParseIP, so the target would
// be dropped entirely — a silent bypass).
var reHostLike = regexp.MustCompile(
	`(?:^|[\s=/'"@])(` +
		// bare IPv6, compressed ("2001:db8::1") or full ("2001:0db8:0:0:0:0:0:1")
		`(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?` +
		`|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}` +
		// hostname
		`|(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}` +
		// IPv4
		`|(?:\d{1,3}\.){3}\d{1,3}` +
		`)(?::(\d{1,5}))?(?:[/\s'"]|$)`)

// ExtractTargets flattens ExtractTargetGroups into one candidate list. Kept for
// callers that only need "which hosts does this call mention" (diagnostics and
// tests). GATE DECISIONS MUST USE ExtractTargetGroups — the union form lets one
// in-scope host vouch for an out-of-scope neighbour.
func ExtractTargets(tool string, input json.RawMessage) (domains, ips, urls []string) {
	groups, _ := ExtractTargetGroups(tool, input)
	seen := map[string]bool{}
	for _, grp := range groups {
		for _, d := range grp.Domains {
			if !seen["d:"+d] {
				seen["d:"+d] = true
				domains = append(domains, d)
			}
		}
		for _, ip := range grp.IPs {
			if !seen["i:"+ip] {
				seen["i:"+ip] = true
				ips = append(ips, ip)
			}
		}
		for _, u := range grp.URLs {
			if !seen["u:"+u] {
				seen["u:"+u] = true
				urls = append(urls, u)
			}
		}
	}
	return domains, ips, urls
}

// ExtractTargetGroups pulls the independently addressable targets a tool call is
// about to contact, one group per target. truncated reports that the call named
// more than maxTargetsPerCall targets, which the caller must treat as a refusal
// (never as "evaluate the first N").
func ExtractTargetGroups(tool string, input json.RawMessage) (groups []TargetGroup, truncated bool) {
	type builder struct {
		hosts   []string // bare hosts / IP literals in first-seen order
		urls    []string
		hostSet map[string]bool
		urlSet  map[string]bool
	}
	b := &builder{hostSet: map[string]bool{}, urlSet: map[string]bool{}}
	addHost := func(host string) {
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if host == "" || b.hostSet[host] {
			return
		}
		b.hostSet[host] = true
		b.hosts = append(b.hosts, host)
	}
	addURL := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || b.urlSet[raw] {
			return
		}
		b.urlSet[raw] = true
		b.urls = append(b.urls, raw)
	}
	absorbHost := func(host string) {
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if host == "" {
			return
		}
		// net.ParseIP accepts v4 and v6; either way the host is an address, and it
		// is kept verbatim (the asset rules match on the canonical text, and
		// net.ParseIP inside EvaluateAssetGate normalizes for CIDR rules).
		if ip := net.ParseIP(host); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				addHost(v4.String())
			} else {
				addHost(ip.String())
			}
			return
		}
		addHost(strings.ToLower(host))
	}

	var args struct {
		URL     string `json:"url"`
		Command string `json:"command"`
		Text    string `json:"text"`
		Query   string `json:"q"`
	}
	_ = json.Unmarshal(input, &args)

	switch tool {
	case "WebFetch", "web_search":
		if u, err := url.Parse(strings.TrimSpace(args.URL)); err == nil && u.Hostname() != "" {
			addURL(args.URL)
			absorbHost(u.Hostname())
		}
	}

	// Free-form text: shell commands, interactive-shell payloads, search queries.
	// strings.Join would turn three empty fields into "\n\n" (non-empty), so the
	// no-text fallback below must test the fields themselves.
	text := strings.TrimSpace(strings.Join([]string{args.Command, args.Text, args.Query}, "\n"))
	if text == "" && tool != "WebFetch" && tool != "web_search" {
		// Unknown tool with a URL-ish argument (custom HTTP tools, MCP fetchers):
		// still scan the raw input as text.
		text = string(input)
	}
	for _, m := range reAbsoluteURL.FindAllString(text, maxTargetsPerCall+1) {
		addURL(m)
		if u, err := url.Parse(m); err == nil && u.Hostname() != "" {
			absorbHost(u.Hostname())
		}
	}
	for _, m := range reBracketedIPv6.FindAllStringSubmatch(text, maxTargetsPerCall+1) {
		if len(m) < 2 {
			continue
		}
		absorbHost(m[1])
	}
	// reHostLike consumes the delimiter on BOTH sides, so a naive FindAll over
	// "allowed.lab evil.example" would eat the space between them and never see the
	// second host. Resume at the end of the captured host instead, letting the
	// trailing delimiter serve as the next match's leading one.
	forEachHostLike(text, func(host string) { absorbHost(host) })

	if len(b.hosts) > maxTargetsPerCall || len(b.urls) > maxTargetsPerCall {
		return nil, true
	}

	// One group per bare host, plus one group per URL (so an exact_url/fuzzy_url
	// rule sees the path it names). A URL's host is already a group of its own, so
	// the URL group carries the host too — EvaluateAssetGate matches domains, ips
	// and urls independently.
	for _, h := range b.hosts {
		grp := TargetGroup{}
		if net.ParseIP(h) != nil {
			grp.IPs = []string{h}
		} else {
			grp.Domains = []string{h}
		}
		groups = append(groups, grp)
	}
	for _, raw := range b.urls {
		grp := TargetGroup{URLs: []string{raw}}
		if u, err := url.Parse(raw); err == nil {
			host := u.Hostname()
			if net.ParseIP(host) != nil {
				grp.IPs = []string{host}
			} else if host != "" {
				grp.Domains = []string{strings.ToLower(host)}
			}
		}
		groups = append(groups, grp)
	}
	return groups, false
}

// forEachHostLike calls fn for every bare host / IP literal in text, with
// overlapping-delimiter-safe scanning (see the call site).
func forEachHostLike(text string, fn func(string)) {
	offset := 0
	for offset < len(text) {
		rest := text[offset:]
		loc := reHostLike.FindStringSubmatchIndex(rest)
		if loc == nil {
			return
		}
		host := rest[loc[2]:loc[3]]
		if host != "" {
			fn(host)
		}
		// loc[3] is the end of the host group; resuming there leaves the trailing
		// delimiter available for the next match.
		next := offset + loc[3]
		if next <= offset {
			return
		}
		offset = next
	}
}

// innerCall unwraps ExecuteExtraTool/mcp dispatch so the rules (and the LLM judge)
// see the tool that is REALLY about to run and its real parameters. Without this a
// deferred MCP tool or a deferred custom tool bypasses every intercept rule that
// keys on tool_name/tool_input.
//
// Only one level is unwrapped: ExecuteExtraTool's own schema has no tool_name, so
// a nested ExecuteExtraTool cannot occur.
func innerCall(tool string, input json.RawMessage) (string, json.RawMessage, bool) {
	if tool != executeExtraToolName {
		return tool, input, false
	}
	var args struct {
		ToolName string          `json:"tool_name"`
		Params   json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(input, &args); err != nil || strings.TrimSpace(args.ToolName) == "" {
		return tool, input, false
	}
	params := args.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	return args.ToolName, params, true
}

// localOnlyTools are the tools that CANNOT send traffic to a target: graph
// write-backs, file edits, todos, and the read-only helpers. Everything else —
// including any name not listed here — is treated as outbound, because an unknown
// name is exactly where a bypass would hide.
var localOnlyTools = map[string]bool{
	"record_fact": true, "TodoWrite": true, "insert_assets": true, "report_finding": true,
	"update_finding_report": true, "bind_finding_traffic": true, "get_finding_traffic": true,
	"Read": true, "Write": true, "Edit": true, "MultiEdit": true, "LS": true, "Glob": true,
	"Grep": true, "TodoRead": true, "list_findings": true, "node_detail": true,
	"graph_overview": true, "list_assets": true, "list_companies": true, "set_goals": true,
	"add_hint": true, "add_task_hint": true, "set_constraints": true, "get_worker_output": true,
	"get_worker_trace": true, "list_worker_traces": true, "search_all_worker_traces": true,
	"prove_goal": true, "kill_work": true, "steer_work": true, "retry_work": true,
	"cancel_intent": true, "add_intent": true, "list_untested_assets": true, "add_task_scope": true,
	"list_task_findings": true, "get_task_graph": true, "get_task_node_detail": true,
	"oast_generate": true, "oast_poll": true, "slot_poll": true, "slot_watch": true,
}

// canReachTarget reports whether this tool call can send a request to a target host.
// It decides whether the scope gate applies at all: a local write-back has no target
// to be in or out of scope, and must keep working when the rule table is unreadable.
func canReachTarget(tool string, input json.RawMessage) bool {
	if localOnlyTools[tool] {
		return false
	}
	// Everything else — Bash, shell_*, WebFetch, web_search, MCP tools, custom http
	// tools, and any name not on the local list — is treated as outbound.
	return true
}
