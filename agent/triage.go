package agent

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/net/html"
)

// Finding triage states recorded on a finding node's payload. They gate goal
// proof: a finding that is not `confirmed` cannot be used as evidence for
// prove_goal, so an unverified guess cannot end the task.
const (
	TriageConfirmed = "confirmed" // evidence verified deterministically
	TriageVerifying = "verifying" // accepted but its evidence was not corroborated
	TriageRejected  = "rejected"  // deterministic false-positive pattern
)

// TriageVerdict is the deterministic pre-check outcome for one report_finding call.
// Verifying is a real state, not a soft accept: the finding is stored for a human
// (and the retester) to settle, but it cannot prove a goal.
type TriageVerdict struct {
	State  string
	Reason string
	// Reject means the call must fail outright: the report is a known
	// false-positive shape with no salvageable content. State is then Rejected.
	Reject bool
}

// StrongEvidence counts evidence pointers that a human can re-check without
// trusting the model: captured traffic, an OAST callback, or a command transcript.
func strongEvidence(refs []string) (strong, weak int) {
	for _, ref := range refs {
		parsed, err := db.ParseEvidenceRef(ref)
		if err != nil {
			weak++
			continue
		}
		switch parsed.Kind {
		case "traffic", "oast", "activity":
			strong++
		default:
			weak++
		}
	}
	return strong, weak
}

// hasImpactProvingRef reports whether any reference is impact-proving by
// construction (currently only a built-in OAST callback).
func hasImpactProvingRef(refs []string) bool {
	for _, ref := range refs {
		if parsed, err := db.ParseEvidenceRef(ref); err == nil && parsed.Kind == "oast" {
			return true
		}
	}
	return false
}

var (
	// Version-banner guesses: "Apache 2.4.49 detected" is a lead, not a finding.
	reVersionOnly   = []string{"版本号", "banner", "指纹判断", "version only", "只根据版本", "根据版本推断"}
	reGuessLanguage = []string{"可能", "疑似", "猜测", "推测", "probably", "might be", "may be", "不确定"}
	// Pure login-page shapes: a 200 response that is just the login form, or a
	// redirect back to it, proves nothing about access control.
	reLoginOnly = []string{"跳转回登录", "重定向到登录", "redirect to login", "302 to /login", "200 ok 登录页", "登录页返回 200", "回到登录页"}
)

// classifyFindingEvidence is the deterministic Auto-Triager gate. It answers one
// question before the finding reaches the graph: is this reportable at all, and if
// so, is its evidence strong enough to act on without a human?
//
// Rules are deliberately conservative in the reject direction: only patterns that
// are provably not a vulnerability (a login page bounce reported as access
// control, a banner reported as an exploit) are refused. Everything else is at
// worst `verifying`, which stores the claim but blocks goal proof.
func classifyFindingEvidence(vulnClass, summary, evidence, poc string, refs []string, boundTraffic int) TriageVerdict {
	text := strings.ToLower(strings.Join([]string{summary, evidence, poc}, " "))
	class := strings.ToLower(strings.TrimSpace(vulnClass))
	strong, _ := strongEvidence(refs)
	hasBinding := boundTraffic > 0
	substantive := strings.TrimSpace(evidence) != "" || strings.TrimSpace(poc) != ""
	if !substantive && !hasBinding && strong == 0 {
		return TriageVerdict{State: TriageRejected, Reject: true,
			Reason: "既没有 evidence 文本，也没有任何可回查证据（traffic/oast/activity）；空报告不能作为漏洞入库"}
	}

	contains := func(needles []string) bool {
		for _, n := range needles {
			if strings.Contains(text, n) {
				return true
			}
		}
		return false
	}
	// summaryOnly tests the summary alone: "the claim is a guess" must not be
	// satisfied by a hedge word inside otherwise solid reproduction output.
	summaryOnly := func(needles []string) bool {
		lowered := strings.ToLower(summary)
		for _, n := range needles {
			if strings.Contains(lowered, n) {
				return true
			}
		}
		return false
	}

	// Web access-control findings whose only evidence is "it answered 200" while
	// the response was really the login page are the single most common AI false
	// positive. Reject only when nothing else corroborates it.
	webClass := strings.Contains(class, "越权") || strings.Contains(class, "未授权") ||
		strings.Contains(class, "auth") || strings.Contains(class, "idor") || strings.Contains(class, "access") ||
		strings.Contains(class, "重定向") || strings.Contains(class, "redirect")
	if webClass && contains(reLoginOnly) && strong == 0 && !hasBinding {
		return TriageVerdict{State: TriageRejected, Reject: true,
			Reason: "访问控制类漏洞的证据只是「登录页返回 200 / 跳回登录页」，没有流量或命令证据能证明拿到了本不该拿到的内容；无鉴权差异的纯登录页响应不是漏洞"}
	}

	// A version banner with no exploit attempt is reconnaissance output.
	if contains(reVersionOnly) && strong == 0 && !hasBinding {
		return TriageVerdict{State: TriageRejected, Reject: true,
			Reason: "报告只是版本号/banner 推断，没有对应的利用或验证证据；版本猜测属于侦察线索，请用 record_fact 记 observation/hypothesis，确证后再 report_finding"}
	}

	// Hedge language is only a red flag when the hedge IS the whole report.
	//
	// Non-HTTP findings (a binary / APK / an internal TCP service) have no traffic or
	// OAST pointer by construction, and their real evidence legitimately reads
	// "attackers can read the config, which may lead to lateral movement" — the
	// conclusion is hedged, the reproduction is not. Refusing those lost true
	// findings, so the gate demands the hedge be in the SUMMARY *and* the evidence be
	// thin: substantial command/reproduction output falls through to verifying
	// (stored, cannot prove a goal) instead of being rejected outright.
	if summaryOnly(reGuessLanguage) && strong == 0 && !hasBinding && thinEvidence(evidence, poc) {
		return TriageVerdict{State: TriageRejected, Reject: true,
			Reason: "摘要措辞为推测（可能/疑似/猜测）且没有任何可回查证据与实质复现输出；推测请用 record_fact 记 hypothesis，验证成功后再上报"}
	}

	// A bound traffic snapshot is NOT proof on its own: an access-control claim whose
	// snapshot is really a 200 login page is the most common AI false positive. The
	// write path cannot see the response body, so it hands the finding to the
	// background triager in `verifying` and lets the response bytes decide. A strong
	// reference that is inherently impact-proving (a blind callback that reached our
	// listener, a command transcript) still confirms immediately.
	if hasBinding {
		return TriageVerdict{State: TriageVerifying,
			Reason: "已绑定流量，但需后台核对响应体是否真的呈现了受影响内容（登录页/拒绝页的 200 不算漏洞）；核对通过前不能用于证明目标"}
	}
	// Only an OAST callback is impact-proving BY CONSTRUCTION: the target itself
	// reached our listener. A `traffic:`/`activity:` pointer merely proves that some
	// exchange or command exists — a 200 landing page is an exchange, `curl -i /login`
	// is an activity — so those must go to the background triager like any other
	// unverified claim. Confirming on "the reference resolves" is exactly the hole the
	// impact check exists to close.
	if hasImpactProvingRef(refs) {
		return TriageVerdict{State: TriageConfirmed,
			Reason: "已带带外回调证据（目标实际回连）"}
	}
	if strong > 0 {
		return TriageVerdict{State: TriageVerifying,
			Reason: fmt.Sprintf("引用了可回查的流量/活动记录（%d 条），但存在不等于证明影响；需后台核对响应体后确认", strong)}
	}

	// Text-only evidence: store it, but it cannot prove a goal until a human (or
	// the retester) confirms the transcript actually demonstrates the impact.
	return TriageVerdict{State: TriageVerifying,
		Reason: "只有文字证据（命令输出/复现步骤），没有绑定流量或带外回调；漏洞已登记但需复核后才能用于证明目标"}
}

// thinEvidence reports whether the report's own evidence is too slight to stand on
// its own. A PoC (a concrete request / payload) is substance by definition no matter
// how short, so its mere presence is enough; otherwise the evidence prose must carry
// at least 60 non-space runes. Above that bar the claim is backed by real output, so
// a hedged summary routes to verifying rather than being thrown away.
func thinEvidence(evidence, poc string) bool {
	if strings.TrimSpace(poc) != "" {
		return false
	}
	return len([]rune(strings.Join(strings.Fields(evidence), ""))) < 60
}

// ExtractEvidenceAnchors pulls the lines of a finding's evidence that can serve as
// a real-output fingerprint: command input, generic HTTP headers, short tokens and
// pure natural-language summaries are dropped because they either never appear in
// tool output or match anything. Long lines are trimmed to their leading 160 runes
// so the anchor still fits inside a truncated activity summary.
func ExtractEvidenceAnchors(evidence string) []string {
	evidence = strings.ReplaceAll(evidence, "\r\n", "\n")
	evidence = strings.ReplaceAll(evidence, "\r", "\n")
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(evidence, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if n := utf8.RuneCountInString(line); n < 16 {
			if n < 12 || !hasStructuredShortToken(line) {
				continue
			}
		}
		lowered := strings.ToLower(line)
		if hasCommandPrefix(lowered) || hasGenericHTTPHeader(lowered) {
			continue
		}
		if !hasASCIIData(line) {
			continue
		}
		if utf8.RuneCountInString(line) > 200 {
			line = strings.TrimSpace(string([]rune(line)[:160]))
		}
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

// hasStructuredShortToken reports whether a short line still carries a
// machine-checkable credential shape: a non-empty key=value / key: value pair
// whose value has no whitespace, or a braced identifier token with no inner
// whitespace. The shape is generic; no product or event name is matched.
func hasStructuredShortToken(line string) bool {
	if open := strings.IndexByte(line, '{'); open >= 0 {
		if close := strings.IndexByte(line[open+1:], '}'); close > 0 {
			inner := line[open+1 : open+1+close]
			return inner != "" && !strings.ContainsAny(inner, " \t")
		}
	}
	for _, sep := range []byte{'=', ':'} {
		i := strings.IndexByte(line, sep)
		if i <= 0 || i >= len(line)-1 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+1:])
		if key != "" && value != "" && !strings.ContainsAny(value, " \t") {
			return true
		}
	}
	return false
}

func hasCommandPrefix(lowered string) bool {
	for _, prefix := range []string{"$ ", "# ", "> ", "ps ", "curl ", "python ", "python3 ", "sqlmap ", "nmap ", "adb ", "jadx "} {
		if strings.HasPrefix(lowered, prefix) {
			return true
		}
	}
	return false
}

func hasGenericHTTPHeader(lowered string) bool {
	for _, prefix := range []string{"http/1.", "http/2", "date:", "server:", "content-type:", "content-length:", "connection:", "transfer-encoding:", "cache-control:"} {
		if strings.HasPrefix(lowered, prefix) {
			return true
		}
	}
	return false
}

// hasASCIIData reports whether a line carries a machine-checkable ASCII signal:
// digits, punctuation used by JSON/SQL/config/paths, or a long identifier run.
// A Chinese conclusion sentence normally has none of these.
func hasASCIIData(line string) bool {
	run := 0
	for _, r := range line {
		if r > 127 {
			run = 0
			continue
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			if r >= '0' && r <= '9' {
				return true
			}
			run++
			continue
		}
		if r == ' ' || r == '\t' {
			run = 0
			continue
		}
		switch r {
		case '=', ':', '{', '}', '/', '\\', '<', '>', '[', ']', '(', ')', '"', '\'', '_', '-', '.', '%', '|', '&', '?', '*', '+', '@', '#', '$', '^', '~', '`', ';', ',':
			return true
		}
		run = 0
	}
	return run >= 16
}

// MatchEvidenceInOutputs decides whether a reported vulnerability's evidence can be
// found in the real outputs of the tools that ran. A fabricated report has to match
// a line the model actually saw, so one long anchor is required, or two different
// shorter anchors. Login-form pages are ignored: they are a common capture that
// proves no impact.
func MatchEvidenceInOutputs(vulnClass, summary, evidence string, outputs []string) (bool, string) {
	if classifyFindingEvidence(vulnClass, summary, evidence, "", nil, 0).Reject {
		return false, ""
	}
	anchors := ExtractEvidenceAnchors(evidence)
	if len(anchors) == 0 {
		return false, ""
	}
	corpus := make([]string, 0, len(outputs))
	for _, out := range outputs {
		out = strings.ReplaceAll(out, "\r\n", "\n")
		out = strings.ReplaceAll(out, "\r", "\n")
		if isLoginFormOnly(out) {
			continue
		}
		corpus = append(corpus, out)
	}
	if len(corpus) == 0 {
		return false, ""
	}
	best := ""
	hits := 0
	for _, anchor := range anchors {
		found := false
		for _, out := range corpus {
			if strings.Contains(out, anchor) {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		hits++
		if utf8.RuneCountInString(anchor) > utf8.RuneCountInString(best) {
			best = anchor
		}
	}
	if hits == 0 {
		return false, ""
	}
	if utf8.RuneCountInString(best) >= 20 || hits >= 2 {
		return true, best
	}
	return false, ""
}

// hiddenHTMLTextTags are the elements whose text is not visible page content:
// form labels/errors, executable scripts, styles and the title.
var hiddenHTMLTextTags = map[string]bool{"form": true, "script": true, "style": true, "title": true}

// isLoginFormOnly reports whether out is an HTML page whose only meaningful
// content is a password login form. It scans with the HTML tokenizer so attribute
// quoting, case and nesting do not decide the answer. A page that embeds business
// data in a script is not a bare login page.
func isLoginFormOnly(out string) bool {
	lowered := strings.ToLower(out)
	if !strings.Contains(lowered, "<") || !strings.Contains(lowered, ">") || !strings.Contains(lowered, "password") {
		return false
	}
	z := html.NewTokenizer(strings.NewReader(out))
	var (
		hasPassword bool
		visible     int
		scriptData  bool
	)
	hidden := map[string]int{}
	hiddenTotal := 0
	for {
		switch tt := z.Next(); tt {
		case html.ErrorToken:
			return hasPassword && visible < 120 && !scriptData
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := strings.ToLower(string(name))
			if tt == html.StartTagToken && hiddenHTMLTextTags[tag] {
				hidden[tag]++
				hiddenTotal++
			}
			if tag == "input" {
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					if strings.EqualFold(string(k), "type") && strings.EqualFold(strings.TrimSpace(string(v)), "password") {
						hasPassword = true
					}
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := strings.ToLower(string(name))
			if hidden[tag] > 0 {
				hidden[tag]--
				hiddenTotal--
			}
		case html.TextToken:
			text := string(z.Text())
			if hiddenTotal > 0 {
				if hidden["script"] > 0 && hasBusinessScriptData(text) {
					scriptData = true
				}
				continue
			}
			visible += len([]rune(strings.Join(strings.Fields(text), "")))
		}
	}
}

// hasBusinessScriptData recognizes a script block that carries application data
// rather than framework code: an assignment of a long literal, or inline JSON.
func hasBusinessScriptData(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	if i := strings.IndexByte(text, '='); i >= 0 {
		value := strings.TrimSpace(strings.TrimLeft(text[i+1:], `"'`))
		end := strings.IndexAny(value, "\"';,)} \t\r\n")
		if end < 0 {
			end = len(value)
		}
		if len([]rune(value[:end])) >= 16 {
			return true
		}
	}
	return strings.Contains(text, "{") && strings.Contains(text, "}") && strings.Contains(text, "\":")
}

// FindingEvidenceHook, if set by the host, is called in a detached goroutine right
// after a finding lands in state "verifying". The host corroborates the reported
// evidence out of band (re-reading the bound traffic snapshots, resolving the OAST
// callbacks) and promotes the finding to "confirmed" only when the evidence really
// shows an impact difference — so a text-only report never blocks on the model, and
// an unverifiable one never silently becomes proof.
//
// Arguments are the ids the host needs; evidenceRefs is the recorded pointer list
// (traffic/oast/activity/...). package-level so the per-run ToolSet stays free of
// host wiring, same pattern as EvidenceRefValidator.
var FindingEvidenceHook func(taskID, explorationID, findingID int64, evidenceRefs []string)

// TriageGateEnabled reports whether the deterministic gate is active. The host
// can switch it off for a task type where its heuristics misfire; nil = on.
var TriageGateDisabled func() bool

// triageFinding runs the gate unless the host disabled it.
func triageFinding(vulnClass, summary, evidence, poc string, refs []string, boundTraffic int) TriageVerdict {
	if TriageGateDisabled != nil && TriageGateDisabled() {
		return TriageVerdict{State: TriageConfirmed, Reason: "自动分诊已关闭"}
	}
	return classifyFindingEvidence(vulnClass, summary, evidence, poc, refs, boundTraffic)
}
