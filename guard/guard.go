// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// executeExtraToolName is the SDK's deferred-tool invoker (actool.ExecuteExtraToolName).
// Redeclared here because guard must not import the tool package for one string.
const executeExtraToolName = "ExecuteExtraTool"

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	attribSince int64          // unix second the counts started covering (0 = never)
	reg         *hook.Registry
	interceptor Interceptor // optional; nil disables user-configured rules
	// assetRules supplies this task's asset block/allow rules (docs §4.5). nil =
	// no asset-level gating. Read per call, so a rule edit applies immediately.
	assetRules AssetInterceptHook
}

// Interceptor is the slice of intercept.Interceptor the guard actually uses.
// Declared as an interface so the gating logic (which rule reaches which call) can
// be tested without a database, and so a future interceptor variant needs no
// change here.
type Interceptor interface {
	IsToolEnabled(name string) bool
	Match(toolName string, input []byte) (intercept.Decision, bool)
	Judge(ctx context.Context, tool string, arguments json.RawMessage) (intercept.Decision, bool)
	Log(ctx context.Context, convID int64, dec intercept.Decision, toolName string, input []byte, status string)
	HandleAsk(ctx context.Context, convID int64, dec intercept.Decision, toolName string, input []byte) bool
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

// newGuard takes the interface so tests can supply a stub; NewWithInterceptor is
// the production entry point and keeps its concrete signature.
func newGuard(ic Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// A deferred MCP tool / custom tool arrives wrapped as ExecuteExtraTool. Every
	// rule below (and the LLM judge) must see the tool that will actually run, with
	// its real parameters — otherwise deferral is a free bypass. The audit log keeps
	// both names so a reviewer can see the wrapper too.
	innerName, innerInput, unwrapped := innerCall(ev.ToolName, ev.Input)

	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch innerName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(innerInput, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(innerInput, &in)
		cmd = in.Text
	}
	auditTool := innerName
	if unwrapped {
		auditTool = ev.ToolName + "→" + innerName
	}
	g.record(auditTool, "allow", "", cmd)

	// Asset scope gate: refuse a request to an out-of-scope target (a global
	// .gov/.edu block, a task's explicit exclusion) at the tool boundary, not only
	// at insert_assets' input. This is what makes the block real for Bash/curl and
	// for a browser MCP tool.
	if ok, reason := g.assetGateDecision(innerName, innerInput); !ok {
		return g.block(auditTool, systemBlockMessage(reason), cmd)
	}

	if unwrapped {
		ev.ToolName, ev.Input = innerName, innerInput
	}
	return g.applyIntercept(ctx, ev, unwrapped)
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
//
// unwrapped means ev.ToolName is an INNER tool reached through ExecuteExtraTool
// (an MCP server tool or a deferred custom tool). Those names are never in the
// user's enabled-tools list — that list is a set of eight built-in names — so the
// normal "is this tool in the intercept scope?" gate would drop every deferred tool
// on the floor: the wrapper was reviewed, the thing that actually ran was not.
// For an unwrapped call the scope question is therefore asked about the WRAPPER
// (was ExecuteExtraTool itself switched off?) and, when it is on, the inner call
// always enters rule matching + the judge.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event, unwrapped bool) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if unwrapped {
		if !g.interceptor.IsToolEnabled(executeExtraToolName) {
			return hook.Result{} // the user turned the deferred-tool surface off entirely
		}
	} else if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【ARTEX 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var (
	reBlocked   = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|captcha|denied)\b`)
	reRateLimit = regexp.MustCompile(`(?i)\b(429|rate.?limit|too many requests|慢一点|限速)\b`)
	// rePlatformBlocked spots ARTEX's own refusal text (see systemBlockMessage and
	// traffic's synthetic egress 403) so it is never attributed to the target.
	rePlatformBlocked = regexp.MustCompile(`ARTEX ?平台管控`)
)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF. The counts are surfaced through graph_overview
// (guard_attributions) so the planner can slow down on a rate-limited target.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if name, _, unwrapped := innerCall(ev.ToolName, ev.Input); unwrapped {
		ev.ToolName = name
	}
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	// A platform refusal (the asset scope gate above, or a task exclusion) is NOT
	// the target defending itself. Counting it as blocked/waf would tell the
	// planner "the site is fighting back, change technique" when what actually
	// happened is that ARTEX stopped the call — the wrong lesson entirely.
	if rePlatformBlocked.Match(ev.Result) {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reRateLimit.Match(ev.Result):
		class = "rate_limited"
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	if class == "blocked" {
		g.attrib["waf"]++
	}
	// Guard attributions exist to inform pacing, so a bounded window is enough:
	// counters from a 6-hour-old run say nothing about the current target state.
	// "since" is the process-relative second the counts started covering.
	if g.attribSince == 0 {
		g.attribSince = time.Now().Unix()
	}
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5): ok / error /
// blocked / waf / rate_limited. This is the G5 observer's output — it was
// collected but never read, so the planner had no way to notice a target that
// keeps answering 403/429.
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
