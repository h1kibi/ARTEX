package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const reviewTextLimit = 4000

// reviewConstraintsLimit bounds the task-constraint block. A task rarely declares
// more than a handful of sentences; the cap keeps a pathological task config from
// crowding out the call being reviewed while still fitting a realistic list.
const reviewConstraintsLimit = 4000

// reviewConstraintEntryLimit bounds ONE constraint entry, so a single verbose
// allowance cannot starve the rest of the list. Denials are still emitted first
// (see boundedConstraints), so truncation can never turn one into an omission.
const reviewConstraintEntryLimit = 500

const BackgroundUserMessage = "user_message"

// ReviewBackground is explicitly bound from the current human message. Generated
// Worker summaries are not accepted. Background cannot override review policy.
type ReviewBackground struct {
	Source    string `json:"source"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ReviewInput contains only the current call, explicitly selected background and
// the task's own operation constraints.
//
// TaskConstraints is application-supplied configuration (task_constraints rows),
// not agent prose: it tells the judge what this engagement already forbids
// ("禁爆破", "仅测当前端口"), so a task-level prohibition is not silently allowed by
// the generic policy. It can only ADD restrictions — the boundary below says so
// explicitly, and an agent cannot inject it through tool arguments.
type ReviewInput struct {
	Version         int               `json:"version"`
	WorkingDir      string            `json:"working_directory,omitempty"`
	Background      *ReviewBackground `json:"background,omitempty"`
	TaskConstraints []string          `json:"task_constraints,omitempty"`
	Tool            string            `json:"tool_name"`
	Arguments       json.RawMessage   `json:"arguments"`
}

type reviewContextKey struct{}
type reviewEnvironment struct {
	workingDir  string
	background  ReviewBackground
	constraints []string
}

// WithReviewContext explicitly binds the permitted background for one run. Never
// fall back to the raw turn transcript: it may contain the full scheduler prompt.
// This is application wiring, not a model-callable tool.
func WithReviewContext(ctx context.Context, workingDir string, background ReviewBackground) context.Context {
	return context.WithValue(ctx, reviewContextKey{}, reviewEnvironment{workingDir: workingDir, background: background})
}

// WithReviewWorkingDirectory preserves only explicitly selected background.
// Chat runs can be human-initiated or scheduled, so the Agent must not infer
// message provenance from the text it receives.
func WithReviewWorkingDirectory(ctx context.Context, workingDir string) context.Context {
	env, _ := ctx.Value(reviewContextKey{}).(reviewEnvironment)
	env.workingDir = workingDir
	return context.WithValue(ctx, reviewContextKey{}, env)
}

// WithReviewConstraints binds this task's operation constraints to the review
// context. Blank entries are dropped; the list is capped and order-preserving so
// the judge sees a stable, bounded block.
func WithReviewConstraints(ctx context.Context, constraints []string) context.Context {
	env, _ := ctx.Value(reviewContextKey{}).(reviewEnvironment)
	env.constraints = boundedConstraints(constraints)
	return context.WithValue(ctx, reviewContextKey{}, env)
}

// boundedConstraints trims, drops empty entries and bounds BOTH each entry and the
// total budget — without ever dropping a restriction.
//
// The block is a task's declared limits, and the asymmetry between the two kinds is
// the whole point: a missing allow entry only makes the judge stricter, but a
// missing deny entry silently grants permission the operator never gave. So:
//
//   - deny-shaped entries come first in the output (they survive a tight budget);
//   - an over-long single entry is truncated, not skipped — a 2500-rune "禁止…"
//     must reach the judge as "禁止…" plus an ellipsis, never as nothing;
//   - the remaining budget is spent in the caller's order, truncating the last
//     entry that partially fits instead of stopping at it.
func boundedConstraints(in []string) []string {
	type entry struct {
		text string
		deny bool
	}
	entries := make([]entry, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		entries = append(entries, entry{text: c, deny: isDenyConstraint(c)})
	}
	// Stable partition: restrictions first, everything else in original order.
	ordered := make([]entry, 0, len(entries))
	for _, e := range entries {
		if e.deny {
			ordered = append(ordered, e)
		}
	}
	for _, e := range entries {
		if !e.deny {
			ordered = append(ordered, e)
		}
	}

	out := make([]string, 0, len(ordered))
	used := 0
	for _, e := range ordered {
		remain := reviewConstraintsLimit - used
		if remain <= 0 {
			break
		}
		text := e.text
		if n := len([]rune(text)); n > reviewConstraintEntryLimit || n > remain {
			text = clipRunes(text, min(reviewConstraintEntryLimit, remain))
		}
		used += len([]rune(text))
		out = append(out, text)
	}
	return out
}

// isDenyConstraint reports whether an entry forbids something. Both the
// "deny: …" prefix written by the tool layer and a bare 禁止 phrasing qualify.
func isDenyConstraint(c string) bool {
	lower := strings.ToLower(strings.TrimSpace(c))
	if strings.HasPrefix(lower, "deny") {
		return true
	}
	return strings.Contains(c, "禁止") || strings.Contains(c, "不得") || strings.Contains(c, "不允许")
}

// clipRunes truncates s to limit runes, marking the cut so the judge knows the
// entry continues. A limit <= 0 yields "".
func clipRunes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "…"
}

func BuildReviewInput(ctx context.Context, tool string, arguments json.RawMessage) (ReviewInput, error) {
	if !json.Valid(arguments) {
		return ReviewInput{}, fmt.Errorf("工具参数不是有效 JSON")
	}
	in := ReviewInput{Version: 5, Tool: tool, Arguments: append(json.RawMessage(nil), arguments...)}
	if env, ok := ctx.Value(reviewContextKey{}).(reviewEnvironment); ok {
		in.WorkingDir = env.workingDir
		background := env.background
		if background.Source == BackgroundUserMessage && strings.TrimSpace(background.Text) != "" {
			var cut bool
			background.Text, cut = bounded(background.Text, reviewTextLimit)
			background.Truncated = background.Truncated || cut
			in.Background = &background
		}
		if len(env.constraints) > 0 {
			in.TaskConstraints = append([]string(nil), env.constraints...)
		}
	}
	return in, nil
}
