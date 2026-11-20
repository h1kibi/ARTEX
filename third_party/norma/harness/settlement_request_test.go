package harness

import (
	"context"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
)

// An external settlement request enters the configured wrap-up phase even when
// no budget was hit, and the run reports ReasonWatchdog.
func TestSettlementRequestEntersWrapUp(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "watchdog requested"
	var toolsSeen [][]string
	turns := [][]llm.StreamEvent{textTurn("已写回事实并总结")}
	call := func(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		names := make([]string, 0, len(req.Tools))
		for _, ts := range req.Tools {
			names = append(names, ts.Name)
		}
		toolsSeen = append(toolsSeen, names)
		evs := turns[len(toolsSeen)-1]
		return func(yield func(llm.StreamEvent, error) bool) {
			for _, ev := range evs {
				if !yield(ev, nil) {
					return
				}
			}
		}
	}
	in := QueryInput{
		Messages:          []llm.Message{llm.UserText("go")},
		Tools:             tool.NewRegistry(tool.NewBash()),
		PermissionMode:    permission.ModeBypass,
		WorkingDir:        t.TempDir(),
		Settlement:        &Settlement{Prompt: "SETTLE_NOW 请写回事实", DisabledTools: []string{"Bash"}},
		SettlementRequest: ch,
	}
	term := drain(t, in, QueryDeps{CallModel: call})
	if term.Reason != ReasonWatchdog {
		t.Fatalf("reason=%v, want ReasonWatchdog", term.Reason)
	}
	found := false
	for _, m := range term.Messages {
		for _, c := range m.Content {
			if strings.Contains(c.Text, "SETTLE_NOW") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("settlement prompt was not injected")
	}
	if len(toolsSeen) != 1 {
		t.Fatalf("model calls=%d, want 1 settlement call", len(toolsSeen))
	}
	if contains(toolsSeen[0], "Bash") {
		t.Fatalf("settlement tools should hide Bash: %v", toolsSeen[0])
	}
}

// A settlement request after a tool round is applied at that boundary, before
// the next model call.
func TestSettlementRequestAfterToolRound(t *testing.T) {
	ch := make(chan string, 1)
	turns := [][]llm.StreamEvent{
		toolTurn("a", "Bash", `{"command":"echo 1"}`),
		textTurn("settled"),
	}
	// The first model call sends the request while it runs; the post-tool
	// boundary must then enter settlement instead of issuing another main turn.
	calls := 0
	call := func(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		idx := calls
		calls++
		if idx == 0 {
			ch <- "watchdog"
		}
		evs := turns[0]
		if idx > 0 {
			evs = turns[1]
		}
		return func(yield func(llm.StreamEvent, error) bool) {
			for _, ev := range evs {
				if !yield(ev, nil) {
					return
				}
			}
		}
	}
	in := QueryInput{
		Messages:          []llm.Message{llm.UserText("go")},
		Tools:             tool.NewRegistry(tool.NewBash()),
		PermissionMode:    permission.ModeBypass,
		WorkingDir:        t.TempDir(),
		Settlement:        &Settlement{Prompt: "SETTLE_NOW", DisabledTools: []string{"Bash"}},
		SettlementRequest: ch,
	}
	term := drain(t, in, QueryDeps{CallModel: call})
	if term.Reason != ReasonWatchdog {
		t.Fatalf("reason=%v, want ReasonWatchdog", term.Reason)
	}
	if calls != 2 {
		t.Fatalf("model calls=%d, want 2 (main + settlement)", calls)
	}
}

// Without a configured Settlement the run ends immediately instead of hanging.
func TestSettlementRequestWithoutConfigFinishes(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "watchdog"
	m := &scriptedModel{turns: [][]llm.StreamEvent{textTurn("should not run")}}
	in := QueryInput{
		Messages:          []llm.Message{llm.UserText("go")},
		PermissionMode:    permission.ModeBypass,
		WorkingDir:        t.TempDir(),
		SettlementRequest: ch,
	}
	term := drain(t, in, QueryDeps{CallModel: m.call})
	if term.Reason != ReasonWatchdog {
		t.Fatalf("reason=%v, want ReasonWatchdog", term.Reason)
	}
	if m.calls != 0 {
		t.Fatalf("model calls=%d, want 0", m.calls)
	}
}
