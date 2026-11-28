package compaction

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// MicroKeepRecent <= 0 must keep the historical default (5): every existing
// spec3/micro test builds Config without it and pins that window.
func TestMicroKeepRecentZeroFallsBackToDefault(t *testing.T) {
	c := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000}, nil)
	if c.cfg.MicroKeepRecent != microKeepRecent {
		t.Fatalf("MicroKeepRecent=%d want %d", c.cfg.MicroKeepRecent, microKeepRecent)
	}
	// The default must still clear everything beyond the 5 most recent results.
	msgs := manyReadPairs(microKeepRecent + 3)
	out, changed := c.microCompact(msgs)
	if !changed || countCleared(out) != 3 {
		t.Fatalf("changed=%v cleared=%d want 3", changed, countCleared(out))
	}
}

// A configured keep window overrides the default for that compactor only.
func TestMicroKeepRecentConfiguredWindow(t *testing.T) {
	c := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000, MicroKeepRecent: 8}, nil)
	msgs := manyReadPairs(11)
	out, changed := c.microCompact(msgs)
	if !changed {
		t.Fatal("expected a change")
	}
	if got := countCleared(out); got != 3 {
		t.Fatalf("cleared=%d want 3 (11 results - 8 kept)", got)
	}
	// The last 8 bodies survive verbatim.
	for i := len(out) - 8; i < len(out); i += 2 {
		if strings.Contains(resultText(out[i].Content[0]), "cleared") {
			t.Fatalf("result %d inside the keep window was cleared", i)
		}
	}
}

// Short tool results — typically one-line errors — stay verbatim even when they
// fall outside the keep window: clearing them saves no context and makes the
// worker repeat a failing command.
func TestMicroKeepsShortResultsBelowMinClearChars(t *testing.T) {
	c := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000, MicroKeepRecent: 1, MinClearChars: 100}, nil)
	var msgs []llm.Message
	msgs = append(msgs, toolPair("Bash", "short", "permission denied")...)     // 16 chars → kept
	msgs = append(msgs, toolPair("Bash", "long", strings.Repeat("y", 500))...) // 500 chars → cleared
	msgs = append(msgs, toolPair("Bash", "live", strings.Repeat("z", 500))...) // inside keep window
	out, changed := c.microCompact(msgs)
	if !changed {
		t.Fatal("the long stale result should have been cleared")
	}
	if !strings.Contains(resultText(out[1].Content[0]), "permission denied") {
		t.Fatalf("short error was cleared: %q", resultText(out[1].Content[0]))
	}
	if !strings.Contains(resultText(out[3].Content[0]), "cleared") {
		t.Fatalf("long stale result survived: %q", resultText(out[3].Content[0])[:40])
	}
}

// MinClearChars=0 keeps the pre-change behavior: size does not protect a result.
func TestMicroMinClearCharsZeroClearsShortResults(t *testing.T) {
	c := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000, MicroKeepRecent: 1}, nil)
	var msgs []llm.Message
	msgs = append(msgs, toolPair("Bash", "short", "permission denied")...)
	msgs = append(msgs, toolPair("Bash", "live", strings.Repeat("z", 500))...)
	out, changed := c.microCompact(msgs)
	if !changed || !strings.Contains(resultText(out[1].Content[0]), "cleared") {
		t.Fatalf("short result not cleared with MinClearChars=0: %q", resultText(out[1].Content[0]))
	}
}

// A cleared result that carried a cmd-output spill pointer must keep the path:
// the file on disk is the only route back to the full output.
func TestMicroClearedResultKeepsSpillPointer(t *testing.T) {
	path := `C:\work\tasks\1\i2\cmd-output\bash-3.txt`
	body := strings.Repeat("q", 400) + "\n\n... <persisted-output>[Output too large: full 999999 bytes / 3 lines." +
		"Full output saved to  " + path + " </persisted-output>"
	c := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000, MicroKeepRecent: 1, MinClearChars: 1}, nil)
	var msgs []llm.Message
	msgs = append(msgs, toolPair("Bash", "old", body)...)
	msgs = append(msgs, toolPair("Bash", "live", strings.Repeat("z", 500))...)
	out, changed := c.microCompact(msgs)
	if !changed {
		t.Fatal("expected the stale result to be cleared")
	}
	got := resultText(out[1].Content[0])
	if !strings.HasPrefix(got, microClearedMessage) {
		t.Fatalf("not cleared first: %q", got)
	}
	if !strings.Contains(got, path) {
		t.Fatalf("spill path lost from the cleared replacement: %q", got)
	}
	if len(got) > len(microClearedMessage)+200 {
		t.Fatalf("replacement kept too much body (%d chars)", len(got))
	}
}

// ExtraCompactableTools joins the built-in whitelist, so ARTEX's own bulk-output
// tools (traffic_*, TaskOutput, traces) fold the same way Bash does.
func TestMicroExtraCompactableTools(t *testing.T) {
	c := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000, MicroKeepRecent: 1,
		ExtraCompactableTools: []string{"traffic_get", "TaskOutput"}}, nil)
	var msgs []llm.Message
	msgs = append(msgs, toolPair("traffic_get", "t1", strings.Repeat("y", 500))...)
	msgs = append(msgs, toolPair("TaskOutput", "t2", strings.Repeat("y", 500))...)
	msgs = append(msgs, toolPair("traffic_get", "t3", strings.Repeat("z", 500))...)
	out, changed := c.microCompact(msgs)
	if !changed {
		t.Fatal("extra compactable tools should be cleared")
	}
	if got := countCleared(out); got != 2 {
		t.Fatalf("cleared=%d want 2 (t1 and t2, t3 kept)", got)
	}
	// Without the extra list those tools are not touched.
	plain := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000, MicroKeepRecent: 1}, nil)
	if _, changed := plain.microCompact(msgs); changed {
		t.Fatal("traffic_get must not be compactable without ExtraCompactableTools")
	}
}

// The cleared marker is idempotent and size/pointer handling never produce a
// second distinguishable state (a re-run must be a no-op).
func TestMicroClearedWithPointerIsIdempotent(t *testing.T) {
	path := "/tmp/cmd-output/bash-9.txt"
	body := strings.Repeat("q", 400) + "\n<persisted-output>[Output too large: full 10 bytes / 1 lines." +
		"Full output saved to  " + path + " </persisted-output>"
	c := New(Config{ContextWindow: 16000, MaxOutputTokens: 1000, MicroKeepRecent: 1, MinClearChars: 1}, nil)
	var msgs []llm.Message
	msgs = append(msgs, toolPair("Bash", "old", body)...)
	msgs = append(msgs, toolPair("Bash", "live", strings.Repeat("z", 500))...)
	out1, _ := c.microCompact(msgs)
	out2, changed2 := c.microCompact(out1)
	if changed2 {
		t.Fatal("second pass must be a no-op")
	}
	if resultText(out1[1].Content[0]) != resultText(out2[1].Content[0]) {
		t.Fatal("second pass rewrote the cleared body")
	}
}
