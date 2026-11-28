package agent

import (
	"strings"
	"testing"
)

// A worker's effective compaction window is clamped to 96k regardless of the
// model's nominal window; a genuinely smaller model window is honored.
func TestWorkerEffectiveWindowClamp(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{256000, workerEffectiveWindowCap},
		{200000, workerEffectiveWindowCap},
		{96000, 96000},
		{64000, 64000},
		{0, workerEffectiveWindowCap},
	}
	for _, tc := range cases {
		if got := workerEffectiveWindow(tc.in); got != tc.want {
			t.Fatalf("workerEffectiveWindow(%d)=%d want %d", tc.in, got, tc.want)
		}
	}
}

// The worker compaction config carries the MicroCompact floors; the shared
// config other agents use must stay untouched (its defaults are pinned by the
// norma compaction tests).
func TestWorkerCompactionConfigFloors(t *testing.T) {
	cfg := workerCompactionConfig(workerEffectiveWindowCap)
	if cfg.ContextWindow != workerEffectiveWindowCap {
		t.Fatalf("ContextWindow=%d", cfg.ContextWindow)
	}
	if cfg.MicroKeepRecent != workerMicroKeepRecent || cfg.MinClearChars != workerMinClearChars {
		t.Fatalf("floors missing: keep=%d min=%d", cfg.MicroKeepRecent, cfg.MinClearChars)
	}
	for _, want := range []string{"TaskOutput", "traffic_get", "traffic_blob", "traffic_search",
		"node_detail", "get_worker_trace", "search_all_worker_traces"} {
		found := false
		for _, got := range cfg.ExtraCompactableTools {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s missing from ExtraCompactableTools: %v", want, cfg.ExtraCompactableTools)
		}
	}
	// The generic config keeps Go defaults so planner/chat/watchdog behavior is
	// unchanged; a shared pointer would leak worker tuning into them.
	generic := compactionConfig(workerEffectiveWindowCap)
	if generic.MicroKeepRecent != 0 || generic.MinClearChars != 0 || len(generic.ExtraCompactableTools) != 0 {
		t.Fatalf("generic compaction config was mutated: %+v", generic)
	}
	// workerCompactionConfig returns a copy: mutating it cannot alter the package
	// table used for the next worker.
	cfg.ExtraCompactableTools[0] = "hacked"
	if workerExtraCompactableTools[0] == "hacked" {
		t.Fatal("ExtraCompactableTools aliases the package table")
	}
}

// The worker's single-step output cap is 12k chars, well under the SDK default,
// while other agents keep the default by leaving the field zero.
func TestWorkerOutputCapConstant(t *testing.T) {
	if workerMaxOutputChars != 12000 {
		t.Fatalf("workerMaxOutputChars=%d want 12000", workerMaxOutputChars)
	}
	if !strings.Contains(workerDefaultTmpl, "完成本意图后用一句话总结") {
		t.Fatal("worker prompt lost its closing contract")
	}
}
