package db

import "testing"

func TestEffortRuntimeLimits(t *testing.T) {
	cases := []struct {
		effort        string
		turns, cycles int
	}{
		{EffortProbe, 35, 0},
		{EffortStandard, 80, 1},
		{EffortDeep, 130, 2},
		{"", 80, 1},
		{"PROBE", 35, 0},
		{"  deep  ", 130, 2},
		{"unknown-tier", 80, 1},
	}
	for _, tc := range cases {
		got := EffortRuntimeLimits(tc.effort)
		if got.MaxTurns != tc.turns || got.MaxAutoCycles != tc.cycles {
			t.Fatalf("EffortRuntimeLimits(%q)=%+v want turns=%d cycles=%d",
				tc.effort, got, tc.turns, tc.cycles)
		}
	}
}

// Historical intents carry no effort field; NormalizeEffort must never fail them.
func TestNormalizeEffortBackwardCompatible(t *testing.T) {
	if got := NormalizeEffort(""); got != EffortStandard {
		t.Fatalf("empty effort=%q want standard", got)
	}
	if got := NormalizeEffort("legacy"); got != EffortStandard {
		t.Fatalf("legacy effort=%q want standard", got)
	}
}

func TestHighValueProgressEventSet(t *testing.T) {
	for _, event := range []string{"validated_weakness", "credential_obtained", "privilege_change",
		"lateral_progress", "objective_milestone", "finding_written"} {
		if !IsHighValueProgressEvent(event) {
			t.Fatalf("%s must count as high value", event)
		}
	}
	for _, event := range []string{"observation", "new_asset", "new_claim", "cleanup_completed", "duplicate_action", ""} {
		if IsHighValueProgressEvent(event) {
			t.Fatalf("%q must not count as high value", event)
		}
	}
}
