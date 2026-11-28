package agent

import "testing"

// The model must never be taught the numeric route budget again: add_intent's
// schema exposes effort (probe|standard|deep) and no budget object.
func TestAddIntentSchemaExposesEffortNotBudget(t *testing.T) {
	for _, sd := range BuiltinToolSeeds() {
		if sd.Key != "add_intent" {
			continue
		}
		props, _ := sd.Schema["properties"].(map[string]any)
		if _, ok := props["budget"]; ok {
			t.Fatal("add_intent schema still exposes the numeric budget object")
		}
		effort, ok := props["effort"].(map[string]any)
		if !ok {
			t.Fatal("add_intent schema is missing effort")
		}
		enum, _ := effort["enum"].([]string)
		if len(enum) != 3 || enum[0] != "probe" || enum[1] != "standard" || enum[2] != "deep" {
			t.Fatalf("effort enum=%v", enum)
		}
		return
	}
	t.Fatal("add_intent seed missing")
}
