package db

import "strings"

// Effort is the discrete run-time tier a planner picks for an intent. It REPLACES
// the model-authored numeric route budget: a black-box LLM cannot integrate a
// route's cumulative input tokens (89.5% of which are cheap cache reads, growing
// O(N²)), so the arithmetic was wrong in 43.5% of add_intent calls and the
// enforcement killed 70% of intents mid-exploration. A tier is something the
// model can actually judge, and the engine maps it to hard limits deterministically.
const (
	EffortProbe    = "probe"    // breadth recon / fingerprint / one-shot probes
	EffortStandard = "standard" // normal single-target exploitation loop
	EffortDeep     = "deep"     // multi-step chains (deserialization, pivoting, reversing)
)

// Efforts lists the writable values in model-preference order.
var Efforts = []string{EffortProbe, EffortStandard, EffortDeep}

// NormalizeEffort maps empty/unknown/legacy values onto the default tier.
// Historical intents have no effort field and must keep working, so unknown input
// is never an error.
func NormalizeEffort(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case EffortProbe:
		return EffortProbe
	case EffortDeep:
		return EffortDeep
	default:
		return EffortStandard
	}
}

// EffortLimits is the engine-side interpretation of a tier.
//
// MaxTurns is the single-run turn budget for the worker. MaxAutoCycles is how many
// Watchdog cycles the run may continue on a green judgment WITHOUT asking a human;
// 0 is a meaningful value (probe hands off at the first boundary), not "unset".
type EffortLimits struct {
	MaxTurns      int
	MaxAutoCycles int
}

// EffortRuntimeLimits maps a tier onto the calibrated run parameters. The values
// come from the historical ledger: the best task solved JNDI deserialization RCE,
// a Solidity reentrancy chain and a Jolokia MBean file read in 116/107/101
// consecutive turns, so deep work must not be cut at 20–35 turns; conversely a
// port/service sweep never needs more than 35.
func EffortRuntimeLimits(effort string) EffortLimits {
	switch NormalizeEffort(effort) {
	case EffortProbe:
		return EffortLimits{MaxTurns: 35, MaxAutoCycles: 0}
	case EffortDeep:
		return EffortLimits{MaxTurns: 130, MaxAutoCycles: 2}
	default:
		return EffortLimits{MaxTurns: 80, MaxAutoCycles: 1}
	}
}
