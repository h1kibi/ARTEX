package db

// Task cost governance (docs §4.1 WP2). The numeric route budget was removed
// because a model cannot integrate a route's cumulative token spend; the
// authoritative backstop moved to the task, where the engine can compute it
// deterministically from the always-on llm_usage ledger.
//
// Equivalent cost weights a cached read at 0.1 and an output token at 4 against
// one uncached input token, which is the ratio the provider bill actually uses:
//   uncached_in + 0.1 * cache_read + 4 * out
//
// input_tokens is the TOTAL input including cached tokens (see
// llm/anthropic.go's norm()), so the uncached part has to be derived by
// subtraction — adding input_tokens to cache_read would double-count the cache.

const (
	// SettingTaskCostCapEnabled turns the per-task equivalent-cost ceiling on.
	SettingTaskCostCapEnabled = "task_cost_cap_enabled"
	// SettingTaskCostCapTokens is the ceiling in equivalent-cost tokens.
	SettingTaskCostCapTokens = "task_cost_cap_tokens"

	// DefaultTaskCostCapTokens is the built-in ceiling: roughly one deep task at
	// the historical ledger's average rate. Administrators raise or lower it.
	DefaultTaskCostCapTokens = 20_000_000
)

// TaskEquivalentCost returns a task's cumulative equivalent cost in tokens.
func (d *DB) TaskEquivalentCost(taskID string) (int64, error) {
	var cost int64
	err := d.QueryRow(`
SELECT COALESCE(SUM(
         GREATEST(input_tokens - cache_read, 0)
       + (cache_read * 0.1)
       + (output_tokens * 4)
       ), 0)::bigint
FROM llm_usage WHERE COALESCE(task_id,'') = $1`, taskID).Scan(&cost)
	return cost, err
}
