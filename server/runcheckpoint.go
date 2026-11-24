package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// writeRunCheckpoint persists the route state a later Planner round and a new
// Worker Run need: phase, objective, confirmed claims, open hypotheses, evidence
// refs, attempted actions, next actions and cumulative route budget.
//
// It uses an existing fact node (fact_type=checkpoint) and an existing intent
// edge, not a new table or a second state machine. The checkpoint is written
// before any terminal state / planner notification, so a wake-up never observes
// a finished run without its checkpoint.
func (e *Engine) writeRunCheckpoint(t *Task, intent *db.Node, runID string, startedAt time.Time, startActivityID int64, reason string) (int64, error) {
	if t == nil || t.Store == nil || intent == nil || intent.ID <= 0 || runID == "" {
		return 0, nil
	}
	route := db.ParseIntentRoute(intent)
	routeID := route.RouteID
	if routeID <= 0 {
		routeID = intent.ID
	}
	outputs, err := t.Store.OutputsYielded(intent.ID)
	if err != nil {
		return 0, fmt.Errorf("读取意图产出: %w", err)
	}
	acts := []db.Activity{}
	cursor := startActivityID
	for {
		page, next, err := t.Store.ActivityList(&intent.ID, cursor, 2000)
		if err != nil {
			return 0, fmt.Errorf("读取运行活动: %w", err)
		}
		acts = append(acts, page...)
		if len(page) < 2000 || next <= cursor {
			break
		}
		cursor = next
		if len(acts) >= 50000 {
			// Pathological guard only: a run with >50k activity rows has far
			// exceeded any sane route budget; stop growing memory.
			break
		}
	}

	var (
		confirmed, openHypotheses, findingIDs []int64
		evidenceRefs, attempted, nextActions  []string
	)
	seenEvidence := map[string]bool{}
	seenAttempted := map[string]bool{}
	seenNext := map[string]bool{}
	addEvidence := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref != "" && !seenEvidence[ref] {
			seenEvidence[ref] = true
			evidenceRefs = append(evidenceRefs, ref)
		}
	}
	addNext := func(action string) {
		action = strings.TrimSpace(action)
		if action != "" && !seenNext[action] {
			seenNext[action] = true
			nextActions = append(nextActions, action)
		}
	}
	for _, n := range outputs {
		if n.Kind == db.KindFinding {
			findingIDs = append(findingIDs, n.ID)
			addEvidence(fmt.Sprintf("finding:%d", n.ID))
			continue
		}
		if n.FactType() == db.FactTypeCheckpoint {
			// A retried run's previous checkpoint is also a yielded fact. Reusing
			// its next_actions/evidence would snowball old runs into the new one.
			continue
		}
		p := db.ParseFactPayload(n.Payload)
		for _, ref := range p.EvidenceRefs {
			addEvidence(ref)
		}
		switch n.FactType() {
		case db.FactTypeClaim:
			confirmed = append(confirmed, n.ID)
		case db.FactTypeHypothesis:
			if p.State == "" || p.State == "open" {
				openHypotheses = append(openHypotheses, n.ID)
			}
		}
		for _, action := range p.NextActions {
			addNext(action)
		}
		for _, action := range p.ValidationActions {
			addNext(action)
		}
	}

	toolCalls := 0
	var inputTokens, outputTokens int
	var summary string
	for i := range acts {
		a := acts[i]
		switch a.Kind {
		case "tool_use":
			toolCalls++
			if len(attempted) < 30 {
				label := strings.TrimSpace(a.Tool + " " + firstLine(a.Detail, 160))
				if label != "" && !seenAttempted[label] {
					seenAttempted[label] = true
					attempted = append(attempted, label)
				}
			}
		case "tool_result":
			// Keep a bounded handle to the raw execution trace even when the model
			// did not cite a traffic id. It is an activity ref, not a copied body.
			if len(evidenceRefs) < 80 {
				addEvidence(fmt.Sprintf("activity:%d", a.ID))
			}
		case "usage", "result":
			if a.InputTokens != nil {
				inputTokens = *a.InputTokens
			}
			if a.OutputTokens != nil {
				outputTokens = *a.OutputTokens
			}
			if a.Kind == "result" {
				if strings.TrimSpace(a.Detail) != "" {
					summary = a.Detail
				} else if strings.TrimSpace(a.Summary) != "" {
					summary = a.Summary
				}
			}
		}
	}
	if len(evidenceRefs) > 80 {
		evidenceRefs = evidenceRefs[:80]
	}
	if summary == "" {
		summary = fmt.Sprintf("运行结束（%s）；已确认 claim %d，待验证 hypothesis %d，finding %d", reason, len(confirmed), len(openHypotheses), len(findingIDs))
	}
	summary = firstLine(summary, 1800)

	used := db.RouteBudgetUsed{
		ToolCalls:    toolCalls,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		WallMS:       time.Since(startedAt).Milliseconds(),
	}
	previous, err := t.Store.LatestCheckpointForRoute(routeID)
	if err != nil {
		return 0, fmt.Errorf("读取路线 checkpoint: %w", err)
	}
	previousUsed := db.RouteBudgetUsed{}
	routeStartedAt := route.RouteStartedAt
	if previous != nil {
		prevPayload := db.ParseFactPayload(previous.Payload)
		previousUsed = prevPayload.BudgetUsed
		if routeStartedAt == "" {
			routeStartedAt = prevPayload.RouteStartedAt
		}
		if prevPayload.CreatedByRun == runID {
			// A retry or a repeated settlement for the same run must not double-count.
			used = previousUsed
		} else {
			used = addBudgetUsed(previousUsed, used)
		}
	}
	if routeStartedAt == "" {
		routeStartedAt = time.Now().UTC().Format(time.RFC3339)
	}
	payload := db.CheckpointPayload(
		summary, route.RouteKind, route.Objective, route.PathPhase,
		runID, reason, routeID, intent.ID,
		confirmed, openHypotheses, findingIDs,
		evidenceRefs, attempted, nextActions, used,
	)
	payload["route_started_at"] = routeStartedAt
	if first, ok := parseRFC3339(routeStartedAt); ok {
		payload["route_elapsed_ms"] = time.Since(first).Milliseconds()
	}

	// Reuse the same-run checkpoint if one already exists (retry/re-settlement).
	// Node/edge insert, previous-checkpoint lineage and the intent's
	// checkpoint/budget cursor are committed in ONE transaction: a Planner or a
	// retried run must never observe a checkpoint without the updated intent.
	var existingCheckpointID, previousCheckpointID int64
	if previous != nil {
		previousCheckpointID = previous.ID
		if db.ParseFactPayload(previous.Payload).CreatedByRun == runID {
			existingCheckpointID = previous.ID
		}
	}
	checkpointID, err := t.Store.SaveRunCheckpoint(
		intent.ID, existingCheckpointID, previousCheckpointID, payload, used, routeStartedAt)
	if err != nil {
		return 0, fmt.Errorf("写入 checkpoint: %w", err)
	}
	meta, _ := json.Marshal(map[string]any{
		"route_id": routeID, "checkpoint_fact_id": checkpointID,
		"run_id": runID, "path_phase": route.PathPhase,
		"budget_used": used,
	})
	e.emitActivity(t, db.Activity{
		Worker: "system", Kind: "checkpoint", NodeID: &intent.ID,
		Summary: fmt.Sprintf("路线 #%d checkpoint：%s", routeID, firstLine(summary, 160)),
		Detail:  summary, Metadata: meta,
	})
	return checkpointID, nil
}

// withRunActivityMetadata adds the run/route provenance without overwriting
// metadata a tool or the Watchdog already attached.
func withRunActivityMetadata(raw json.RawMessage, runID string, routeID int64) json.RawMessage {
	if runID == "" && routeID <= 0 {
		return raw
	}
	p := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	if runID != "" {
		if _, exists := p["run_id"]; !exists {
			p["run_id"] = runID
		}
	}
	if routeID > 0 {
		if _, exists := p["route_id"]; !exists {
			p["route_id"] = routeID
		}
	}
	out, err := json.Marshal(p)
	if err != nil {
		return raw
	}
	return out
}

func addBudgetUsed(a, b db.RouteBudgetUsed) db.RouteBudgetUsed {
	return db.RouteBudgetUsed{
		ToolCalls:    a.ToolCalls + b.ToolCalls,
		InputTokens:  a.InputTokens + b.InputTokens,
		OutputTokens: a.OutputTokens + b.OutputTokens,
		WallMS:       a.WallMS + b.WallMS,
	}
}

func parseRFC3339(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	return t, err == nil
}
