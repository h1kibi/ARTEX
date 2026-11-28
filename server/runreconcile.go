package server

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// High-value progress events that mean a real breakthrough was made — the run
// found something a human would want in the findings table. Kept local to the
// reconciliation rule (db.HighValueProgressEvents also carries lateral_progress,
// objective_milestone and finding_written, which are progress bookkeeping rather
// than evidence of a weakness or a usable credential).
var reconcileHighValueEvents = map[string]bool{
	"validated_weakness":  true,
	"credential_obtained": true,
	"privilege_change":    true,
}

// reconcileFindingCandidate turns this run's genuinely high-value output into ONE
// finding_candidate fact when the worker never called report_finding.
//
// History (docs §4.4 症结五): the previous rule swept up every `claim` and
// `hypothesis` and blindly promoted them, so an offline checklist of services
// ("ports 22/80/443 open", "Apache 2.4.49") became a "候选漏洞" while real
// breakthroughs written as plain `observation` (a validated SQLi, a recovered
// credential) evaporated — 70–80% of true findings were lost that way. The rule is
// now precise in both directions:
//
//   - a plain inventory claim is NOT promoted (no high-value signal → no candidate);
//   - ANY fact of this intent — observation, claim, hypothesis, or an already
//     written finding_candidate — that carries a high-value progress_event, or
//     whose fact_type IS finding_candidate, is captured into the candidate.
//
// The candidate still never creates a findings row: confirmed findings go through
// report_finding with reproducible evidence, and the planner decides what to
// validate.
func (e *Engine) reconcileFindingCandidate(t *Task, intent *db.Node, runID string) (int64, error) {
	if t == nil || t.Store == nil || intent == nil || intent.ID <= 0 {
		return 0, nil
	}
	outputs, err := t.Store.OutputsYielded(intent.ID)
	if err != nil {
		return 0, fmt.Errorf("读取意图产出: %w", err)
	}
	var (
		hasFinding                               bool
		claimIDs, hypothesisIDs, observationIDs  []int64
		evidenceRefs, nextActions                []string
		summary, hypothesisSummary, breakthrough string
		confidence                               string
		highValueEvents                          []string
		capturedSignals                          int
	)
	seenEvidence := map[string]bool{}
	addEvidence := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref != "" && !seenEvidence[ref] {
			seenEvidence[ref] = true
			evidenceRefs = append(evidenceRefs, ref)
		}
	}
	seenEvent := map[string]bool{}
	for _, n := range outputs {
		if n.Kind == db.KindFinding {
			hasFinding = true
			continue
		}
		p := db.ParseFactPayload(n.Payload)
		ft := n.FactType()
		if ft == db.FactTypeCheckpoint || ft == db.FactTypeDecision || n.State == db.StateOrigin {
			continue // route bookkeeping / task root — never a vulnerability signal
		}
		highValue := reconcileHighValueEvents[strings.TrimSpace(p.ProgressEvent)]
		if ft == db.FactTypeFindingCandidate {
			highValue = true // the worker already judged this a candidate
		}
		if !highValue {
			// Ordinary output: counted as intent output, never promoted.
			continue
		}

		capturedSignals++
		event := strings.TrimSpace(p.ProgressEvent)
		if event != "" && !seenEvent[event] {
			seenEvent[event] = true
			highValueEvents = append(highValueEvents, event)
		}
		if breakthrough == "" {
			breakthrough = strings.TrimSpace(p.Summary)
		}
		switch ft {
		case db.FactTypeObservation:
			observationIDs = append(observationIDs, n.ID)
		case db.FactTypeClaim:
			claimIDs = append(claimIDs, n.ID)
			if summary == "" && strings.TrimSpace(p.Summary) != "" {
				summary = p.Summary
			}
			if p.Confidence == "observed" || confidence == "" {
				confidence = p.Confidence
			}
		case db.FactTypeHypothesis:
			if p.State == "" || p.State == "open" || p.State == "supported" {
				hypothesisIDs = append(hypothesisIDs, n.ID)
				if hypothesisSummary == "" && strings.TrimSpace(p.Summary) != "" {
					hypothesisSummary = p.Summary
				}
			}
		case db.FactTypeFindingCandidate:
			// Reuse the candidate's own notion of evidence.
			if summary == "" && strings.TrimSpace(p.Summary) != "" {
				summary = p.Summary
			}
		}
		if confidence == "" {
			confidence = p.Confidence
		}
		for _, ref := range p.EvidenceRefs {
			addEvidence(ref)
		}
		for _, id := range p.SourceActivityIDs {
			addEvidence(fmt.Sprintf("activity:%d", id))
		}
		for _, action := range p.ValidationActions {
			if s := strings.TrimSpace(action); s != "" {
				nextActions = append(nextActions, s)
			}
		}
		for _, action := range p.NextActions {
			if s := strings.TrimSpace(action); s != "" {
				nextActions = append(nextActions, s)
			}
		}
	}
	// No high-value signal at all → nothing to reconcile. This is the branch that
	// stops a plain inventory claim from being reported as a candidate.
	if hasFinding || capturedSignals == 0 {
		return 0, nil
	}
	// A breakthrough with no resolvable evidence pointer still becomes a candidate:
	// the point of this pass is to stop true findings from vanishing, and the
	// planner can ask for validation. But say so, so it is not mistaken for proof.
	if summary == "" {
		summary = hypothesisSummary
	}
	if summary == "" {
		summary = breakthrough
	}
	if summary == "" {
		signal := "finding_candidate"
		if len(highValueEvents) > 0 {
			signal = strings.Join(highValueEvents, "/")
		}
		summary = "本次意图出现高价值进展（" + signal + "），但未写出摘要"
	}
	if len(evidenceRefs) > 40 {
		evidenceRefs = evidenceRefs[:40]
	}
	if len(claimIDs) > 20 {
		claimIDs = claimIDs[:20]
	}
	if len(hypothesisIDs) > 20 {
		hypothesisIDs = hypothesisIDs[:20]
	}
	if len(observationIDs) > 20 {
		observationIDs = observationIDs[:20]
	}
	if len(nextActions) > 10 {
		nextActions = nextActions[:10]
	}
	route := db.ParseIntentRoute(intent)
	payload := map[string]any{
		"fact_type":        db.FactTypeFindingCandidate,
		"summary":          "待确认候选：" + firstLine(summary, 300),
		"validation_state": "pending",
		"confidence":       fallbackString(confidence, "inferred"),
		"route_id":         route.RouteID,
		"intent_id":        intent.ID,
		"run_id":           runID,
		"observed_at":      time.Now().UTC().Format(time.RFC3339),
		"source":           "reconcile",
	}
	if len(highValueEvents) > 0 {
		payload["progress_events"] = highValueEvents
	}
	if len(evidenceRefs) > 0 {
		payload["evidence_refs"] = evidenceRefs
	}
	// Only emit the linkage keys that exist: a hypothesis-only run must not write
	// "claim_ids": [] and a claim-only run must not write "hypothesis_ids": [].
	if len(claimIDs) > 0 {
		payload["claim_ids"] = claimIDs
	}
	if len(hypothesisIDs) > 0 {
		payload["hypothesis_ids"] = hypothesisIDs
	}
	if len(observationIDs) > 0 {
		payload["observation_ids"] = observationIDs
	}
	if len(nextActions) > 0 {
		payload["next_actions"] = nextActions
	}

	// One candidate per intent. Re-extract on a retry and update the existing node
	// instead of inflating the graph with duplicate candidates.
	existing, err := t.Store.FindFactByIntentType(intent.ID, db.FactTypeFindingCandidate)
	if err != nil {
		return 0, fmt.Errorf("读取 finding_candidate: %w", err)
	}
	if existing != nil {
		// A terminal candidate was decided on purpose: a retry/re-extraction must
		// not silently reopen a rejected (or confirmed/expired) candidate.
		switch strings.ToLower(strings.TrimSpace(db.ParseFactPayload(existing.Payload).ValidationState)) {
		case "rejected", "confirmed", "expired":
			return existing.ID, nil
		}
		if err := t.Store.UpdateFactPayload(existing.ID, payload); err != nil {
			return 0, fmt.Errorf("更新 finding_candidate: %w", err)
		}
		if err := t.Store.Link(intent.ID, db.RelYields, existing.ID); err != nil {
			log.Printf("[reconcile] task %s 意图 #%d 连接 candidate 失败: %v", t.ID, intent.ID, err)
		}
		return existing.ID, nil
	}
	id, err := t.Store.AddNodeLinked(db.KindFact, payload, 0, "confirmed", "system", nil, intent.ID, db.RelYields)
	if err != nil {
		return 0, fmt.Errorf("写入 finding_candidate: %w", err)
	}
	meta, _ := json.Marshal(map[string]any{"finding_candidate_id": id, "route_id": route.RouteID})
	e.emitActivity(t, db.Activity{
		Worker: "system", Kind: "finding_candidate", NodeID: &intent.ID,
		Summary: fmt.Sprintf("候选漏洞待确认：%s", firstLine(summary, 160)),
		Detail:  summary, Metadata: meta,
	})
	return id, nil
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
