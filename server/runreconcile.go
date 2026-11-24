package server

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// reconcileFindingCandidate turns this run's typed Claims/Hypotheses into ONE
// finding_candidate fact when the worker did not report a confirmed finding.
// It never creates a findings row: confirmed findings still go through
// report_finding with reproducible evidence. The Planner sees the candidate in
// graph_overview and decides whether to validate and report it.
func (e *Engine) reconcileFindingCandidate(t *Task, intent *db.Node, runID string) (int64, error) {
	if t == nil || t.Store == nil || intent == nil || intent.ID <= 0 {
		return 0, nil
	}
	outputs, err := t.Store.OutputsYielded(intent.ID)
	if err != nil {
		return 0, fmt.Errorf("读取意图产出: %w", err)
	}
	var (
		hasFinding                    bool
		claimIDs, hypothesisIDs       []int64
		evidenceRefs, nextActions     []string
		summary, hypothesisSummary    string
		confidence                    string
	)
	seenEvidence := map[string]bool{}
	addEvidence := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref != "" && !seenEvidence[ref] {
			seenEvidence[ref] = true
			evidenceRefs = append(evidenceRefs, ref)
		}
	}
	for _, n := range outputs {
		if n.Kind == db.KindFinding {
			hasFinding = true
			continue
		}
		p := db.ParseFactPayload(n.Payload)
		switch n.FactType() {
		case db.FactTypeClaim:
			claimIDs = append(claimIDs, n.ID)
			if summary == "" && strings.TrimSpace(p.Summary) != "" {
				summary = p.Summary
			}
			if p.Confidence == "observed" || confidence == "" {
				confidence = p.Confidence
			}
			for _, ref := range p.EvidenceRefs {
				addEvidence(ref)
			}
			for _, id := range p.SourceActivityIDs {
				addEvidence(fmt.Sprintf("activity:%d", id))
			}
		case db.FactTypeHypothesis:
			if p.State == "" || p.State == "open" || p.State == "supported" {
				hypothesisIDs = append(hypothesisIDs, n.ID)
				if hypothesisSummary == "" && strings.TrimSpace(p.Summary) != "" {
					hypothesisSummary = p.Summary
				}
			}
			for _, action := range p.ValidationActions {
				if s := strings.TrimSpace(action); s != "" {
					nextActions = append(nextActions, s)
				}
			}
			for _, ref := range p.EvidenceRefs {
				addEvidence(ref)
			}
		}
	}
	if hasFinding || (len(claimIDs) == 0 && len(hypothesisIDs) == 0) || len(evidenceRefs) == 0 {
		return 0, nil
	}
	if summary == "" {
		summary = hypothesisSummary
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
	if len(nextActions) > 10 {
		nextActions = nextActions[:10]
	}
	route := db.ParseIntentRoute(intent)
	payload := map[string]any{
		"fact_type":        db.FactTypeFindingCandidate,
		"summary":          "待确认候选：" + firstLine(summary, 300),
		"evidence_refs":    evidenceRefs,
		"validation_state": "pending",
		"confidence":       fallbackString(confidence, "inferred"),
		"route_id":         route.RouteID,
		"intent_id":        intent.ID,
		"run_id":           runID,
		"observed_at":      time.Now().UTC().Format(time.RFC3339),
	}
	// Only emit the linkage keys that exist: a hypothesis-only run must not write
	// "claim_ids": [] and a claim-only run must not write "hypothesis_ids": [].
	if len(claimIDs) > 0 {
		payload["claim_ids"] = claimIDs
	}
	if len(hypothesisIDs) > 0 {
		payload["hypothesis_ids"] = hypothesisIDs
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
