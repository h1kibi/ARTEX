package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Route Graph / Information Graph / Evidence Layer query views. These are
// read-only projections over existing exploration nodes, anchors and activity;
// they never copy bodies into another store.

type RouteIntentDTO struct {
	ID             string  `json:"id"`
	Summary        string  `json:"summary"`
	State          string  `json:"state"`
	Origin         string  `json:"origin,omitempty"`
	Phase          string  `json:"phase,omitempty"`
	AssetIDs       []int64 `json:"asset_ids,omitempty"`
	WorkerSeconds  float64 `json:"worker_seconds"`
	WorkerRuns     int     `json:"worker_runs"`
	CheckpointID   int64   `json:"checkpoint_fact_id,omitempty"`
	TerminalReason string  `json:"terminal_reason,omitempty"`
	DeleteReason   string  `json:"delete_reason,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

type RouteCheckpointDTO struct {
	ID                string             `json:"id"`
	RouteID           int64              `json:"route_id"`
	IntentID          int64              `json:"intent_id,omitempty"`
	RunID             string             `json:"run_id,omitempty"`
	Phase             string             `json:"path_phase,omitempty"`
	Summary           string             `json:"summary"`
	SettlementReason  string             `json:"settlement_reason,omitempty"`
	ConfirmedClaimIDs []int64            `json:"confirmed_claim_ids,omitempty"`
	OpenHypothesisIDs []int64            `json:"open_hypothesis_ids,omitempty"`
	FindingIDs        []int64            `json:"finding_ids,omitempty"`
	EvidenceRefs      []string           `json:"evidence_refs,omitempty"`
	AttemptedActions  []string           `json:"attempted_actions,omitempty"`
	NextActions       []string           `json:"next_actions,omitempty"`
	BudgetUsed        db.RouteBudgetUsed `json:"budget_used"`
	CreatedAt         string             `json:"created_at"`
}

type RouteFindingDTO struct {
	ID           string   `json:"id"`
	FindingID    string   `json:"finding_id,omitempty"`
	Summary      string   `json:"summary"`
	Severity     string   `json:"severity,omitempty"`
	VulnClass    string   `json:"vulnclass,omitempty"`
	State        string   `json:"state"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	TrafficCount int      `json:"traffic_count,omitempty"`
}

type RouteDTO struct {
	RouteID          int64                `json:"route_id"`
	RouteKind        string               `json:"route_kind,omitempty"`
	Objective        string               `json:"objective,omitempty"`
	Phase            string               `json:"phase,omitempty"`
	SuccessCondition string               `json:"success_condition,omitempty"`
	ExpectedEvidence []string             `json:"expected_evidence,omitempty"`
	Status           string               `json:"status"`
	Budget           db.RouteBudget       `json:"budget,omitempty"`
	BudgetUsed       db.RouteBudgetUsed   `json:"budget_used"`
	IntentCount      int                  `json:"intent_count"`
	ActiveIntents    int                  `json:"active_intents"`
	AssetIDs         []int64              `json:"asset_ids,omitempty"`
	Intents          []RouteIntentDTO     `json:"intents"`
	Checkpoints      []RouteCheckpointDTO `json:"checkpoints"`
	Findings         []RouteFindingDTO    `json:"findings"`
	CreatedAt        string               `json:"created_at"`
}

type InformationNodeDTO struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"` // fact | finding
	FactType          string   `json:"fact_type"`
	Summary           string   `json:"summary"`
	Detail            string   `json:"detail,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
	State             string   `json:"state,omitempty"`
	ValidationState   string   `json:"validation_state,omitempty"`
	Alternatives      []string `json:"alternatives_rejected,omitempty"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	SourceActivityIDs []int64  `json:"source_activity_ids,omitempty"`
	ClaimIDs          []int64  `json:"claim_ids,omitempty"`
	HypothesisIDs     []int64  `json:"hypothesis_ids,omitempty"`
	RouteID           int64    `json:"route_id,omitempty"`
	IntentID          int64    `json:"intent_id,omitempty"`
	RunID             string   `json:"run_id,omitempty"`
	ObservedAt        string   `json:"observed_at,omitempty"`
	ValidUntil        string   `json:"valid_until,omitempty"`
	Sensitivity       string   `json:"sensitivity,omitempty"`
	InheritancePolicy string   `json:"inheritance_policy,omitempty"`
	Expired           bool     `json:"expired,omitempty"`
	Origin            string   `json:"origin,omitempty"`
	Severity          string   `json:"severity,omitempty"`
	VulnClass         string   `json:"vulnclass,omitempty"`
	FindingID         string   `json:"finding_id,omitempty"`
	Inherited         bool     `json:"inherited,omitempty"`
	SourceTaskID      string   `json:"source_task_id,omitempty"`
	CreatedAt         string   `json:"created_at"`
}

type InformationResponse struct {
	Nodes     []InformationNodeDTO `json:"nodes"`
	Total     int                  `json:"total"`
	Counts    map[string]int       `json:"counts"`
	Truncated bool                 `json:"truncated"`
}

type EvidenceRefDTO struct {
	Ref              string   `json:"ref"`
	Kind             string   `json:"kind"`
	ID               string   `json:"id"`
	Available        *bool    `json:"available,omitempty"`
	SourceNodeIDs    []int64  `json:"source_node_ids"`
	SourceKinds      []string `json:"source_kinds,omitempty"`
	EvidenceVersions []int64  `json:"evidence_versions,omitempty"`
	SnapshotIDs      []string `json:"snapshot_ids,omitempty"`
}

type EvidenceResponse struct {
	Refs           []EvidenceRefDTO `json:"refs"`
	TrafficEnabled bool             `json:"traffic_enabled"`
}

func (s *Server) taskRoutes(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	intents, err := t.Store.ListByKind(db.KindIntent, 1000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	facts, err := t.Store.ListByKind(db.KindFact, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	findings, err := t.Store.ListByKind(db.KindFinding, 1000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := t.Store.PopulateFindingTrafficIDs(findings); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	findingIntent, err := t.Store.FindingIntents()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	intentIDs := make([]int64, 0, len(intents))
	for _, n := range intents {
		if !n.Inherited {
			intentIDs = append(intentIDs, n.ID)
		}
	}
	anchors, err := t.Store.AssetIDsForNodes(intentIDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	routes := map[int64]*RouteDTO{}
	intentToRoute := map[int64]int64{}
	latestBudgetIntent := map[int64]int64{}
	for _, n := range intents {
		if n.Inherited {
			continue
		}
		route := db.ParseIntentRoute(n)
		routeID := route.RouteID
		if routeID <= 0 {
			routeID = n.ID
		}
		intentToRoute[n.ID] = routeID
		rd := routes[routeID]
		if rd == nil {
			rd = &RouteDTO{
				RouteID: routeID, RouteKind: route.RouteKind, Budget: route.Budget,
				Intents: []RouteIntentDTO{}, Checkpoints: []RouteCheckpointDTO{}, Findings: []RouteFindingDTO{},
			}
			routes[routeID] = rd
		}
		if route.Objective != "" && rd.Objective == "" {
			rd.Objective = route.Objective
		}
		if route.PathPhase != "" && rd.Phase == "" {
			rd.Phase = route.PathPhase
		}
		if route.SuccessCondition != "" && rd.SuccessCondition == "" {
			rd.SuccessCondition = route.SuccessCondition
		}
		if len(route.ExpectedEvidence) > 0 && len(rd.ExpectedEvidence) == 0 {
			rd.ExpectedEvidence = route.ExpectedEvidence
		}
		// The newest intent on the route owns the authoritative cumulative budget:
		// a continuation may legitimately raise it, so the first intent's copy is
		// stale and must not win forever.
		if n.ID > latestBudgetIntent[routeID] {
			latestBudgetIntent[routeID] = n.ID
			if !route.Budget.Empty() {
				rd.Budget = route.Budget
			}
			if route.BudgetUsed != (db.RouteBudgetUsed{}) {
				rd.BudgetUsed = route.BudgetUsed
			}
		}
		var p struct {
			Summary  string  `json:"summary"`
			AssetIDs []int64 `json:"asset_ids"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		ids := append([]int64(nil), anchors[n.ID]...)
		for _, id := range p.AssetIDs {
			if id > 0 {
				ids = appendUniqueInt64(ids, id)
			}
		}
		rd.AssetIDs = appendUniqueInt64(rd.AssetIDs, ids...)
		rd.Intents = append(rd.Intents, RouteIntentDTO{
			ID: i64s(n.ID), Summary: p.Summary, State: n.State, Origin: n.Origin,
			Phase: route.PathPhase, AssetIDs: ids,
			WorkerSeconds: taskIntentWorkerSeconds(n), WorkerRuns: n.WorkerRuns,
			CheckpointID: route.CheckpointFactID, TerminalReason: n.TerminalReason,
			DeleteReason: n.DeleteReason, CreatedAt: rfc3339(n.CreatedAt),
		})
		rd.IntentCount++
		if n.State == "running" {
			rd.ActiveIntents++
		}
		if rd.CreatedAt == "" || n.CreatedAt.Before(parseTime(rd.CreatedAt)) {
			rd.CreatedAt = rfc3339(n.CreatedAt)
		}
	}
	for _, n := range facts {
		if n.Inherited || n.FactType() != db.FactTypeCheckpoint {
			continue
		}
		p := db.ParseFactPayload(n.Payload)
		rd := routes[p.RouteID]
		if rd == nil {
			continue
		}
		rd.Checkpoints = append(rd.Checkpoints, RouteCheckpointDTO{
			ID: i64s(n.ID), RouteID: p.RouteID, IntentID: p.IntentID, RunID: p.CreatedByRun,
			Phase: p.PathPhase, Summary: p.Summary, SettlementReason: p.SettlementReason,
			ConfirmedClaimIDs: p.ConfirmedClaimIDs, OpenHypothesisIDs: p.OpenHypothesisIDs,
			FindingIDs: p.FindingIDs, EvidenceRefs: p.EvidenceRefs,
			AttemptedActions: p.AttemptedActions, NextActions: p.NextActions,
			BudgetUsed: p.BudgetUsed, CreatedAt: rfc3339(n.CreatedAt),
		})
	}
	for _, n := range findings {
		if n.Inherited {
			continue
		}
		var p struct {
			Summary      string   `json:"summary"`
			Severity     string   `json:"severity"`
			VulnClass    string   `json:"vulnclass"`
			RouteID      int64    `json:"route_id"`
			IntentID     int64    `json:"intent_id"`
			EvidenceRefs []string `json:"evidence_refs"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		routeID := p.RouteID
		if routeID <= 0 {
			routeID = intentToRoute[p.IntentID]
		}
		if routeID <= 0 {
			routeID = intentToRoute[findingIntent[n.ID]]
		}
		rd := routes[routeID]
		if rd == nil {
			continue
		}
		fid := ""
		if n.FindingID > 0 {
			fid = i64s(n.FindingID)
		}
		rd.Findings = append(rd.Findings, RouteFindingDTO{
			ID: i64s(n.ID), FindingID: fid, Summary: p.Summary,
			Severity: p.Severity, VulnClass: p.VulnClass, State: n.State,
			EvidenceRefs: p.EvidenceRefs, TrafficCount: n.TrafficCount,
		})
	}

	out := make([]RouteDTO, 0, len(routes))
	for _, rd := range routes {
		sort.Slice(rd.Intents, func(i, j int) bool { return lessNodeID(rd.Intents[i].ID, rd.Intents[j].ID) })
		sort.Slice(rd.Checkpoints, func(i, j int) bool { return lessNodeID(rd.Checkpoints[i].ID, rd.Checkpoints[j].ID) })
		if n := len(rd.Checkpoints); n > 0 && rd.Checkpoints[n-1].BudgetUsed != (db.RouteBudgetUsed{}) {
			rd.BudgetUsed = rd.Checkpoints[n-1].BudgetUsed
		}
		rd.Status = routeStatus(rd.Intents)
		out = append(out, *rd)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ActiveIntents != out[j].ActiveIntents {
			return out[i].ActiveIntents > out[j].ActiveIntents
		}
		return out[i].RouteID > out[j].RouteID
	})
	writeJSON(w, http.StatusOK, map[string]any{"routes": out})
}

func (s *Server) taskInformation(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 500)
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	routeFilter, _ := strconv.ParseInt(r.URL.Query().Get("route_id"), 10, 64)
	includeSources := r.URL.Query().Get("include_sources") == "1" || r.URL.Query().Get("include_sources") == "true"
	// Counts/total are computed in SQL over the whole graph; the page is limited
	// separately. Previously the handler truncated first and then reported the
	// truncated list as the total, which made "500/500" sessions look complete.
	nodes, counts, total, truncated, err := t.Store.InformationQueryWithSources(filter, routeFilter, limit, includeSources)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
	out := make([]InformationNodeDTO, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, informationNodeDTO(n, now))
	}
	writeJSON(w, http.StatusOK, InformationResponse{
		Nodes: out, Total: total, Counts: counts, Truncated: truncated,
	})
}

// informationNodeDTO projects a stored node into the read-only Information
// Graph shape. Inherited nodes keep their source task and never inherit the
// local task's route/intent ids.
func informationNodeDTO(n *db.Node, now time.Time) InformationNodeDTO {
	dto := InformationNodeDTO{
		ID: i64s(n.ID), State: n.State, Origin: n.Origin,
		Inherited: n.Inherited, CreatedAt: rfc3339(n.CreatedAt),
	}
	if n.SourceTaskID > 0 {
		dto.SourceTaskID = i64s(n.SourceTaskID)
	}
	if n.Kind == db.KindFinding {
		var p struct {
			Summary      string   `json:"summary"`
			Severity     string   `json:"severity"`
			VulnClass    string   `json:"vulnclass"`
			RouteID      int64    `json:"route_id"`
			IntentID     int64    `json:"intent_id"`
			EvidenceRefs []string `json:"evidence_refs"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		dto.Kind = "finding"
		dto.FactType = "finding"
		dto.Summary = p.Summary
		dto.Severity = p.Severity
		dto.VulnClass = p.VulnClass
		dto.EvidenceRefs = p.EvidenceRefs
		if !n.Inherited {
			dto.RouteID, dto.IntentID = p.RouteID, p.IntentID
		}
		if n.FindingID > 0 {
			dto.FindingID = i64s(n.FindingID)
		}
		return dto
	}
	p := db.ParseFactPayload(n.Payload)
	dto.Kind = "fact"
	dto.FactType = n.FactType()
	dto.Summary, dto.Detail = p.Summary, p.Detail
	dto.Confidence, dto.State = p.Confidence, p.State
	dto.ValidationState = p.ValidationState
	dto.Alternatives = p.Alternatives
	dto.EvidenceRefs = p.EvidenceRefs
	dto.SourceActivityIDs = p.SourceActivityIDs
	dto.ClaimIDs, dto.HypothesisIDs = p.ClaimIDs, p.HypothesisIDs
	dto.RunID, dto.ObservedAt, dto.ValidUntil = p.RunID, p.ObservedAt, p.ValidUntil
	dto.Sensitivity, dto.InheritancePolicy = p.Sensitivity, p.InheritancePolicy
	dto.Expired = db.IsFactExpired(p, now)
	if !n.Inherited {
		dto.RouteID, dto.IntentID = p.RouteID, p.IntentID
	}
	return dto
}

func (s *Server) taskEvidence(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	includeSources := r.URL.Query().Get("include_sources") == "1" || r.URL.Query().Get("include_sources") == "true"
	nodes, err := t.Store.EvidenceNodes(includeSources)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type source struct {
		nodes     []int64
		kinds     []string
		versions  []int64
		snapshots []string
		inherited bool
	}
	byRef := map[string]*source{}
	addSource := func(key string, nodeID int64, kind string, inherited bool) *source {
		src := byRef[key]
		if src == nil {
			src = &source{}
			byRef[key] = src
		}
		src.nodes = appendUniqueInt64(src.nodes, nodeID)
		if !containsString(src.kinds, kind) {
			src.kinds = append(src.kinds, kind)
		}
		src.inherited = src.inherited || inherited
		return src
	}
	for _, n := range nodes {
		kind := "fact"
		var refs []string
		if n.Kind == db.KindFinding {
			kind = "finding"
			var p struct {
				EvidenceRefs []string `json:"evidence_refs"`
			}
			_ = json.Unmarshal(n.Payload, &p)
			refs = p.EvidenceRefs
		} else {
			refs = db.ParseFactPayload(n.Payload).EvidenceRefs
		}
		for _, ref := range refs {
			parsed, err := db.ParseEvidenceRef(ref)
			if err != nil {
				continue
			}
			addSource(parsed.String(), n.ID, kind, n.Inherited)
		}
	}
	// report_finding stores HTTP evidence in finding_traffic_bindings, not in
	// payload.evidence_refs. Merge those refs (plus their snapshot/version) so a
	// confirmed vuln's core traffic is visible here too.
	mergeBindings := func(store *db.ExplorationStore, inherited bool) error {
		bindings, err := store.FindingTrafficRefs()
		if err != nil {
			return err
		}
		for _, b := range bindings {
			if strings.TrimSpace(b.TrafficID) == "" {
				continue
			}
			src := addSource("traffic:"+b.TrafficID, b.NodeID, "finding_traffic", inherited)
			if b.EvidenceVersion > 0 && !containsInt64(src.versions, b.EvidenceVersion) {
				src.versions = append(src.versions, b.EvidenceVersion)
			}
			if s := strings.TrimSpace(b.SnapshotID); s != "" && !containsString(src.snapshots, s) {
				src.snapshots = append(src.snapshots, s)
			}
		}
		return nil
	}
	if err := mergeBindings(t.Store, false); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if includeSources {
		sources, err := t.Store.DirectSourceStores()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, src := range sources {
			if err := mergeBindings(src.Store, true); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	tr := s.m.Traffic()
	refs := make([]EvidenceRefDTO, 0, len(byRef))
	for ref, src := range byRef {
		parsed, _ := db.ParseEvidenceRef(ref)
		dto := EvidenceRefDTO{Ref: ref, Kind: parsed.Kind, ID: parsed.ID,
			SourceNodeIDs: src.nodes, SourceKinds: src.kinds,
			EvidenceVersions: src.versions, SnapshotIDs: src.snapshots}
		if src.inherited {
			// The referenced node/activity belongs to a source task; this task's
			// store cannot resolve it. Traffic ids are global and still checkable.
			if parsed.Kind == "traffic" && tr != nil {
				if ok, err := tr.Exists(parsed.ID); err == nil {
					available := ok
					dto.Available = &available
				}
			}
			refs = append(refs, dto)
			continue
		}
		switch parsed.Kind {
		case "traffic":
			available := false
			if tr != nil {
				if ok, err := tr.Exists(parsed.ID); err == nil {
					available = ok
				}
			}
			dto.Available = &available
		case "activity":
			id, _ := strconv.ParseInt(parsed.ID, 10, 64)
			if ok, err := t.Store.ActivityExists(id); err == nil {
				available := ok
				dto.Available = &available
			}
		case "node", "finding":
			id, _ := strconv.ParseInt(parsed.ID, 10, 64)
			if n, err := t.Store.GetNode(id); err == nil {
				available := n != nil
				dto.Available = &available
			}
		}
		refs = append(refs, dto)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Ref < refs[j].Ref })
	writeJSON(w, http.StatusOK, EvidenceResponse{Refs: refs, TrafficEnabled: tr != nil})
}

const (
	routeStatusProposed   = "proposed"
	routeStatusActive     = "active"
	routeStatusPaused     = "paused"
	routeStatusSucceeded  = "succeeded"
	routeStatusBlocked    = "blocked"
	routeStatusExhausted  = "exhausted"
	routeStatusStopped    = "stopped"
	routeStatusSuperseded = "superseded"
)

// routeStatus projects the route lifecycle from its intents. The newest
// non-deleted intent owns the state: on a multi-stage route I1(done) -> I2,
// I1 must not mask I2 ending blocked/exhausted/stopped as "succeeded". A live
// intent is always the newest by construction (a route is serial), so the same
// rule keeps running/paused/open routes accurate.
func routeStatus(intents []RouteIntentDTO) string {
	var latest *RouteIntentDTO
	for i := range intents {
		n := &intents[i]
		switch n.State {
		case "deleted", "pending_delete":
			continue
		}
		if latest == nil || lessNodeID(latest.ID, n.ID) {
			latest = n
		}
	}
	if latest == nil {
		return routeStatusProposed
	}
	switch latest.State {
	case "running":
		return routeStatusActive
	case "paused":
		return routeStatusPaused
	case "open":
		// Queued, not claimed: an open intent must not look live.
		return routeStatusProposed
	case "done":
		return routeStatusSucceeded
	case "blocked":
		return routeStatusBlocked
	case "exhausted":
		return routeStatusExhausted
	case "stopped":
		if strings.EqualFold(strings.TrimSpace(latest.TerminalReason), "superseded") {
			return routeStatusSuperseded
		}
		return routeStatusStopped
	default:
		return routeStatusProposed
	}
}

func containsString(in []string, value string) bool {
	for _, v := range in {
		if v == value {
			return true
		}
	}
	return false
}

func containsInt64(in []int64, value int64) bool {
	for _, v := range in {
		if v == value {
			return true
		}
	}
	return false
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func appendUniqueInt64(dst []int64, values ...int64) []int64 {
	seen := make(map[int64]bool, len(dst)+len(values))
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range values {
		if v > 0 && !seen[v] {
			seen[v] = true
			dst = append(dst, v)
		}
	}
	return dst
}

func taskIntentWorkerSeconds(n *db.Node) float64 {
	ms := n.WorkerMS
	if n.State == "running" && n.WorkerStartedAt != nil {
		ms += time.Since(*n.WorkerStartedAt).Milliseconds()
	}
	if ms < 0 {
		ms = 0
	}
	return float64(ms) / 1000
}

func lessNodeID(a, b string) bool {
	ai, _ := strconv.ParseInt(a, 10, 64)
	bi, _ := strconv.ParseInt(b, 10, 64)
	return ai < bi
}
