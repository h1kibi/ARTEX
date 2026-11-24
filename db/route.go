package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// AddNodeLinked inserts a node and one outgoing edge in the same transaction.
// Checkpoint and candidate facts need this so a reader never sees the node
// without its intent->yields lineage.
func (s *ExplorationStore) AddNodeLinked(kind string, payload map[string]any, priority int, state, origin string, anchors []int64, from int64, rel string) (int64, error) {
	raw, _ := json.Marshal(payload)
	raw = jsonbClean(raw)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var id int64
	if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		s.expID, kind, string(raw), priority, state, origin).Scan(&id); err != nil {
		return 0, err
	}
	for _, a := range anchors {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, a); err != nil {
			return 0, err
		}
	}
	if from > 0 && rel != "" {
		if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id) VALUES ($1,$2,$3,$4)
ON CONFLICT (exploration_id, src_id, rel, dst_id) DO NOTHING`, s.expID, from, rel, id); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// NewEdge is one lineage edge from an existing node into the node being created.
type NewEdge struct {
	From int64
	Rel  string
}

// AddIntentWithEdges inserts an intent, its anchors and all lineage edges in one
// transaction. A brand-new route gets route_id = its own intent id, which is the
// stable identity continuation intents inherit. routeID<=0 means "new route".
func (s *ExplorationStore) AddIntentWithEdges(payload map[string]any, priority int, anchors []int64, origin string, routeID int64, edges []NewEdge) (id int64, route int64, err error) {
	raw, _ := json.Marshal(payload)
	raw = jsonbClean(raw)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1, 'intent', $2, $3, 'open', $4) RETURNING id`,
		s.expID, string(raw), priority, origin).Scan(&id); err != nil {
		return 0, 0, err
	}
	route = routeID
	if route <= 0 {
		route = id
	}
	// The database is authoritative for route identity: a caller cannot create a
	// continuation whose stored payload disagrees with the inherited route.
	raw, _ = json.Marshal(map[string]any{"route_id": route})
	if _, err := tx.Exec(`UPDATE exploration_nodes
SET payload = payload || $1::jsonb, content_version = content_version + 1
WHERE id=$2`, string(raw), id); err != nil {
		return 0, 0, err
	}
	for _, a := range anchors {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, a); err != nil {
			return 0, 0, err
		}
	}
	for _, e := range edges {
		if e.From <= 0 || e.Rel == "" || e.From == id {
			continue
		}
		if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id) VALUES ($1,$2,$3,$4)
ON CONFLICT (exploration_id, src_id, rel, dst_id) DO NOTHING`, s.expID, e.From, e.Rel, id); err != nil {
			return 0, 0, err
		}
	}
	return id, route, tx.Commit()
}

// UpdateFactPayload rewrites one local fact payload and bumps content_version so
// a digest that covered the node is invalidated. It is scoped to kind='fact'.
func (s *ExplorationStore) UpdateFactPayload(id int64, payload map[string]any) error {
	raw, _ := json.Marshal(payload)
	raw = jsonbClean(raw)
	res, err := s.db.Exec(`UPDATE exploration_nodes
SET payload=$1, content_version=content_version+1
WHERE id=$2 AND exploration_id=$3 AND kind='fact'`, string(raw), id, s.expID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("fact %d not found", id)
	}
	return nil
}

// SetIntentRouteProgress records the checkpoint and the cumulative route usage
// on the intent. A retry of the same intent (new run_id) must inherit the spent
// budget, not start again from zero.
func (s *ExplorationStore) SetIntentRouteProgress(intentID, checkpointID int64, used RouteBudgetUsed, routeStartedAt string) error {
	if intentID <= 0 || checkpointID <= 0 {
		return fmt.Errorf("intentID and checkpointID are required")
	}
	usedRaw, _ := json.Marshal(used)
	extra := map[string]any{"checkpoint_fact_id": checkpointID, "route_budget_used": json.RawMessage(usedRaw)}
	if routeStartedAt != "" {
		extra["route_started_at"] = routeStartedAt
	}
	extraRaw, _ := json.Marshal(extra)
	res, err := s.db.Exec(`UPDATE exploration_nodes
SET payload = payload || $1::jsonb,
    content_version = content_version + 1
WHERE id=$2 AND exploration_id=$3 AND kind='intent'`, string(extraRaw), intentID, s.expID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("intent %d not found", intentID)
	}
	return nil
}

// SaveRunCheckpoint persists a run checkpoint, its lineage edges, and the
// intent's updated checkpoint/budget cursor inside ONE transaction. The planner
// and a retried run therefore never observe a committed checkpoint without the
// updated intent state (or vice versa).
func (s *ExplorationStore) SaveRunCheckpoint(
	intentID, existingCheckpointID, previousCheckpointID int64,
	payload map[string]any, used RouteBudgetUsed, routeStartedAt string,
) (int64, error) {
	if intentID <= 0 {
		return 0, fmt.Errorf("intentID is required")
	}
	raw, _ := json.Marshal(payload)
	raw = jsonbClean(raw)
	usedRaw, _ := json.Marshal(used)
	extra := map[string]any{"route_budget_used": json.RawMessage(usedRaw)}
	if routeStartedAt != "" {
		extra["route_started_at"] = routeStartedAt
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	checkpointID := existingCheckpointID
	if checkpointID > 0 {
		res, err := tx.Exec(`UPDATE exploration_nodes
SET payload=$1, content_version=content_version+1
WHERE id=$2 AND exploration_id=$3 AND kind='fact'`, string(raw), checkpointID, s.expID)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return 0, fmt.Errorf("checkpoint fact %d not found", checkpointID)
		}
	} else {
		if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1, 'fact', $2, 0, 'confirmed', 'system') RETURNING id`,
			s.expID, string(raw)).Scan(&checkpointID); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id) VALUES ($1,$2,$3,$4)
ON CONFLICT (exploration_id, src_id, rel, dst_id) DO NOTHING`,
		s.expID, intentID, RelYields, checkpointID); err != nil {
		return 0, err
	}
	if previousCheckpointID > 0 && previousCheckpointID != checkpointID {
		if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id) VALUES ($1,$2,$3,$4)
ON CONFLICT (exploration_id, src_id, rel, dst_id) DO NOTHING`,
			s.expID, previousCheckpointID, RelDerivedFrom, checkpointID); err != nil {
			return 0, err
		}
	}
	extra["checkpoint_fact_id"] = checkpointID
	extraRaw, _ := json.Marshal(extra)
	res, err := tx.Exec(`UPDATE exploration_nodes
SET payload = payload || $1::jsonb,
    content_version = content_version + 1
WHERE id=$2 AND exploration_id=$3 AND kind='intent'`, string(extraRaw), intentID, s.expID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, fmt.Errorf("intent %d not found", intentID)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return checkpointID, nil
}

// RouteBudgetExhausted reports the first exhausted dimension of a cumulative
// route budget. Wall-clock usage is compared in milliseconds; the returned
// values are raw counts for that dimension. A zero limit means unlimited.
func RouteBudgetExhausted(budget RouteBudget, used RouteBudgetUsed) (dimension string, usedValue, limit int64) {
	switch {
	case budget.MaxToolCalls > 0 && used.ToolCalls >= budget.MaxToolCalls:
		return "tool_calls", int64(used.ToolCalls), int64(budget.MaxToolCalls)
	case budget.MaxInputTokens > 0 && used.InputTokens >= budget.MaxInputTokens:
		return "input_tokens", int64(used.InputTokens), int64(budget.MaxInputTokens)
	case budget.MaxWallSeconds > 0 && used.WallMS >= int64(budget.MaxWallSeconds)*1000:
		return "wall_seconds", used.WallMS / 1000, int64(budget.MaxWallSeconds)
	default:
		return "", 0, 0
	}
}

// LatestIntentForRoute returns the newest intent on a route (highest id). A
// continuation may raise the cumulative budget, so this intent owns the
// authoritative limits; older intents keep their historical copy.
func (s *ExplorationStore) LatestIntentForRoute(routeID int64) (*Node, error) {
	if routeID <= 0 {
		return nil, nil
	}
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent'
  AND COALESCE(NULLIF(payload->>'route_id',''), id::text) = $2
ORDER BY id DESC LIMIT 1`, s.expID, fmt.Sprint(routeID)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// LatestCheckpointForRoute returns the newest checkpoint fact of one route.
func (s *ExplorationStore) LatestCheckpointForRoute(routeID int64) (*Node, error) {
	if routeID <= 0 {
		return nil, nil
	}
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind='fact'
  AND payload->>'fact_type' = $2
  AND payload->>'route_id' = $3
ORDER BY id DESC LIMIT 1`, s.expID, FactTypeCheckpoint, fmt.Sprint(routeID)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// ListFactsByType lists facts of one information type newest first.
func (s *ExplorationStore) ListFactsByType(factType string, limit int) ([]*Node, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind='fact' AND payload->>'fact_type'=$2
ORDER BY id DESC LIMIT $3`, s.expID, factType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// ActiveIntentForRoute returns an open/running/paused intent on the route, or nil.
// A route is a serial attack path: only one live Intent may advance it at a time.
func (s *ExplorationStore) ActiveIntentForRoute(routeID int64) (*Node, error) {
	if routeID <= 0 {
		return nil, nil
	}
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent'
  AND payload->>'route_id'=$2 AND state IN ('open','running','paused')
ORDER BY id LIMIT 1`, s.expID, fmt.Sprint(routeID)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// FindFactByIntentType returns the newest fact of one type produced by an
// intent. The finding-candidate reconciler uses it to update in place.
func (s *ExplorationStore) FindFactByIntentType(intentID int64, factType string) (*Node, error) {
	if intentID <= 0 || factType == "" {
		return nil, nil
	}
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind='fact'
  AND payload->>'fact_type'=$2 AND payload->>'intent_id'=$3
ORDER BY id DESC LIMIT 1`, s.expID, factType, fmt.Sprint(intentID)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// OutputsYielded returns the fact/finding nodes an intent produced via yields.
func (s *ExplorationStore) OutputsYielded(intentID int64) ([]*Node, error) {
	if intentID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT n.id FROM exploration_nodes n
JOIN exploration_edges e ON e.dst_id = n.id AND e.exploration_id = n.exploration_id
WHERE n.exploration_id=$1 AND e.src_id=$2 AND e.rel=$3 AND n.kind IN ('fact','finding')
ORDER BY n.id`, s.expID, intentID, RelYields)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	nodes, err := s.NodesByIDs(ids)
	if err != nil {
		return nil, err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes, nil
}

// LastToolResultActivity returns the newest successful-or-failed tool_result for
// one intent. record_fact uses it to attach a reviewable provenance activity when
// the model did not supply an explicit source.
func (s *ExplorationStore) LastToolResultActivity(intentID int64) (*Activity, error) {
	if intentID <= 0 {
		return nil, nil
	}
	var a Activity
	var worker, kind, tool, toolUseID, summary string
	var metadata []byte
	err := s.db.QueryRow(`SELECT id, COALESCE(worker,''), COALESCE(kind,''), COALESCE(tool,''),
		COALESCE(tool_use_id,''), is_error, COALESCE(summary,''), metadata, created_at
FROM activity
WHERE exploration_id=$1 AND node_id=$2 AND kind='tool_result'
ORDER BY id DESC LIMIT 1`, s.expID, intentID).Scan(
		&a.ID, &worker, &kind, &tool, &toolUseID, &a.IsError, &summary, &metadata, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.NodeID = &intentID
	a.Worker, a.Kind, a.Tool, a.ToolUseID, a.Summary = worker, kind, tool, toolUseID, summary
	a.Metadata = metadata
	return &a, nil
}

// ActivityExists reports whether an activity id belongs to this exploration.
func (s *ExplorationStore) ActivityExists(id int64) (bool, error) {
	if id <= 0 {
		return false, nil
	}
	var ok bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM activity WHERE id=$1 AND exploration_id=$2)`, id, s.expID).Scan(&ok)
	return ok, err
}

// FindingOrNodeExists reports whether id matches a finding node in this
// exploration (or a findings row owned by its task).
func (s *ExplorationStore) FindingOrNodeExists(id int64) (bool, error) {
	if id <= 0 {
		return false, nil
	}
	var ok bool
	err := s.db.QueryRow(`SELECT (
  EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='finding')
  OR EXISTS(
    SELECT 1 FROM findings f
    JOIN tasks t ON t.id = f.task_id
    WHERE f.id=$1 AND t.exploration_id=$2 AND t.deleted_at IS NULL
  )
)`, id, s.expID).Scan(&ok)
	return ok, err
}

// InformationCounts returns exact per-type totals for the Information Graph,
// excluding task-root origin facts and route checkpoints before counting.
func (s *ExplorationStore) InformationCounts(routeID int64) (map[string]int, int, error) {
	counts := map[string]int{}
	args := []any{s.expID}
	routeCond := ""
	if routeID > 0 {
		args = append(args, fmt.Sprint(routeID))
		routeCond = ` AND (
  n.payload->>'route_id' = $2
  OR EXISTS (
    SELECT 1 FROM exploration_edges e
    JOIN exploration_nodes i ON i.id = e.src_id AND i.exploration_id = e.exploration_id
    WHERE e.exploration_id = n.exploration_id AND e.dst_id = n.id AND e.rel = 'yields'
      AND i.kind = 'intent' AND COALESCE(NULLIF(i.payload->>'route_id',''), i.id::text) = $2
  )
)`
	}
	rows, err := s.db.Query(`
SELECT CASE
         WHEN n.kind = 'finding' THEN 'finding'
         ELSE COALESCE(NULLIF(BTRIM(n.payload->>'fact_type'), ''), 'legacy_unknown')
       END AS info_type,
       COUNT(*)
FROM exploration_nodes n
WHERE n.exploration_id = $1
  AND (
    (n.kind = 'fact' AND n.state <> 'origin' AND COALESCE(n.payload->>'fact_type', '') <> 'checkpoint')
    OR n.kind = 'finding'
  )`+routeCond+`
GROUP BY info_type`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var typ string
		var cnt int
		if err := rows.Scan(&typ, &cnt); err != nil {
			return nil, 0, err
		}
		counts[typ] = cnt
		total += cnt
	}
	return counts, total, rows.Err()
}

// InformationNodesPage returns up to limit Information Graph nodes newest first,
// filtering out checkpoints and origin facts inside SQL so they never crowd out
// observations/claims/hypotheses.
func (s *ExplorationStore) InformationNodesPage(factType string, routeID int64, limit int) ([]*Node, bool, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	args := []any{s.expID}
	var conds []string
	conds = append(conds, "n.exploration_id = $1")
	switch factType {
	case "", "all":
		conds = append(conds, "((n.kind = 'fact' AND n.state <> 'origin' AND COALESCE(n.payload->>'fact_type', '') <> 'checkpoint') OR n.kind = 'finding')")
	case "finding":
		conds = append(conds, "n.kind = 'finding'")
	case FactTypeLegacyUnknown:
		conds = append(conds, "n.kind = 'fact' AND n.state <> 'origin' AND NULLIF(BTRIM(n.payload->>'fact_type'), '') IS NULL")
	default:
		args = append(args, factType)
		conds = append(conds, fmt.Sprintf("n.kind = 'fact' AND n.state <> 'origin' AND n.payload->>'fact_type' = $%d", len(args)))
	}
	if routeID > 0 {
		args = append(args, fmt.Sprint(routeID))
		p := len(args)
		conds = append(conds, fmt.Sprintf(`(
  n.payload->>'route_id' = $%d
  OR EXISTS (
    SELECT 1 FROM exploration_edges e
    JOIN exploration_nodes i ON i.id = e.src_id AND i.exploration_id = e.exploration_id
    WHERE e.exploration_id = n.exploration_id AND e.dst_id = n.id AND e.rel = 'yields'
      AND i.kind = 'intent' AND COALESCE(NULLIF(i.payload->>'route_id',''), i.id::text) = $%d
  )
)`, p, p))
	}
	args = append(args, limit+1)
	q := `SELECT n.id, n.kind, n.payload, n.priority, n.state, COALESCE(n.origin,''), COALESCE(n.owner,''),
       COALESCE(n.blocked_reason,''), COALESCE(n.delete_reason,''), COALESCE(n.terminal_reason,''),
       n.worker_ms, n.worker_runs, n.worker_started_at, n.created_at
FROM exploration_nodes n
WHERE ` + strings.Join(conds, " AND ") + `
ORDER BY n.id DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	nodes, err := scanNodes(rows)
	if err != nil {
		return nil, false, err
	}
	truncated := len(nodes) > limit
	if truncated {
		nodes = nodes[:limit]
	}
	return nodes, truncated, nil
}

// InformationQueryWithSources returns the Information Graph slice and exact
// per-type counts. By default only the current task is queried; when
// includeSources is true, direct source tasks are merged through CanInheritFact
// (filtering expired, sensitive, and unverified records).
func (s *ExplorationStore) InformationQueryWithSources(factType string, routeID int64, limit int, includeSources bool) ([]*Node, map[string]int, int, bool, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	counts, total, err := s.InformationCounts(routeID)
	if err != nil {
		return nil, nil, 0, false, err
	}
	nodes, truncated, err := s.InformationNodesPage(factType, routeID, limit)
	if err != nil {
		return nil, nil, 0, false, err
	}
	if !includeSources || routeID > 0 {
		return nodes, counts, total, truncated, nil
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, nil, 0, false, err
	}
	now := time.Now()
	for _, src := range sources {
		srcNodes, _, err := src.Store.InformationNodesPage("", 0, 2000)
		if err != nil {
			return nil, nil, 0, false, err
		}
		for _, n := range srcNodes {
			if n.Kind == KindFact {
				if ok, _ := CanInheritFact(n, now); !ok {
					continue
				}
			}
			typ := "finding"
			if n.Kind == KindFact {
				typ = n.FactType()
			}
			counts[typ]++
			total++
			if factType != "" && factType != "all" && typ != factType {
				continue
			}
			nodes = append(nodes, markInheritedNode(n, src.Task.TaskID))
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID > nodes[j].ID })
	if len(nodes) > limit {
		nodes = nodes[:limit]
		truncated = true
	}
	return nodes, counts, total, truncated, nil
}

// EvidenceNodes returns facts and findings carrying structured evidence_refs,
// propagating DB errors instead of masquerading as empty.
func (s *ExplorationStore) EvidenceNodes(includeSources bool) ([]*Node, error) {
	query := func(store *ExplorationStore, inherited bool, taskID int64) ([]*Node, error) {
		rows, err := store.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1
  AND kind IN ('fact','finding')
  AND jsonb_typeof(payload->'evidence_refs') = 'array'
  AND jsonb_array_length(payload->'evidence_refs') > 0
ORDER BY id DESC LIMIT 2000`, store.expID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		list, err := scanNodes(rows)
		if err != nil {
			return nil, err
		}
		if !inherited {
			return list, nil
		}
		now := time.Now()
		out := make([]*Node, 0, len(list))
		for _, n := range list {
			if n.Kind == KindFact {
				if ok, _ := CanInheritFact(n, now); !ok {
					continue
				}
			}
			out = append(out, markInheritedNode(n, taskID))
		}
		return out, nil
	}
	out, err := query(s, false, 0)
	if err != nil {
		return nil, err
	}
	if !includeSources {
		return out, nil
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, src := range sources {
		list, err := query(src.Store, true, src.Task.TaskID)
		if err != nil {
			return nil, err
		}
		out = append(out, list...)
	}
	return out, nil
}

// referencedNodeIDsTx returns every exploration node id referenced by a fact
// payload (checkpoint, candidate, decision, hypothesis). CancelIntent uses it to
// keep a Claim alive while another Route, Checkpoint or Candidate still points
// at it. Physical deletion remains the caller's decision; this is a protection
// set, not a cascade.
func (s *ExplorationStore) referencedNodeIDsTx(tx *sql.Tx) (map[int64]bool, error) {
	protected := map[int64]bool{}
	rows, err := tx.Query(`SELECT payload FROM exploration_nodes
WHERE exploration_id=$1 AND kind='fact'`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p FactPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			continue
		}
		for _, group := range [][]int64{
			p.ClaimIDs, p.ObservationIDs, p.HypothesisIDs,
			p.ConfirmedClaimIDs, p.OpenHypothesisIDs, p.FindingIDs,
		} {
			for _, id := range group {
				if id > 0 {
					protected[id] = true
				}
			}
		}
		if p.CheckpointFactID > 0 {
			protected[p.CheckpointFactID] = true
		}
		if p.NextIntentID > 0 {
			protected[p.NextIntentID] = true
		}
	}
	return protected, rows.Err()
}

// AssetIDsForNodes returns the anchored asset ids for the given exploration
// nodes. Route and information views use it to show asset links without copying
// asset bodies into the route payload.
func (s *ExplorationStore) AssetIDsForNodes(ids []int64) (map[int64][]int64, error) {
	out := map[int64][]int64{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(`SELECT node_id, asset_id FROM exploration_anchors
WHERE node_id = ANY($1) ORDER BY node_id, asset_id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID, assetID int64
		if err := rows.Scan(&nodeID, &assetID); err != nil {
			return nil, err
		}
		out[nodeID] = append(out[nodeID], assetID)
	}
	return out, rows.Err()
}

// RouteIDsForAsset returns the distinct route ids of intents anchored to one
// asset. The coverage-graph drawer uses it to show "this asset was part of which
// routes" without copying route bodies into the asset graph.
func (s *ExplorationStore) RouteIDsForAsset(assetID int64) ([]int64, error) {
	if assetID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT DISTINCT n.payload->>'route_id'
FROM exploration_nodes n
JOIN exploration_anchors a ON a.node_id=n.id
WHERE n.exploration_id=$1 AND n.kind='intent' AND a.asset_id=$2
  AND n.payload->>'route_id' IS NOT NULL`, s.expID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if raw.Valid {
			if id := infoInt64(strings.TrimSpace(raw.String)); id > 0 {
				out = append(out, id)
			}
		}
	}
	return out, rows.Err()
}
