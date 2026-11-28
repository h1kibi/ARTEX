package db

import (
	"fmt"
	"strings"
)

// HighValueProgressEvents are the ProgressEvent values that count as real
// forward motion on a route. The set is the single source of truth: the agent
// layer (IsHighValueProgress) and the route-health aggregation below must agree,
// or a run can be judged dry by one and productive by the other.
var HighValueProgressEvents = []string{
	"validated_weakness", "credential_obtained", "privilege_change",
	"lateral_progress", "objective_milestone", "finding_written",
}

// IsHighValueProgressEvent reports whether a ProgressEvent name is a high-value
// advance (as opposed to a plain observation write).
func IsHighValueProgressEvent(event string) bool {
	for _, v := range HighValueProgressEvents {
		if v == event {
			return true
		}
	}
	return false
}

// RouteHealth is the route-level autonomy signal the planner needs to stop
// re-opening a dead route with the same evidence:
//
//   - TotalRuns counts FINISHED intents on the route (done/blocked/exhausted/
//     stopped). Running/open/paused intents are not runs yet.
//   - ConsecutiveDryRuns counts, from the newest finished intent backwards, how
//     many consecutive runs produced neither a finding nor a high-value
//     ProgressEvent. Two dry runs mean the route has been paid for twice with
//     nothing to show.
//   - HumanInvolved reports that a human owns this route (origin="human", a human
//     message to one of its intents, or a human "continue" on its watchdog card).
//     Human-owned routes are exempt from autonomous suspension and from silent
//     cycle termination.
//   - RunsSinceLastFinding counts finished runs after the newest run that yielded
//     a confirmed finding; a route that never produced a finding equals TotalRuns.
//     A long tail means the route keeps spending runs without a confirmed result.
//   - WorkerSeconds is the accumulated completed worker time on the route.
//   - AutonomyStatus is derived from the signals above: human > two dry runs >
//     parked stagnation (no finding for four runs, or two runs with 40 minutes of
//     worker time) > active.
type RouteHealth struct {
	RouteID              int64  `json:"route_id"`
	TotalRuns            int    `json:"total_runs"`
	ConsecutiveDryRuns   int    `json:"consecutive_dry_runs"`
	RunsSinceLastFinding int    `json:"runs_since_finding"`
	WorkerSeconds        int64  `json:"worker_seconds"`
	HumanInvolved        bool   `json:"human_involved"`
	AutonomyStatus       string `json:"autonomy_status"`
}

const (
	RouteAutonomyActive         = "active"
	RouteAutonomySuspendedDry   = "suspended_dry"
	RouteAutonomyParkedStagnant = "parked_stagnant"
)

// RouteHealthByID aggregates health for the given route ids. Empty ids returns an
// empty map (no query). Routes absent from the graph are simply omitted.
func (s *ExplorationStore) RouteHealthByID(routeIDs []int64) (map[int64]RouteHealth, error) {
	out := map[int64]RouteHealth{}
	if s == nil || len(routeIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(routeIDs))
	for _, id := range routeIDs {
		ids = append(ids, fmt.Sprint(id))
	}
	filter := ` AND COALESCE(NULLIF(n.payload->>'route_id',''), n.id::text)::bigint IN (` + strings.Join(ids, ",") + `)`

	health, err := s.routeHealthAggregate(filter)
	if err != nil {
		return nil, err
	}
	for _, r := range routeIDs {
		if h, ok := health[r]; ok {
			out[r] = h
		}
	}
	return out, nil
}

// RouteHealth returns the health of one route.
func (s *ExplorationStore) RouteHealth(routeID int64) (RouteHealth, error) {
	if s == nil || routeID <= 0 {
		return RouteHealth{RouteID: routeID}, nil
	}
	m, err := s.RouteHealthByID([]int64{routeID})
	if err != nil {
		return RouteHealth{}, err
	}
	if h, ok := m[routeID]; ok {
		return h, nil
	}
	return RouteHealth{RouteID: routeID}, nil
}

// RouteHealthAll aggregates every route in this exploration. Used by the
// graph_overview redirect.
func (s *ExplorationStore) RouteHealthAll() (map[int64]RouteHealth, error) {
	if s == nil {
		return map[int64]RouteHealth{}, nil
	}
	return s.routeHealthAggregate("")
}

// routeHealthAggregate runs the one aggregation query behind both entry points.
//   - the route universe is EVERY route with a non-deleted intent, not just routes
//     that already have a finished run: a brand-new human-owned intent is protected
//     from its very first (still running) run, when no terminal row exists yet.
//   - terminal intents: done/blocked/exhausted/stopped are runs; deleted intents
//     are excluded entirely (they never happened for autonomy purposes).
//   - a run is "productive" when it yields a finding or a fact carrying a
//     high-value progress_event.
//   - consecutive dry runs are counted from the newest terminal intent backwards
//     until the first productive one.
func (s *ExplorationStore) routeHealthAggregate(routeFilter string) (map[int64]RouteHealth, error) {
	const q = `
WITH intents AS (
    SELECT n.id,
           COALESCE(NULLIF(n.payload->>'route_id',''), n.id::text)::bigint AS route_id,
           n.state, COALESCE(n.origin,'') AS origin,
           GREATEST(COALESCE(n.worker_ms, 0), 0) AS worker_ms
      FROM exploration_nodes n
     WHERE n.exploration_id = $1 AND n.kind = 'intent'
       AND n.state <> 'deleted'` + `%FILTER%` + `
), terminal AS (
    SELECT id, route_id, origin FROM intents
     WHERE state IN ('done','blocked','exhausted','stopped')
), productive AS (
    SELECT e.src_id AS intent_id
      FROM exploration_edges e
      JOIN exploration_nodes n ON n.id = e.dst_id
     WHERE e.exploration_id = $1 AND e.rel = $2
       AND (n.kind = 'finding'
            OR (n.kind = 'fact' AND COALESCE(n.payload->>'progress_event','') = ANY($3)))
     GROUP BY e.src_id
), finding_runs AS (
    SELECT e.src_id AS intent_id
      FROM exploration_edges e
      JOIN exploration_nodes n ON n.id = e.dst_id
     WHERE e.exploration_id = $1 AND e.rel = $2 AND n.kind = 'finding'
     GROUP BY e.src_id
), ordered AS (
    SELECT t.route_id, t.id, (p.intent_id IS NULL) AS dry
      FROM terminal t LEFT JOIN productive p ON p.intent_id = t.id
), last_productive AS (
    SELECT route_id, MAX(id) AS last_id FROM ordered WHERE NOT dry GROUP BY route_id
), last_finding AS (
    SELECT t.route_id, MAX(t.id) AS last_id
      FROM terminal t JOIN finding_runs f ON f.intent_id = t.id
     GROUP BY t.route_id
), runs AS (
    SELECT o.route_id,
           COUNT(*) AS total,
           COUNT(*) FILTER (WHERE o.id > COALESCE(lp.last_id, 0)) AS dry_tail,
           COUNT(*) FILTER (WHERE o.id > COALESCE(lf.last_id, 0)) AS since_finding
      FROM ordered o
      LEFT JOIN last_productive lp ON lp.route_id = o.route_id
      LEFT JOIN last_finding lf ON lf.route_id = o.route_id
     GROUP BY o.route_id
), workers AS (
    SELECT route_id, (COALESCE(SUM(worker_ms), 0) / 1000)::bigint AS worker_seconds
      FROM intents GROUP BY route_id
), human AS (
    SELECT route_id FROM intents WHERE origin = 'human'
    UNION
    SELECT i.route_id
      FROM activity a JOIN intents i ON i.id = a.node_id
     WHERE a.exploration_id = $1 AND a.worker = 'user'
    UNION
    SELECT i.route_id
      FROM watchdog_requests w JOIN intents i ON i.id = w.intent_id
     WHERE w.answer = 'continue'
)
SELECT ar.route_id, COALESCE(r.total, 0), COALESCE(r.dry_tail, 0),
       COALESCE(r.since_finding, 0), COALESCE(w.worker_seconds, 0),
       EXISTS (SELECT 1 FROM human h WHERE h.route_id = ar.route_id) AS human_involved
  FROM (SELECT DISTINCT route_id FROM intents) ar
  LEFT JOIN runs r ON r.route_id = ar.route_id
  LEFT JOIN workers w ON w.route_id = ar.route_id`

	query := strings.Replace(q, "%FILTER%", routeFilter, 1)
	rows, err := s.db.Query(query, s.expID, RelYields, HighValueProgressEvents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]RouteHealth{}
	for rows.Next() {
		var h RouteHealth
		if err := rows.Scan(&h.RouteID, &h.TotalRuns, &h.ConsecutiveDryRuns,
			&h.RunsSinceLastFinding, &h.WorkerSeconds, &h.HumanInvolved); err != nil {
			return nil, err
		}
		h.AutonomyStatus = routeAutonomyStatus(h)
		out[h.RouteID] = h
	}
	return out, rows.Err()
}

// routeAutonomyStatus derives the deterministic autonomy label. A human-owned
// route is always active: no autonomous rule governs a line a person watches.
func routeAutonomyStatus(h RouteHealth) string {
	if h.HumanInvolved {
		return RouteAutonomyActive
	}
	if h.ConsecutiveDryRuns >= 2 {
		return RouteAutonomySuspendedDry
	}
	if h.RunsSinceLastFinding >= 4 || (h.RunsSinceLastFinding >= 2 && h.WorkerSeconds >= 2400) {
		return RouteAutonomyParkedStagnant
	}
	return RouteAutonomyActive
}

// HasRelevantOutsideEvidence reports whether one of nodeIDs is external evidence
// that can legitimately unlock a suspended or parked route. External means the
// node was not yielded by any intent of routeID and does not declare routeID in
// its payload. Relevance is met by a confirmed finding, credential/token/secret
// material, a credential or privilege-change progress event, or a shared target
// asset with the current route.
func (s *ExplorationStore) HasRelevantOutsideEvidence(routeID int64, routeAssetIDs []int64, nodeIDs []int64) (bool, error) {
	if s == nil || routeID <= 0 || len(nodeIDs) == 0 {
		return false, nil
	}
	query := `SELECT EXISTS (
  SELECT 1 FROM exploration_nodes n
   WHERE n.id = ANY($3::bigint[])
     AND n.kind IN ('fact','finding')
     AND n.state <> 'origin'
     AND COALESCE(n.payload->>'fact_type','') <> 'checkpoint'
     AND COALESCE(n.payload->>'route_id','') <> $2::text
     AND NOT EXISTS (
        SELECT 1 FROM exploration_edges e
         WHERE e.exploration_id = $1 AND e.rel = 'yields' AND e.dst_id = n.id
           AND e.src_id IN (
              SELECT i.id FROM exploration_nodes i
               WHERE i.exploration_id = $1 AND i.kind = 'intent'
                 AND COALESCE(NULLIF(i.payload->>'route_id',''), i.id::text) = $2::text))
     AND (
        n.kind = 'finding'
        OR LOWER(COALESCE(n.payload->>'sensitivity','')) IN ('credential','token','secret')
        OR COALESCE(n.payload->>'progress_event','') IN ('credential_obtained','privilege_change')
        OR (cardinality($4::bigint[]) > 0 AND EXISTS (
              SELECT 1 FROM exploration_anchors a
               WHERE a.node_id = n.id AND a.asset_id = ANY($4::bigint[])))
     ))`
	if routeAssetIDs == nil {
		// pgx binds a nil slice as NULL, and cardinality(NULL) is NULL, which makes
		// the shared-asset disjunct never true. An empty non-nil slice binds as {}.
		routeAssetIDs = []int64{}
	}
	var ok bool
	if err := s.db.QueryRow(query, s.expID, fmt.Sprint(routeID),
		nodeIDs, routeAssetIDs).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

// NodesOutsideRoute reports whether any of nodeIDs is evidence that did NOT come
// from this route: the node exists as a fact/finding and is not yielded by an
// intent of the route. This is the "re-activation key" of the two-dry-run
// suspension — a route may be re-opened with the same evidence only if that
// evidence actually crossed route boundaries (new credentials, a fact from
// another host, a finding from a parallel lane).
//
// nodeIDs are NOT restricted to this exploration: add_intent validates each parent
// via GetNodeWithSources first, so a credential inherited from a related source
// task is legitimate evidence — and a cross-task credential is exactly the
// strongest case for re-activating a stale route.
func (s *ExplorationStore) NodesOutsideRoute(routeID int64, nodeIDs []int64) (bool, error) {
	if s == nil || routeID <= 0 || len(nodeIDs) == 0 {
		return false, nil
	}
	args := make([]any, 0, len(nodeIDs)+2)
	args = append(args, s.expID, fmt.Sprint(routeID))
	marks := make([]string, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		args = append(args, id)
		marks = append(marks, fmt.Sprintf("$%d", len(args)))
	}
	query := `SELECT EXISTS (
  SELECT 1 FROM exploration_nodes n
   WHERE n.id IN (` + strings.Join(marks, ",") + `)
     AND n.kind IN ('fact','finding')
     AND n.state <> 'origin'
     AND n.id NOT IN (
        SELECT e.dst_id FROM exploration_edges e
         WHERE e.exploration_id = $1 AND e.rel = 'yields'
           AND e.src_id IN (
              SELECT i.id FROM exploration_nodes i
               WHERE i.exploration_id = $1 AND i.kind = 'intent'
                 AND COALESCE(NULLIF(i.payload->>'route_id',''), i.id::text) = $2::text)))`
	var ok bool
	if err := s.db.QueryRow(query, args...).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}
