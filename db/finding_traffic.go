package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/notify"
)

var (
	ErrEvidenceConflict = errors.New("流量证据已变更，请刷新后重试")

	ErrFindingNotFound  = errors.New("漏洞不存在")
	ErrEvidenceNotFound = errors.New("流量证据不存在")
)

// This lock covers the evidence filesystem as well as its SQL references. All
// processes sharing the database use it, including readers, exports and GC.
const findingEvidenceLockKey int64 = 7337741004

func (d *DB) WithEvidenceTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, findingEvidenceLockKey); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type TrafficRef struct {
	TrafficID string `json:"traffic_id"`
	Role      string `json:"role"`
	Note      string `json:"note"`
}

func NormalizeTrafficRefs(refs []TrafficRef) ([]TrafficRef, error) {
	out := make([]TrafficRef, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref.TrafficID = strings.TrimSpace(ref.TrafficID)
		if ref.TrafficID == "" {
			return nil, errors.New("traffic_id 不能为空")
		}
		if ref.Role == "" {
			ref.Role = "supporting"
		}
		if !ValidTrafficRole(ref.Role) {
			return nil, fmt.Errorf("无效的流量用途 %q", ref.Role)
		}
		if !seen[ref.TrafficID] {
			out = append(out, ref)
			seen[ref.TrafficID] = true
		}
	}
	return out, nil
}

func ValidTrafficRole(role string) bool {
	return role == "baseline" || role == "proof" || role == "verification" || role == "supporting"
}

type TrafficEvidenceSnapshot struct {
	ID              string    `json:"id"`
	SourceTrafficID string    `json:"source_traffic_id"`
	CapturedAt      int64     `json:"captured_at"`
	URL             string    `json:"url"`
	Method          string    `json:"method"`
	Status          int       `json:"status"`
	ContentType     string    `json:"content_type"`
	ReqHead         string    `json:"req_head,omitempty"`
	RespHead        string    `json:"resp_head,omitempty"`
	ReqHash         string    `json:"req_hash"`
	RespHash        string    `json:"resp_hash"`
	ReqLen          int64     `json:"req_len"`
	RespLen         int64     `json:"resp_len"`
	CreatedAt       time.Time `json:"created_at"`
}

type FindingTrafficBinding struct {
	ID         int64                   `json:"id,string"`
	FindingID  int64                   `json:"finding_id,string"`
	SnapshotID string                  `json:"snapshot_id"`
	Role       string                  `json:"role"`
	Note       string                  `json:"note"`
	Position   int                     `json:"position"`
	CreatedAt  time.Time               `json:"created_at"`
	Snapshot   TrafficEvidenceSnapshot `json:"snapshot"`
}

type FindingTraffic struct {
	FindingID     int64                   `json:"finding_id,string"`
	Version       int64                   `json:"version"`
	ReportVersion int64                   `json:"report_version"`
	Bindings      []FindingTrafficBinding `json:"bindings"`
}

type PreparedTrafficEvidence struct {
	Ref      TrafficRef
	Snapshot TrafficEvidenceSnapshot
}

// Normalize makes the snapshot's text columns safe for PostgreSQL. URL and the
// head blocks come straight off the wire, so a target answering with a non-UTF-8
// header (a GBK `Content-Disposition: filename=…`, a NUL byte) would otherwise
// abort the INSERT and roll back the whole finding — losing a confirmed finding
// over a malformed response header. Applied before hashing so the ID always
// matches the bytes that actually land in the table.
func (s TrafficEvidenceSnapshot) Normalize() TrafficEvidenceSnapshot {
	s.SourceTrafficID = utf8Clean(s.SourceTrafficID)
	s.URL = utf8Clean(s.URL)
	s.Method = utf8Clean(s.Method)
	s.ContentType = utf8Clean(s.ContentType)
	s.ReqHead = utf8Clean(s.ReqHead)
	s.RespHead = utf8Clean(s.RespHead)
	return s
}

func TrafficSnapshotID(snapshot TrafficEvidenceSnapshot) string {
	snapshot = snapshot.Normalize()
	snapshot.ID = ""
	snapshot.CreatedAt = time.Time{}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// LockTaskEvidenceTx serializes writes with archive queueing (which locks the
// same task row). Once queued, its snapshot must not acquire new evidence.
func LockTaskEvidenceTx(tx *sql.Tx, taskID int64) error {
	if taskID == 0 {
		return nil
	}
	var deleted sql.NullTime
	if err := tx.QueryRow(`SELECT deleted_at FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&deleted); err != nil {
		return err
	}
	if deleted.Valid {
		return ErrTaskArchiveState
	}
	var state string
	err := tx.QueryRow(`SELECT state FROM task_archives WHERE task_id=$1`, taskID).Scan(&state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && state != ArchiveFailed {
		return ErrTaskArchiveState
	}
	return nil
}

func LockFindingEvidenceTx(tx *sql.Tx, findingID int64, version *int64) error {
	var taskID sql.NullInt64
	if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, findingID).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if err := LockTaskEvidenceTx(tx, taskID.Int64); err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if version != nil && *version != current {
		return ErrEvidenceConflict
	}
	return nil
}

func InsertEvidenceSnapshotTx(tx *sql.Tx, s TrafficEvidenceSnapshot) error {
	if s.ID != TrafficSnapshotID(s) {
		return errors.New("证据快照元数据哈希不匹配")
	}
	// The ID was computed over the normalized form; store those same bytes.
	id := s.ID
	s = s.Normalize()
	s.ID = id
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	_, err := tx.Exec(`INSERT INTO traffic_evidence_snapshots
(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`,
		s.ID, s.SourceTrafficID, s.CapturedAt, s.URL, s.Method, s.Status, s.ContentType, s.ReqHead, s.RespHead, s.ReqHash, s.RespHash, s.ReqLen, s.RespLen, s.CreatedAt)
	return err
}

func AddFindingTrafficTx(tx *sql.Tx, findingID int64, prepared []PreparedTrafficEvidence) error {
	var position int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(position)+1,0) FROM finding_traffic_bindings WHERE finding_id=$1`, findingID).Scan(&position); err != nil {
		return err
	}
	changed := false
	for _, item := range prepared {
		if err := InsertEvidenceSnapshotTx(tx, item.Snapshot); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots SET unreferenced_at=NULL WHERE id=$1`, item.Snapshot.ID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id,snapshot_id) DO NOTHING`, findingID, item.Snapshot.ID, item.Ref.Role, item.Ref.Note, position)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			changed = true
			position++
		}
	}
	if changed {
		return bumpEvidenceVersionTx(tx, findingID)
	}
	return nil
}

func bumpEvidenceVersionTx(tx *sql.Tx, findingID int64) error {
	var version int64
	var nodeID sql.NullInt64
	if err := tx.QueryRow(`UPDATE findings SET evidence_version=evidence_version+1
WHERE id=$1 RETURNING evidence_version, node_id`, findingID).Scan(&version, &nodeID); err != nil {
		return err
	}
	// Mirror the version onto the graph node in the same transaction. The goal-proof
	// gate reads the NODE, and it compares the version a confirmation was bound to
	// against the current one — so a version that only exists in the findings table
	// would make every confirmed finding look stale the moment evidence changed.
	if nodeID.Valid {
		if _, err := tx.Exec(`UPDATE exploration_nodes
SET payload = jsonb_set(payload, '{evidence_version}', to_jsonb($1::bigint), true)
WHERE id=$2`, version, nodeID.Int64); err != nil {
			return err
		}
	}
	return nil
}

func FindingTrafficTx(tx *sql.Tx, findingID int64) (*FindingTraffic, error) {
	out := &FindingTraffic{FindingID: findingID, Bindings: []FindingTrafficBinding{}}
	if err := tx.QueryRow(`SELECT evidence_version,report_evidence_version FROM findings WHERE id=$1`, findingID).Scan(&out.Version, &out.ReportVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	rows, err := tx.Query(`SELECT b.id,b.finding_id,b.snapshot_id,b.role,b.note,b.position,b.created_at,to_jsonb(s)
FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1 ORDER BY b.position,b.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b FindingTrafficBinding
		var raw []byte
		if err := rows.Scan(&b.ID, &b.FindingID, &b.SnapshotID, &b.Role, &b.Note, &b.Position, &b.CreatedAt, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &b.Snapshot); err != nil {
			return nil, err
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingTraffic(ctx context.Context, findingID int64) (out *FindingTraffic, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = FindingTrafficTx(tx, findingID); return e })
	return
}

func (d *DB) EditFindingTraffic(ctx context.Context, findingID, bindingID, version int64, role, note *string, remove bool, order []int64) error {
	if role != nil && !ValidTrafficRole(*role) {
		return errors.New("无效的流量用途")
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, &version); err != nil {
			return err
		}
		if order != nil {
			current, err := FindingTrafficTx(tx, findingID)
			if err != nil {
				return err
			}
			if len(order) != len(current.Bindings) {
				return ErrEvidenceConflict
			}
			ids := map[int64]bool{}
			for _, b := range current.Bindings {
				ids[b.ID] = true
			}
			for position, id := range order {
				if !ids[id] {
					return ErrEvidenceConflict
				}
				delete(ids, id)
				if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET position=$1 WHERE finding_id=$2 AND id=$3`, position, findingID, id); err != nil {
					return err
				}
			}
		} else {
			var res sql.Result
			var err error
			if remove {
				res, err = tx.Exec(`DELETE FROM finding_traffic_bindings WHERE finding_id=$1 AND id=$2`, findingID, bindingID)
			} else {
				res, err = tx.Exec(`UPDATE finding_traffic_bindings SET role=COALESCE($3,role),note=COALESCE($4,note) WHERE finding_id=$1 AND id=$2`, findingID, bindingID, role, note)
			}
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrEvidenceNotFound
			}
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

type RecordFindingInput struct {
	TaskID, ExplorationID, IntentID                      int64
	VulnClass, Name, Severity, Summary, Evidence, Worker string
	AssetIDs                                             []int64
	EvidenceRefs                                         []string
	RouteID                                              int64
	RunID                                                string
	// TriageState is the Auto-Triager verdict for this report: "confirmed" when
	// re-checkable evidence backs it, "verifying" when only text evidence exists.
	// Empty means "not triaged" and reads as confirmed (legacy callers/tests), so
	// goal proof keeps working for every pre-existing row.
	TriageState string
}

type RecordedFinding struct {
	FindingID int64           `json:"finding_id,string"`
	NodeID    int64           `json:"finding_node_id,string"`
	Traffic   *FindingTraffic `json:"traffic"`
}

// ctx 由调用方传入本次事务所用的上下文（而非在内部取 context.Background）：
// 事务内新加的推送事件写入同样应受调用方的取消与超时约束。
func RecordFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	if err := LockTaskEvidenceTx(tx, in.TaskID); err != nil {
		return nil, err
	}
	if in.TaskID > 0 {
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, in.TaskID).Scan(&expID); err != nil {
			return nil, err
		}
		if expID != in.ExplorationID {
			return nil, errors.New("漏洞所属任务与探索记录不匹配")
		}
	}
	if in.IntentID > 0 {
		var ok bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, in.IntentID, in.ExplorationID).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("intent_id 必须是本任务的意图（关联任务意图只读）")
		}
	}
	payloadMap := map[string]any{"vulnclass": in.VulnClass, "name": in.Name, "severity": in.Severity, "summary": in.Summary, "evidence": map[string]any{"by": in.Worker, "poc": in.Evidence}}
	if len(in.EvidenceRefs) > 0 {
		payloadMap["evidence_refs"] = in.EvidenceRefs
	}
	if in.RouteID > 0 {
		payloadMap["route_id"] = in.RouteID
	}
	if in.IntentID > 0 {
		payloadMap["intent_id"] = in.IntentID
	}
	if in.RunID != "" {
		payloadMap["run_id"] = in.RunID
	}
	if in.TriageState != "" {
		payloadMap["triage_state"] = in.TriageState
	}
	payload, _ := json.Marshal(payloadMap)
	out := &RecordedFinding{}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES($1,'finding',$2,9,'confirmed',$3) RETURNING id`, in.ExplorationID, string(payload), in.Worker).Scan(&out.NodeID); err != nil {
		return nil, err
	}
	for _, asset := range in.AssetIDs {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, out.NodeID, asset); err != nil {
			return nil, err
		}
	}
	if in.IntentID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, in.ExplorationID, in.IntentID, RelYields, out.NodeID); err != nil {
			return nil, err
		}
	}
	assets := in.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	raw, _ := json.Marshal(assets)
	triage := in.TriageState
	if triage == "" {
		triage = "confirmed"
	}
	if err := tx.QueryRow(`INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,asset_ids,triage_state)
VALUES(NULLIF($1,0),$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`, in.TaskID, out.NodeID, in.VulnClass, in.Name, in.Severity, in.Summary, in.Evidence, in.Worker, string(raw), triage).Scan(&out.FindingID); err != nil {
		return nil, err
	}
	// 在**同一事务**里登记一条推送事件：提交即保证「漏洞落库」与「推送任务存在」
	// 原子一致，不存在提交成功却没入队、消息永久丢失的窗口。
	// 这里的失败被隔离在保存点上、不影响漏洞写入（见函数注释），因此忽略返回值。
	RecordNotificationEventTx(ctx, tx, notify.EventFindingCreated, out.FindingID, notify.Snapshot{
		Kind:      notify.EventFindingCreated,
		FindingID: out.FindingID,
		TaskID:    in.TaskID,
		VulnClass: in.VulnClass,
		Name:      in.Name,
		Severity:  in.Severity,
		Summary:   in.Summary,
		AssetIDs:  assets,
	})
	if err := AddFindingTrafficTx(tx, out.FindingID, prepared); err != nil {
		return nil, err
	}
	var err error
	out.Traffic, err = FindingTrafficTx(tx, out.FindingID)
	return out, err
}

// RecordFinding is the atomic legacy/no-recorder path used by tools and tests.
func (s *ExplorationStore) RecordFinding(ctx context.Context, in RecordFindingInput) (out *RecordedFinding, err error) {
	in.ExplorationID = s.expID
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = RecordFindingTx(ctx, tx, in, nil); return e })
	return
}

func (d *DB) FindingIDByNodeID(nodeID int64) (id int64, err error) {
	err = d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
	return
}

// BoundTrafficRef is one finding_traffic_bindings row projected for the read-only
// Evidence view. The binding itself stores no traffic id; the snapshot does.
type BoundTrafficRef struct {
	NodeID          int64
	FindingID       int64
	TrafficID       string
	SnapshotID      string
	EvidenceVersion int64
}

// FindingTrafficRefs lists every traffic binding attached to a finding node in
// this exploration. report_finding stores refs in findings/traffic tables, not
// in payload.evidence_refs, so the Evidence view needs this separate query.
func (s *ExplorationStore) FindingTrafficRefs() ([]BoundTrafficRef, error) {
	rows, err := s.db.Query(`SELECT f.node_id, f.id, COALESCE(s.source_traffic_id,''), b.snapshot_id,
       COALESCE(f.evidence_version, 0)
FROM findings f
JOIN exploration_nodes n ON n.id = f.node_id AND n.exploration_id = $1
JOIN finding_traffic_bindings b ON b.finding_id = f.id
JOIN traffic_evidence_snapshots s ON s.id = b.snapshot_id
WHERE COALESCE(s.source_traffic_id,'') <> ''
ORDER BY f.node_id, b.position, b.id`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BoundTrafficRef{}
	for rows.Next() {
		var r BoundTrafficRef
		if err := rows.Scan(&r.NodeID, &r.FindingID, &r.TrafficID, &r.SnapshotID, &r.EvidenceVersion); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PopulateFindingTrafficIDs only enriches already-visible nodes. It performs no
// discovery or ID guessing, and leaves the legacy node ID unchanged.
func (s *ExplorationStore) PopulateFindingTrafficIDs(nodes []*Node) error {
	byID := map[int64]*Node{}
	var args []any
	var placeholders []string
	for _, n := range nodes {
		if n == nil || n.Kind != KindFinding || byID[n.ID] != nil {
			continue
		}
		byID[n.ID] = n
		args = append(args, n.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT f.id,f.node_id,(SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id) FROM findings f WHERE f.node_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var findingID, nodeID int64
		var count int
		if err := rows.Scan(&findingID, &nodeID, &count); err != nil {
			return err
		}
		n := byID[nodeID]
		n.FindingID, n.FindingNodeID, n.TrafficCount = findingID, nodeID, count
	}
	return rows.Err()
}

// FindingIDForAnyID resolves a finding row from EITHER id a caller may hold:
// findings.node_id (the exploration node report_finding's first line prints) or
// findings.id (the standalone record id the report_finding JSON returns). The two
// are different numbers for the same vuln, and models routinely pass one where the
// tool wanted the other.
//
// The two id spaces are independent BIGSERIAL sequences, so a single number can
// name one row's record id AND another row's node id — collisions are the norm in
// a long-lived database, not a corner case. Resolution therefore looks at both
// candidates and prefers the row whose findings.id matches (report_finding's
// structured output is the authoritative identifier); node_id is the fallback for
// the legacy first-line convention. taskID, when > 0, narrows the candidates to
// that task first, which is the only tie-break that is actually meaningful: a node
// id is task-scoped while a record id is global. Returns 0 (no error) when nothing
// matches.
func (d *DB) FindingIDForAnyID(id int64) (int64, error) {
	return d.FindingIDForAnyIDInTask(id, 0)
}

// FindingIDByNodeIDInTask resolves a graph node id to the finding that owns it,
// scoped to the caller's task. This is the unambiguous counterpart of
// FindingIDForAnyIDInTask: a caller that KNOWS it holds a node id (the reporter gets
// one from its trigger context) must not be routed through the "either sequence"
// resolver, where a coincidental findings.id silently wins.
func (d *DB) FindingIDByNodeIDInTask(nodeID, _ int64) (int64, error) {
	if nodeID <= 0 {
		return 0, nil
	}
	var fid int64
	err := d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&fid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	// Ownership is NOT decided here: cross-task reads and inherited findings are
	// legitimate (a handoff hint carries another task's finding), so the caller's
	// provenance check decides. This resolver only fixes the NUMBERING.
	return fid, nil
}

// FindingIDByRecordID resolves a findings.id, scoped to the caller's task. It never
// falls back to the node-id space: a caller that was given a record id means that
// record.
func (d *DB) FindingIDByRecordID(recordID, _ int64) (int64, error) {
	if recordID <= 0 {
		return 0, nil
	}
	var fid int64
	err := d.QueryRow(`SELECT id FROM findings WHERE id=$1`, recordID).Scan(&fid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	// See FindingIDByNodeIDInTask: numbering here, ownership in the caller.
	return fid, nil
}

// FindingIDForAnyIDInTask is FindingIDForAnyID with a task preference. See above.
func (d *DB) FindingIDForAnyIDInTask(id, taskID int64) (int64, error) {
	if id <= 0 {
		return 0, nil
	}
	rows, err := d.Query(`SELECT id, COALESCE(task_id,0) FROM findings WHERE id=$1 OR node_id=$1`, id)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var recordID, nodeID, recordInTask, nodeInTask int64
	for rows.Next() {
		var fid, tid int64
		if err := rows.Scan(&fid, &tid); err != nil {
			return 0, err
		}
		if fid == id {
			recordID = fid
			if tid == taskID {
				recordInTask = fid
			}
		} else {
			nodeID = fid
			if tid == taskID {
				nodeInTask = fid
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// A number that names TWO different findings is not decidable without the task:
	// findings.id and exploration_nodes.id are independent sequences, so id=17 can be
	// one task's finding record and another task's finding node. Left unresolved this
	// silently targets the WRONG finding, so the ambiguity is logged at least once per
	// call — real agent runs always carry a task and never reach this branch.
	if taskID <= 0 && recordID > 0 && nodeID > 0 && recordID != nodeID {
		log.Printf("[finding] 编号 %d 同时是漏洞记录 #%d 与节点 #%d 的编号；无任务上下文，按记录编号解析。请在任务内调用以避免歧义", id, recordID, nodeID)
	}
	// Preference order, most specific first:
	//   1. a same-task row (cross-task evidence must not shadow the caller's own);
	//   2. without a task, the record id (report_finding's structured output is the
	//      modern contract) then the node id (the legacy first-line convention).
	for _, candidate := range []int64{recordInTask, nodeInTask, recordID, nodeID} {
		if candidate > 0 {
			return candidate, nil
		}
	}
	return 0, nil
}

// SetFindingReportVersionByNodeID is the strict node-keyed write: the argument IS
// an exploration node id (the historical contract of every in-task caller and of
// SetFindingReportByNodeID). It must NOT fall back to findings.id — the two id
// spaces are independent sequences, so a node id can equal an unrelated finding's
// record id and a fallback would silently write the report onto the wrong vuln.
func (d *DB) SetFindingReportVersionByNodeID(ctx context.Context, nodeID int64, report string, version *int64) (n int64, err error) {
	var findingID int64
	if err := d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&findingID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return d.setFindingReportVersionByID(ctx, findingID, report, version)
}

// SetFindingReportVersionByAnyID writes a report for callers that only know "some
// finding id" and cannot say which of the two it is (finding_id vs finding_node_id
// — see FindingIDForAnyIDInTask). The returned id is the canonical findings.id
// actually written (0 = not found).
func (d *DB) SetFindingReportVersionByAnyID(ctx context.Context, id, taskID int64, report string, version *int64) (findingID, n int64, err error) {
	findingID, err = d.FindingIDForAnyIDInTask(id, taskID)
	if err != nil || findingID == 0 {
		return 0, 0, err
	}
	n, err = d.setFindingReportVersionByID(ctx, findingID, report, version)
	return findingID, n, err
}

// SetFindingReportVersionByID writes a finding's report, gated on the evidence
// version the caller read. findingID must already be a canonical findings.id (the
// explicit-id tool path resolves it by the numbering the caller used).
func (d *DB) SetFindingReportVersionByID(ctx context.Context, findingID int64, report string, version *int64) (n int64, err error) {
	return d.setFindingReportVersionByID(ctx, findingID, report, version)
}

func (d *DB) setFindingReportVersionByID(ctx context.Context, findingID int64, report string, version *int64) (n int64, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, version); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE findings SET report=$2,report_evidence_version=COALESCE($3::bigint,CASE WHEN evidence_version=0 THEN 0 ELSE -1 END) WHERE id=$1`, findingID, report, version)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return
}
