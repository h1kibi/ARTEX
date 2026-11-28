package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Watchdog 控制面的数据访问层。三张表各自解决一个独立问题，互不替代：
//   - worker_runs       每个运行中 intent 的实时阶段、心跳与周期
//   - watchdog_jobs     10 分钟触发的 Slow Path 判断任务（同一 run/周期唯一）
//   - watchdog_requests 用户判断卡片与 Watchdog 不可用卡片
//
// 运行监控在内存里完成热路径更新，这张表负责进程重启后的清理、API 展示与
// 排障；Slow Path 的任务状态与请求状态则只以数据库为准，Fast Path 与 HTTP
// 处理函数共享同一份条件更新结果。

const (
	WorkerRunPhaseIdle     = "idle"
	WorkerRunPhaseLLM      = "llm"
	WorkerRunPhaseTool     = "tool"
	WorkerRunPhaseApproval = "approval"
	WorkerRunPhasePaused   = "paused"
	WorkerRunPhaseSettling = "settling"

	WorkerRunStateRunning   = "running"
	WorkerRunStateFinished  = "finished"
	WorkerRunStateAbandoned = "abandoned"

	SlowPathNone    = "none"
	SlowPathQueued  = "queued"
	SlowPathRunning = "running"
	SlowPathDone    = "done"
	SlowPathFailed  = "failed"
	SlowPathStale   = "stale"

	WatchdogDecisionNone     = "none"
	WatchdogDecisionOpen     = "open"
	WatchdogDecisionAnswered = "answered"

	WatchdogJobQueued  = "queued"
	WatchdogJobRunning = "running"
	WatchdogJobDone    = "done"
	WatchdogJobFailed  = "failed"
	WatchdogJobStale   = "stale"

	WatchdogRequestAsk         = "watchdog_ask"
	WatchdogRequestUnavailable = "watchdog_unavailable"

	WatchdogRequestOpen       = "open"
	WatchdogRequestAnswered   = "answered"
	WatchdogRequestExpired    = "expired"
	WatchdogRequestSuperseded = "superseded"
)

// WorkerRun is one running intent's control-plane row. Timestamps are nullable so
// the API can distinguish \"not started yet\" from the zero time.
type WorkerRun struct {
	ID             int64      `json:"-"`
	TaskID         string     `json:"task_id"`
	IntentID       int64      `json:"intent_id"`
	RunID          string     `json:"run_id"`
	WorkerName     string     `json:"worker_name"`
	Phase          string     `json:"phase"`
	PhaseStartedAt *time.Time `json:"phase_started_at,omitempty"`
	HeartbeatAt    *time.Time `json:"heartbeat_at,omitempty"`
	LastEventAt    *time.Time `json:"last_event_at,omitempty"`
	LastOutputAt   *time.Time `json:"last_output_at,omitempty"`
	CycleStart     *time.Time `json:"cycle_start,omitempty"`
	CycleNo        int        `json:"cycle_no"`
	AutoCyclesUsed int        `json:"auto_cycles_used"`
	PressureSent   bool       `json:"pressure_sent"`
	SlowPathState  string     `json:"slow_path_state"`
	DecisionState  string     `json:"decision_state"`
	LeaseUntil     *time.Time `json:"lease_until,omitempty"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

const workerRunCols = `id,task_id,intent_id,run_id,worker_name,phase,phase_started_at,heartbeat_at,
last_event_at,last_output_at,cycle_start,cycle_no,auto_cycles_used,pressure_sent,slow_path_state,decision_state,
lease_until,state,created_at,updated_at`

func scanWorkerRun(sc interface{ Scan(...any) error }) (*WorkerRun, error) {
	var r WorkerRun
	if err := sc.Scan(&r.ID, &r.TaskID, &r.IntentID, &r.RunID, &r.WorkerName, &r.Phase,
		&r.PhaseStartedAt, &r.HeartbeatAt, &r.LastEventAt, &r.LastOutputAt, &r.CycleStart,
		&r.CycleNo, &r.AutoCyclesUsed, &r.PressureSent, &r.SlowPathState, &r.DecisionState, &r.LeaseUntil,
		&r.State, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func timeArg(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// SaveWorkerRun inserts or updates one run row by run_id. The monitor calls this
// on registration, phase changes, effective output, and periodic flushes; the
// row is not the hot-path source of truth while the process is alive.
func (d *DB) SaveWorkerRun(ctx context.Context, r *WorkerRun) error {
	if r == nil || r.RunID == "" {
		return fmt.Errorf("worker run requires run_id")
	}
	if r.Phase == "" {
		r.Phase = WorkerRunPhaseIdle
	}
	if r.SlowPathState == "" {
		r.SlowPathState = SlowPathNone
	}
	if r.DecisionState == "" {
		r.DecisionState = WatchdogDecisionNone
	}
	if r.State == "" {
		r.State = WorkerRunStateRunning
	}
	_, err := d.ExecContext(ctx, `
INSERT INTO worker_runs(task_id,intent_id,run_id,worker_name,phase,phase_started_at,heartbeat_at,
last_event_at,last_output_at,cycle_start,cycle_no,auto_cycles_used,pressure_sent,slow_path_state,decision_state,
lease_until,state)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT (run_id) DO UPDATE SET
  task_id=EXCLUDED.task_id, intent_id=EXCLUDED.intent_id, worker_name=EXCLUDED.worker_name,
  phase=EXCLUDED.phase, phase_started_at=EXCLUDED.phase_started_at,
  heartbeat_at=EXCLUDED.heartbeat_at, last_event_at=EXCLUDED.last_event_at,
  last_output_at=EXCLUDED.last_output_at, cycle_start=EXCLUDED.cycle_start,
  cycle_no=EXCLUDED.cycle_no, auto_cycles_used=EXCLUDED.auto_cycles_used,
  pressure_sent=EXCLUDED.pressure_sent,
  slow_path_state=EXCLUDED.slow_path_state, decision_state=EXCLUDED.decision_state,
  lease_until=EXCLUDED.lease_until, state=EXCLUDED.state, updated_at=now()`,
		r.TaskID, r.IntentID, r.RunID, r.WorkerName, r.Phase, timeArg(r.PhaseStartedAt),
		timeArg(r.HeartbeatAt), timeArg(r.LastEventAt), timeArg(r.LastOutputAt),
		timeArg(r.CycleStart), r.CycleNo, r.AutoCyclesUsed, r.PressureSent, r.SlowPathState,
		r.DecisionState, timeArg(r.LeaseUntil), r.State)
	return err
}

// TouchWorkerRuns refreshes heartbeat + lease for the given live runs in one
// statement. The monitor flushes every Fast Path tick, so a long-running tool
// (which emits no activity) still proves the worker process is alive.
func (d *DB) TouchWorkerRuns(ctx context.Context, runIDs []string, heartbeat, lease time.Time) error {
	if len(runIDs) == 0 {
		return nil
	}
	args := make([]any, 0, len(runIDs)+3)
	args = append(args, heartbeat, lease)
	marks := make([]string, len(runIDs))
	for i, id := range runIDs {
		args = append(args, id)
		marks[i] = fmt.Sprintf("$%d", len(args))
	}
	args = append(args, WorkerRunStateRunning)
	_, err := d.ExecContext(ctx, `
UPDATE worker_runs SET heartbeat_at=$1, lease_until=$2, updated_at=now()
WHERE run_id IN (`+strings.Join(marks, ",")+`) AND state=$`+fmt.Sprint(len(args)), args...)
	return err
}

// FinishWorkerRun marks a row finished and releases its lease. The row is kept
// for diagnostics until the task is deleted/archived or the process restarts.
func (d *DB) FinishWorkerRun(ctx context.Context, runID, state string) error {
	if runID == "" {
		return nil
	}
	if state == "" {
		state = WorkerRunStateFinished
	}
	_, err := d.ExecContext(ctx, `
UPDATE worker_runs SET state=$2, lease_until=NULL, heartbeat_at=now(), updated_at=now()
WHERE run_id=$1`, runID, state)
	return err
}

// FinishWorkerRuns marks multiple run rows finished in one statement. It is
// used by task-level cleanup, where issuing one UPDATE per live run adds
// avoidable round trips while the task is already being torn down.
func (d *DB) FinishWorkerRuns(ctx context.Context, runIDs []string, state string) error {
	if len(runIDs) == 0 {
		return nil
	}
	if state == "" {
		state = WorkerRunStateFinished
	}
	args := make([]any, 0, len(runIDs)+1)
	marks := make([]string, len(runIDs))
	for i, id := range runIDs {
		args = append(args, id)
		marks[i] = fmt.Sprintf("$%d", i+1)
	}
	args = append(args, state)
	_, err := d.ExecContext(ctx, `
UPDATE worker_runs SET state=$`+fmt.Sprint(len(args))+`, lease_until=NULL, heartbeat_at=now(), updated_at=now()
WHERE run_id IN (`+strings.Join(marks, ",")+`)`, args...)
	return err
}

// ListWorkerRuns returns this task's rows, newest first. runningOnly filters to
// state='running' for the Fast Path / API.
func (d *DB) ListWorkerRuns(ctx context.Context, taskID string, runningOnly bool) ([]*WorkerRun, error) {
	query := `SELECT ` + workerRunCols + ` FROM worker_runs WHERE task_id=$1`
	args := []any{taskID}
	if runningOnly {
		query += ` AND state=$2`
		args = append(args, WorkerRunStateRunning)
	}
	query += ` ORDER BY id`
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WorkerRun
	for rows.Next() {
		r, err := scanWorkerRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// WorkerRunByID returns one run or nil when absent.
func (d *DB) WorkerRunByID(ctx context.Context, runID string) (*WorkerRun, error) {
	r, err := scanWorkerRun(d.QueryRowContext(ctx, `SELECT `+workerRunCols+` FROM worker_runs WHERE run_id=$1`, runID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func deleteWatchdogTaskDataTx(tx *sql.Tx, taskID string) error {
	for _, table := range []string{"worker_runs", "watchdog_jobs", "watchdog_requests"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE task_id=$1`, taskID); err != nil {
			return err
		}
	}
	return nil
}

// ClearWorkerRunsOnStartup removes every stale row from the prior process. This
// deployment is single-instance: a worker goroutine cannot be adopted across
// process restarts, so leaving rows as "running" would create ghosts.
func (d *DB) ClearWorkerRunsOnStartup(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `DELETE FROM worker_runs WHERE lease_until IS NULL OR lease_until < now()`)
	return err
}

// PurgeExpiredWorkerRuns removes rows whose owning process stopped refreshing
// its lease. Called from the Fast Path tick so a crashed instance's rows do not
// linger as "running" after their lease window.
func (d *DB) PurgeExpiredWorkerRuns(ctx context.Context, now time.Time) error {
	_, err := d.ExecContext(ctx, `
DELETE FROM worker_runs WHERE state=$1 AND (lease_until IS NULL OR lease_until < $2)`,
		WorkerRunStateRunning, now)
	return err
}

// WatchdogJob is one Slow Path judgment request. Snapshot is the bounded
// evidence captured at enqueue time; the agent reads live state through tools
// and the snapshot anchors what the Fast Path saw.
type WatchdogJob struct {
	ID          int64           `json:"id"`
	TaskID      string          `json:"task_id"`
	IntentID    int64           `json:"intent_id"`
	RunID       string          `json:"run_id"`
	CycleNo     int             `json:"cycle_no"`
	CycleStart  *time.Time      `json:"cycle_start,omitempty"`
	Status      string          `json:"status"`
	Snapshot    json.RawMessage `json:"snapshot"`
	Attempts    int             `json:"attempts"`
	LastError   string          `json:"last_error,omitempty"`
	NextRetryAt *time.Time      `json:"next_retry_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

const watchdogJobCols = `id,task_id,intent_id,run_id,cycle_no,cycle_start,status,snapshot,
attempts,last_error,next_retry_at,created_at,updated_at`

func scanWatchdogJob(sc interface{ Scan(...any) error }) (*WatchdogJob, error) {
	var j WatchdogJob
	var snapshot []byte
	if err := sc.Scan(&j.ID, &j.TaskID, &j.IntentID, &j.RunID, &j.CycleNo, &j.CycleStart,
		&j.Status, &snapshot, &j.Attempts, &j.LastError, &j.NextRetryAt, &j.CreatedAt, &j.UpdatedAt); err != nil {
		return nil, err
	}
	if len(snapshot) == 0 {
		snapshot = []byte(`{}`)
	}
	j.Snapshot = json.RawMessage(snapshot)
	return &j, nil
}

// EnqueueWatchdogJob inserts the one job for (run_id, cycle_no). A duplicate is
// not an error: the cycle already has its judgment queued, so the caller only
// needs the existing row id. created reports whether this call inserted it.
func (d *DB) EnqueueWatchdogJob(ctx context.Context, j *WatchdogJob) (id int64, created bool, err error) {
	if j == nil || j.RunID == "" {
		return 0, false, fmt.Errorf("watchdog job requires run_id")
	}
	snapshot := j.Snapshot
	if len(snapshot) == 0 {
		snapshot = json.RawMessage(`{}`)
	}
	err = d.QueryRowContext(ctx, `
INSERT INTO watchdog_jobs(task_id,intent_id,run_id,cycle_no,cycle_start,status,snapshot)
VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (run_id,cycle_no) DO NOTHING
RETURNING id`, j.TaskID, j.IntentID, j.RunID, j.CycleNo, timeArg(j.CycleStart), WatchdogJobQueued, string(snapshot)).Scan(&id)
	if err == nil {
		return id, true, nil
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}
	err = d.QueryRowContext(ctx, `SELECT id FROM watchdog_jobs WHERE run_id=$1 AND cycle_no=$2`, j.RunID, j.CycleNo).Scan(&id)
	return id, false, err
}

// ClaimWatchdogJob takes the oldest due job and marks it running in one
// statement. FOR UPDATE SKIP LOCKED means a second service instance can run
// beside this one without both claiming the same row.
func (d *DB) ClaimWatchdogJob(ctx context.Context, now time.Time) (*WatchdogJob, error) {
	row := d.QueryRowContext(ctx, `
WITH due AS (
    SELECT id FROM watchdog_jobs
    WHERE status IN ($2,$3)
      AND (next_retry_at IS NULL OR next_retry_at <= $1)
    ORDER BY created_at, id
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE watchdog_jobs SET status=$4, attempts=watchdog_jobs.attempts+1, updated_at=now()
FROM due WHERE watchdog_jobs.id=due.id
RETURNING watchdog_jobs.id,watchdog_jobs.task_id,watchdog_jobs.intent_id,watchdog_jobs.run_id,
watchdog_jobs.cycle_no,watchdog_jobs.cycle_start,watchdog_jobs.status,watchdog_jobs.snapshot,
watchdog_jobs.attempts,watchdog_jobs.last_error,watchdog_jobs.next_retry_at,
watchdog_jobs.created_at,watchdog_jobs.updated_at`,
		now, WatchdogJobQueued, WatchdogJobFailed, WatchdogJobRunning)
	j, err := scanWatchdogJob(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// FinishWatchdogJob settles one job. next is the retry time for failed jobs;
// nil means no further retry (done/stale).
func (d *DB) FinishWatchdogJob(ctx context.Context, id int64, status, lastError string, next *time.Time) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_jobs SET status=$2, last_error=$3, next_retry_at=$4, updated_at=now()
WHERE id=$1`, id, status, lastError, timeArg(next))
	return err
}

// ResetRunningWatchdogJobs returns jobs left running by a crashed process to
// queued so the service can pick them up again. The attempt counter is kept,
// making a crash loop visible in the UI and logs.
func (d *DB) ResetRunningWatchdogJobs(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_jobs SET status=$1, updated_at=now() WHERE status=$2`,
		WatchdogJobQueued, WatchdogJobRunning)
	return err
}

// WatchdogJobByCycle returns the job for one run/cycle, or nil.
func (d *DB) WatchdogJobByCycle(ctx context.Context, runID string, cycleNo int) (*WatchdogJob, error) {
	j, err := scanWatchdogJob(d.QueryRowContext(ctx,
		`SELECT `+watchdogJobCols+` FROM watchdog_jobs WHERE run_id=$1 AND cycle_no=$2`, runID, cycleNo))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// WatchdogJobStats aggregates the reports still waiting in this task's queue.
// The unavailable card counts distinct reports, so retries of one report must
// not inflate alert_count; MIN/MAX come from the same rows.
func (d *DB) WatchdogJobStats(ctx context.Context, taskID string) (count int, first, last *time.Time, err error) {
	var firstAt, lastAt sql.NullTime
	err = d.QueryRowContext(ctx, `
SELECT count(*), min(created_at), max(created_at)
FROM watchdog_jobs
WHERE task_id=$1 AND status IN ($2,$3,$4)`,
		taskID, WatchdogJobQueued, WatchdogJobRunning, WatchdogJobFailed).Scan(&count, &firstAt, &lastAt)
	if firstAt.Valid {
		t := firstAt.Time
		first = &t
	}
	if lastAt.Valid {
		t := lastAt.Time
		last = &t
	}
	return count, first, last, err
}

// WatchdogRequest is one user-facing card: a reasoning decision or the
// unavailable notice. Evidence/Options are JSONB because their shape belongs to
// the card kind, not to a fixed set of columns.
type WatchdogRequest struct {
	ID             int64           `json:"id"`
	TaskID         string          `json:"task_id"`
	IntentID       *int64          `json:"intent_id,omitempty"`
	RunID          string          `json:"run_id,omitempty"`
	CycleNo        int             `json:"cycle_no"`
	Kind           string          `json:"kind"`
	Status         string          `json:"status"`
	Question       string          `json:"question"`
	Evidence       json.RawMessage `json:"evidence"`
	Options        json.RawMessage `json:"options"`
	Answer         string          `json:"answer,omitempty"`
	AnswerReason   string          `json:"answer_reason,omitempty"`
	AnsweredAt     *time.Time      `json:"answered_at,omitempty"`
	DeadlineAt     *time.Time      `json:"deadline_at,omitempty"`
	HardDeadlineAt *time.Time      `json:"hard_deadline_at,omitempty"`
	AlertCount     int             `json:"alert_count,omitempty"`
	FirstAlertAt   *time.Time      `json:"first_alert_at,omitempty"`
	LastAlertAt    *time.Time      `json:"last_alert_at,omitempty"`
	Attempts       int             `json:"attempts,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
	NextRetryAt    *time.Time      `json:"next_retry_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

const watchdogRequestCols = `id,task_id,intent_id,run_id,cycle_no,kind,status,question,evidence,
options,answer,answer_reason,answered_at,deadline_at,hard_deadline_at,alert_count,first_alert_at,
last_alert_at,attempts,last_error,next_retry_at,created_at,updated_at`

func scanWatchdogRequest(sc interface{ Scan(...any) error }) (*WatchdogRequest, error) {
	var r WatchdogRequest
	var intentID sql.NullInt64
	var runID sql.NullString
	var evidence, options []byte
	if err := sc.Scan(&r.ID, &r.TaskID, &intentID, &runID, &r.CycleNo, &r.Kind, &r.Status,
		&r.Question, &evidence, &options, &r.Answer, &r.AnswerReason, &r.AnsweredAt,
		&r.DeadlineAt, &r.HardDeadlineAt, &r.AlertCount, &r.FirstAlertAt, &r.LastAlertAt,
		&r.Attempts, &r.LastError, &r.NextRetryAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	if intentID.Valid {
		v := intentID.Int64
		r.IntentID = &v
	}
	if runID.Valid {
		r.RunID = runID.String
	}
	if len(evidence) == 0 {
		evidence = []byte(`{}`)
	}
	if len(options) == 0 {
		options = []byte(`[]`)
	}
	r.Evidence = json.RawMessage(evidence)
	r.Options = json.RawMessage(options)
	return &r, nil
}

// CreateWatchdogAsk inserts the one open decision card for this run/cycle.
// The partial unique index makes concurrent Fast Path ticks safe; created=false
// returns the card that already exists.
func (d *DB) CreateWatchdogAsk(ctx context.Context, r *WatchdogRequest) (*WatchdogRequest, bool, error) {
	evidence := r.Evidence
	if len(evidence) == 0 {
		evidence = json.RawMessage(`{}`)
	}
	options := r.Options
	if len(options) == 0 {
		options = json.RawMessage(`[]`)
	}
	row := d.QueryRowContext(ctx, `
INSERT INTO watchdog_requests(task_id,intent_id,run_id,cycle_no,kind,status,question,evidence,options,deadline_at,hard_deadline_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (run_id,cycle_no) WHERE status='open' AND kind='watchdog_ask' DO NOTHING
RETURNING `+watchdogRequestCols,
		r.TaskID, r.IntentID, r.RunID, r.CycleNo, WatchdogRequestAsk, WatchdogRequestOpen,
		r.Question, string(evidence), string(options), timeArg(r.DeadlineAt), timeArg(r.HardDeadlineAt))
	created, err := scanWatchdogRequest(row)
	if err == nil {
		return created, true, nil
	}
	if err != sql.ErrNoRows {
		return nil, false, err
	}
	existing, err := d.OpenWatchdogAsk(ctx, r.RunID, r.CycleNo)
	return existing, false, err
}

// OpenWatchdogAsk returns the open decision card for one run/cycle, or nil.
func (d *DB) OpenWatchdogAsk(ctx context.Context, runID string, cycleNo int) (*WatchdogRequest, error) {
	r, err := scanWatchdogRequest(d.QueryRowContext(ctx, `SELECT `+watchdogRequestCols+`
FROM watchdog_requests WHERE run_id=$1 AND cycle_no=$2 AND kind=$3 AND status=$4`,
		runID, cycleNo, WatchdogRequestAsk, WatchdogRequestOpen))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// LatestWatchdogAsk returns the newest card for a run/cycle regardless of status.
// The cycle processor uses it to honour an answer or a prior default result.
func (d *DB) LatestWatchdogAsk(ctx context.Context, runID string, cycleNo int) (*WatchdogRequest, error) {
	r, err := scanWatchdogRequest(d.QueryRowContext(ctx, `SELECT `+watchdogRequestCols+`
FROM watchdog_requests WHERE run_id=$1 AND cycle_no=$2 AND kind=$3 ORDER BY id DESC LIMIT 1`,
		runID, cycleNo, WatchdogRequestAsk))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// WatchdogRequestByID returns one card or nil.
func (d *DB) WatchdogRequestByID(ctx context.Context, id int64) (*WatchdogRequest, error) {
	r, err := scanWatchdogRequest(d.QueryRowContext(ctx, `SELECT `+watchdogRequestCols+`
FROM watchdog_requests WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// ListWatchdogRequests returns a task's cards, optionally filtered by status.
func (d *DB) ListWatchdogRequests(ctx context.Context, taskID, status string) ([]*WatchdogRequest, error) {
	query := `SELECT ` + watchdogRequestCols + ` FROM watchdog_requests WHERE task_id=$1`
	args := []any{taskID}
	if status != "" {
		query += ` AND status=$2`
		args = append(args, status)
	}
	query += ` ORDER BY id`
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WatchdogRequest
	for rows.Next() {
		r, err := scanWatchdogRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AnswerWatchdogRequest conditionally answers one open decision card. Returns
// nil, nil when another request already changed its status (repeat submit or
// expiry); the HTTP layer maps that to 409.
func (d *DB) AnswerWatchdogRequest(ctx context.Context, id int64, answer, reason string) (*WatchdogRequest, error) {
	r, err := scanWatchdogRequest(d.QueryRowContext(ctx, `
UPDATE watchdog_requests SET status=$2, answer=$3, answer_reason=$4, answered_at=now(), updated_at=now()
WHERE id=$1 AND status=$5 AND kind=$6
RETURNING `+watchdogRequestCols,
		id, WatchdogRequestAnswered, answer, reason, WatchdogRequestOpen, WatchdogRequestAsk))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// ExpireAnsweredWatchdogAsk retracts an answer whose control action lost the race
// with the run's settlement. The card was already committed as answered, but the
// stop/continue was refused (the run had entered its terminal commit), so leaving
// it answered would show a decision the system never applied.
func (d *DB) ExpireAnsweredWatchdogAsk(ctx context.Context, id int64, answer, reason string) (bool, error) {
	res, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$2, answer=$3, answer_reason=$4, answered_at=now(), updated_at=now()
WHERE id=$1 AND status=$5`, id, WatchdogRequestExpired, answer, reason, WatchdogRequestAnswered)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SettleWatchdogAsk closes an open decision card with a non-answer outcome
// (expired default, superseded by effective output, cancelled by task delete).
func (d *DB) SettleWatchdogAsk(ctx context.Context, id int64, status, answer, reason string) (bool, error) {
	res, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$2, answer=$3, answer_reason=$4, answered_at=now(), updated_at=now()
WHERE id=$1 AND status=$5`, id, status, answer, reason, WatchdogRequestOpen)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ExpireOpenWatchdogAsks closes every open decision card for one run/cycle.
// answer is written for the silent-default path so the audit trail says why the
// cycle advanced or terminated.
func (d *DB) ExpireOpenWatchdogAsks(ctx context.Context, runID string, cycleNo int, status, answer, reason string) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$4, answer=$5, answer_reason=$6, answered_at=now(), updated_at=now()
WHERE run_id=$1 AND cycle_no=$2 AND kind=$3 AND status=$7`,
		runID, cycleNo, WatchdogRequestAsk, status, answer, reason, WatchdogRequestOpen)
	return err
}

// SupersedeOpenWatchdogAsks closes every open decision card for a run after its
// cycle reset on effective output. The card is historical; the next cycle can
// create a new one.
func (d *DB) SupersedeOpenWatchdogAsks(ctx context.Context, runID string) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$2, answer_reason=$3, answered_at=now(), updated_at=now()
WHERE run_id=$1 AND kind=$4 AND status=$5`,
		runID, WatchdogRequestSuperseded, "运行产生了新的有效写入，周期已重新计算",
		WatchdogRequestAsk, WatchdogRequestOpen)
	return err
}

// SupersedeOpenWatchdogAsksForTask closes every open worker decision card for a
// task when the Watchdog Agent becomes unavailable. The default-card state is
// task-wide; leaving an older ask actionable would keep showing a worker card
// that cannot be evaluated.
func (d *DB) SupersedeOpenWatchdogAsksForTask(ctx context.Context, taskID, reason string) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$2, answer_reason=$3, answered_at=now(), updated_at=now()
WHERE task_id=$1 AND kind=$4 AND status=$5`,
		taskID, WatchdogRequestSuperseded, reason, WatchdogRequestAsk, WatchdogRequestOpen)
	return err
}

// CreateOrUpdateWatchdogUnavailable keeps exactly one open unavailable card per
// task. Counts/timestamps are computed from the queue, so retrying one report
// never inflates them.
func (d *DB) CreateOrUpdateWatchdogUnavailable(ctx context.Context, taskID, question string, alertCount int, first, last *time.Time, next *time.Time) (*WatchdogRequest, error) {
	r, err := scanWatchdogRequest(d.QueryRowContext(ctx, `
INSERT INTO watchdog_requests(task_id,kind,status,question,alert_count,first_alert_at,last_alert_at,next_retry_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (task_id) WHERE status='open' AND kind='watchdog_unavailable'
DO UPDATE SET question=EXCLUDED.question, alert_count=EXCLUDED.alert_count,
  first_alert_at=EXCLUDED.first_alert_at, last_alert_at=EXCLUDED.last_alert_at,
  next_retry_at=EXCLUDED.next_retry_at, updated_at=now()
RETURNING `+watchdogRequestCols,
		taskID, WatchdogRequestUnavailable, WatchdogRequestOpen, question, alertCount,
		timeArg(first), timeArg(last), timeArg(next)))
	return r, err
}

// RefreshOpenWatchdogUnavailable updates an already-open task card without
// inserting one. Fast Path calls this after enqueueing a report; it must not
// resurrect a card that recovery/retry just closed.
func (d *DB) RefreshOpenWatchdogUnavailable(ctx context.Context, taskID string, alertCount int, first, last, next *time.Time) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET alert_count=$2, first_alert_at=$3, last_alert_at=$4,
  next_retry_at=$5, updated_at=now()
WHERE task_id=$1 AND kind=$6 AND status=$7`,
		taskID, alertCount, timeArg(first), timeArg(last), timeArg(next),
		WatchdogRequestUnavailable, WatchdogRequestOpen)
	return err
}

// OpenWatchdogUnavailable returns the task's open unavailable card, or nil.
func (d *DB) OpenWatchdogUnavailable(ctx context.Context, taskID string) (*WatchdogRequest, error) {
	r, err := scanWatchdogRequest(d.QueryRowContext(ctx, `SELECT `+watchdogRequestCols+`
FROM watchdog_requests WHERE task_id=$1 AND kind=$2 AND status=$3`,
		taskID, WatchdogRequestUnavailable, WatchdogRequestOpen))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// CloseWatchdogUnavailable expires the open unavailable card after a successful
// agent run. A later failure opens a fresh card, which keeps the audit history.
func (d *DB) CloseWatchdogUnavailable(ctx context.Context, taskID string) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$2, answer_reason=$3, answered_at=now(), updated_at=now()
WHERE task_id=$1 AND kind=$4 AND status=$5`,
		taskID, WatchdogRequestExpired, "Watchdog Agent 已恢复", WatchdogRequestUnavailable, WatchdogRequestOpen)
	return err
}

// TouchWatchdogUnavailable updates the retry time on the open card without
// changing its alert aggregates.
func (d *DB) TouchWatchdogUnavailable(ctx context.Context, taskID string, next *time.Time) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET next_retry_at=$2, updated_at=now()
WHERE task_id=$1 AND kind=$3 AND status=$4`,
		taskID, timeArg(next), WatchdogRequestUnavailable, WatchdogRequestOpen)
	return err
}

// RetryWatchdogQueue makes every failed/queued job for this task due now and
// wakes the service. It does not change cycle timing or worker state.
func (d *DB) RetryWatchdogQueue(ctx context.Context, taskID string) error {
	_, err := d.ExecContext(ctx, `
UPDATE watchdog_jobs SET next_retry_at=now(), updated_at=now()
WHERE task_id=$1 AND status IN ($2,$3)`, taskID, WatchdogJobQueued, WatchdogJobFailed)
	return err
}

// DeleteWatchdogJobsForRun removes the control-plane jobs for one run when its
// cycle is reset/rekeyed. Cycle numbers restart at C0, so keeping an old
// (run_id, cycle_no) row would make the next EnqueueWatchdogJob collide with a
// finished/running job and silently skip the new cycle's judgment. An in-flight
// judge keeps its local job ID; its Finish is a no-op and its result is rejected
// by the cycle-start check. Reports/activities remain the audit trail.
func (d *DB) DeleteWatchdogJobsForRun(ctx context.Context, runID string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM watchdog_jobs WHERE run_id=$1`, runID)
	return err
}

// DeleteWatchdogTaskData removes a task's control rows outside a larger
// transaction. Deletion/archive transactions use deleteWatchdogTaskDataTx so
// cleanup remains atomic with the task mutation.
func (d *DB) DeleteWatchdogTaskData(ctx context.Context, taskID string) error {
	for _, table := range []string{"worker_runs", "watchdog_jobs", "watchdog_requests"} {
		if _, err := d.ExecContext(ctx, `DELETE FROM `+table+` WHERE task_id=$1`, taskID); err != nil {
			return err
		}
	}
	return nil
}

// RecoverWatchdogOnStartup cleans state that cannot survive a process restart:
// live runs are gone, running jobs must be re-claimed, and open cards belong to
// a run that no longer exists. Historical rows are kept for audit.
func (d *DB) RecoverWatchdogOnStartup(ctx context.Context) error {
	if err := d.ClearWorkerRunsOnStartup(ctx); err != nil {
		return fmt.Errorf("clear worker runs: %w", err)
	}
	if err := d.ResetRunningWatchdogJobs(ctx); err != nil {
		return fmt.Errorf("reset watchdog jobs: %w", err)
	}
	if _, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$1, answer_reason=$2, updated_at=now()
WHERE status=$3 AND kind=$4`, WatchdogRequestExpired,
		"服务重启，原运行已结束", WatchdogRequestOpen, WatchdogRequestAsk); err != nil {
		return fmt.Errorf("expire open asks: %w", err)
	}
	// The unavailable card describes a queue that was just reset/requeued. Close it;
	// a still-broken judge will open a fresh card with current counts.
	if _, err := d.ExecContext(ctx, `
UPDATE watchdog_requests SET status=$1, answer_reason=$2, updated_at=now()
WHERE status=$3 AND kind=$4`, WatchdogRequestExpired,
		"服务重启，等待重新判断", WatchdogRequestOpen, WatchdogRequestUnavailable); err != nil {
		return fmt.Errorf("expire unavailable cards: %w", err)
	}
	return nil
}
