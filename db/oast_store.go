package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// oastSchema persists every out-of-band callback interaction. The in-process OAST
// server keeps its own ring buffers so a hit is answerable immediately, but a ring
// dies with the process: after a restart an `oast:<id>` reference in a checkpoint
// or finding would resolve to nothing and the evidence could not be reviewed. The
// table is the durable half of that pair.
const oastSchema = `
CREATE TABLE IF NOT EXISTS oast_interactions (
    id           BIGINT PRIMARY KEY,
    token        TEXT NOT NULL DEFAULT '',
    task_id      BIGINT NOT NULL DEFAULT 0,
    intent_id    BIGINT NOT NULL DEFAULT 0,
    at           TEXT NOT NULL DEFAULT '',
    remote_ip    TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    query        TEXT NOT NULL DEFAULT '',
    host         TEXT NOT NULL DEFAULT '',
    headers      JSONB NOT NULL DEFAULT '{}',
    body_preview TEXT NOT NULL DEFAULT '',
    body_truncated BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_oast_interactions_task ON oast_interactions(task_id, id);
`

// IDConflictError reports that an interaction id is already present. The caller
// already handed out `oast:<id>`, so publishing a second event under it would change
// what an existing evidence reference means.
type IDConflictError struct{ ID int64 }

func (e *IDConflictError) Error() string {
	return fmt.Sprintf("带外回调 id %d 已存在：证据标识冲突，本次回调未写入数据库（已有记录保留）", e.ID)
}

// OASTInteraction is one persisted callback. It mirrors oast.Interaction without
// importing that package (db is the lower layer).
type OASTInteraction struct {
	ID            int64               `json:"id"`
	Token         string              `json:"token"`
	TaskID        int64               `json:"task_id"`
	IntentID      int64               `json:"intent_id"`
	At            string              `json:"at"`
	RemoteIP      string              `json:"remote_ip"`
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	Query         string              `json:"query"`
	Host          string              `json:"host"`
	Headers       map[string][]string `json:"headers"`
	BodyPreview   string              `json:"body_preview"`
	BodyTruncated bool                `json:"body_truncated"`
}

// EnsureOASTTable creates the durable callback table.
func (d *DB) EnsureOASTTable() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(oastSchema); err != nil {
		return err
	}
	return tx.Commit()
}

// InsertOASTInteraction stores one callback.
//
// A repeated id is a REAL fault, not a harmless duplicate: the caller already handed
// out `oast:<id>`, so two different callbacks under one id means an evidence
// reference silently changed meaning. The insert therefore keeps the first row (the
// original capture is the evidence) and returns an error naming the collision, which
// the OAST server logs loudly — `ON CONFLICT DO NOTHING` alone would hide it.
func (d *DB) InsertOASTInteraction(in OASTInteraction) error {
	headers := in.Headers
	if headers == nil {
		headers = map[string][]string{}
	}
	raw, err := json.Marshal(headers)
	if err != nil {
		raw = []byte("{}")
	}
	res, err := d.Exec(`
INSERT INTO oast_interactions(id,token,task_id,intent_id,at,remote_ip,method,path,query,host,headers,body_preview,body_truncated)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (id) DO NOTHING`,
		in.ID, in.Token, in.TaskID, in.IntentID, in.At, in.RemoteIP, in.Method,
		in.Path, in.Query, in.Host, string(raw), in.BodyPreview, in.BodyTruncated)
	if err != nil {
		return err
	}
	if n, rerr := res.RowsAffected(); rerr == nil && n == 0 {
		// Typed so the OAST server can tell "id taken" (must not publish) from "database
		// unavailable" (publish in memory only). A plain error would erase that
		// distinction and let the same reference mean two different events.
		return &IDConflictError{ID: in.ID}
	}
	return nil
}

// OASTInteractionTask resolves the task a persisted callback belongs to. found is
// false when no such interaction was ever recorded.
func (d *DB) OASTInteractionTask(id int64) (taskID int64, found bool, err error) {
	err = d.QueryRow(`SELECT task_id FROM oast_interactions WHERE id=$1`, id).Scan(&taskID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return taskID, true, nil
}
