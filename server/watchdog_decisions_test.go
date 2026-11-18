package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestWatchdogRequestDTOMarksDefaultRules(t *testing.T) {
	s := &Server{}
	ask := &db.WatchdogRequest{ID: 1, TaskID: "2", CycleNo: 0, Kind: db.WatchdogRequestAsk,
		Status: db.WatchdogRequestOpen, Question: "q"}
	dto := s.watchdogRequestDTO(ask)
	if dto["default_rule"] != "c0_continue" {
		t.Fatalf("C0 default_rule=%v", dto["default_rule"])
	}
	ask.CycleNo = 1
	if dto = s.watchdogRequestDTO(ask); dto["default_rule"] != "c1_plus_terminate" {
		t.Fatalf("C1 default_rule=%v", dto["default_rule"])
	}
	unavailable := &db.WatchdogRequest{ID: 2, TaskID: "2", Kind: db.WatchdogRequestUnavailable,
		Status: db.WatchdogRequestOpen, AlertCount: 3, LastError: "secret worker failure"}
	dto = s.watchdogRequestDTO(unavailable)
	if dto["auto_retry_sec"] == nil {
		t.Fatal("unavailable card missing auto_retry_sec")
	}
	if _, leaked := dto["last_error"]; leaked {
		t.Fatal("unavailable card leaked last_error")
	}
}

func TestWatchdogRunsAPI(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	s.engine.SetRunMonitor(s.watchdog.monitor)
	s.watchdog.monitor.Register(task.ID, intent.ID, "run-api", "work#1")
	req := httptest.NewRequest("GET", "/api/watchdog/runs?task_id="+task.ID, nil)
	rec := httptest.NewRecorder()
	s.watchdogRuns(rec, req)
	if rec.Code != 200 {
		t.Fatalf("runs code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Runs []watchdogRunDTO `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Runs) != 1 || out.Runs[0].IntentID != intent.ID || out.Runs[0].RunID != "run-api" {
		t.Fatalf("runs=%+v", out.Runs)
	}
}

func TestWatchdogDecideStaleRequestExpires(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	monitor := NewRunMonitor(m.pg, func() time.Time { return now })
	s := newAdmissionTestServer(m, nil)
	s.engine.SetRunMonitor(monitor)
	s.watchdog = &watchdogRuntime{s: s, monitor: monitor}
	card, _, err := m.pg.CreateWatchdogAsk(context.Background(), &db.WatchdogRequest{
		TaskID: task.ID, IntentID: &intent.ID, RunID: "missing-run", CycleNo: 0,
		Kind: db.WatchdogRequestAsk, Question: "continue?", DeadlineAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"answer": "continue"})
	req := httptest.NewRequest("POST", "/api/watchdog/requests/"+strconv.FormatInt(card.ID, 10)+"/decision", bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(card.ID, 10))
	rec := httptest.NewRecorder()
	s.watchdogDecide(rec, req)
	if rec.Code != 409 {
		t.Fatalf("stale decision code=%d body=%s", rec.Code, rec.Body.String())
	}
	got, err := m.pg.WatchdogRequestByID(context.Background(), card.ID)
	if err != nil || got == nil || got.Status != db.WatchdogRequestExpired {
		t.Fatalf("stale card=%+v err=%v", got, err)
	}
}

func TestWatchdogRetryClosesCardWithoutQueue(t *testing.T) {
	m, task, _ := testWatchdogTask(t)
	s := newAdmissionTestServer(m, nil)
	now := time.Now()
	card, err := m.pg.CreateOrUpdateWatchdogUnavailable(context.Background(), task.ID,
		"Watchdog Agent 不可用，请检查 Watchdog Agent 配置", 1, &now, &now, &now)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/watchdog/requests/"+strconv.FormatInt(card.ID, 10)+"/retry", nil)
	req.SetPathValue("id", strconv.FormatInt(card.ID, 10))
	rec := httptest.NewRecorder()
	s.watchdogRetry(rec, req)
	if rec.Code != 200 {
		t.Fatalf("retry code=%d body=%s", rec.Code, rec.Body.String())
	}
	got, err := m.pg.WatchdogRequestByID(context.Background(), card.ID)
	if err != nil || got == nil || got.Status != db.WatchdogRequestExpired {
		t.Fatalf("card after retry=%+v err=%v", got, err)
	}
}

func TestWatchdogDecideContinueAdvancesC3ToC4(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	runID := "run-decision-c3"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	monitor.SetCycle(runID, 3, now, false, db.SlowPathNone, db.WatchdogDecisionOpen)
	deadline := now.Add(20 * time.Minute)
	card, _, err := m.pg.CreateWatchdogAsk(context.Background(), &db.WatchdogRequest{
		TaskID: task.ID, IntentID: &intent.ID, RunID: runID, CycleNo: 3,
		Kind: db.WatchdogRequestAsk, Question: "continue to C4?", DeadlineAt: &deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"answer": "continue", "reason": "still useful"})
	req := httptest.NewRequest("POST", "/api/watchdog/requests/"+strconv.FormatInt(card.ID, 10)+"/decision", bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(card.ID, 10))
	rec := httptest.NewRecorder()
	s.watchdogDecide(rec, req)
	if rec.Code != 200 {
		t.Fatalf("C3 decision code=%d body=%s", rec.Code, rec.Body.String())
	}
	if snap := monitor.Lookup(intent.ID); snap == nil || snap.CycleNo != 4 {
		t.Fatalf("C3 consent did not advance to C4: %+v", snap)
	}
}

func TestWatchdogDecideContinueAdvancesCycle(t *testing.T) {
	m, task, intent := testWatchdogTask(t)
	now := time.Now()
	s := newAdmissionTestServer(m, nil)
	s.watchdog = newWatchdogRuntime(s, func() time.Time { return now })
	monitor := s.watchdog.monitor
	s.engine.SetRunMonitor(monitor)
	runID := "run-decision"
	monitor.Register(task.ID, intent.ID, runID, "work#1")
	card, _, err := m.pg.CreateWatchdogAsk(context.Background(), &db.WatchdogRequest{
		TaskID: task.ID, IntentID: &intent.ID, RunID: runID, CycleNo: 0,
		Kind: db.WatchdogRequestAsk, Question: "continue?", DeadlineAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"answer": "continue", "reason": "still useful"})
	req := httptest.NewRequest("POST", "/api/watchdog/requests/"+strconv.FormatInt(card.ID, 10)+"/decision", bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(card.ID, 10))
	rec := httptest.NewRecorder()
	s.watchdogDecide(rec, req)
	if rec.Code != 200 {
		t.Fatalf("decision code=%d body=%s", rec.Code, rec.Body.String())
	}
	snap := monitor.Lookup(intent.ID)
	if snap == nil || snap.CycleNo != 1 {
		t.Fatalf("cycle did not advance: %+v", snap)
	}
	got, err := m.pg.WatchdogRequestByID(context.Background(), card.ID)
	if err != nil || got == nil || got.Status != db.WatchdogRequestAnswered || got.Answer != "continue" {
		t.Fatalf("answered card=%+v err=%v", got, err)
	}
}
