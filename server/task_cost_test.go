package server

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// The task-level equivalent-cost ceiling is the replacement for the removed
// numeric route budget, so it must be computed with the documented weights and
// actually stop the task when reached. Both halves are asserted here: the SQL
// weighting (a cached read must not cost the same as an uncached one) and the
// engine gate (reaching the ceiling pauses the task instead of claiming more).
func TestTaskEquivalentCostWeightsCacheAndOutput(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("cost weights", "measure", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	// 1000 uncached input + 10000 cache read + 100 output
	// = 1000 + 1000 + 400 = 2400 equivalent tokens.
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{
		TaskID: task.ID, Worker: "worker", Model: "test",
		InputTokens: 11000, CacheRead: 10000, OutputTokens: 100,
	}); err != nil {
		t.Fatal(err)
	}
	cost, err := m.pg.TaskEquivalentCost(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cost != 2400 {
		t.Fatalf("equivalent cost = %d, want 2400 (1000 uncached + 1000 cache + 400 out)", cost)
	}

	// A second task's spend must not leak into the first one's total.
	other, err := m.CreateTask("cost isolation", "measure", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(other.ID, DeleteTaskOptions{}) })
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: other.ID, Worker: "worker", InputTokens: 999999}); err != nil {
		t.Fatal(err)
	}
	if again, err := m.pg.TaskEquivalentCost(task.ID); err != nil || again != 2400 {
		t.Fatalf("cost after another task's usage = %d (err=%v), want 2400", again, err)
	}
}

// Reaching the ceiling must park the task, not merely stop one loop: the Pause
// path returns in-flight intents to the frontier so a resume loses nothing.
func TestTaskCostCapPausesTaskAtCeiling(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("cost ceiling", "measure", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	engine := NewEngine(m)
	t.Cleanup(func() { engine.StopTask(task.ID) })

	if err := m.pg.SetBool(db.SettingTaskCostCapEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetBool(db.SettingTaskCostCapEnabled, false) })
	if err := m.pg.SetSetting(db.SettingTaskCostCapTokens, "1000"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = m.pg.SetSetting(db.SettingTaskCostCapTokens, "20000000")
		engine.costCap.Clear()
	})

	// Below the ceiling: no pause.
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "worker", InputTokens: 500}); err != nil {
		t.Fatal(err)
	}
	engine.costCap.Clear()
	if engine.taskCostCapExceeded(task) {
		t.Fatal("task paused below the ceiling")
	}
	if engine.IsPaused(task.ID) {
		t.Fatal("task paused below the ceiling")
	}

	// Crossing it pauses the task.
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "worker", InputTokens: 900}); err != nil {
		t.Fatal(err)
	}
	engine.costCap.Clear()
	if !engine.taskCostCapExceeded(task) {
		t.Fatal("cost ceiling not detected")
	}
	if !engine.IsPaused(task.ID) {
		t.Fatal("reaching the cost ceiling did not pause the task")
	}
	// The disabled switch must win over an already-crossed ceiling.
	if err := m.pg.SetBool(db.SettingTaskCostCapEnabled, false); err != nil {
		t.Fatal(err)
	}
	engine.costCap.Clear()
	if got, ok := engine.taskCost(task.ID); !ok || got < 1000 {
		t.Fatalf("cached cost = %d (ok=%v), want >= 1000", got, ok)
	}
	if enabled, _ := m.taskCostCap(); enabled {
		t.Fatal("cap reported enabled while the switch is off")
	}
	_ = context.Background()
}

// The cap must stop the task through the SAME lifecycle the resume endpoint
// checks. An in-memory-only pause shows "paused" in the UI while "continue" keeps
// returning 409, so an operator who raises the ceiling can never resume.
func TestCostCapPauseIsResumableThroughControlAPI(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	if err := s.m.pg.SetBool(db.SettingTaskCostCapEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.SetBool(db.SettingTaskCostCapEnabled, false) })
	if err := s.m.pg.SetSetting(db.SettingTaskCostCapTokens, "100"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.SetSetting(db.SettingTaskCostCapTokens, "20000000") })

	task, err := s.m.CreateTask("resume after cap", "spend", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	if err := s.m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "worker", InputTokens: 500}); err != nil {
		t.Fatal(err)
	}
	s.engine.costCap.Clear()
	if !s.engine.taskCostCapExceeded(task) {
		t.Fatal("cost cap not detected")
	}
	// The pause must be persisted, not only in Engine memory.
	persisted, err := s.m.pg.GetTask(mustID(t, task.ID))
	if err != nil || persisted == nil {
		t.Fatalf("reload task: %v", err)
	}
	if !persisted.Paused {
		t.Fatal("cap pause was not persisted; the resume endpoint would reject it")
	}

	// Raise the ceiling, then resume through the real control endpoint.
	if err := s.m.pg.SetSetting(db.SettingTaskCostCapTokens, "100000000"); err != nil {
		t.Fatal(err)
	}
	s.engine.costCap.Clear()
	if r := request("POST", "/api/tasks/"+task.ID+"/control", `{"action":"resume"}`); r.Code != 200 {
		t.Fatalf("resume after raising the cap: %d %s", r.Code, r.Body)
	}
	if s.engine.IsPaused(task.ID) {
		t.Fatal("task still paused after a successful resume")
	}
}

func mustID(t *testing.T, raw string) int64 {
	t.Helper()
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A failed pause write must not leave the "shows paused, cannot resume" dead state.
// The engine pause is rolled back so the sweep retries instead of wedging the task.
func TestCostCapRollsBackWhenPausePersistFails(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("cap rollback", "spend", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	engine := NewEngine(m)
	t.Cleanup(func() { engine.StopTask(task.ID) })
	if err := m.pg.SetBool(db.SettingTaskCostCapEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetBool(db.SettingTaskCostCapEnabled, false) })
	if err := m.pg.SetSetting(db.SettingTaskCostCapTokens, "100"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetSetting(db.SettingTaskCostCapTokens, "20000000") })
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "worker", InputTokens: 500}); err != nil {
		t.Fatal(err)
	}
	engine.costCap.Clear()

	// Make the write fail for real: the task row is gone, so the conditional UPDATE
	// matches nothing and the rollback path runs. (Closing the pool did NOT exercise
	// it — the cap setting read then fails first and the function returns early.)
	if _, err := m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, mustID(t, task.ID)); err != nil {
		t.Fatal(err)
	}
	applied := engine.taskCostCapExceeded(task)
	if applied {
		t.Fatal("cap reported applied while the pause could not be persisted")
	}
	if engine.IsPaused(task.ID) {
		t.Fatal("in-memory pause left in place after a failed persist: resume would be rejected forever")
	}
}

// The sweep and a worker can judge the cap at the same time. Whichever commits the
// pause first owns it; the loser must NOT roll it back, or the database ends up
// paused while the engine keeps running.
func TestCostCapKeepsPeerCommittedPause(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("cap peer pause", "spend", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	engine := NewEngine(m)
	t.Cleanup(func() { engine.StopTask(task.ID) })

	if err := m.pg.SetBool(db.SettingTaskCostCapEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetBool(db.SettingTaskCostCapEnabled, false) })
	if err := m.pg.SetSetting(db.SettingTaskCostCapTokens, "100"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetSetting(db.SettingTaskCostCapTokens, "20000000") })
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "worker", InputTokens: 500}); err != nil {
		t.Fatal(err)
	}
	engine.costCap.Clear()

	// A peer commits the pause first (the worker's claim gate, another sweep tick,
	// or the operator). Our ApplyTaskPause then misses its conditional UPDATE.
	if err := m.ApplyTaskPause(task.ID); err != nil {
		t.Fatal(err)
	}
	if !m.TaskPersistentlyPaused(task.ID) {
		t.Fatal("peer pause not persisted")
	}

	if !engine.taskCostCapExceeded(task) {
		t.Fatal("cap did not recognize the already-committed pause")
	}
	if !engine.IsPaused(task.ID) {
		t.Fatal("engine pause was rolled back even though the task is paused in the database")
	}
	if !m.TaskPersistentlyPaused(task.ID) {
		t.Fatal("database pause lost")
	}
}

// A resume that clears the persistent paused flag and the Engine's pause bit must
// not interleave with a cost-cap pause that writes the opposite state. The two
// paths share Manager.pauseMu, so after every interleaving the database and the
// engine agree; without it the resume's later Resume call could erase a pause the
// sweep had just committed, leaving the row paused while the task keeps running.
func TestCostCapPauseAndResumeStayConsistentUnderRace(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("cost resume race", "spend", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	s := newAdmissionTestServer(m, nil)
	t.Cleanup(func() { s.engine.StopTask(task.ID) })
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(false, defaultConcurrencyLimit); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetBool(db.SettingTaskCostCapEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetBool(db.SettingTaskCostCapEnabled, false) })
	if err := m.pg.SetSetting(db.SettingTaskCostCapTokens, "100"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetSetting(db.SettingTaskCostCapTokens, "20000000") })
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "worker", InputTokens: 500}); err != nil {
		t.Fatal(err)
	}

	check := func(stage string) {
		t.Helper()
		persisted := m.TaskPersistentlyPaused(task.ID)
		inMemory := s.engine.IsPaused(task.ID)
		if persisted != inMemory {
			t.Fatalf("%s: database paused=%v engine paused=%v", stage, persisted, inMemory)
		}
	}
	pauseAtCap := func() {
		t.Helper()
		if err := m.pg.SetSetting(db.SettingTaskCostCapTokens, "100"); err != nil {
			t.Fatal(err)
		}
		s.engine.costCap.Clear()
		if !s.engine.taskCostCapExceeded(task) {
			t.Fatal("cost cap did not pause the task")
		}
	}

	for i := range 25 {
		pauseAtCap()
		check("paused before race")

		var wg sync.WaitGroup
		wg.Add(2)
		// The operator raises the ceiling and resumes through the real admission path.
		go func() {
			defer wg.Done()
			if err := m.pg.SetSetting(db.SettingTaskCostCapTokens, "1000000000"); err != nil {
				t.Errorf("raise cap: %v", err)
				return
			}
			s.engine.costCap.Clear()
			if _, err := s.admitPausedTask(task); err != nil {
				t.Errorf("resume: %v", err)
			}
		}()
		// A sweep tick runs concurrently with the cached over-cap reading.
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%3) * time.Millisecond)
			s.engine.costCap.Clear()
			s.engine.taskCostCapExceeded(task)
		}()
		wg.Wait()
		check("after race")
	}
	pauseAtCap()
	check("final")
}
