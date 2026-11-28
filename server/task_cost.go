package server

import (
	"context"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// Task-level cost governance (docs §4.1 WP2). Removing the model-authored numeric
// route budget left the system without any hard ceiling, so the backstop moved to
// the task and is computed by the engine from the always-on llm_usage ledger. The
// model never sees a number it cannot integrate; the engine enforces one it can
// measure.
//
// The cap is checked when an intent is claimed (one query per run) and refreshed
// at most every costCapRefresh while loops wait, so a single very long run cannot
// run away unnoticed without making every 800ms poll a database round trip.

const costCapRefresh = 30 * time.Second

type costCapEntry struct {
	cost int64
	at   time.Time
}

// taskCostCap resolves the effective ceiling. enabled=false means no ceiling.
func (m *Manager) taskCostCap() (enabled bool, limit int64) {
	if m == nil || m.pg == nil {
		return false, 0
	}
	if !m.pg.GetBool(db.SettingTaskCostCapEnabled, false) {
		return false, 0
	}
	n := int64(settingsInt(m.pg, db.SettingTaskCostCapTokens, db.DefaultTaskCostCapTokens))
	if n <= 0 {
		n = db.DefaultTaskCostCapTokens
	}
	return true, n
}

// taskCost returns the task's cached cumulative equivalent cost, refreshing when
// the cached value is older than costCapRefresh.
func (e *Engine) taskCost(taskID string) (int64, bool) {
	if e == nil || e.m == nil || e.m.pg == nil {
		return 0, false
	}
	if v, ok := e.costCap.Load(taskID); ok {
		entry := v.(costCapEntry)
		if time.Since(entry.at) < costCapRefresh {
			return entry.cost, true
		}
	}
	cost, err := e.m.pg.TaskEquivalentCost(taskID)
	if err != nil {
		return 0, false
	}
	e.costCap.Store(taskID, costCapEntry{cost: cost, at: time.Now()})
	return cost, true
}

// taskCostCapExceeded reports whether this task has spent its equivalent-cost
// ceiling. On the first observation it parks the task through Pause with a named
// cause, so the shutdown is visible in the activity trace and the task is
// resumable (every in-flight intent returns to the frontier).
//
// A read failure is NOT treated as "over the cap": pausing a task because the
// metering table was momentarily unreadable would stop work the operator did not
// ask to stop, and the next tick retries anyway.
func (e *Engine) taskCostCapExceeded(t *Task) bool {
	if e == nil || e.m == nil {
		return false
	}
	enabled, limit := e.m.taskCostCap()
	if !enabled || t == nil {
		return false
	}
	cost, ok := e.taskCost(t.ID)
	if !ok || cost < limit {
		return false
	}
	// Same lifecycle as the normal pause path (server/task_control.go): pause the
	// engine, then persist. The resume endpoint requires the STORED lifecycle to say
	// paused, so an in-memory-only pause shows "paused" while "continue" keeps being
	// rejected and the operator can never resume after raising the ceiling.
	//
	// Rollback rules, all decided under the SAME lock the manual pause path uses:
	//   - the engine bit, the persistent row and any rollback happen together, so a
	//     concurrent pauser can never be undone by this call;
	//   - if the database already says paused, a peer committed it — keep both halves;
	//   - only a pause THIS call installed is rolled back, and only when no pause is
	//     persisted. Leaving the engine bit set after a failed write would recreate
	//     the "shows paused, resume rejected" dead state; rolling back lets the sweep
	//     retry on its next pass.
	e.m.pauseMu.Lock()
	wasPaused := e.IsPaused(t.ID)
	e.Pause(t.ID, agent.AbortTaskCostCap)
	pauseErr := e.m.ApplyTaskPause(t.ID)
	if pauseErr != nil && !e.m.TaskPersistentlyPaused(t.ID) && !wasPaused {
		e.Resume(t)
	}
	e.m.pauseMu.Unlock()
	if pauseErr != nil {
		if e.m.TaskPersistentlyPaused(t.ID) {
			// Someone else committed the pause. Keep both halves: the task is paused
			// and the engine agrees.
			log.Printf("[cost] task %s 已由其他路径落库暂停，保留暂停: %v", t.ID, pauseErr)
			e.emitActivity(t, db.Activity{
				Worker: "system", Kind: "text", IsError: true,
				Summary: "任务已到达等效成本上限，暂停已生效",
				Detail:  "累计等效成本 " + itoa64(cost) + " ≥ 上限 " + itoa64(limit) + "；暂停状态由并发路径写入，此处保留。",
			})
			return true
		}
		log.Printf("[cost] task %s 成本上限暂停落库失败，回滚内存暂停并下轮重试: %v", t.ID, pauseErr)
		e.emitActivity(t, db.Activity{
			Worker: "system", Kind: "text", IsError: true,
			Summary: "任务已达等效成本上限，但暂停状态未能落库；本轮未执行暂停",
			Detail: "暂停写入失败（" + pauseErr.Error() + "），已回滚内存暂停以免出现「界面已暂停、恢复被拒」的死状态；" +
				"巡检会在下一轮重试。累计等效成本 " + itoa64(cost) + " ≥ 上限 " + itoa64(limit) + "。",
		})
		return false
	}
	e.emitActivity(t, db.Activity{
		Worker: "system", Kind: "text", IsError: true,
		Summary: "任务已到达等效成本上限，停止领取新意图",
		Detail: "累计等效成本 " + itoa64(cost) + " ≥ 上限 " + itoa64(limit) +
			"（未缓存输入 + 0.1×缓存读 + 4×输出）。已写入的事实、资产与漏洞全部保留；提高上限或缩小任务范围后恢复任务即可继续。",
	})
	return true
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// costCapSweepInterval bounds how often the periodic sweep runs. It matches the
// per-task cache TTL: the sweep exists so a task whose workers are ALL busy is
// still checked, since the claim-time gate is never reached while every slot is
// occupied.
const costCapSweepInterval = costCapRefresh

// runCostCapSweep periodically checks every running task against its ceiling. The
// claim-time gate alone cannot cover the case the ceiling matters most: a task
// that keeps all its workers busy never claims a new intent, so nothing would
// observe the spend until a run finished.
func (s *Server) runCostCapSweep(ctx context.Context) {
	ticker := time.NewTicker(costCapSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepCostCaps()
		}
	}
}

// sweepCostCaps checks each live task once. Skipped states mirror the claim gate:
// paused/deleting/settling/terminal tasks are not spending on new work.
func (s *Server) sweepCostCaps() {
	if s == nil || s.m == nil || s.engine == nil {
		return
	}
	if enabled, _ := s.m.taskCostCap(); !enabled {
		return
	}
	for _, t := range s.m.List() {
		if t == nil || s.engine.IsDeleting(t.ID) || s.engine.IsPaused(t.ID) ||
			s.engine.isSettling(t.ID) || isTerminalStatus(t.lifecycleSnapshot().Status) {
			continue
		}
		if s.engine.taskCostCapExceeded(t) {
			log.Printf("[cost] task %s 已因等效成本上限暂停（周期性巡检）", t.ID)
		}
	}
}
