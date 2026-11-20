package server

import (
	"context"
	"fmt"
	"log"
	"time"
)

// watchdogRuntime owns the two independent loops of the watchdog: the 5-second
// Fast Path and the Slow Path queue consumer. Keeping them in separate
// goroutines is what lets a slow model call coexist with pressure/cycle timers.
type watchdogRuntime struct {
	s       *Server
	monitor *RunMonitor
	fast    *watchdogFast
	service *watchdogService
}

func newWatchdogRuntime(s *Server, now func() time.Time) *watchdogRuntime {
	monitor := NewRunMonitor(s.m.pg, now)
	fast := newWatchdogFast(s, monitor)
	fast.now = now
	service := newWatchdogService(s, monitor)
	service.now = now
	return &watchdogRuntime{s: s, monitor: monitor, fast: fast, service: service}
}

// Run starts both loops. It returns immediately; cancellation is owned by the
// server's root context.
func (w *watchdogRuntime) Run(ctx context.Context) {
	if w == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.fast.Tick(ctx)
			}
		}
	}()
	go w.service.Run(ctx)
}

// removeWatchdogTask drops in-memory run state after a successful delete or
// archive. Lightweight tests may build a Server without a watchdog runtime.
func (s *Server) removeWatchdogTask(taskID string) {
	if s != nil && s.watchdog != nil && s.watchdog.monitor != nil {
		s.watchdog.monitor.RemoveTask(taskID)
	}
}

// Wake nudges the Slow Path service. The Fast Path never waits on this channel.
func (w *watchdogRuntime) Wake() {
	if w != nil && w.service != nil {
		w.service.Wake()
	}
}

// watchdogOnRunFinish closes the control-plane leftovers of a run that ended
// normally, failed, was cancelled or was terminated. Every operation is
// idempotent: task deletion/archive may already have removed the rows, and the
// finish hook may race detachWork's peer expiry.
func (s *Server) watchdogOnRunFinish(snap RunSnapshot) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.m.pg.SupersedeOpenWatchdogAsks(ctx, snap.RunID); err != nil {
		log.Printf("[watchdog] 运行结束关闭判断卡失败 run=%s: %v", snap.RunID, err)
	}
	if err := s.m.pg.DeleteWatchdogJobsForRun(ctx, snap.RunID); err != nil {
		log.Printf("[watchdog] 运行结束清理 Slow Path 任务失败 run=%s: %v", snap.RunID, err)
	}
	if s.engine != nil {
		s.engine.ExpirePeerRequestsForIntent(snap.IntentID, snap.RunID, "holder_finished")
	}
	if t, ok := s.m.Task(snap.TaskID); s.engine != nil && ok && t != nil {
		s.emitWatchdogActivity(t, "watchdog_run_finished",
			fmt.Sprintf("意图 #%d 运行结束（%s）", snap.IntentID, snap.State),
			"已关闭该运行的开放判断卡、Slow Path 任务和未完成资源请求",
			watchdogAudit{
				State: snap.State, Reason: "run_finished", CycleNo: snap.CycleNo,
				Phase: snap.Phase, Facts: snap.Facts, Assets: snap.Assets, Findings: snap.Findings,
			})
	}
}

// onCycleReset closes asks and removes jobs from the cycle that just ended.
// Cycle numbers restart at C0, so a leftover job with the same (run, cycle)
// would suppress the next cycle's enqueue. An in-flight judge's Finish becomes
// a no-op and its cycle-start check rejects the result.
func (s *Server) watchdogOnCycleReset(snap RunSnapshot) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.m.pg.SupersedeOpenWatchdogAsks(ctx, snap.RunID); err != nil {
		log.Printf("[watchdog] run %s 关闭旧周期请求失败: %v", snap.RunID, err)
	}
	if err := s.m.pg.DeleteWatchdogJobsForRun(ctx, snap.RunID); err != nil {
		log.Printf("[watchdog] run %s 清理旧周期任务失败: %v", snap.RunID, err)
	}
}
