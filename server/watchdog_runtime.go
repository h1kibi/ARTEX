package server

import (
	"context"
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
