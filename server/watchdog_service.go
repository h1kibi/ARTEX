package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// watchdogService consumes Slow Path jobs. It owns the only model call in the
// Watchdog path: Fast Path enqueues, this goroutine runs the judge, and the
// action is still performed by the Engine. A judge run never blocks Fast Path.
type watchdogService struct {
	s       *Server
	monitor *RunMonitor
	now     func() time.Time
	wake    chan struct{}
	// arbitrationCh carries worker resource-request judgments. It is separate
	// from Slow Path jobs: the two have different prompts and cooldowns.
	arbitrationCh chan PeerArbitration
}

func newWatchdogService(s *Server, monitor *RunMonitor) *watchdogService {
	return &watchdogService{s: s, monitor: monitor, now: time.Now, wake: make(chan struct{}, 1),
		arbitrationCh: make(chan PeerArbitration, 16)}
}

// Run consumes jobs until the server context is cancelled. The ticker also
// re-checks failed jobs after their next_retry_at; the wake channel lets the
// unavailable card's Try again bypass that wait.
func (w *watchdogService) Run(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-w.arbitrationCh:
				w.runPeerArbitration(ctx, req)
			}
		}
	}()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Tick(ctx)
		case <-w.wake:
			w.Tick(ctx)
		}
	}
}

// Wake asks the service to attempt queued work now. Non-blocking: a pending
// wake already means "run soon", and coalescing requests is safe.
func (w *watchdogService) Wake() {
	if w == nil {
		return
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Tick claims up to a small batch of due jobs. Claiming one at a time keeps the
// database lock short; a single slow judge run only delays this goroutine, not
// the Fast Path ticker.
func (w *watchdogService) Tick(ctx context.Context) {
	if w == nil || w.s == nil {
		return
	}
	cfg := w.s.watchdogConfig()
	if !cfg.Enabled {
		return
	}
	for range 4 {
		job, err := w.s.m.pg.ClaimWatchdogJob(ctx, w.now())
		if err != nil {
			log.Printf("[watchdog] 领取慢速判断失败: %v", err)
			return
		}
		if job == nil {
			return
		}
		w.runJob(ctx, job, cfg)
	}
}

func (w *watchdogService) runJob(ctx context.Context, job *db.WatchdogJob, cfg watchdogConfig) {
	t, ok := w.s.m.Task(job.TaskID)
	if !ok || t == nil {
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "任务已不存在", nil)
		return
	}
	if !w.s.watchdogTaskActive(t) {
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "任务已暂停、收尾或删除", nil)
		w.closeUnavailableIfEmpty(ctx, job.TaskID)
		return
	}
	snap := w.monitor.LookupRun(job.RunID)
	if snap == nil || snap.State != db.WorkerRunStateRunning || snap.CycleNo != job.CycleNo ||
		cycleStartChanged(job.CycleStart, snap.CycleStart) {
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "运行或周期已变化", nil)
		w.closeUnavailableIfEmpty(ctx, job.TaskID)
		return
	}
	if watchdogDecisionPending(snap.DecisionState) {
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "用户判断卡开放，跳过慢速判断", nil)
		w.closeUnavailableIfEmpty(ctx, job.TaskID)
		return
	}
	w.monitor.SetSlowPath(job.RunID, db.SlowPathRunning, "", "", nil, job.CycleNo)

	watchdogAgent, err := w.s.m.pg.GetAgentByKey(cfg.AgentKey)
	if err != nil || watchdogAgent == nil || !watchdogAgent.Enabled {
		w.unavailable(ctx, t, job, cfg, firstNonEmpty(err, fmt.Errorf("Agent %q 不存在或已停用", cfg.AgentKey)))
		return
	}
	prov, ok := w.providerFor(t, cfg.AgentKey)
	if !ok {
		w.unavailable(ctx, t, job, cfg, fmt.Errorf("Task %s 没有可用的 LLM 配置", t.ID))
		return
	}
	runTimeout := time.Duration(watchdogAgent.RunSecs) * time.Second
	if runTimeout <= 0 {
		runTimeout = 120 * time.Second
	}
	judge := agent.NewWatchdog(prov, cfg.AgentKey, w.s.m.dir, scopeWatchdogTools(w.s.watchdogReadTools(), t.ID),
		watchdogAgent.MaxTurns, runTimeout, (&taskLLMRuntime{s: w.s, taskID: t.ID, agentKey: cfg.AgentKey}).CompactionWindow())

	runCtx, cancel := context.WithTimeout(ctx, runTimeout+10*time.Second)
	report, runErr := judge.Analyze(runCtx, job.RunID, job.Snapshot)
	cancel()
	if runErr != nil {
		next := w.now().Add(cfg.AgentRetry)
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobFailed, runErr.Error(), &next)
		w.monitor.SetSlowPath(job.RunID, db.SlowPathFailed, "", "", nil, job.CycleNo)
		// 配置/供应商不可用时才出默认卡片；模型输出格式错误只是本次判断失败，
		// 不应把 Watchdog 整体标成不可用。
		if isWatchdogUnavailableError(runErr) {
			w.unavailable(ctx, t, job, cfg, runErr)
		} else {
			log.Printf("[watchdog] task %s 意图 #%d 慢速判断失败，将重试: %v", t.ID, job.IntentID, runErr)
		}
		return
	}
	_ = w.s.m.pg.CloseWatchdogUnavailable(ctx, t.ID)
	if !w.s.watchdogConfig().Enabled {
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "运行看护已关闭", nil)
		w.closeUnavailableIfEmpty(ctx, job.TaskID)
		return
	}
	if !w.s.watchdogTaskActive(t) {
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "任务已暂停、收尾或删除", nil)
		w.closeUnavailableIfEmpty(ctx, job.TaskID)
		return
	}

	// 模型运行期间周期可能已经推进或 worker 已结束；这种结果只能作为历史。
	current := w.monitor.LookupRun(job.RunID)
	if current == nil || current.State != db.WorkerRunStateRunning || current.CycleNo != job.CycleNo ||
		cycleStartChanged(job.CycleStart, current.CycleStart) {
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "判断完成时周期已变化", nil)
		w.closeUnavailableIfEmpty(ctx, job.TaskID)
		w.s.emitWatchdogActivity(t, "watchdog_report",
			fmt.Sprintf("意图 #%d 的慢速判断已过期，未执行", job.IntentID),
			report.Summary, watchdogAudit{Classification: report.Classification, CycleNo: job.CycleNo})
		return
	}
	if watchdogDecisionPending(current.DecisionState) {
		// The card owns the decision. A model result that arrived after the card
		// opened (or was already in flight) is historical, not a new termination.
		_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobStale, "用户判断卡开放，结果未执行", nil)
		w.monitor.SetSlowPath(job.RunID, db.SlowPathStale, report.Classification,
			report.Summary, report.Evidence, job.CycleNo)
		w.s.emitWatchdogActivity(t, "watchdog_report",
			fmt.Sprintf("意图 #%d 的慢速判断在用户判断卡开放期间完成，未执行", job.IntentID),
			report.Summary, watchdogAudit{Classification: report.Classification, CycleNo: job.CycleNo, Evidence: report.Evidence})
		w.closeUnavailableIfEmpty(ctx, job.TaskID)
		return
	}
	w.monitor.SetSlowPath(job.RunID, db.SlowPathDone, report.Classification,
		report.Summary, report.Evidence, job.CycleNo)
	// Re-read after SetSlowPath so a card opened by this judgment carries the
	// classification/summary/evidence, not the pre-judgment snapshot.
	current = w.monitor.LookupRun(job.RunID)
	w.s.emitWatchdogActivity(t, "watchdog_report",
		fmt.Sprintf("慢速判断（意图 #%d · C%d）：%s", job.IntentID, job.CycleNo, report.Summary),
		report.Reason, watchdogAudit{Classification: report.Classification, CycleNo: job.CycleNo, Evidence: report.Evidence})
	_ = w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobDone, "", nil)
	if current == nil {
		return
	}

	if report.Classification == agent.WatchdogAskUser && w.s.watchdog != nil && w.s.watchdog.fast != nil {
		// Slow Path 在周期中途要求用户判断：立即出卡，截止时间仍是当前周期边界。
		w.s.watchdog.fast.createAsk(ctx, t, *current, cfg, false)
	}
	if report.Classification == agent.WatchdogTerminate {
		// 慢速判断明确要求终止时立即执行，不等到 20 分钟边界；ask_user/continue
		// 交给周期表，provider_error 交给任务模型链。
		if w.s.watchdog == nil || w.s.watchdog.fast == nil {
			log.Printf("[watchdog] task %s 意图 #%d 终止请求缺少 Fast Path", t.ID, job.IntentID)
			return
		}
		reason := "慢速判断：" + report.Summary
		w.s.watchdog.fast.terminateAsync(ctx, *current, reason, "stopped")
	}
}

// closeUnavailableIfEmpty expires the task's unavailable card once no report is
// still waiting. A stale job is the last reference to that card; leaving it open
// would tell the user to retry a queue that no longer exists.
func (w *watchdogService) closeUnavailableIfEmpty(ctx context.Context, taskID string) {
	count, _, _, err := w.s.m.pg.WatchdogJobStats(ctx, taskID)
	if err != nil || count != 0 {
		return
	}
	if err := w.s.m.pg.CloseWatchdogUnavailable(ctx, taskID); err != nil {
		log.Printf("[watchdog] task %s 关闭不可用卡片失败: %v", taskID, err)
	}
}

// providerFor resolves the judge's provider through the same precedence as task
// agents: agent binding → task chain → global. A missing/exhausted source is an
// unavailable card, not a failed job that retries forever invisibly.
func (w *watchdogService) providerFor(t *Task, agentKey string) (llm.Provider, bool) {
	rt := &taskLLMRuntime{s: w.s, taskID: t.ID, agentKey: agentKey}
	sel, err := rt.current()
	if err != nil || sel.provider == nil {
		return nil, false
	}
	return sel.provider, true
}

func firstNonEmpty(values ...error) error {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func cycleStartChanged(jobStart *time.Time, runStart time.Time) bool {
	if jobStart == nil || runStart.IsZero() {
		return false
	}
	diff := jobStart.Sub(runStart)
	if diff < 0 {
		diff = -diff
	}
	return diff > 2*time.Second
}

func isWatchdogUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	// A wrong JSON contract is a failed judgment; retry it without opening the
	// configuration card, even if the model's prose happens to contain a word
	// such as "timeout".
	if errors.Is(err, agent.ErrWatchdogReport) {
		return false
	}
	var target *taskLLMError
	if errors.As(err, &target) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// The judge run has its own wall-clock cap. A provider outage (auth, quota,
	// rate limit, 5xx, network, timeout) is an unavailable Agent; a generic
	// model-output/tool error is not.
	return classifyProviderError(err) != ""
}

// unavailable opens/updates the task's single unavailable card. Counts come from
// the queue, so retries of the same report never inflate them.
func (w *watchdogService) unavailable(ctx context.Context, t *Task, job *db.WatchdogJob, cfg watchdogConfig, cause error) {
	next := w.now().Add(cfg.AgentRetry)
	if err := w.s.m.pg.FinishWatchdogJob(ctx, job.ID, db.WatchdogJobFailed, "Watchdog Agent 不可用", &next); err != nil {
		log.Printf("[watchdog] task %s 标记判断失败失败: %v", t.ID, err)
	}
	w.monitor.SetSlowPath(job.RunID, db.SlowPathFailed, "", "", nil, job.CycleNo)
	count, first, last, err := w.s.m.pg.WatchdogJobStats(ctx, t.ID)
	if err != nil {
		log.Printf("[watchdog] task %s 读取队列统计失败: %v", t.ID, err)
		return
	}
	before, _ := w.s.m.pg.OpenWatchdogUnavailable(ctx, t.ID)
	card, err := w.s.m.pg.CreateOrUpdateWatchdogUnavailable(ctx, t.ID,
		"Watchdog Agent 不可用，请检查 Watchdog Agent 配置", count, first, last, &next)
	if err != nil {
		log.Printf("[watchdog] task %s 更新不可用卡片失败: %v", t.ID, err)
		return
	}
	if err := w.s.m.pg.SupersedeOpenWatchdogAsksForTask(ctx, t.ID,
		"Watchdog Agent 不可用，已有判断卡关闭"); err != nil {
		log.Printf("[watchdog] task %s 关闭旧判断卡失败: %v", t.ID, err)
	}
	if before == nil && card != nil {
		w.s.emitWatchdogActivity(t, "watchdog_unavailable",
			"Watchdog Agent 不可用，已保留慢速判断队列", "系统会按配置间隔自动重试",
			watchdogAudit{RequestID: card.ID, AlertCount: count})
	}
	log.Printf("[watchdog] task %s Watchdog Agent 不可用(%v)，队列保留 %d 条，%s 后重试", t.ID, cause, count, cfg.AgentRetry)
}
