package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// PeerArbitration is one queued Watchdog judgment over a peer request. The
// registry remains in memory; the activity stream records the outcome.
type PeerArbitration struct {
	RequestID    string    `json:"request_id"`
	TaskID       string    `json:"task_id"`
	FromIntentID int64     `json:"from_intent_id"`
	ToIntentID   int64     `json:"to_intent_id"`
	FromRunID    string    `json:"from_run_id"`
	ToRunID      string    `json:"to_run_id"`
	FromWorker   string    `json:"from_worker,omitempty"`
	ToWorker     string    `json:"to_worker,omitempty"`
	Reason       string    `json:"reason"`
	EnqueuedAt   time.Time `json:"enqueued_at"`
}

// SetPeerArbitrationRunner installs the service queue consumed by the Watchdog
// runtime. nil disables arbitration (lightweight tests).
func (e *Engine) SetPeerArbitrationRunner(fn func(PeerArbitration) error) {
	e.peerMu.Lock()
	e.arbitrate = fn
	e.peerMu.Unlock()
}

// RequestPeerArbitration is the worker's request_arbitration tool. It accepts a
// rejected request, or an accepted request whose release confirmation is
// overdue. The actual judgment runs asynchronously in the Watchdog service.
func (e *Engine) RequestPeerArbitration(fromIntentID int64, requestID, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("reason 必填")
	}
	now := e.peerClock()

	fwTask, _, fromWorker, ok := e.peerWork(fromIntentID)
	if !ok {
		return fmt.Errorf("发起方意图 %d 没有运行中的 work", fromIntentID)
	}

	e.peerMu.Lock()
	r := e.peerRequests[requestID]
	if r == nil {
		e.peerMu.Unlock()
		return errPeerNotFound
	}
	if r.FromIntentID != fromIntentID {
		e.peerMu.Unlock()
		return fmt.Errorf("只有请求方可以申请仲裁")
	}
	if r.TaskID != fwTask {
		e.peerMu.Unlock()
		return fmt.Errorf("请求不属于当前任务")
	}
	switch r.Status {
	case peerRejected:
	case peerAccepted:
		if now.Sub(r.AnsweredAt) < peerReleaseTimeout {
			e.peerMu.Unlock()
			return fmt.Errorf("接收方已接受，释放确认尚未超过 %s", peerReleaseTimeout)
		}
	case peerCancelled, peerExpired, peerReleased:
		e.peerMu.Unlock()
		return fmt.Errorf("请求已 %s，不能仲裁", r.Status)
	default:
		e.peerMu.Unlock()
		return fmt.Errorf("请求当前状态为 %s，尚未到可仲裁阶段", r.Status)
	}
	if e.arbitrating[requestID] {
		e.peerMu.Unlock()
		return fmt.Errorf("该请求已经在仲裁中")
	}
	if last := e.peerLastArb[fromIntentID][r.ToIntentID]; !last.IsZero() && now.Sub(last) < peerArbitrationCooldown {
		left := peerArbitrationCooldown - now.Sub(last)
		e.peerMu.Unlock()
		return fmt.Errorf("仲裁冷却中，%s 后可再次申请", left.Round(time.Second))
	}
	_, toRun, toWorker, ok := e.peerWork(r.ToIntentID)
	if !ok {
		e.peerMu.Unlock()
		return fmt.Errorf("接收方意图 %d 已经结束，不能仲裁", r.ToIntentID)
	}
	runner := e.arbitrate
	if runner == nil {
		e.peerMu.Unlock()
		return fmt.Errorf("Watchdog 仲裁服务未启动")
	}
	req := PeerArbitration{
		RequestID: requestID, TaskID: r.TaskID,
		FromIntentID: r.FromIntentID, ToIntentID: r.ToIntentID,
		FromRunID: r.FromRunID, ToRunID: toRun,
		FromWorker: fromWorker, ToWorker: toWorker,
		Reason: reason, EnqueuedAt: now,
	}
	e.arbitrating[requestID] = true
	e.peerMu.Unlock()

	if err := runner(req); err != nil {
		e.peerMu.Lock()
		delete(e.arbitrating, requestID)
		e.peerMu.Unlock()
		return err
	}
	e.peerMu.Lock()
	if e.peerLastArb[fromIntentID] == nil {
		e.peerLastArb[fromIntentID] = map[int64]time.Time{}
	}
	e.peerLastArb[fromIntentID][r.ToIntentID] = now
	e.peerMu.Unlock()
	e.peerArbitrationActivity(r.TaskID, req, peerKindArbitration, "requested",
		fmt.Sprintf("意图 #%d 请求 Watchdog 仲裁（%s）", fromIntentID, requestID), reason)
	return nil
}

// ApplyPeerArbitration executes the final decision. target validation is
// mandatory: an arbitrator can never affect a different intent.
func (e *Engine) ApplyPeerArbitration(req PeerArbitration, decision, reason string) error {
	switch decision {
	case "keep", "release", "terminate":
	default:
		return fmt.Errorf("未知仲裁 decision %q", decision)
	}
	e.peerMu.Lock()
	r := e.peerRequests[req.RequestID]
	if r == nil {
		e.peerMu.Unlock()
		return errPeerNotFound
	}
	if r.FromIntentID != req.FromIntentID || r.ToIntentID != req.ToIntentID || r.TaskID != req.TaskID {
		e.peerMu.Unlock()
		return fmt.Errorf("仲裁目标与请求不一致")
	}
	delete(e.arbitrating, req.RequestID)
	if r.Status == peerReleased || r.Status == peerCancelled || r.Status == peerExpired {
		// The request completed (or expired) while the judgment was running.
		// Never act on the worker after the fact; keep the audit only.
		copy := *r
		e.peerMu.Unlock()
		e.peerArbitrationActivity(req.TaskID, req, peerKindArbitration, "stale",
			"Watchdog 仲裁结果已过期：请求已结束", reason)
		e.enqueuePeerMessage(copy.FromIntentID, peerKindArbitration, &copy)
		return nil
	}
	r.ArbitrationDecision = decision
	r.ArbitrationReason = reason
	if decision == "release" && r.Status == peerRejected {
		// The arbitrator overrides a rejection: make the receiver able to
		// confirm the release with the same request id. The rejection removed
		// this request from peerByIntent, so re-add it; otherwise a later run
		// finish cannot expire the outstanding accepted request.
		r.Status = peerAccepted
		r.Answer = "accepted"
		r.AnswerReason = "Watchdog 仲裁要求释放"
	}
	if decision == "release" {
		e.peerIndexAddLocked(r)
	}
	copy := *r
	e.peerMu.Unlock()

	e.peerArbitrationActivity(req.TaskID, req, peerKindArbitration, decision, "Watchdog 仲裁结果："+decision, reason)
	switch decision {
	case "keep":
		e.enqueuePeerMessage(r.FromIntentID, peerKindArbitration, &copy)
		e.enqueuePeerMessage(r.ToIntentID, peerKindArbitration, &copy)
	case "release":
		text := fmt.Sprintf("Watchdog 仲裁决定：请释放资源，并在实际释放后调用 release_request（request_id=%s）。", req.RequestID)
		if err := e.SteerWorkFrom(r.ToIntentID, "watchdog", text); err != nil {
			log.Printf("[watchdog] 仲裁释放指令未投递 request=%s: %v", req.RequestID, err)
		}
		e.enqueuePeerMessage(r.FromIntentID, peerKindArbitration, &copy)
	case "terminate":
		var snap *RunSnapshot
		if e.monitor != nil {
			snap = e.monitor.Lookup(r.ToIntentID)
		}
		if snap == nil || snap.State != db.WorkerRunStateRunning ||
			(req.ToRunID != "" && snap.RunID != req.ToRunID) {
			// Receiver already ended (or was re-run): audit only, never touch a
			// newer run that the arbitration was not about.
			e.enqueuePeerMessage(r.FromIntentID, peerKindArbitration, &copy)
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(),
			watchdogSettlementWait+workControlWaitTimeout+5*time.Second)
		defer cancel()
		if _, err := e.TerminateWorkForCycle(ctx, snap.IntentID, snap.RunID, reason, "stopped", snap.CycleNo); err != nil {
			log.Printf("[watchdog] 仲裁终止未生效 request=%s intent=%d: %v", req.RequestID, snap.IntentID, err)
		}
		e.enqueuePeerMessage(r.FromIntentID, peerKindArbitration, &copy)
	}
	return nil
}

func (e *Engine) peerArbitrationActivity(taskID string, req PeerArbitration, kind, decision, summary, reason string) {
	if e == nil || e.m == nil {
		return
	}
	t, ok := e.m.Task(taskID)
	if !ok || t == nil {
		return
	}
	nodeID := req.ToIntentID
	cooldown := 0
	if decision == "requested" {
		cooldown = int(peerArbitrationCooldown / time.Second)
	}
	e.emitActivity(t, db.Activity{
		Worker: "system", Kind: kind, NodeID: &nodeID,
		Summary: summary, Detail: reason,
		Metadata: marshalPeerMetadata(peerAudit{
			RequestID: req.RequestID, FromIntentID: req.FromIntentID, ToIntentID: req.ToIntentID,
			FromWorker: req.FromWorker, ToWorker: req.ToWorker,
			Decision: decision, Reason: reason, Status: decision, CooldownSec: cooldown,
		}),
	})
}

// EnqueueArbitration is the service-side queue. It is non-blocking: a full
// queue tells the requester to keep its current state instead of blocking a
// worker tool call.
func (w *watchdogService) EnqueueArbitration(req PeerArbitration) error {
	if w == nil {
		return fmt.Errorf("Watchdog 运行时未启动")
	}
	select {
	case w.arbitrationCh <- req:
		return nil
	default:
		return fmt.Errorf("Watchdog 仲裁队列已满，请稍后重试")
	}
}

// runPeerArbitration builds a two-sided evidence snapshot, asks the read-only
// judge, and applies its decision through the same Engine paths as Slow Path.
func (w *watchdogService) runPeerArbitration(ctx context.Context, req PeerArbitration) {
	if w == nil || w.s == nil || w.s.engine == nil {
		return
	}
	fail := func(format string, args ...any) {
		reason := fmt.Sprintf(format, args...)
		log.Printf("[watchdog] 仲裁失败 request=%s: %s", req.RequestID, reason)
		w.s.engine.peerArbitrationActivity(req.TaskID, req, peerKindArbitrationFailed, "failed", "Watchdog 仲裁失败", reason)
		w.s.engine.peerMu.Lock()
		delete(w.s.engine.arbitrating, req.RequestID)
		w.s.engine.peerMu.Unlock()
		w.s.engine.enqueuePeerMessage(req.FromIntentID, peerKindArbitration, &peerRequest{
			RequestID: req.RequestID, TaskID: req.TaskID,
			FromIntentID: req.FromIntentID, ToIntentID: req.ToIntentID,
			ArbitrationDecision: "failed", ArbitrationReason: reason,
		})
	}
	t, ok := w.s.m.Task(req.TaskID)
	if !ok || t == nil {
		fail("任务已不存在")
		return
	}
	if !w.s.watchdogTaskActive(t) {
		fail("任务已暂停、收尾或删除")
		return
	}
	fromSnap := w.monitor.LookupRun(req.FromRunID)
	toSnap := w.monitor.LookupRun(req.ToRunID)
	if fromSnap == nil || fromSnap.State != db.WorkerRunStateRunning {
		fail("请求方已结束")
		return
	}
	if toSnap == nil || toSnap.State != db.WorkerRunStateRunning {
		fail("接收方已结束")
		return
	}
	fromBody, err := w.s.buildWatchdogSnapshot(t, *fromSnap)
	if err != nil {
		fail("读取请求方证据失败: %v", err)
		return
	}
	toBody, err := w.s.buildWatchdogSnapshot(t, *toSnap)
	if err != nil {
		fail("读取接收方证据失败: %v", err)
		return
	}
	cfg := w.s.watchdogConfig()
	watchdogAgent, err := w.s.m.pg.GetAgentByKey(cfg.AgentKey)
	if err != nil || watchdogAgent == nil || !watchdogAgent.Enabled {
		fail("Watchdog Agent %q 不存在或已停用", cfg.AgentKey)
		return
	}
	prov, ok := w.providerFor(t, cfg.AgentKey)
	if !ok {
		fail("任务没有可用的 LLM 配置")
		return
	}
	runTimeout := time.Duration(watchdogAgent.RunSecs) * time.Second
	if runTimeout <= 0 {
		runTimeout = 120 * time.Second
	}
	judge := agent.NewWatchdogWithPrompt(prov, agent.ArbitrationSystemPrompt, w.s.m.dir,
		scopeWatchdogTools(w.s.watchdogReadTools(), t.ID),
		watchdogAgent.MaxTurns, runTimeout,
		(&taskLLMRuntime{s: w.s, taskID: t.ID, agentKey: cfg.AgentKey}).CompactionWindow())

	snapshot, _ := json.Marshal(map[string]any{
		"task_id": req.TaskID,
		"request": map[string]any{
			"request_id": req.RequestID, "from_intent_id": req.FromIntentID,
			"to_intent_id": req.ToIntentID, "reason": req.Reason,
		},
		"from": json.RawMessage(fromBody),
		"to":   json.RawMessage(toBody),
	})
	report, err := judge.AnalyzeArbitration(ctx, req.RequestID, snapshot)
	if err != nil {
		fail("%v", err)
		return
	}
	if report.TargetIntentID != req.ToIntentID {
		fail("仲裁目标 intent %d 与接收方 %d 不一致", report.TargetIntentID, req.ToIntentID)
		return
	}
	if err := w.s.engine.ApplyPeerArbitration(req, report.Decision, report.Reason); err != nil {
		fail("%v", err)
	}
}
