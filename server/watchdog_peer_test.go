package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

type peerTestRig struct {
	m      *Manager
	task   *Task
	s      *Server
	e      *Engine
	a, b   int64
	second *db.Node
	now    time.Time
}

func newPeerTestRig(t *testing.T) *peerTestRig {
	t.Helper()
	m, task, first := testWatchdogTask(t)
	r := &peerTestRig{m: m, task: task, s: newAdmissionTestServer(m, nil), a: first.ID, now: time.Now()}
	r.e = r.s.engine
	r.e.now = func() time.Time { return r.now }
	id, err := task.Store.AddIntent(map[string]any{"summary": "second peer intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentState(id, "running"); err != nil {
		t.Fatal(err)
	}
	second, err := task.Store.GetNode(id)
	if err != nil || second == nil {
		t.Fatalf("second intent=%+v err=%v", second, err)
	}
	r.b, r.second = id, second
	_, cancelA := context.WithCancelCause(context.Background())
	_, cancelB := context.WithCancelCause(context.Background())
	r.e.registerWorkRunFull(r.a, "run-a", task.ID, "work#1", cancelA, nil)
	r.e.registerWorkRunFull(r.b, "run-b", task.ID, "work#2", cancelB, nil)
	t.Cleanup(func() {
		_, doneA := r.e.detachWork(r.a)
		doneA(nil)
		_, doneB := r.e.detachWork(r.b)
		doneB(nil)
	})
	return r
}

func (r *peerTestRig) advance(d time.Duration) { r.now = r.now.Add(d) }

func TestPeerRequestOnlyRunningTarget(t *testing.T) {
	r := newPeerTestRig(t)
	if _, err := r.e.CreatePeerRequest(r.a, 999999, "release_container_slot", "x"); err == nil {
		t.Fatal("request to a non-running target was accepted")
	}
	if _, err := r.e.CreatePeerRequest(r.a, r.a, "release_container_slot", "x"); err == nil {
		t.Fatal("self request was accepted")
	}
	if _, err := r.e.CreatePeerRequest(r.a, r.b, "bogus", "x"); err == nil {
		t.Fatal("unknown request type was accepted")
	}
}

func TestPeerRequestBatchInjectionAndSystemPriority(t *testing.T) {
	r := newPeerTestRig(t)
	if err := r.e.SteerWorkFrom(r.b, "planner", "先看规划者纠偏"); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for range 3 {
		id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	msg, ok := r.e.drainSteer(r.b)
	if !ok || msg.Source != "planner" || !strings.Contains(msg.Text, "规划者纠偏") {
		t.Fatalf("system steer was not first: %+v ok=%v", msg, ok)
	}
	msgs := r.e.drainPeer(r.b, peerMaxBatch)
	if len(msgs) != 3 {
		t.Fatalf("peer batch size=%d, want 3", len(msgs))
	}
	for i, m := range msgs {
		if m.RequestID != ids[i] || !strings.Contains(m.Text, "answer_request") {
			t.Fatalf("peer message %d=%+v, want FIFO %s", i, m, ids[i])
		}
	}
	if got := r.e.drainPeer(r.b, peerMaxBatch); len(got) != 0 {
		t.Fatalf("queue not drained: %+v", got)
	}
}

func TestPeerRequestCancelBeforeAndAfterDelivery(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.e.CancelPeerRequest(r.a, id); err != nil {
		t.Fatal(err)
	}
	if got := r.e.drainPeer(r.b, peerMaxBatch); len(got) != 0 {
		t.Fatalf("cancelled pending request was delivered: %+v", got)
	}
	if err := r.e.CancelPeerRequest(r.a, id); err != nil {
		t.Fatalf("cancel is not idempotent: %v", err)
	}
	if err := r.e.AnswerPeerRequest(r.b, id, "accepted", ""); !errors.Is(err, errPeerTooLate) {
		t.Fatalf("answer after cancel err=%v, want too late", err)
	}

	id2, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.e.drainPeer(r.b, peerMaxBatch); len(got) != 1 {
		t.Fatalf("delivered request count=%d", len(got))
	}
	if err := r.e.CancelPeerRequest(r.a, id2); err != nil {
		t.Fatal(err)
	}
	got := r.e.drainPeer(r.b, peerMaxBatch)
	if len(got) != 1 || got[0].Kind != peerKindCancel || !strings.Contains(got[0].Text, string(peerCancelled)) {
		t.Fatalf("receiver did not get cancel notice: %+v", got)
	}
	if err := r.e.AnswerPeerRequest(r.b, id2, "accepted", ""); !errors.Is(err, errPeerTooLate) {
		t.Fatalf("answer after delivered cancel err=%v, want too late", err)
	}
}

func TestPeerRequestAnswerReleaseAndTooLate(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "accepted", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := r.e.CancelPeerRequest(r.a, id); !errors.Is(err, errPeerTooLate) {
		t.Fatalf("cancel after accept err=%v, want too late", err)
	}
	accepted := r.e.drainPeer(r.a, peerMaxBatch)
	if len(accepted) != 1 || !strings.Contains(accepted[0].Text, "accepted") {
		t.Fatalf("requester did not get accepted answer: %+v", accepted)
	}
	if err := r.e.ReleasePeerRequest(r.b, id); err != nil {
		t.Fatal(err)
	}
	released := r.e.drainPeer(r.a, peerMaxBatch)
	if len(released) != 1 || !strings.Contains(released[0].Text, "released") {
		t.Fatalf("requester did not get released: %+v", released)
	}
	if err := r.e.ReleasePeerRequest(r.b, id); err != nil {
		t.Fatalf("release is not idempotent: %v", err)
	}
}

func TestPeerRequestRejectCooldownAndLimits(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "rejected", "no"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "again"); err == nil {
		t.Fatal("request inside reject cooldown was accepted")
	}
	r.advance(peerRejectCooldown + time.Second)
	if _, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "after cooldown"); err != nil {
		t.Fatalf("request after cooldown failed: %v", err)
	}

	// Pair cap: three more open requests (the cooldown request is open too).
	for i := range peerMaxPendingPerPair - 1 {
		if _, err := r.e.CreatePeerRequest(r.a, r.b, "request_container_slot", "more"); err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}
	if _, err := r.e.CreatePeerRequest(r.a, r.b, "request_container_slot", "over cap"); err == nil {
		t.Fatal("pair pending cap was not enforced")
	}
}

func TestPeerRequestExpiresWhenHolderFinishes(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.ExpirePeerRequestsForIntent(r.b, "run-b", "holder_finished")
	if got := r.e.peerRequests[id]; got == nil || got.Status != peerExpired {
		t.Fatalf("request status=%v, want expired", got)
	}
	notices := r.e.drainPeer(r.a, peerMaxBatch)
	if len(notices) != 1 || notices[0].Kind != peerKindCancel || !strings.Contains(notices[0].Text, "expired") {
		t.Fatalf("requester expiry notice=%+v", notices)
	}
}

func TestPeerArbitrationRequestAndKeep(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "rejected", "busy"); err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.a, peerMaxBatch) // consume rejected answer
	var got PeerArbitration
	r.e.SetPeerArbitrationRunner(func(req PeerArbitration) error {
		got = req
		return nil
	})
	if err := r.e.RequestPeerArbitration(r.a, id, "request blocked"); err != nil {
		t.Fatal(err)
	}
	if got.RequestID != id || got.FromIntentID != r.a || got.ToIntentID != r.b {
		t.Fatalf("arbitration request=%+v", got)
	}
	if err := r.e.RequestPeerArbitration(r.a, id, "again"); err == nil {
		t.Fatal("duplicate arbitration request was accepted")
	}
	if err := r.e.ApplyPeerArbitration(got, "keep", "both progressing"); err != nil {
		t.Fatal(err)
	}
	notices := r.e.drainPeer(r.a, peerMaxBatch)
	if len(notices) != 1 || notices[0].Kind != peerKindArbitration || !strings.Contains(notices[0].Text, "keep") {
		t.Fatalf("requester arbitration notice=%+v", notices)
	}
}

func TestPeerArbitrationRequiresReleaseTimeout(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "accepted", "ok"); err != nil {
		t.Fatal(err)
	}
	r.e.SetPeerArbitrationRunner(func(PeerArbitration) error { return nil })
	if err := r.e.RequestPeerArbitration(r.a, id, "waiting"); err == nil {
		t.Fatal("arbitration before release timeout was accepted")
	}
	r.advance(peerReleaseTimeout + time.Second)
	if err := r.e.RequestPeerArbitration(r.a, id, "release overdue"); err != nil {
		t.Fatalf("arbitration after release timeout failed: %v", err)
	}
}

func TestPeerArbitrationReleaseSendsSteer(t *testing.T) {
	r := newPeerTestRig(t)
	monitor := NewRunMonitor(r.m.pg, func() time.Time { return r.now })
	r.s.watchdog = &watchdogRuntime{s: r.s, monitor: monitor}
	monitor.SetFinishHook(r.s.watchdogOnRunFinish)
	monitor.Register(r.task.ID, r.b, "run-b", "work#2")
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "rejected", "busy"); err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.a, peerMaxBatch)
	var got PeerArbitration
	r.e.SetPeerArbitrationRunner(func(req PeerArbitration) error { got = req; return nil })
	if err := r.e.RequestPeerArbitration(r.a, id, "blocked"); err != nil {
		t.Fatal(err)
	}
	if err := r.e.ApplyPeerArbitration(got, "release", "receiver idle"); err != nil {
		t.Fatal(err)
	}
	steer, ok := r.e.drainSteer(r.b)
	if !ok || !strings.Contains(steer.Text, "release_request") {
		t.Fatalf("receiver did not get release steer: %+v ok=%v", steer, ok)
	}
	if got := r.e.peerRequests[id]; got == nil || got.Status != peerAccepted {
		t.Fatalf("released-by-arbitration request status=%v, want accepted", got)
	}
	r.e.peerMu.Lock()
	_, indexed := r.e.peerByIntent[r.b][id]
	r.e.peerMu.Unlock()
	if !indexed {
		t.Fatal("released-by-arbitration request was not re-added to the holder index")
	}

	// The receiver ending its run must expire the arbitration-promoted request.
	monitor.Finish("run-b", db.WorkerRunStateFinished)
	if got := r.e.peerRequests[id]; got == nil || got.Status != peerExpired {
		t.Fatalf("arbitration-accepted request did not expire with finished holder: %v", got)
	}
}

func TestPeerArbitrationTerminateUsesEngine(t *testing.T) {
	r := newPeerTestRig(t)
	monitor := NewRunMonitor(r.m.pg, func() time.Time { return r.now })
	r.s.engine.SetRunMonitor(monitor)
	r.s.watchdog = &watchdogRuntime{s: r.s, monitor: monitor}
	monitor.Register(r.task.ID, r.b, "run-b", "work#2")
	ctxB, cancelB := context.WithCancelCause(context.Background())
	r.e.registerWorkRunFull(r.b, "run-b", r.task.ID, "work#2", cancelB, nil)
	go func() {
		<-ctxB.Done()
		cause, _ := context.Cause(ctxB).(*agent.AbortCause)
		if cause != nil {
			r.e.settleWatchdogTermination(r.task, "work#2", r.second, "run-b", cause.Text, cause.TerminalState)
		}
		_, done := r.e.detachWork(r.b)
		done(nil)
	}()

	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "rejected", "busy"); err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.a, peerMaxBatch)
	var got PeerArbitration
	r.e.SetPeerArbitrationRunner(func(req PeerArbitration) error { got = req; return nil })
	if err := r.e.RequestPeerArbitration(r.a, id, "blocked"); err != nil {
		t.Fatal(err)
	}
	if err := r.e.ApplyPeerArbitration(got, "terminate", "receiver stalled"); err != nil {
		t.Fatal(err)
	}
	node, err := r.task.Store.GetNode(r.b)
	if err != nil || node == nil || node.State != "stopped" {
		t.Fatalf("receiver state=%+v err=%v, want stopped", node, err)
	}
}

func TestPeerArbitrationQueueFull(t *testing.T) {
	r := newPeerTestRig(t)
	svc := newWatchdogService(r.s, NewRunMonitor(r.m.pg, nil))
	for i := 0; i < cap(svc.arbitrationCh); i++ {
		svc.arbitrationCh <- PeerArbitration{RequestID: "x"}
	}
	if err := svc.EnqueueArbitration(PeerArbitration{RequestID: "overflow"}); err == nil {
		t.Fatal("full arbitration queue accepted work")
	}
}

func TestRunFinishClosesControlRowsOnce(t *testing.T) {
	r := newPeerTestRig(t)
	monitor := NewRunMonitor(r.m.pg, func() time.Time { return r.now })
	r.s.watchdog = &watchdogRuntime{s: r.s, monitor: monitor}
	monitor.SetFinishHook(r.s.watchdogOnRunFinish)
	monitor.Register(r.task.ID, r.a, "run-a", "work#1")
	intentID := r.a
	if _, _, err := r.m.pg.CreateWatchdogAsk(t.Context(), &db.WatchdogRequest{
		TaskID: r.task.ID, IntentID: &intentID, RunID: "run-a", CycleNo: 0, Question: "q",
	}); err != nil {
		t.Fatal(err)
	}
	start := r.now
	if _, _, err := r.m.pg.EnqueueWatchdogJob(t.Context(), &db.WatchdogJob{
		TaskID: r.task.ID, IntentID: r.a, RunID: "run-a", CycleNo: 0, CycleStart: &start,
	}); err != nil {
		t.Fatal(err)
	}
	peerID, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}

	monitor.Finish("run-a", db.WorkerRunStateFinished)
	if card, err := r.m.pg.OpenWatchdogAsk(t.Context(), "run-a", 0); err != nil || card != nil {
		t.Fatalf("open ask after finish=%+v err=%v", card, err)
	}
	if count, _, _, err := r.m.pg.WatchdogJobStats(t.Context(), r.task.ID); err != nil || count != 0 {
		t.Fatalf("job count after finish=%d err=%v", count, err)
	}
	if got := r.e.peerRequests[peerID]; got == nil || got.Status != peerExpired {
		t.Fatalf("peer status after finish=%v", got)
	}
	countFinish := func() int {
		acts, _, err := r.task.Store.ActivityList(nil, 0, 200)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, a := range acts {
			if a.Kind == "watchdog_run_finished" {
				n++
			}
		}
		return n
	}
	if got := countFinish(); got != 1 {
		t.Fatalf("run_finished activities=%d, want 1", got)
	}
	monitor.Finish("run-a", db.WorkerRunStateFinished)
	if got := countFinish(); got != 1 {
		t.Fatalf("run_finished activities after repeat=%d, want 1", got)
	}
}

func TestPeerArbitrationRejectsDeadTarget(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "rejected", "busy"); err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.a, peerMaxBatch)
	r.e.workMu.Lock()
	delete(r.e.work, r.b)
	r.e.workMu.Unlock()
	r.e.SetPeerArbitrationRunner(func(PeerArbitration) error { return nil })
	err = r.e.RequestPeerArbitration(r.a, id, "blocked")
	if err == nil || !strings.Contains(err.Error(), "接收方") {
		t.Fatalf("dead-target arbitration err=%v", err)
	}
}

func TestPeerArbitrationRejectsWrongTarget(t *testing.T) {
	r := newPeerTestRig(t)
	id, err := r.e.CreatePeerRequest(r.a, r.b, "release_container_slot", "need slot")
	if err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.b, peerMaxBatch)
	if err := r.e.AnswerPeerRequest(r.b, id, "rejected", "busy"); err != nil {
		t.Fatal(err)
	}
	r.e.drainPeer(r.a, peerMaxBatch)
	req := PeerArbitration{
		RequestID: id, TaskID: r.task.ID,
		FromIntentID: r.a, ToIntentID: r.a, // wrong target
		FromRunID: "run-a", ToRunID: "run-a", Reason: "fixture",
	}
	if err := r.e.ApplyPeerArbitration(req, "keep", "wrong target"); err == nil {
		t.Fatal("arbitration with a mismatched target was accepted")
	}
}

func TestPeerArbitrationFailureWritesAudit(t *testing.T) {
	r := newPeerTestRig(t)
	monitor := NewRunMonitor(r.m.pg, func() time.Time { return r.now })
	monitor.Register(r.task.ID, r.a, "run-a", "work#1")
	monitor.Register(r.task.ID, r.b, "run-b", "work#2")
	svc := newWatchdogService(r.s, monitor)
	restoreSettings(t, r.m, []string{settingWatchdogAgentKey})
	if err := r.m.pg.SetSetting(settingWatchdogAgentKey, "missing-watchdog"); err != nil {
		t.Fatal(err)
	}
	req := PeerArbitration{
		RequestID: "arb-failure", TaskID: r.task.ID,
		FromIntentID: r.a, ToIntentID: r.b, FromRunID: "run-a", ToRunID: "run-b",
		Reason: "fixture", EnqueuedAt: r.now,
	}
	svc.runPeerArbitration(t.Context(), req)
	acts, _, err := r.task.Store.ActivityList(nil, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range acts {
		if a.Kind == peerKindArbitrationFailed {
			found = true
		}
	}
	if !found {
		t.Fatal("failed arbitration did not write peer_arbitration_failed")
	}
}

func TestRunFinishTaskClosesMultipleRuns(t *testing.T) {
	r := newPeerTestRig(t)
	monitor := NewRunMonitor(r.m.pg, func() time.Time { return r.now })
	r.s.watchdog = &watchdogRuntime{s: r.s, monitor: monitor}
	monitor.SetFinishHook(r.s.watchdogOnRunFinish)
	for _, run := range []struct {
		intent int64
		id     string
	}{{r.a, "run-a"}, {r.b, "run-b"}} {
		monitor.Register(r.task.ID, run.intent, run.id, "work")
		intentID := run.intent
		if _, _, err := r.m.pg.CreateWatchdogAsk(t.Context(), &db.WatchdogRequest{
			TaskID: r.task.ID, IntentID: &intentID, RunID: run.id, CycleNo: 0, Question: "q",
		}); err != nil {
			t.Fatal(err)
		}
		start := r.now
		if _, _, err := r.m.pg.EnqueueWatchdogJob(t.Context(), &db.WatchdogJob{
			TaskID: r.task.ID, IntentID: run.intent, RunID: run.id, CycleNo: 0, CycleStart: &start,
		}); err != nil {
			t.Fatal(err)
		}
	}
	monitor.FinishTask(r.task.ID, db.WorkerRunStateAbandoned)
	for _, runID := range []string{"run-a", "run-b"} {
		if card, err := r.m.pg.OpenWatchdogAsk(t.Context(), runID, 0); err != nil || card != nil {
			t.Fatalf("open ask after FinishTask run=%s: %+v err=%v", runID, card, err)
		}
		row, err := r.m.pg.WorkerRunByID(t.Context(), runID)
		if err != nil || row == nil || row.State != db.WorkerRunStateAbandoned {
			t.Fatalf("finished row run=%s row=%+v err=%v", runID, row, err)
		}
	}
	if count, _, _, err := r.m.pg.WatchdogJobStats(t.Context(), r.task.ID); err != nil || count != 0 {
		t.Fatalf("job count after FinishTask=%d err=%v", count, err)
	}
	acts, _, err := r.task.Store.ActivityList(nil, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range acts {
		if a.Kind == "watchdog_run_finished" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("run_finished activities=%d, want 2", n)
	}
	monitor.FinishTask(r.task.ID, db.WorkerRunStateAbandoned)
	acts, _, err = r.task.Store.ActivityList(nil, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	n = 0
	for _, a := range acts {
		if a.Kind == "watchdog_run_finished" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("run_finished activities after repeated FinishTask=%d, want 2", n)
	}
}
