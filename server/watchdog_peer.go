package server

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Worker-to-worker resource requests. The registry is deliberately in-memory:
// these are short-lived coordination messages between two live runs in this
// process. The exploration activity stream is the durable audit trail; there is
// no resource-ownership table and no cross-process hand-off.
type peerRequestStatus string

const (
	peerPending   peerRequestStatus = "pending"
	peerDelivered peerRequestStatus = "delivered"
	peerAccepted  peerRequestStatus = "accepted"
	peerRejected  peerRequestStatus = "rejected"
	peerReleased  peerRequestStatus = "released"
	peerCancelled peerRequestStatus = "cancelled"
	peerExpired   peerRequestStatus = "expired"
)

// Peer steer message kinds. System course-corrections use an empty Kind.
const (
	peerKindRequest           = "peer_request"
	peerKindAnswer            = "peer_answer"
	peerKindCancel            = "peer_cancel"
	peerKindArbitration       = "peer_arbitration"
	peerKindArbitrationFailed = "peer_arbitration_failed"
	peerKindExpired           = "peer_request_expired"
)

const (
	peerMaxPendingPerPair   = 4
	peerMaxPendingPerTask   = 32
	peerRequestTTL          = 10 * time.Minute
	peerReleaseTimeout      = 10 * time.Minute
	peerRejectCooldown      = 10 * time.Minute
	peerArbitrationCooldown = 20 * time.Minute
	peerMaxBatch            = 8
)

var (
	errPeerNotFound = errors.New("peer request not found")
	errPeerTooLate  = errors.New("peer request already answered or finished")
)

func validPeerRequestType(v string) bool {
	switch v {
	case "release_container_slot", "request_container_slot":
		return true
	}
	return false
}

func peerOpen(s peerRequestStatus) bool {
	return s == peerPending || s == peerDelivered || s == peerAccepted
}

type peerRequest struct {
	RequestID    string
	TaskID       string
	FromIntentID int64
	ToIntentID   int64
	FromRunID    string
	ToRunID      string
	FromWorker   string
	ToWorker     string
	RequestType  string
	Reason       string
	Status       peerRequestStatus
	CreatedAt    time.Time
	DeliveredAt  time.Time
	AnsweredAt   time.Time
	ReleaseAt    time.Time
	Answer       string
	AnswerReason string
	// ArbitrationDecision/Reason are set by the Watchdog arbitrator.
	ArbitrationDecision string
	ArbitrationReason   string
}

func (r *peerRequest) open() bool { return peerOpen(r.Status) }

func (e *Engine) peerClock() time.Time { return e.now() }

// peerWork returns the live work identity for an intent.
func (e *Engine) peerWork(intentID int64) (taskID, runID, worker string, ok bool) {
	e.workMu.Lock()
	defer e.workMu.Unlock()
	run := e.work[intentID]
	if run == nil {
		return "", "", "", false
	}
	return run.taskID, run.runID, run.workerName, true
}

func (e *Engine) peerIndexAddLocked(r *peerRequest) {
	for _, id := range []int64{r.FromIntentID, r.ToIntentID} {
		if e.peerByIntent[id] == nil {
			e.peerByIntent[id] = map[string]struct{}{}
		}
		e.peerByIntent[id][r.RequestID] = struct{}{}
	}
}

func (e *Engine) peerIndexRemoveLocked(r *peerRequest) {
	for _, id := range []int64{r.FromIntentID, r.ToIntentID} {
		if set := e.peerByIntent[id]; set != nil {
			delete(set, r.RequestID)
			if len(set) == 0 {
				delete(e.peerByIntent, id)
			}
		}
	}
}

func (e *Engine) finishPeerLocked(r *peerRequest, status peerRequestStatus) {
	r.Status = status
	e.peerIndexRemoveLocked(r)
}

// CreatePeerRequest implements agent.PeerOps. It validates both ends, the
// cooldown and the pending caps, then queues one notification for the target.
func (e *Engine) CreatePeerRequest(fromIntentID, toIntentID int64, requestType, reason string) (string, error) {
	if fromIntentID <= 0 || toIntentID <= 0 {
		return "", fmt.Errorf("from_intent_id 和 to_intent_id 必填")
	}
	if fromIntentID == toIntentID {
		return "", fmt.Errorf("不能向自己发起资源请求")
	}
	if !validPeerRequestType(requestType) {
		return "", fmt.Errorf("不支持的 request_type %q（可用 release_container_slot / request_container_slot）", requestType)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", fmt.Errorf("reason 必填")
	}
	fromTask, fromRun, fromWorker, ok := e.peerWork(fromIntentID)
	if !ok {
		return "", fmt.Errorf("发起方意图 %d 没有运行中的 work", fromIntentID)
	}
	toTask, toRun, toWorker, ok := e.peerWork(toIntentID)
	if !ok {
		return "", fmt.Errorf("目标意图 %d 没有运行中的 work", toIntentID)
	}
	if fromTask == "" || fromTask != toTask {
		return "", fmt.Errorf("资源请求只能在同一任务的两个 Worker 之间发起")
	}

	now := e.peerClock()
	e.peerMu.Lock()
	if last := e.peerLastAsk[fromIntentID][toIntentID]; !last.IsZero() && now.Sub(last) < peerRejectCooldown {
		left := peerRejectCooldown - now.Sub(last)
		e.peerMu.Unlock()
		return "", fmt.Errorf("接收方刚拒绝过请求，%s 后可再次请求", left.Round(time.Second))
	}
	pair, task := 0, 0
	for _, r := range e.peerRequests {
		if !r.open() {
			continue
		}
		if r.TaskID == fromTask {
			task++
		}
		if (r.FromIntentID == fromIntentID && r.ToIntentID == toIntentID) ||
			(r.FromIntentID == toIntentID && r.ToIntentID == fromIntentID) {
			pair++
		}
	}
	if pair >= peerMaxPendingPerPair {
		e.peerMu.Unlock()
		return "", fmt.Errorf("这两条 Worker 之间已有 %d 个未完成请求，达到上限 %d", pair, peerMaxPendingPerPair)
	}
	if task >= peerMaxPendingPerTask {
		e.peerMu.Unlock()
		return "", fmt.Errorf("本任务已有 %d 个未完成资源请求，达到上限 %d", task, peerMaxPendingPerTask)
	}
	r := &peerRequest{
		RequestID: uuid.NewString(), TaskID: fromTask,
		FromIntentID: fromIntentID, ToIntentID: toIntentID,
		FromRunID: fromRun, ToRunID: toRun, FromWorker: fromWorker, ToWorker: toWorker,
		RequestType: requestType, Reason: reason,
		Status: peerPending, CreatedAt: now,
	}
	e.peerRequests[r.RequestID] = r
	e.peerIndexAddLocked(r)
	e.peerMu.Unlock()

	e.peerAuditActivity(fromTask, peerKindRequest, r,
		fmt.Sprintf("意图 #%d 向 #%d 请求资源（%s）", fromIntentID, toIntentID, requestType), reason)
	if !e.enqueuePeerMessage(toIntentID, peerKindRequest, r) {
		// The target finished between validation and enqueue. Expire the row so
		// the caller gets an immediate error instead of a request that can never
		// be delivered.
		e.peerMu.Lock()
		if cur := e.peerRequests[r.RequestID]; cur != nil && cur.Status == peerPending {
			cur.Answer = "target_finished"
			cur.AnswerReason = "目标 Worker 在请求入队前结束"
			e.finishPeerLocked(cur, peerExpired)
		}
		e.peerMu.Unlock()
		return "", fmt.Errorf("目标意图 %d 在请求入队前结束", toIntentID)
	}
	return r.RequestID, nil
}

// AnswerPeerRequest is called by the receiver's answer_request tool.
func (e *Engine) AnswerPeerRequest(receiverIntentID int64, requestID, answer, reason string) error {
	answer = strings.TrimSpace(answer)
	if answer != "accepted" && answer != "rejected" {
		return fmt.Errorf("answer 必须是 accepted 或 rejected")
	}
	now := e.peerClock()
	e.peerMu.Lock()
	r := e.peerRequests[requestID]
	if r == nil {
		e.peerMu.Unlock()
		return errPeerNotFound
	}
	if r.ToIntentID != receiverIntentID {
		e.peerMu.Unlock()
		return fmt.Errorf("只有接收方可以应答这个请求")
	}
	if r.Status != peerDelivered {
		status := r.Status
		e.peerMu.Unlock()
		if status == peerCancelled || status == peerExpired {
			return fmt.Errorf("%w: 请求已 %s", errPeerTooLate, status)
		}
		return fmt.Errorf("请求当前状态为 %s，不能应答", status)
	}
	r.AnsweredAt = now
	r.Answer = answer
	r.AnswerReason = strings.TrimSpace(reason)
	if answer == "rejected" {
		e.finishPeerLocked(r, peerRejected)
		if e.peerLastAsk[r.FromIntentID] == nil {
			e.peerLastAsk[r.FromIntentID] = map[int64]time.Time{}
		}
		e.peerLastAsk[r.FromIntentID][r.ToIntentID] = now
	} else {
		r.Status = peerAccepted
	}
	copy := *r
	e.peerMu.Unlock()

	e.peerAuditActivity(copy.TaskID, peerKindAnswer, &copy,
		fmt.Sprintf("意图 #%d 对 #%d 的请求应答 %s", receiverIntentID, copy.FromIntentID, answer), copy.AnswerReason)
	e.enqueuePeerMessage(copy.FromIntentID, peerKindAnswer, &copy)
	return nil
}

// ReleasePeerRequest is called by the receiver after it actually releases the
// resource. The requester must wait for this confirmation before continuing.
func (e *Engine) ReleasePeerRequest(receiverIntentID int64, requestID string) error {
	now := e.peerClock()
	e.peerMu.Lock()
	r := e.peerRequests[requestID]
	if r == nil {
		e.peerMu.Unlock()
		return errPeerNotFound
	}
	if r.ToIntentID != receiverIntentID {
		e.peerMu.Unlock()
		return fmt.Errorf("只有接收方可以确认释放")
	}
	if r.Status == peerReleased {
		e.peerMu.Unlock()
		return nil
	}
	if r.Status != peerAccepted {
		status := r.Status
		e.peerMu.Unlock()
		return fmt.Errorf("请求当前状态为 %s，不能确认释放", status)
	}
	r.ReleaseAt = now
	r.Answer = "released"
	e.finishPeerLocked(r, peerReleased)
	copy := *r
	e.peerMu.Unlock()

	e.peerAuditActivity(copy.TaskID, peerKindAnswer, &copy,
		fmt.Sprintf("意图 #%d 已释放资源（请求 %s）", receiverIntentID, requestID), copy.AnswerReason)
	e.enqueuePeerMessage(copy.FromIntentID, peerKindAnswer, &copy)
	return nil
}

// CancelPeerRequest is called by the requester. It is idempotent for requests
// already cancelled/expired, and "too late" once an answer exists.
func (e *Engine) CancelPeerRequest(fromIntentID int64, requestID string) error {
	e.peerMu.Lock()
	r := e.peerRequests[requestID]
	if r == nil {
		e.peerMu.Unlock()
		return errPeerNotFound
	}
	if r.FromIntentID != fromIntentID {
		e.peerMu.Unlock()
		return fmt.Errorf("只有请求方可以取消这个请求")
	}
	status := r.Status
	switch status {
	case peerCancelled, peerExpired:
		e.peerMu.Unlock()
		return nil
	case peerAccepted, peerRejected, peerReleased:
		e.peerMu.Unlock()
		return fmt.Errorf("%w: 请求已 %s", errPeerTooLate, status)
	case peerPending:
		e.peerMu.Unlock()
		e.removePeerRequestMessage(r.ToIntentID, requestID)
		e.peerMu.Lock()
		// Re-check: the receiver may have delivered/answered between the two locks.
		if cur := e.peerRequests[requestID]; cur == nil || cur.Status != peerPending {
			e.peerMu.Unlock()
			return e.CancelPeerRequest(fromIntentID, requestID)
		}
		r = e.peerRequests[requestID]
		e.finishPeerLocked(r, peerCancelled)
		copy := *r
		e.peerMu.Unlock()
		e.peerAuditActivity(copy.TaskID, peerKindCancel, &copy,
			fmt.Sprintf("意图 #%d 取消了请求 %s", fromIntentID, requestID), "请求方取消")
		return nil
	case peerDelivered:
		e.finishPeerLocked(r, peerCancelled)
		copy := *r
		e.peerMu.Unlock()
		e.peerAuditActivity(copy.TaskID, peerKindCancel, &copy,
			fmt.Sprintf("意图 #%d 取消了请求 %s", fromIntentID, requestID), "请求方取消（接收方已收到）")
		e.enqueuePeerMessage(r.ToIntentID, peerKindCancel, &copy)
		return nil
	default:
		e.peerMu.Unlock()
		return fmt.Errorf("请求当前状态为 %s，不能取消", status)
	}
}

// ExpirePeerRequestsForIntent closes every unfinished request that belongs to
// one run's intent (either side). The survivor gets a notice when it is still
// running; the activity stream records the expiry.
func (e *Engine) ExpirePeerRequestsForIntent(intentID int64, runID, reason string) {
	if intentID <= 0 {
		return
	}
	var expired []*peerRequest
	e.peerMu.Lock()
	ids := make([]string, 0, len(e.peerByIntent[intentID]))
	for id := range e.peerByIntent[intentID] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := e.peerRequests[id]
		if r == nil || !r.open() {
			continue
		}
		if r.FromIntentID == intentID && r.ToIntentID != intentID {
			if runID != "" && r.FromRunID != "" && r.FromRunID != runID {
				continue // a newer run of the same requester intent
			}
		}
		if r.ToIntentID == intentID && r.FromIntentID != intentID {
			if runID != "" && r.ToRunID != "" && r.ToRunID != runID {
				continue // a newer run of the same target intent
			}
		}
		r.Answer = string(peerExpired)
		r.AnswerReason = reason
		e.finishPeerLocked(r, peerExpired)
		copy := *r
		expired = append(expired, &copy)
	}
	e.peerMu.Unlock()
	if len(expired) == 0 {
		return
	}
	for _, r := range expired {
		other := r.ToIntentID
		if other == intentID {
			other = r.FromIntentID
		}
		e.peerAuditActivity(r.TaskID, peerKindExpired, r,
			fmt.Sprintf("请求 %s 已过期（%s）", r.RequestID, reason), reason)
		// Tell the other side only if it is still running. The final
		// enqueuePeerMessage check handles a concurrently finished work.
		e.enqueuePeerMessage(other, peerKindCancel, r)
	}
}

// SweepExpiredPeerRequests expires pending/delivered requests past their TTL.
// It is called from the Watchdog Fast Path; completed/accepted requests are
// left for the release/arbitration flow.
func (e *Engine) SweepExpiredPeerRequests() {
	now := e.peerClock()
	var expired []*peerRequest
	e.peerMu.Lock()
	for id, r := range e.peerRequests {
		if (r.Status == peerPending || r.Status == peerDelivered) &&
			now.Sub(r.CreatedAt) >= peerRequestTTL {
			r.Answer = string(peerExpired)
			r.AnswerReason = "超过请求有效期"
			e.finishPeerLocked(r, peerExpired)
			copy := *r
			expired = append(expired, &copy)
		}
		// Terminal requests stay readable long enough for their queued notices
		// to be rendered, then leave the in-memory registry.
		if !r.open() && now.Sub(r.CreatedAt) > time.Hour {
			delete(e.peerRequests, id)
		}
	}
	e.peerMu.Unlock()
	for _, r := range expired {
		e.peerAuditActivity(r.TaskID, peerKindExpired, r,
			fmt.Sprintf("请求 %s 超过有效期", r.RequestID), r.AnswerReason)
		e.enqueuePeerMessage(r.ToIntentID, peerKindCancel, r)
		e.enqueuePeerMessage(r.FromIntentID, peerKindCancel, r)
	}
}

// drainPeer pops up to max peer notices for one intent (FIFO), marks request
// notices delivered, and renders the text the worker sees before its next tool
// call. System steer messages are never touched here.
