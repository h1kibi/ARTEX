package server

import (
	"fmt"
	"strings"
)

func (e *Engine) enqueuePeerMessage(intentID int64, kind string, r *peerRequest) bool {
	if intentID <= 0 {
		return false
	}
	if _, _, _, ok := e.peerWork(intentID); !ok {
		return false
	}
	e.steerMu.Lock()
	e.steerBox[intentID] = append(e.steerBox[intentID], steerMessage{
		Source: "peer", Kind: kind, RequestID: r.RequestID,
		FromIntentID: r.FromIntentID, ToIntentID: r.ToIntentID,
	})
	e.steerMu.Unlock()
	return true
}

// removePeerRequestMessage drops a still-queued request notification after the
// requester cancels it. Delivered requests have no queue entry; the receiver
// gets an explicit peer_cancel notice instead.
func (e *Engine) removePeerRequestMessage(intentID int64, requestID string) {
	e.steerMu.Lock()
	defer e.steerMu.Unlock()
	q := e.steerBox[intentID]
	out := q[:0]
	for _, m := range q {
		if m.Kind == peerKindRequest && m.RequestID == requestID {
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		delete(e.steerBox, intentID)
	} else {
		e.steerBox[intentID] = out
	}
}

// drainPeer pops up to max peer notices for one intent (FIFO), marks request
// notices delivered, and renders the text the worker sees before its next tool
// call. System steer messages are never touched here.
func (e *Engine) drainPeer(intentID int64, max int) []steerMessage {
	if max <= 0 {
		max = peerMaxBatch
	}
	e.steerMu.Lock()
	q := e.steerBox[intentID]
	if len(q) == 0 {
		e.steerMu.Unlock()
		return nil
	}
	var picked []steerMessage
	rest := make([]steerMessage, 0, len(q))
	for _, m := range q {
		if m.Kind != "" && len(picked) < max {
			picked = append(picked, m)
			continue
		}
		rest = append(rest, m)
	}
	if len(rest) == 0 {
		delete(e.steerBox, intentID)
	} else {
		e.steerBox[intentID] = rest
	}
	e.steerMu.Unlock()

	if len(picked) == 0 {
		return nil
	}
	now := e.peerClock()
	out := make([]steerMessage, 0, len(picked))
	e.peerMu.Lock()
	for _, m := range picked {
		r := e.peerRequests[m.RequestID]
		if r == nil {
			continue
		}
		if m.Kind == peerKindRequest {
			if r.Status != peerPending {
				continue // cancelled/expired before delivery
			}
			r.Status = peerDelivered
			r.DeliveredAt = now
		}
		m.Text = formatPeerNotice(m.Kind, r)
		out = append(out, m)
	}
	e.peerMu.Unlock()
	return out
}

func formatPeerNotice(kind string, r *peerRequest) string {
	switch kind {
	case peerKindRequest:
		return fmt.Sprintf("【其他 Worker 的资源请求】\nrequest_id: %s\nfrom_intent_id: %d\nto_intent_id: %d\nrequest_type: %s\nreason: %s\n请使用 answer_request 返回 accepted 或 rejected。",
			r.RequestID, r.FromIntentID, r.ToIntentID, r.RequestType, r.Reason)
	case peerKindAnswer:
		answer := r.Answer
		if answer == "" {
			answer = string(r.Status)
		}
		return fmt.Sprintf("【其他 Worker 的应答】\nrequest_id: %s\nanswer: %s\nreason: %s",
			r.RequestID, answer, firstNonEmptyString(r.AnswerReason, r.Reason))
	case peerKindCancel:
		return fmt.Sprintf("【其他 Worker 的请求状态变更】\nrequest_id: %s\nstatus: %s\nreason: %s",
			r.RequestID, r.Status, firstNonEmptyString(r.AnswerReason, r.Reason))
	case peerKindArbitration:
		return fmt.Sprintf("【Watchdog 资源仲裁】\nrequest_id: %s\ndecision: %s\nreason: %s",
			r.RequestID, r.ArbitrationDecision, r.ArbitrationReason)
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
