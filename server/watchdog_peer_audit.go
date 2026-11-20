package server

import (
	"encoding/json"
	"time"

	"github.com/Autumn-27/artex/db"
)

// peerAudit is the structured metadata attached to peer_* activities.
type peerAudit struct {
	RequestID    string `json:"request_id,omitempty"`
	FromIntentID int64  `json:"from_intent_id,omitempty"`
	ToIntentID   int64  `json:"to_intent_id,omitempty"`
	FromWorker   string `json:"from_worker,omitempty"`
	ToWorker     string `json:"to_worker,omitempty"`
	RequestType  string `json:"request_type,omitempty"`
	Status       string `json:"status,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Answer       string `json:"answer,omitempty"`
	Decision     string `json:"decision,omitempty"`
	CooldownSec  int    `json:"cooldown_sec,omitempty"`
	UpgradeSec   int    `json:"upgrade_sec,omitempty"`
}

type peerActivityMetadata struct {
	Peer *peerAudit `json:"peer,omitempty"`
}

func marshalPeerMetadata(a peerAudit) json.RawMessage {
	raw, _ := json.Marshal(peerActivityMetadata{Peer: &a})
	return raw
}

func (e *Engine) peerAuditActivity(taskID, kind string, r *peerRequest, summary, detail string) {
	if e == nil || e.m == nil || taskID == "" {
		return
	}
	t, ok := e.m.Task(taskID)
	if !ok || t == nil {
		return
	}
	nodeID := r.ToIntentID
	if kind == peerKindAnswer || kind == peerKindCancel || kind == peerKindExpired {
		nodeID = r.FromIntentID
	}
	cooldown, upgrade := 0, 0
	if kind == peerKindAnswer {
		switch r.Status {
		case peerRejected:
			cooldown = int(peerRejectCooldown / time.Second)
		case peerAccepted:
			upgrade = int(peerReleaseTimeout / time.Second)
		}
	}
	e.emitActivity(t, db.Activity{
		Worker: "system", Kind: kind, NodeID: &nodeID,
		Summary: summary, Detail: detail,
		Metadata: marshalPeerMetadata(peerAudit{
			RequestID: r.RequestID, FromIntentID: r.FromIntentID, ToIntentID: r.ToIntentID,
			FromWorker: r.FromWorker, ToWorker: r.ToWorker,
			RequestType: r.RequestType, Status: string(r.Status), Reason: r.Reason,
			Answer: r.Answer, Decision: r.ArbitrationDecision,
			CooldownSec: cooldown, UpgradeSec: upgrade,
		}),
	})
}
