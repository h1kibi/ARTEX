package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/db"
)

// watchdogRunDTO is the API shape for one live run. Times are RFC3339 or empty,
// matching the frontend's Activity/task conventions instead of Go's zero time.
type watchdogRunDTO struct {
	TaskID          string `json:"task_id"`
	IntentID        int64  `json:"intent_id"`
	RunID           string `json:"run_id"`
	WorkerName      string `json:"worker_name"`
	Phase           string `json:"phase"`
	PhaseStartedAt  string `json:"phase_started_at,omitempty"`
	HeartbeatAt     string `json:"heartbeat_at,omitempty"`
	LastEventAt     string `json:"last_event_at,omitempty"`
	LastOutputAt    string `json:"last_output_at,omitempty"`
	CycleStart      string `json:"cycle_start,omitempty"`
	CycleNo         int    `json:"cycle_no"`
	PressureSent    bool   `json:"pressure_sent"`
	SlowPathState   string `json:"slow_path_state"`
	DecisionState   string `json:"decision_state"`
	State           string `json:"state"`
	Tool            string `json:"tool,omitempty"`
	Facts           int    `json:"facts"`
	Assets          int    `json:"assets"`
	Findings        int    `json:"findings"`
	ProviderError   string `json:"provider_error,omitempty"`
	SlowPathClass   string `json:"slow_path_class,omitempty"`
	SlowPathSummary string `json:"slow_path_summary,omitempty"`
	// Autonomy budget for this run: the intent's effort tier when set, otherwise
	// the current Watchdog configuration.
	MaxAutoCycles       int    `json:"max_auto_cycles"`
	AutoCyclesUsed      int    `json:"auto_cycles_used"`
	AutoCyclesRemaining int    `json:"auto_cycles_remaining"`
	Effort              string `json:"effort,omitempty"`
	HumanInvolved       bool   `json:"human_involved,omitempty"`
}

// applyAutoBudget fills the informational autonomy fields from the run's real
// count of green-light advances. User-approved cycles are not included.
func (d *watchdogRunDTO) applyAutoBudget(maxAuto, used int) {
	if maxAuto < 0 {
		maxAuto = defaultWatchdogMaxAuto
	}
	if maxAuto > 4 {
		maxAuto = 4
	}
	if used < 0 {
		used = 0
	}
	if used > maxAuto {
		used = maxAuto
	}
	d.MaxAutoCycles = maxAuto
	d.AutoCyclesUsed = used
	d.AutoCyclesRemaining = maxAuto - used
}

func optionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return rfc3339(t)
}

func watchdogRunDTOFromSnapshot(s RunSnapshot) watchdogRunDTO {
	return watchdogRunDTO{
		TaskID: s.TaskID, IntentID: s.IntentID, RunID: s.RunID, WorkerName: s.WorkerName,
		Phase: s.Phase, PhaseStartedAt: optionalTime(s.PhaseStartedAt),
		HeartbeatAt: optionalTime(s.HeartbeatAt), LastEventAt: optionalTime(s.LastEventAt),
		LastOutputAt: optionalTime(s.LastOutputAt), CycleStart: optionalTime(s.CycleStart),
		CycleNo: s.CycleNo, PressureSent: s.PressureSent, SlowPathState: s.SlowPathState,
		DecisionState: s.DecisionState, State: s.State, Tool: s.Tool,
		Facts: s.Facts, Assets: s.Assets, Findings: s.Findings,
		ProviderError: s.ProviderError, SlowPathClass: s.SlowPathClass,
		SlowPathSummary: s.SlowPathSummary,
	}
}

func optionalTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return optionalTime(*t)
}

func watchdogRunDTOFromDB(r *db.WorkerRun) watchdogRunDTO {
	return watchdogRunDTO{
		TaskID: r.TaskID, IntentID: r.IntentID, RunID: r.RunID, WorkerName: r.WorkerName,
		Phase: r.Phase, PhaseStartedAt: optionalTimePtr(r.PhaseStartedAt),
		HeartbeatAt: optionalTimePtr(r.HeartbeatAt), LastEventAt: optionalTimePtr(r.LastEventAt),
		LastOutputAt: optionalTimePtr(r.LastOutputAt), CycleStart: optionalTimePtr(r.CycleStart),
		CycleNo: r.CycleNo, PressureSent: r.PressureSent,
		SlowPathState: r.SlowPathState, DecisionState: r.DecisionState, State: r.State,
	}
}

// watchdogDefaultRule is the rule the backend applies when the user never
// answers. C0 is the only cycle that silently consents; C1 and later treat
// silence as a stop.
func watchdogDefaultRule(cycleNo int) string {
	if cycleNo <= 0 {
		return "c0_continue"
	}
	return "c1_plus_terminate"
}

func (s *Server) watchdogRequestDTO(r *db.WatchdogRequest) map[string]any {
	out := map[string]any{
		"id": r.ID, "task_id": r.TaskID, "cycle_no": r.CycleNo, "kind": r.Kind,
		"status": r.Status, "question": r.Question, "evidence": r.Evidence, "options": r.Options,
		"answer": r.Answer, "answer_reason": r.AnswerReason,
		"created_at": rfc3339(r.CreatedAt), "updated_at": rfc3339(r.UpdatedAt),
	}
	if r.IntentID != nil {
		out["intent_id"] = *r.IntentID
	}
	if r.RunID != "" {
		out["run_id"] = r.RunID
	}
	if r.AnsweredAt != nil {
		out["answered_at"] = rfc3339(*r.AnsweredAt)
	}
	if r.DeadlineAt != nil {
		out["deadline_at"] = rfc3339(*r.DeadlineAt)
	}
	if r.HardDeadlineAt != nil {
		out["hard_deadline_at"] = rfc3339(*r.HardDeadlineAt)
	}
	if r.Kind == db.WatchdogRequestAsk {
		out["default_rule"] = watchdogDefaultRule(r.CycleNo)
	}
	if r.Kind == db.WatchdogRequestUnavailable {
		out["auto_retry_sec"] = int(s.watchdogConfig().AgentRetry / time.Second)
	}
	if r.AlertCount > 0 {
		out["alert_count"] = r.AlertCount
	}
	if r.FirstAlertAt != nil {
		out["first_alert_at"] = rfc3339(*r.FirstAlertAt)
	}
	if r.LastAlertAt != nil {
		out["last_alert_at"] = rfc3339(*r.LastAlertAt)
	}
	if r.NextRetryAt != nil {
		out["next_retry_at"] = rfc3339(*r.NextRetryAt)
	}
	if r.Kind == db.WatchdogRequestAsk {
		if r.Attempts > 0 {
			out["attempts"] = r.Attempts
		}
		if r.LastError != "" {
			out["last_error"] = r.LastError
		}
	}
	return out
}

// watchdogRuns serves the live phases and cycle state of one task. The monitor
// is authoritative while the process is alive; the database is the fallback for
// tests and for a page opened after a restart (where no run is live anyway).
func (s *Server) watchdogRuns(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		writeErr(w, 400, "task_id 为必填")
		return
	}
	maxAuto := s.watchdogConfig().MaxAutoCycles
	var runs []watchdogRunDTO
	if s.watchdog != nil && s.watchdog.monitor != nil {
		for _, snap := range s.watchdog.monitor.ListRunning(taskID) {
			dto := watchdogRunDTOFromSnapshot(snap)
			// effort 档位是本次 run 的真实自治预算（probe=0 是有效值），全局配置只是
			// 未标档位时的兜底——UI 必须显示实际生效的值，否则 probe 棒会显示成还有额度。
			runMaxAuto := maxAuto
			if snap.HasEffortMaxAutoCycles {
				runMaxAuto = snap.EffortMaxAutoCycles
			}
			dto.applyAutoBudget(runMaxAuto, snap.AutoCyclesUsed)
			dto.Effort = snap.Effort
			dto.HumanInvolved = snap.HumanInvolved
			runs = append(runs, dto)
		}
	} else if s.m != nil && s.m.pg != nil {
		rows, err := s.m.pg.ListWorkerRuns(r.Context(), taskID, true)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		for _, row := range rows {
			dto := watchdogRunDTOFromDB(row)
			dto.applyAutoBudget(maxAuto, row.AutoCyclesUsed)
			runs = append(runs, dto)
		}
	}
	writeJSON(w, 200, map[string]any{"runs": runs})
}

// watchdogRequests lists the task's cards. ?status=open is the normal polling
// shape; history is available by omitting status.
func (s *Server) watchdogRequests(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		writeErr(w, 400, "task_id 为必填")
		return
	}
	rows, err := s.m.pg.ListWatchdogRequests(r.Context(), taskID, r.URL.Query().Get("status"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.watchdogRequestDTO(row))
	}
	writeJSON(w, 200, map[string]any{"requests": out})
}

// watchdogDecide records one answer and immediately applies its cycle action.
// A stale run/cycle is rejected before the answer is committed, so a late click
// cannot advance a newer cycle.
func (s *Server) watchdogDecide(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad request id")
		return
	}
	var req struct {
		Answer string `json:"answer"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Answer != "continue" && req.Answer != "stop" {
		writeErr(w, 400, "answer 必须是 continue 或 stop")
		return
	}
	card, err := s.m.pg.WatchdogRequestByID(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if card == nil {
		writeErr(w, 404, "请求不存在")
		return
	}
	if card.Kind != db.WatchdogRequestAsk {
		writeErr(w, 400, "该卡片不是用户判断请求")
		return
	}
	if card.Status != db.WatchdogRequestOpen {
		writeErr(w, 409, "该请求已处理或已过期")
		return
	}
	if card.HardDeadlineAt != nil && time.Now().After(*card.HardDeadlineAt) {
		_, _ = s.m.pg.SettleWatchdogAsk(r.Context(), card.ID, db.WatchdogRequestExpired,
			req.Answer, "请求已到硬截止时间")
		writeErr(w, 409, "该请求已过期")
		return
	}
	t, exists := s.m.Task(card.TaskID)
	if !exists {
		writeErr(w, 404, "任务不存在")
		return
	}
	if s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "任务正在删除")
		return
	}
	if !s.watchdogTaskActive(t) {
		writeErr(w, 409, "任务已暂停、排队或正在收尾")
		return
	}
	if card.RunID == "" || s.watchdog == nil {
		writeErr(w, 409, "该请求对应的运行已结束")
		return
	}
	snap := s.watchdog.monitor.LookupRun(card.RunID)
	if snap == nil || snap.State != db.WorkerRunStateRunning || snap.CycleNo != card.CycleNo {
		_, _ = s.m.pg.SettleWatchdogAsk(r.Context(), card.ID, db.WatchdogRequestExpired,
			req.Answer, "运行或周期已变化，本次选择不再生效")
		writeErr(w, 409, "该请求已过期")
		return
	}
	answered, err := s.m.pg.AnswerWatchdogRequest(r.Context(), card.ID, req.Answer, req.Reason)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if answered == nil {
		writeErr(w, 409, "该请求已被其他操作处理")
		return
	}
	if s.watchdog != nil && s.watchdog.monitor != nil && card.RunID != "" {
		s.watchdog.monitor.SetDecisionState(card.RunID, db.WatchdogDecisionAnswered)
	}
	s.emitWatchdogActivity(t, "watchdog_decision",
		fmt.Sprintf("用户选择%s：意图 #%d · C%d", map[string]string{"continue": "继续", "stop": "终止"}[req.Answer], card.IntentID, card.CycleNo),
		req.Reason, watchdogAudit{CycleNo: card.CycleNo, RequestID: card.ID, State: req.Answer})
	actionErr := error(nil)
	if req.Answer == "continue" {
		actionErr = s.watchdogContinueCycle(t, *snap, "用户明确同意进入下一周期")
	} else {
		_, actionErr = s.watchdogTerminateCycle(t, *snap, "用户明确拒绝继续", "stopped")
	}
	if actionErr != nil {
		// The run settled between the card being answered and the action commit, so
		// the choice was never applied. Retract the answer as expired: keeping it
		// answered would show a stop the intent never took (and a resume the card
		// says should be impossible).
		if errors.Is(actionErr, errWorkControlConflict) || errors.Is(actionErr, errWatchdogRunMismatch) {
			detail := "运行已进入终态提交，本次选择不再生效"
			if _, xerr := s.m.pg.ExpireAnsweredWatchdogAsk(r.Context(), card.ID, req.Answer, detail); xerr != nil {
				log.Printf("[watchdog] 回收已作答决策卡 #%d 失败: %v", card.ID, xerr)
			}
			if s.watchdog != nil && s.watchdog.monitor != nil {
				s.watchdog.monitor.SetDecisionState(card.RunID, db.WatchdogDecisionNone)
			}
		}
		writeErr(w, 409, actionErr.Error())
		return
	}
	writeJSON(w, 200, s.watchdogRequestDTO(answered))
}

// watchdogRetry handles the unavailable card's Try again action: make the
// task's queued reports due immediately and wake the Slow Path service. It does
// not touch the 8/10/20 minute cycle timers.
func (s *Server) watchdogRetry(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad request id")
		return
	}
	card, err := s.m.pg.WatchdogRequestByID(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if card == nil {
		writeErr(w, 404, "请求不存在")
		return
	}
	if card.Kind != db.WatchdogRequestUnavailable || card.Status != db.WatchdogRequestOpen {
		writeErr(w, 400, "只有开放的 Watchdog 不可用卡片可以重试")
		return
	}
	if err := s.m.pg.RetryWatchdogQueue(r.Context(), card.TaskID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	now := time.Now()
	if err := s.m.pg.TouchWatchdogUnavailable(r.Context(), card.TaskID, &now); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if count, _, _, err := s.m.pg.WatchdogJobStats(r.Context(), card.TaskID); err == nil && count == 0 {
		if err := s.m.pg.CloseWatchdogUnavailable(r.Context(), card.TaskID); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if s.watchdog != nil {
		s.watchdog.Wake()
	}
	updated, err := s.m.pg.WatchdogRequestByID(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, s.watchdogRequestDTO(updated))
}

// watchdogTaskActive is the shared lifecycle guard for Watchdog actions. A task
// that paused, queued, entered settlement or is being deleted must not receive a
// pressure prompt, a new judgment or a termination, even if a Slow Path model
// call started before that transition and finishes afterwards.
func (s *Server) watchdogTaskActive(t *Task) bool {
	if s == nil || s.engine == nil || t == nil {
		return false
	}
	lifecycle := t.lifecycleSnapshot()
	return !isTerminalStatus(lifecycle.Status) && !lifecycle.Paused && !lifecycle.Queued &&
		!s.engine.IsPaused(t.ID) && !s.engine.IsDeleting(t.ID) && !s.engine.isSettling(t.ID)
}

// emitWatchdogActivity writes one system-audit record. Errors here are logged by
// emitActivity; the control action must not fail because an audit row could not
// be stored.
func (s *Server) emitWatchdogActivity(t *Task, kind, summary, detail string, audit watchdogAudit) db.Activity {
	return s.engine.emitActivity(t, db.Activity{
		Worker: "system", Kind: kind, Summary: summary, Detail: detail,
		Metadata: marshalWatchdogMetadata(audit),
	})
}
