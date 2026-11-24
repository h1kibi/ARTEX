package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// EvidenceRefValidator is installed by the host to resolve traffic/artifact
// references against the real Evidence Layer. Structural validation always runs;
// this callback adds existence checks when a traffic recorder is available.
var EvidenceRefValidator func(context.Context, db.EvidenceRef) error

var progressEvents = map[string]bool{
	"observation": true, "new_asset": true, "new_claim": true,
	"hypothesis_supported": true, "hypothesis_rejected": true,
	"validated_weakness": true, "credential_obtained": true,
	"privilege_change": true, "lateral_progress": true,
	"objective_milestone": true, "finding_written": true,
	"cleanup_completed": true, "duplicate_action": true,
	"provider_failure": true,
}

func IsHighValueProgress(event string) bool {
	switch event {
	case "validated_weakness", "credential_obtained", "privilege_change",
		"lateral_progress", "objective_milestone", "finding_written",
		"cleanup_completed":
		return true
	default:
		return false
	}
}

func factTypeList() string {
	return strings.Join(db.FactTypes, "、")
}

// normalizeFactInput validates the information semantics and returns the payload
// plus the intent it belongs to. It is the single entry used by record_fact; the
// model cannot bypass it by omitting fields or by declaring a type it did not
// support.
func (t *ToolSet) normalizeFactInput(ctx context.Context, it factItem, defaultIntent int64) (map[string]any, int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return nil, 0, fmt.Errorf("summary 不能为空")
	}
	factType := strings.ToLower(strings.TrimSpace(it.FactType))
	if factType == "" {
		return nil, 0, fmt.Errorf("fact_type 必填：%s（历史节点由系统读为 legacy_unknown，新节点不能写它）", factTypeList())
	}
	if !db.IsWritableFactType(factType) {
		return nil, 0, fmt.Errorf("不支持的 fact_type %q；可用类型：%s", factType, factTypeList())
	}
	intentID := pid(it.IntentID)
	if intentID <= 0 {
		intentID = defaultIntent
	}
	var intentNode *db.Node
	if intentID > 0 {
		n, err := t.ts.GetNode(intentID)
		if err != nil {
			return nil, 0, err
		}
		if n == nil || n.Kind != db.KindIntent {
			return nil, 0, fmt.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）")
		}
		intentNode = n
	}
	routeID := int64(0)
	if intentNode != nil {
		routeID = db.ParseIntentRoute(intentNode).RouteID
	}
	runInfo := RunInfoFrom(ctx)

	evidenceRefs, err := db.NormalizeEvidenceRefs(it.EvidenceRefs)
	if err != nil {
		return nil, 0, err
	}
	for _, ref := range evidenceRefs {
		parsed, _ := db.ParseEvidenceRef(ref)
		if err := t.validateEvidenceRef(ctx, parsed); err != nil {
			return nil, 0, err
		}
	}
	sourceIDs := pidList(it.SourceActivityIDs)
	observationIDs := pidList(it.ObservationIDs)
	claimIDs := pidList(it.ClaimIDs)
	hypothesisIDs := pidList(it.HypothesisIDs)

	// A worker records a conclusion about the tool result it just saw. When the
	// model omits explicit provenance, attach the newest tool_result for this
	// intent. It is a real, reviewable activity id, not model prose.
	if len(sourceIDs) == 0 && len(evidenceRefs) == 0 &&
		(factType == db.FactTypeObservation || factType == db.FactTypeClaim ||
			factType == db.FactTypeHypothesis || factType == db.FactTypeFindingCandidate) {
		if intentID > 0 {
			if act, err := t.ts.LastToolResultActivity(intentID); err == nil && act != nil {
				sourceIDs = []int64{act.ID}
			}
		}
	}
	if len(sourceIDs) > 0 {
		for _, id := range sourceIDs {
			ok, err := t.ts.ActivityExists(id)
			if err != nil {
				return nil, 0, err
			}
			if !ok {
				return nil, 0, fmt.Errorf("source_activity_ids 中的 %d 不属于本任务", id)
			}
		}
	}
	if err := t.validateInformationNodes(claimIDs, []string{db.FactTypeClaim, db.FactTypeLegacyUnknown}, "claim_ids"); err != nil {
		return nil, 0, err
	}
	if err := t.validateInformationNodes(observationIDs, []string{db.FactTypeObservation, db.FactTypeLegacyUnknown}, "observation_ids"); err != nil {
		return nil, 0, err
	}
	if err := t.validateInformationNodes(hypothesisIDs, []string{db.FactTypeHypothesis}, "hypothesis_ids"); err != nil {
		return nil, 0, err
	}

	validationActions := trimmedStrings(it.ValidationActions)
	nextActions := trimmedStrings(it.NextActions)
	progressEvent := strings.TrimSpace(it.ProgressEvent)
	if progressEvent != "" && !progressEvents[progressEvent] {
		return nil, 0, fmt.Errorf("未知 progress_event %q", progressEvent)
	}
	observedAt := strings.TrimSpace(it.ObservedAt)
	if observedAt == "" {
		observedAt = time.Now().UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, observedAt); err != nil {
		return nil, 0, fmt.Errorf("observed_at 必须是 RFC3339 时间: %w", err)
	}
	validUntil := strings.TrimSpace(it.ValidUntil)
	if validUntil != "" {
		if _, err := time.Parse(time.RFC3339, validUntil); err != nil {
			return nil, 0, fmt.Errorf("valid_until 必须是 RFC3339 时间: %w", err)
		}
	}
	sensitivity := strings.ToLower(strings.TrimSpace(it.Sensitivity))
	if sensitivity != "" && !db.ValidSensitivities[sensitivity] {
		return nil, 0, fmt.Errorf("不支持的 sensitivity %q；可用 normal/credential/token/secret/internal_file/user_data/ephemeral_port/task_auth", it.Sensitivity)
	}
	inheritancePolicy := strings.ToLower(strings.TrimSpace(it.InheritancePolicy))
	if inheritancePolicy != "" && !db.ValidInheritancePolicies[inheritancePolicy] {
		return nil, 0, fmt.Errorf("不支持的 inheritance_policy %q；可用 auto/inheritable/local_only", it.InheritancePolicy)
	}

	payload := map[string]any{"fact_type": factType, "summary": it.Summary}
	if it.Detail != "" {
		payload["detail"] = it.Detail
	}
	if e := strings.TrimSpace(it.Evidence); e != "" {
		payload["evidence"] = e
	}
	if c := strings.TrimSpace(it.Confidence); c != "" {
		payload["confidence"] = c
	}
	if len(evidenceRefs) > 0 {
		payload["evidence_refs"] = evidenceRefs
	}
	if len(sourceIDs) > 0 {
		payload["source_activity_ids"] = sourceIDs
	}
	if len(observationIDs) > 0 {
		payload["observation_ids"] = observationIDs
	}
	if len(claimIDs) > 0 {
		payload["claim_ids"] = claimIDs
	}
	if len(hypothesisIDs) > 0 {
		payload["hypothesis_ids"] = hypothesisIDs
	}
	if len(validationActions) > 0 {
		payload["validation_actions"] = validationActions
	}
	if len(it.Alternatives) > 0 {
		payload["alternatives_rejected"] = trimmedStrings(it.Alternatives)
	}
	if len(nextActions) > 0 {
		payload["next_actions"] = nextActions
	}
	payload["observed_at"] = observedAt
	if validUntil != "" {
		payload["valid_until"] = validUntil
	}
	if sensitivity != "" {
		payload["sensitivity"] = sensitivity
	}
	if inheritancePolicy != "" {
		payload["inheritance_policy"] = inheritancePolicy
	}
	if progressEvent != "" {
		payload["progress_event"] = progressEvent
	}
	if routeID > 0 {
		payload["route_id"] = routeID
	}
	if intentID > 0 {
		payload["intent_id"] = intentID
	}
	if runInfo.RunID != "" {
		payload["run_id"] = runInfo.RunID
	}

	switch factType {
	case db.FactTypeObservation:
		if len(sourceIDs) == 0 && len(evidenceRefs) == 0 {
			return nil, 0, fmt.Errorf("observation 必须带 source_activity_ids 或 evidence_refs（traffic:<id>/artifact:<path>）；模型文字本身不能作为观察来源")
		}
	case db.FactTypeClaim:
		if len(sourceIDs) == 0 && len(evidenceRefs) == 0 && len(observationIDs) == 0 {
			return nil, 0, fmt.Errorf("claim 必须引用 observation（observation_ids）或 evidence_refs / source_activity_ids")
		}
		if c := strings.TrimSpace(it.Confidence); c == "" {
			return nil, 0, fmt.Errorf("claim 必须标注 confidence（observed|inferred）")
		} else if c != "observed" && c != "inferred" {
			return nil, 0, fmt.Errorf("confidence 只能是 observed 或 inferred")
		}
	case db.FactTypeHypothesis:
		if len(validationActions) == 0 {
			return nil, 0, fmt.Errorf("hypothesis 必须给出 validation_actions（至少一步验证动作）")
		}
		if len(claimIDs) == 0 && len(observationIDs) == 0 && len(evidenceRefs) == 0 && len(sourceIDs) == 0 {
			return nil, 0, fmt.Errorf("hypothesis 必须带支撑引用（claim_ids/observation_ids/evidence_refs/source_activity_ids）")
		}
		state := strings.ToLower(strings.TrimSpace(it.State))
		if state == "" {
			state = "open"
		}
		switch state {
		case "open", "supported", "rejected", "expired":
		default:
			return nil, 0, fmt.Errorf("hypothesis 的 state 只能是 open|supported|rejected|expired")
		}
		payload["state"] = state
	case db.FactTypeDecision:
		if len(claimIDs) == 0 && len(hypothesisIDs) == 0 {
			return nil, 0, fmt.Errorf("decision 必须引用支撑的 claim_ids 或 hypothesis_ids")
		}
		nextIntentID := pid(it.NextIntentID)
		checkpointID := pid(it.CheckpointFactID)
		if nextIntentID <= 0 && checkpointID <= 0 {
			return nil, 0, fmt.Errorf("decision 必须给出 next_intent_id 或 checkpoint_fact_id")
		}
		if nextIntentID > 0 {
			n, err := t.ts.GetNode(nextIntentID)
			if err != nil || n == nil || n.Kind != db.KindIntent {
				return nil, 0, fmt.Errorf("next_intent_id %d 必须是本任务的意图", nextIntentID)
			}
			payload["next_intent_id"] = nextIntentID
		}
		if checkpointID > 0 {
			n, err := t.ts.GetNode(checkpointID)
			if err != nil || n == nil || n.FactType() != db.FactTypeCheckpoint {
				return nil, 0, fmt.Errorf("checkpoint_fact_id %d 必须是本任务的 checkpoint fact", checkpointID)
			}
			payload["checkpoint_fact_id"] = checkpointID
		}
	case db.FactTypeFindingCandidate:
		if len(claimIDs) == 0 && len(evidenceRefs) == 0 && len(sourceIDs) == 0 {
			return nil, 0, fmt.Errorf("finding_candidate 必须引用 claim_ids、evidence_refs 或 source_activity_ids")
		}
		validationState := strings.ToLower(strings.TrimSpace(it.ValidationState))
		if validationState == "" {
			validationState = "pending"
		}
		if validationState == "confirmed" {
			return nil, 0, fmt.Errorf("finding_candidate 不能写 confirmed；确认漏洞必须调用 report_finding")
		}
		if validationState != "pending" && validationState != "rejected" {
			return nil, 0, fmt.Errorf("finding_candidate 的 validation_state 只能是 pending 或 rejected")
		}
		payload["validation_state"] = validationState
		if c := strings.TrimSpace(it.Confidence); c != "" {
			payload["confidence"] = c
		}
	}
	return payload, intentID, nil
}

// anchorableFactType limits proof/anchor evidence to confirmed observations and
// claims. Hypothesis, decision, finding_candidate, checkpoint and origin facts
// all live under KindFact but are not confirmed evidence.
func anchorableFactType(ft string) bool {
	switch ft {
	case db.FactTypeObservation, db.FactTypeClaim, db.FactTypeLegacyUnknown:
		return true
	default:
		return false
	}
}

// validateProofAnchor verifies an evidence/parent node is confirmed knowledge and,
// when inherited from a source task, passes the cross-task inheritance policy.
func (t *ToolSet) validateProofAnchor(n *db.Node) error {
	if n == nil {
		return fmt.Errorf("节点不存在")
	}
	if n.Kind == db.KindFinding {
		if n.State != "confirmed" {
			return fmt.Errorf("漏洞节点 #%d 状态为 %q，只有 confirmed 漏洞能作为已确认证据", n.ID, n.State)
		}
		return nil
	}
	if n.Kind != db.KindFact {
		return fmt.Errorf("节点 #%d 是 %q，不能作为已确认事实/锚点", n.ID, n.Kind)
	}
	if n.State == db.StateOrigin {
		return fmt.Errorf("节点 #%d 是任务根事实，不能作为已确认证据", n.ID)
	}
	if ft := n.FactType(); !anchorableFactType(ft) {
		return fmt.Errorf("节点 #%d 的 fact_type 是 %s，只有 observation/claim（或历史 legacy_unknown）能作为已确认证据；hypothesis/decision/finding_candidate/checkpoint 都不能证明目标", n.ID, ft)
	}
	if db.IsFactExpired(db.ParseFactPayload(n.Payload), time.Now()) {
		return fmt.Errorf("节点 #%d 已超过 valid_until 有效期，不能作为已确认证据", n.ID)
	}
	if n.Inherited {
		if ok, why := db.CanInheritFact(n, time.Now()); !ok {
			return fmt.Errorf("节点 #%d 来自关联任务，但受继承策略限制（%s），不能作为已确认证据", n.ID, why)
		}
	}
	return nil
}

// validateInformationNodes checks the supplied ids are fact nodes of the allowed
// information types in this task.
func (t *ToolSet) validateInformationNodes(ids []int64, allowed []string, field string) error {
	if len(ids) == 0 {
		return nil
	}
	allow := make(map[string]bool, len(allowed))
	for _, v := range allowed {
		allow[v] = true
	}
	for _, id := range ids {
		n, err := t.ts.GetNode(id)
		if err != nil {
			return err
		}
		if n == nil {
			return fmt.Errorf("%s 中的 %d 不存在于本任务（关联任务节点只读）", field, id)
		}
		if n.Kind != db.KindFact {
			return fmt.Errorf("%s 中的 %d 不是 fact 节点（%s）", field, id, n.Kind)
		}
		ft := n.FactType()
		if !allow[ft] {
			return fmt.Errorf("%s 中的 %d 是 %s，不能用于 %s", field, id, ft, field)
		}
	}
	return nil
}

// validateEvidenceRef verifies that every referenced evidence pointer resolves
// in the current task's store, working directory, or traffic recorder.
func (t *ToolSet) validateEvidenceRef(ctx context.Context, ref db.EvidenceRef) error {
	switch ref.Kind {
	case "activity":
		id, err := strconv.ParseInt(ref.ID, 10, 64)
		if err != nil || id <= 0 {
			return fmt.Errorf("证据引用 %s 不是有效的活动 id", ref.String())
		}
		ok, err := t.ts.ActivityExists(id)
		if err != nil {
			return fmt.Errorf("校验活动引用 %s 失败: %w", ref.String(), err)
		}
		if !ok {
			return fmt.Errorf("活动引用 %s 不存在于本任务", ref.String())
		}
	case "node":
		id, err := strconv.ParseInt(ref.ID, 10, 64)
		if err != nil || id <= 0 {
			return fmt.Errorf("证据引用 %s 不是有效的节点 id", ref.String())
		}
		n, err := t.ts.GetNodeWithSources(id)
		if err != nil {
			return fmt.Errorf("校验节点引用 %s 失败: %w", ref.String(), err)
		}
		if n == nil {
			return fmt.Errorf("节点引用 %s 不存在于本任务或直接来源任务", ref.String())
		}
		if n.Inherited && n.Kind == db.KindFact {
			if ok, why := db.CanInheritFact(n, time.Now()); !ok {
				return fmt.Errorf("节点引用 %s 受继承策略限制不可引用（%s）", ref.String(), why)
			}
		}
	case "finding":
		id, err := strconv.ParseInt(ref.ID, 10, 64)
		if err != nil || id <= 0 {
			return fmt.Errorf("证据引用 %s 不是有效的漏洞 id", ref.String())
		}
		ok, err := t.ts.FindingOrNodeExists(id)
		if err != nil {
			return fmt.Errorf("校验漏洞引用 %s 失败: %w", ref.String(), err)
		}
		if !ok {
			return fmt.Errorf("漏洞引用 %s 不存在于本任务", ref.String())
		}
	case "artifact":
		clean, err := db.ValidateArtifactPath(ref.ID)
		if err != nil {
			return err
		}
		if len(t.artifactRoots) > 0 {
			found := false
			for _, root := range t.artifactRoots {
				if strings.TrimSpace(root) == "" {
					continue
				}
				base := filepath.Clean(root)
				full := filepath.Clean(filepath.Join(base, filepath.FromSlash(clean)))
				if full != base && !strings.HasPrefix(full, base+string(os.PathSeparator)) {
					continue
				}
				// Resolve symlinks before the containment check: a link created
				// inside the task directory must not expose files outside it.
				resolvedBase, err := filepath.EvalSymlinks(base)
				if err != nil {
					continue
				}
				resolved, err := filepath.EvalSymlinks(full)
				if err != nil {
					continue
				}
				if resolved != resolvedBase && !strings.HasPrefix(resolved, resolvedBase+string(os.PathSeparator)) {
					continue
				}
				if fi, statErr := os.Stat(resolved); statErr == nil && !fi.IsDir() {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("产物引用 %s 在当前工作目录中不存在（请先写入文件并传工作目录内的相对路径）", ref.String())
			}
		}
	}
	if EvidenceRefValidator != nil {
		return EvidenceRefValidator(ctx, ref)
	}
	return nil
}

// mergeRouteBudget preserves an existing route budget dimension when the caller
// omits it (0) on continuation, while allowing explicit expansion (> 0).
func mergeRouteBudget(requested, inherited db.RouteBudget) db.RouteBudget {
	out := inherited
	if requested.MaxToolCalls > 0 {
		out.MaxToolCalls = requested.MaxToolCalls
	}
	if requested.MaxInputTokens > 0 {
		out.MaxInputTokens = requested.MaxInputTokens
	}
	if requested.MaxWallSeconds > 0 {
		out.MaxWallSeconds = requested.MaxWallSeconds
	}
	return out
}

// exhaustedBudgetMessage prevents a continuation from inheriting an already
// exhausted route budget and getting killed again on the next Fast Path tick.
func exhaustedBudgetMessage(routeID int64, budget db.RouteBudget, used db.RouteBudgetUsed) string {
	dimension, usedValue, limit := db.RouteBudgetExhausted(budget, used)
	if dimension == "" {
		return ""
	}
	label, field := db.RouteBudgetDimensionMeta(dimension)
	return fmt.Sprintf("路线 #%d 累计%s预算已耗尽（%d/%d），不追加预算时接续会在下一周期立即再次被终止；若需继续此路线，请显式传入更大的 budget.%s（须大于 %d），否则请停止该路线或改派新路线",
		routeID, label, usedValue, limit, field, usedValue)
}

func trimmedStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// FactTypeFromInput classifies a record_fact call without reading the node back.
func FactTypeFromInput(raw json.RawMessage) string {
	var a struct {
		FactType string `json:"fact_type"`
		Facts    []struct {
			FactType string `json:"fact_type"`
		} `json:"facts"`
	}
	if json.Unmarshal(raw, &a) != nil {
		return ""
	}
	if t := strings.ToLower(strings.TrimSpace(a.FactType)); t != "" {
		return t
	}
	for _, f := range a.Facts {
		if t := strings.ToLower(strings.TrimSpace(f.FactType)); t != "" {
			return t
		}
	}
	return ""
}
