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
		"lateral_progress", "objective_milestone", "finding_written":
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
		factType = db.FactTypeObservation
	}
	if !db.IsWritableFactType(factType) {
		return nil, 0, fmt.Errorf("不支持的 fact_type %q；可用类型：%s", factType, factTypeList())
	}
	intentID := pid(it.IntentID)
	if intentID <= 0 {
		intentID = defaultIntent
	}
	var intentNode *db.Node
	resolveIntent := func(id int64) bool {
		if id <= 0 {
			return false
		}
		n, err := t.ts.GetNode(id)
		if err != nil || n == nil || n.Kind != db.KindIntent {
			return false
		}
		intentID = id
		intentNode = n
		return true
	}
	if !resolveIntent(intentID) && intentID > 0 && pid(it.IntentID) > 0 {
		return nil, 0, fmt.Errorf("intent_id 必须是本任务的意图（关联任务意图只读）")
	}
	if intentNode == nil && t.ownerNode > 0 {
		resolveIntent(t.ownerNode)
	}
	runInfo := RunInfoFrom(ctx)
	if intentNode == nil {
		resolveIntent(runInfo.IntentID)
	}
	if intentNode == nil {
		intentID = 0
	}
	routeID := int64(0)
	if intentNode != nil {
		routeID = db.ParseIntentRoute(intentNode).RouteID
	}

	evidenceRefs, err := db.NormalizeEvidenceRefs(t.normalizeEvidenceRefPaths(it.EvidenceRefs))
	if err != nil {
		return nil, 0, err
	}
	sourceIDs := pidList(it.SourceActivityIDs)
	observationIDs := pidList(it.ObservationIDs)
	claimIDs := pidList(it.ClaimIDs)
	hypothesisIDs := pidList(it.HypothesisIDs)
	validationActions := trimmedStrings(it.ValidationActions)
	nextActions := trimmedStrings(it.NextActions)

	confidence := strings.TrimSpace(it.Confidence)
	if factType == db.FactTypeClaim {
		if confidence == "" {
			confidence = "inferred"
		}
		if confidence != "observed" && confidence != "inferred" {
			return nil, 0, fmt.Errorf("confidence 只能是 observed 或 inferred")
		}
	}
	if factType == db.FactTypeHypothesis && len(validationActions) == 0 {
		if len(nextActions) > 0 {
			validationActions = append(validationActions, nextActions...)
		} else if len(sourceIDs)+len(evidenceRefs)+len(observationIDs)+len(claimIDs) > 0 {
			// No validation step and no next action: the claim is an observation of
			// what was seen, not a testable hypothesis. Keep the knowledge instead of
			// rejecting the write; claim-only provenance becomes node refs.
			if len(sourceIDs) == 0 && len(evidenceRefs) == 0 && len(observationIDs) == 0 {
				for _, id := range claimIDs {
					evidenceRefs = append(evidenceRefs, "node:"+itoa64(id))
				}
				var err error
				evidenceRefs, err = db.NormalizeEvidenceRefs(evidenceRefs)
				if err != nil {
					return nil, 0, err
				}
			}
			factType = db.FactTypeObservation
		}
	}

	for _, ref := range evidenceRefs {
		parsed, _ := db.ParseEvidenceRef(ref)
		if err := t.validateEvidenceRef(ctx, parsed); err != nil {
			return nil, 0, err
		}
	}

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
	if confidence != "" {
		payload["confidence"] = confidence
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
	if it.NeedHuman {
		// Recorded so the hand-off survives a restart and is visible to the planner
		// and the human, not only to the in-memory WriteCounts of this run.
		payload["need_human"] = true
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
		if len(sourceIDs) == 0 && len(evidenceRefs) == 0 && len(observationIDs) == 0 && len(claimIDs) == 0 {
			return nil, 0, fmt.Errorf("claim 必须引用 observation（observation_ids）、claim（claim_ids）或 evidence_refs / source_activity_ids")
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
		// Auto-Triager: a finding whose evidence was never corroborated (text only,
		// state verifying) is stored, but it must not be able to prove a goal —
		// otherwise an unverified guess still ends the task.
		if ts := FindingTriageState(n); ts == TriageVerifying || ts == TriageRejected {
			return fmt.Errorf("漏洞节点 #%d 分诊状态为 %q：证据尚未核实（无绑定流量/带外回调），不能作为证明目标的已确认证据", n.ID, ts)
		}
		// A version-bound confirmation only certifies the evidence it judged. If the
		// evidence moved on (proof traffic removed, a new binding added), the old
		// confirmed verdict must not keep proving a goal the current evidence no longer
		// supports. triage_evidence_version = 0 means unbound (legacy / human verdict).
		if stale := staleTriageVersion(n); stale != "" {
			return fmt.Errorf("漏洞节点 #%d %s：漏洞证据已变更，请重新核验后再用作证明", n.ID, stale)
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

// FindingTriageState reads a finding node's Auto-Triager state. Missing/empty =
// confirmed, so every pre-existing finding keeps proving goals.
func FindingTriageState(n *db.Node) string {
	if n == nil || n.Kind != db.KindFinding || len(n.Payload) == 0 {
		return TriageConfirmed
	}
	var p struct {
		TriageState string `json:"triage_state"`
	}
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		return TriageConfirmed
	}
	switch st := strings.ToLower(strings.TrimSpace(p.TriageState)); st {
	case "":
		return TriageConfirmed
	default:
		return st
	}
}

// validateIntentAnchor is the looser lineage boundary used by add_intent:
// an intent may derive from tentative knowledge (open/supported hypothesis,
// pending finding_candidate) because the intent is what validates it. Goal
// proof (validateProofAnchor) stays strict. Checkpoints, the task root, rejected/
// expired nodes and non-inheritable source nodes are never valid anchors.
func (t *ToolSet) validateIntentAnchor(n *db.Node) error {
	if n == nil {
		return fmt.Errorf("节点不存在")
	}
	if n.Kind == db.KindFinding {
		if n.State != "confirmed" {
			return fmt.Errorf("漏洞节点 #%d 状态为 %q，只有 confirmed 漏洞能作为意图锚点", n.ID, n.State)
		}
		return nil
	}
	if n.Kind != db.KindFact {
		return fmt.Errorf("节点 #%d 是 %q，不能作为意图锚点", n.ID, n.Kind)
	}
	if n.State == db.StateOrigin {
		return fmt.Errorf("节点 #%d 是任务根事实，不能作为意图锚点", n.ID)
	}
	if n.State != "confirmed" {
		return fmt.Errorf("节点 #%d 状态为 %q，已否定节点不能作为意图锚点", n.ID, n.State)
	}
	ft := n.FactType()
	p := db.ParseFactPayload(n.Payload)
	switch ft {
	case db.FactTypeObservation, db.FactTypeClaim, db.FactTypeLegacyUnknown, db.FactTypeDecision:
	case db.FactTypeHypothesis:
		state := strings.ToLower(strings.TrimSpace(p.State))
		if state == "" {
			state = "open"
		}
		if state != "open" && state != "supported" {
			return fmt.Errorf("hypothesis #%d 状态为 %s，只有 open/supported 假设能派生验证意图", n.ID, state)
		}
	case db.FactTypeFindingCandidate:
		state := strings.ToLower(strings.TrimSpace(p.ValidationState))
		if state == "" {
			state = "pending"
		}
		if state != "pending" {
			return fmt.Errorf("finding_candidate #%d 的 validation_state 为 %s，只有 pending 候选能派生验证意图", n.ID, state)
		}
	case db.FactTypeCheckpoint:
		return fmt.Errorf("节点 #%d 是 checkpoint，不能作为意图锚点", n.ID)
	default:
		return fmt.Errorf("节点 #%d 的 fact_type 是 %s，不能作为意图锚点", n.ID, ft)
	}
	if db.IsFactExpired(p, time.Now()) {
		return fmt.Errorf("节点 #%d 已超过 valid_until 有效期，不能作为意图锚点", n.ID)
	}
	if n.Inherited {
		if ok, why := db.CanInheritFact(n, time.Now()); !ok {
			return fmt.Errorf("节点 #%d 来自关联任务，但受继承策略限制（%s），不能作为意图锚点", n.ID, why)
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

// normalizeArtifactPath folds an absolute artifact path that points inside one of
// this run's artifact roots back to the clean relative form the graph stores.
// Windows drive form and the WSL /mnt/<drive>/... form are the same path. Paths
// outside every root are returned unchanged and are rejected by
// db.ValidateArtifactPath because they remain absolute.
func (t *ToolSet) normalizeArtifactPath(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return raw
	}
	key := artifactCompareKey(p)
	for _, root := range t.artifactRoots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		rootKey := strings.TrimSuffix(artifactCompareKey(root), "/")
		if rootKey == "" {
			continue
		}
		lowerKey, lowerRoot := strings.ToLower(key), strings.ToLower(rootKey)
		if !strings.HasPrefix(lowerKey, lowerRoot+"/") {
			continue
		}
		rel := key[len(rootKey)+1:]
		if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains("/"+rel+"/", "/../") {
			continue
		}
		return rel
	}
	return p
}

// normalizeEvidenceRefPaths rewrites artifact refs to their root-relative form
// before structural validation; other ref kinds pass through untouched.
func (t *ToolSet) normalizeEvidenceRefPaths(refs []string) []string {
	if len(refs) == 0 || len(t.artifactRoots) == 0 {
		return refs
	}
	out := make([]string, len(refs))
	for i, ref := range refs {
		kind, id, ok := strings.Cut(strings.TrimSpace(ref), ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(kind), "artifact") {
			out[i] = ref
			continue
		}
		out[i] = "artifact:" + t.normalizeArtifactPath(id)
	}
	return out
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

// staleTriageVersion reports a non-empty reason when a finding's confirmation was
// bound to an evidence version that no longer matches. It reads the finding's own
// payload: triage_evidence_version is written next to triage_state, and
// evidence_version is mirrored into the payload by the binding path.
// ConfirmationIsStale reports whether a finding node's automatic confirmation was
// bound to an evidence version that no longer matches. Exported for the host's
// regression tests; the goal-proof gate uses the same predicate.
func ConfirmationIsStale(n *db.Node) bool { return staleTriageVersion(n) != "" }

func staleTriageVersion(n *db.Node) string {
	if n == nil || len(n.Payload) == 0 {
		return ""
	}
	var p struct {
		TriageEvidenceVersion int64 `json:"triage_evidence_version"`
		EvidenceVersion       int64 `json:"evidence_version"`
	}
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		return ""
	}
	if p.TriageEvidenceVersion <= 0 {
		return "" // unbound: legacy or human verdict
	}
	if p.TriageEvidenceVersion != p.EvidenceVersion {
		return "的确认版本 " + itoa64(p.TriageEvidenceVersion) + " 与当前证据版本 " + itoa64(p.EvidenceVersion) + " 不一致"
	}
	return ""
}

func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}

// RevalidateProofEvidence re-runs the evidence rules that can change BETWEEN the
// caller's pre-check and the prove transaction: state, expiry, and (for findings) the
// triage verdict and the evidence version that verdict was bound to. It is the
// in-transaction half of validateProofAnchor.
func RevalidateProofEvidence(kind, state string, payload []byte) error {
	switch kind {
	case db.KindFinding:
		if state != "confirmed" {
			return fmt.Errorf("漏洞节点状态为 %q，只有 confirmed 漏洞能作为已确认证据", state)
		}
		n := &db.Node{Kind: kind, State: state, Payload: payload}
		if ts := FindingTriageState(n); ts == TriageVerifying || ts == TriageRejected {
			return fmt.Errorf("分诊状态为 %q：证据已不再被确认为可证明目标", ts)
		}
		if stale := staleTriageVersion(n); stale != "" {
			return fmt.Errorf("%s", stale)
		}
		return nil
	case db.KindFact:
		if state == db.StateOrigin {
			return fmt.Errorf("任务根事实不能作为已确认证据")
		}
		n := &db.Node{Kind: kind, State: state, Payload: payload}
		if ft := n.FactType(); !anchorableFactType(ft) {
			return fmt.Errorf("fact_type 为 %s，不能证明目标", ft)
		}
		if db.IsFactExpired(db.ParseFactPayload(payload), time.Now()) {
			return fmt.Errorf("已超过 valid_until 有效期")
		}
		return nil
	default:
		return fmt.Errorf("节点类型 %q 不能作为已确认证据", kind)
	}
}

// RevalidateProofEvidenceInTx is RevalidateProofEvidence plus the cross-task
// inheritance policy for evidence inherited from a DIRECT SOURCE task. The caller's
// pre-check reads the node through the source view; inside the transaction the same
// node is identified by id alone, so the policy (sensitivity, validity, fact type)
// must be re-applied there instead of trusting the earlier read.
func RevalidateProofEvidenceInTx(kind, state string, payload []byte, inherited bool) error {
	if err := RevalidateProofEvidence(kind, state, payload); err != nil {
		return err
	}
	if !inherited || kind != db.KindFact {
		return nil
	}
	if ok, why := db.CanInheritFact(&db.Node{Kind: kind, State: state, Payload: payload}, time.Now()); !ok {
		return fmt.Errorf("来源任务的证据受继承策略限制（%s），不能作为已确认证据", why)
	}
	return nil
}
