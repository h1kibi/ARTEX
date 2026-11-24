package db

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Information Graph 的类型语义。物理上继续使用 kind='fact' 的探索节点；
// fact_type 只存在于 payload 中，历史节点没有该字段时按 legacy_unknown 读取。
//
// 施工方案（11-24）要求由程序校验这些类型，不能只相信模型填写的 fact_type。
const (
	FactTypeObservation      = "observation"
	FactTypeClaim            = "claim"
	FactTypeHypothesis       = "hypothesis"
	FactTypeDecision         = "decision"
	FactTypeCheckpoint       = "checkpoint"
	FactTypeFindingCandidate = "finding_candidate"
	FactTypeLegacyUnknown    = "legacy_unknown"
)

// Information Graph 敏感性与继承策略（方案 §4 / §9）。
const (
	SensitivityNormal        = "normal"
	SensitivityCredential    = "credential"
	SensitivityToken         = "token"
	SensitivitySecret        = "secret"
	SensitivityInternalFile  = "internal_file"
	SensitivityUserData      = "user_data"
	SensitivityEphemeralPort = "ephemeral_port"
	SensitivityTaskAuth      = "task_auth"

	InheritanceAuto        = "auto"
	InheritanceInheritable = "inheritable"
	InheritanceLocalOnly   = "local_only"
)

var SensitiveTags = map[string]bool{
	SensitivityCredential:    true,
	SensitivityToken:         true,
	SensitivitySecret:        true,
	SensitivityInternalFile:  true,
	SensitivityUserData:      true,
	SensitivityEphemeralPort: true,
	SensitivityTaskAuth:      true,
}

var ValidSensitivities = map[string]bool{
	SensitivityNormal:        true,
	SensitivityCredential:    true,
	SensitivityToken:         true,
	SensitivitySecret:        true,
	SensitivityInternalFile:  true,
	SensitivityUserData:      true,
	SensitivityEphemeralPort: true,
	SensitivityTaskAuth:      true,
}

var ValidInheritancePolicies = map[string]bool{
	InheritanceAuto:        true,
	InheritanceInheritable: true,
	InheritanceLocalOnly:   true,
}

// FactTypes lists the writable information types, in the order the model should
// prefer them. legacy_unknown is deliberately absent: only reads may produce it.
var FactTypes = []string{
	FactTypeObservation,
	FactTypeClaim,
	FactTypeHypothesis,
	FactTypeDecision,
	FactTypeFindingCandidate,
}

// IsWritableFactType reports whether record_fact may create a node of this type.
func IsWritableFactType(t string) bool {
	for _, v := range FactTypes {
		if v == t {
			return true
		}
	}
	return false
}

// RoutePhases are the only phase labels the route view accepts.
var RoutePhases = []string{
	"recon", "validation", "exploitation", "privilege", "lateral",
	"objective", "verification", "evidence", "cleanup",
}

func IsRoutePhase(p string) bool {
	for _, v := range RoutePhases {
		if v == p {
			return true
		}
	}
	return false
}

// RouteBudget is the cumulative budget for one Route (one attack path). A route
// spans multiple intents and worker runs; each new run inherits the remaining
// budget, it does not receive a fresh one.
type RouteBudget struct {
	MaxToolCalls   int `json:"max_tool_calls,omitempty"`
	MaxInputTokens int `json:"max_input_tokens,omitempty"`
	MaxWallSeconds int `json:"max_wall_seconds,omitempty"`
}

func (b RouteBudget) Empty() bool {
	return b.MaxToolCalls <= 0 && b.MaxInputTokens <= 0 && b.MaxWallSeconds <= 0
}

// RouteBudgetUsed is the cumulative usage recorded in a checkpoint.
type RouteBudgetUsed struct {
	ToolCalls    int   `json:"tool_calls,omitempty"`
	InputTokens  int   `json:"input_tokens,omitempty"`
	OutputTokens int   `json:"output_tokens,omitempty"`
	WallMS       int64 `json:"wall_ms,omitempty"`
}

// FactPayload is the typed view of a fact node payload. It intentionally covers
// every information type rather than defining a parallel storage model.
type FactPayload struct {
	FactType   string `json:"fact_type,omitempty"`
	Summary    string `json:"summary,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Confidence string `json:"confidence,omitempty"`

	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	SourceActivityIDs []int64  `json:"source_activity_ids,omitempty"`
	ObservationIDs    []int64  `json:"observation_ids,omitempty"`
	ClaimIDs          []int64  `json:"claim_ids,omitempty"`
	HypothesisIDs     []int64  `json:"hypothesis_ids,omitempty"`

	// Hypothesis semantic state. The physical node state remains confirmed so
	// the exploration_nodes CHECK constraint stays unchanged.
	State             string   `json:"state,omitempty"`
	ValidationState   string   `json:"validation_state,omitempty"`
	ValidationActions []string `json:"validation_actions,omitempty"`
	NextActions       []string `json:"next_actions,omitempty"`
	ProgressEvent     string   `json:"progress_event,omitempty"`
	ObservedAt        string   `json:"observed_at,omitempty"`
	ValidUntil        string   `json:"valid_until,omitempty"`
	Sensitivity       string   `json:"sensitivity,omitempty"`
	InheritancePolicy string   `json:"inheritance_policy,omitempty"`

	// Route / checkpoint fields.
	RouteID           int64           `json:"route_id,omitempty"`
	RouteKind         string          `json:"route_kind,omitempty"`
	Objective         string          `json:"objective,omitempty"`
	PathPhase         string          `json:"path_phase,omitempty"`
	ParentIntentID    int64           `json:"parent_intent_id,omitempty"`
	NextIntentID      int64           `json:"next_intent_id,omitempty"`
	CheckpointFactID  int64           `json:"checkpoint_fact_id,omitempty"`
	IntentID          int64           `json:"intent_id,omitempty"`
	RunID             string          `json:"run_id,omitempty"`
	SuccessCondition  string          `json:"success_condition,omitempty"`
	ExpectedEvidence  []string        `json:"expected_evidence,omitempty"`
	Budget            RouteBudget     `json:"budget,omitempty"`
	BudgetUsed        RouteBudgetUsed `json:"budget_used,omitempty"`
	AttemptedActions  []string        `json:"attempted_actions,omitempty"`
	ConfirmedClaimIDs []int64         `json:"confirmed_claim_ids,omitempty"`
	OpenHypothesisIDs []int64         `json:"open_hypothesis_ids,omitempty"`
	FindingIDs        []int64         `json:"finding_ids,omitempty"`
	CreatedByRun      string          `json:"created_by_run,omitempty"`
	SettlementReason  string          `json:"settlement_reason,omitempty"`
	RouteStartedAt    string          `json:"route_started_at,omitempty"`
}

// ParseFactPayload reads the typed portion of a fact payload. Missing
// fact_type is NOT inferred; callers use Node.FactType to obtain
// legacy_unknown for historical nodes.
func ParseFactPayload(raw json.RawMessage) FactPayload {
	var p FactPayload
	if len(raw) == 0 {
		return p
	}
	_ = json.Unmarshal(raw, &p)
	p.FactType = strings.TrimSpace(p.FactType)
	return p
}

// FactType returns the declared information type of a fact node. Historical
// facts without the field are readable as legacy_unknown and are never rewritten.
func (n *Node) FactType() string {
	if n == nil || n.Kind != KindFact {
		return ""
	}
	t := ParseFactPayload(n.Payload).FactType
	if t == "" {
		return FactTypeLegacyUnknown
	}
	return t
}

// IntentRoute reads the route fields stored in an intent payload. A legacy
// intent without route_id keeps its own id as the route id, which preserves the
// rule "route_id = first intent id" for old data.
type IntentRoute struct {
	RouteID          int64
	RouteKind        string
	Objective        string
	PathPhase        string
	ParentIntentID   int64
	CheckpointFactID int64
	SuccessCondition string
	ExpectedEvidence []string
	Budget           RouteBudget
	BudgetUsed       RouteBudgetUsed
	RouteStartedAt   string
}

func ParseIntentRoute(n *Node) IntentRoute {
	var r IntentRoute
	if n == nil {
		return r
	}
	var raw map[string]any
	if err := json.Unmarshal(n.Payload, &raw); err != nil {
		return r
	}
	r.RouteID = infoInt64(raw["route_id"])
	if r.RouteID <= 0 && n.Kind == KindIntent {
		r.RouteID = n.ID
	}
	r.RouteKind = infoString(raw["route_kind"])
	if r.RouteKind == "" {
		r.RouteKind = "path_stage"
	}
	r.Objective = infoString(raw["objective"])
	r.PathPhase = infoString(raw["path_phase"])
	if r.PathPhase == "" {
		r.PathPhase = infoString(raw["phase"])
	}
	r.ParentIntentID = infoInt64(raw["parent_intent_id"])
	r.CheckpointFactID = infoInt64(raw["checkpoint_fact_id"])
	r.SuccessCondition = infoString(raw["success_condition"])
	r.ExpectedEvidence = infoStrings(raw["expected_evidence"])
	r.RouteStartedAt = infoString(raw["route_started_at"])
	r.Budget = infoRouteBudget(raw["budget"])
	r.BudgetUsed = infoRouteBudgetUsed(raw["route_budget_used"])
	return r
}

// RouteID returns the route id declared by an intent or fact payload. It is 0
// when the node has no route identity.
func (n *Node) RouteID() int64 {
	if n == nil {
		return 0
	}
	if n.Kind == KindIntent {
		return ParseIntentRoute(n).RouteID
	}
	return ParseFactPayload(n.Payload).RouteID
}

func infoInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return 0
	}
}

func infoString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func infoStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		if ss, ok := v.([]string); ok {
			return append([]string(nil), ss...)
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s := infoString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func infoRouteBudget(v any) RouteBudget {
	m, ok := v.(map[string]any)
	if !ok {
		return RouteBudget{}
	}
	return RouteBudget{
		MaxToolCalls:   int(infoInt64(m["max_tool_calls"])),
		MaxInputTokens: int(infoInt64(m["max_input_tokens"])),
		MaxWallSeconds: int(infoInt64(m["max_wall_seconds"])),
	}
}

func infoRouteBudgetUsed(v any) RouteBudgetUsed {
	m, ok := v.(map[string]any)
	if !ok {
		return RouteBudgetUsed{}
	}
	return RouteBudgetUsed{
		ToolCalls:    int(infoInt64(m["tool_calls"])),
		InputTokens:  int(infoInt64(m["input_tokens"])),
		OutputTokens: int(infoInt64(m["output_tokens"])),
		WallMS:       infoInt64(m["wall_ms"]),
	}
}

// EvidenceRef is the normalized form of a checkpoint / information reference.
// The Evidence Layer is logical: traffic and artifact are the stable public
// kinds; activity/node/finding let a checkpoint reference local audit rows.
type EvidenceRef struct {
	Kind string
	ID   string
}

func (r EvidenceRef) String() string { return r.Kind + ":" + r.ID }

// ParseEvidenceRef validates one reference and splits it into kind/id.
func ParseEvidenceRef(ref string) (EvidenceRef, error) {
	ref = strings.TrimSpace(ref)
	kind, id, ok := strings.Cut(ref, ":")
	if !ok || strings.TrimSpace(kind) == "" || strings.TrimSpace(id) == "" {
		return EvidenceRef{}, fmt.Errorf("证据引用 %q 必须写成 traffic:<id>、artifact:<path>、activity:<id>、node:<id> 或 finding:<id>", ref)
	}
	kind, id = strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(id)
	if strings.IndexFunc(id, func(r rune) bool { return r == '\n' || r == '\r' || r == '\x00' }) >= 0 {
		return EvidenceRef{}, fmt.Errorf("证据引用 %q 含非法字符", ref)
	}
	switch kind {
	case "traffic":
		return EvidenceRef{Kind: kind, ID: id}, nil
	case "artifact":
		clean, err := ValidateArtifactPath(id)
		if err != nil {
			return EvidenceRef{}, err
		}
		return EvidenceRef{Kind: kind, ID: clean}, nil
	case "activity", "node", "finding":
		if _, err := strconv.ParseInt(id, 10, 64); err != nil || id == "" {
			return EvidenceRef{}, fmt.Errorf("证据引用 %q 的 %s 部分必须是数字 id", ref, kind)
		}
		return EvidenceRef{Kind: kind, ID: id}, nil
	default:
		return EvidenceRef{}, fmt.Errorf("不支持的证据引用类型 %q；可用 traffic、artifact、activity、node、finding", kind)
	}
}

// ValidateArtifactPath normalizes an artifact reference path and rejects
// absolute paths or ".." traversal outside the agent working directory.
func ValidateArtifactPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("artifact 路径不能为空")
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") || (len(p) >= 2 && p[1] == ':') {
		return "", fmt.Errorf("artifact 引用 %q 必须使用工作目录内的相对路径", raw)
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("artifact 引用 %q 不能包含 .. 路径穿越", raw)
		}
	}
	clean := strings.TrimPrefix(p, "./")
	if clean == "" || clean == "." {
		return "", fmt.Errorf("artifact 引用 %q 无效", raw)
	}
	return clean, nil
}

// NormalizeEvidenceRefs trims, validates, and deduplicates refs while preserving
// order. Empty refs are rejected so a malformed list cannot silently collapse.
func NormalizeEvidenceRefs(refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		if strings.TrimSpace(ref) == "" {
			return nil, fmt.Errorf("evidence_refs 不能包含空字符串")
		}
		parsed, err := ParseEvidenceRef(ref)
		if err != nil {
			return nil, err
		}
		norm := parsed.String()
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

// IsFactExpired reports whether a fact payload declares a valid_until timestamp
// that has already elapsed at now.
func IsFactExpired(p FactPayload, now time.Time) bool {
	if strings.TrimSpace(p.ValidUntil) == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(p.ValidUntil))
	if err != nil {
		return false
	}
	return now.After(t)
}

// CanInheritFact enforces the source, validity, and sensitivity filter for
// cross-task read-only inheritance (方案 §4 / §9).
func CanInheritFact(n *Node, now time.Time) (bool, string) {
	if n == nil || n.Kind != KindFact {
		return true, ""
	}
	if n.State == StateOrigin {
		return false, "任务根事实仅属于原任务"
	}
	p := ParseFactPayload(n.Payload)
	if IsFactExpired(p, now) {
		return false, "已超过 valid_until 有效期"
	}
	if strings.EqualFold(strings.TrimSpace(p.InheritancePolicy), InheritanceLocalOnly) {
		return false, "inheritance_policy=local_only"
	}
	ft := n.FactType()
	switch ft {
	case FactTypeCheckpoint, FactTypeDecision, FactTypeFindingCandidate:
		return false, ft + " 默认不可跨任务继承"
	case FactTypeHypothesis:
		if !strings.EqualFold(strings.TrimSpace(p.State), "supported") ||
			!strings.EqualFold(strings.TrimSpace(p.InheritancePolicy), InheritanceInheritable) {
			return false, "未验证或非显式可继承的 hypothesis 默认不可跨任务继承"
		}
	}
	sens := strings.ToLower(strings.TrimSpace(p.Sensitivity))
	if SensitiveTags[sens] && !strings.EqualFold(strings.TrimSpace(p.InheritancePolicy), InheritanceInheritable) {
		return false, "敏感或临时数据(" + sens + ")默认不可跨任务继承"
	}
	return true, ""
}

// CheckpointPayload builds the checkpoint fact payload. The caller supplies the
// route and run facts; this function only centralizes the JSON shape and the
// observed-at timestamp so engine code stays small.
func CheckpointPayload(summary, routeKind, objective, phase, runID, settlementReason string, routeID, intentID int64, confirmed, openHypotheses, findingIDs []int64, evidenceRefs, attempted, nextActions []string, used RouteBudgetUsed) map[string]any {
	p := map[string]any{
		"fact_type":           FactTypeCheckpoint,
		"summary":             summary,
		"route_id":            routeID,
		"route_kind":          routeKind,
		"objective":           objective,
		"path_phase":          phase,
		"intent_id":           intentID,
		"run_id":              runID,
		"created_by_run":      runID,
		"confirmed_claim_ids": int64Slice(confirmed),
		"open_hypothesis_ids": int64Slice(openHypotheses),
		"finding_ids":         int64Slice(findingIDs),
		"evidence_refs":       stringSlice(evidenceRefs),
		"attempted_actions":   stringSlice(attempted),
		"next_actions":        stringSlice(nextActions),
		"budget_used":         used,
		"observed_at":         time.Now().UTC().Format(time.RFC3339),
	}
	if settlementReason != "" {
		p["settlement_reason"] = settlementReason
	}
	return p
}

func int64Slice(v []int64) []int64 {
	if v == nil {
		return []int64{}
	}
	return v
}

func stringSlice(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
