package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// wireFindingEvidenceVerification installs the background half of the Auto-Triager
// (docs §4.4 WP7). report_finding's deterministic gate can only see the report
// text: a finding with substantial prose but no re-checkable pointer lands as
// `verifying`, which is stored but cannot prove a goal. This hook re-reads what the
// finding actually references and settles the state:
//
//   - refuted  — a bound response proves the claim FALSE (a login page answering
//     200, a 401/403 refusal). The finding is demoted so it can never prove a
//     goal, and the refuting reason is recorded for the planner and the human.
//   - confirmed — a bound response shows the affected content really came back
//     (2xx without an auth bounce), or every cited oast:/traffic: pointer resolves
//     to this task's own evidence.
//   - otherwise stays `verifying` — nothing resolvable, so nothing is settled.
//
// Resolving a pointer is not proof of impact on its own, which is why the traffic
// branch now reads the response body instead of accepting the mere existence of a
// snapshot. The OAST/traffic resolution branch remains as the corroboration path
// for findings whose impact is inherent in the callback (a blind SSRF that
// reached our listener does not need a second response body).
//
// The hook never fails a report: an error just leaves the state untouched, because
// the failure mode we are guarding against is a lost finding, not a loose one.
func (s *Server) wireFindingEvidenceVerification() {
	agent.FindingEvidenceHook = func(taskID, explorationID, findingID int64, refs []string) {
		if findingID <= 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		// A verified verdict needs a positive signal, never an absence of errors.
		confirmed := false
		refuted := false
		reason := ""

		// The evidence version the verdict is computed from: the write below only
		// applies while it is still current.
		var version int64
		if traffic, err := s.m.pg.GetFindingTraffic(ctx, findingID); err == nil {
			version = traffic.Version
			if len(traffic.Bindings) > 0 {
				confirmed, refuted, reason = s.judgeBindings(ctx, traffic.Bindings)
			}
		}

		if !confirmed && !refuted {
			// Corroboration path, and ONLY for pointers that are impact-proving by
			// construction: an OAST callback shows the target actually reached us.
			//
			// A bare `traffic:`/`activity:` reference is deliberately excluded. Both
			// merely prove that some exchange or command exists — a 200 landing page is
			// an exchange, and `curl -i /login` is an activity. Confirming on existence
			// is exactly the hole the impact check exists to close, so those reports
			// stay `verifying` for a human or the retester.
			resolvable, total := 0, 0
			for _, ref := range refs {
				parsed, err := db.ParseEvidenceRef(ref)
				if err != nil || parsed.Kind != "oast" {
					continue
				}
				total++
				if s.m.oastReferenceResolvable(taskID, parsed.ID) {
					resolvable++
				}
			}
			if total > 0 && resolvable == total {
				confirmed = true
				reason = "引用的带外回调证据可回查"
			}
		}

		// Non-HTTP findings have neither traffic nor OAST references. Their real
		// evidence is the command output recorded in activity, so match the report
		// against those bytes (and any task artifact they point at).
		if !confirmed && !refuted {
			if ok, why := s.corroborateFromToolOutputs(ctx, taskID, explorationID, findingID, refs); ok {
				confirmed = true
				reason = why
			}
		}

		state := ""
		logVerb := ""
		switch {
		case refuted:
			state, logVerb = agent.TriageRejected, "复核不通过"
		case confirmed:
			state, logVerb = agent.TriageConfirmed, "复核通过"
		default:
			return
		}
		applied, err := s.m.pg.SetFindingTriageStateIfVersion(findingID, version, state)
		if err != nil {
			log.Printf("[triage] finding %d %s但状态更新失败: %v", findingID, logVerb, err)
			return
		}
		if !applied {
			// A human, a retester or new evidence settled it while this verdict was
			// being computed. Theirs wins; a stale background verdict must not
			// overwrite it.
			log.Printf("[triage] finding %d %s判定已过期（证据版本或状态已变化），未落库", findingID, logVerb)
			return
		}
		log.Printf("[triage] finding %d %s（%s）→ %s", findingID, logVerb, strings.TrimSpace(reason), state)
	}
}

// oastReferenceResolvable reports whether an oast interaction id is known AND
// owned by the given task — the same ownership rule the write boundary enforces.
func (m *Manager) oastReferenceResolvable(taskID int64, rawID string) bool {
	osrv := m.OAST()
	if osrv != nil {
		if ev, ok := osrv.Lookup(parseID(rawID)); ok {
			return ev.TaskID > 0 && (taskID <= 0 || ev.TaskID == taskID)
		}
	}
	if m.pg == nil {
		return false
	}
	owner, found, err := m.pg.OASTInteractionTask(parseID(rawID))
	return err == nil && found && owner > 0 && (taskID <= 0 || owner == taskID)
}

// judgeBindings reads a finding's bound snapshots ROLE BY ROLE.
//
// The roles are not interchangeable: `baseline` captures the "before" / authorised
// view (a 403, a login page) and `proof`/`verification` capture the claimed impact.
// Taking the first binding that yields any verdict therefore let two failures
// through:
//   - a baseline 403 read first would refute a finding that its proof snapshot
//     actually demonstrated;
//   - a plain 200 landing page read first would "prove" a finding whose proof
//     snapshot shows nothing.
//
// So the impact-bearing roles are judged on their own, and a refusal only settles
// the finding when there is no impact-bearing evidence at all.
func (s *Server) judgeBindings(ctx context.Context, bindings []db.FindingTrafficBinding) (confirmed, refuted bool, reason string) {
	// refuteReason is set ONLY by a proof/verification snapshot that positively shows
	// the claim is false. A successful `supporting` response is an observation about
	// the finding, not a refutation — treating it as one turned "evidence is not
	// conclusive" into "the vulnerability does not exist".
	var refuteReason, baselineReason, inconclusiveReason string
	impactSeen := false
	for _, b := range bindings {
		body := s.readSnapshotBody(b.Snapshot, "response")
		verdict := assessImpact(b.Snapshot, body)
		switch b.Role {
		case "baseline":
			// A control response: its refusals describe the authorised view, not the
			// claim. Remembered only as a tie-breaker when nothing else resolves.
			if verdict.Refuted && baselineReason == "" {
				baselineReason = "对照流量（baseline）：" + verdict.Reason
			}
			continue
		}
		// Only `proof` and `verification` are expected to DEMONSTRATE the claim.
		// `supporting` is a corroborating response (a nearby endpoint, a related
		// service); a 200 with a body there says nothing about the specific impact, so
		// it may not confirm on its own — and being merely successful, it must not
		// refute either.
		if b.Role == "supporting" {
			if verdict.Proven && inconclusiveReason == "" {
				inconclusiveReason = "supporting 响应成功，但 supporting 证据不足以证明所声明的影响"
			}
			continue
		}
		impactSeen = true
		if verdict.Proven {
			return true, false, "已绑定流量快照（" + b.Role + "）：" + verdict.Reason
		}
		if verdict.Refuted && refuteReason == "" {
			refuteReason = verdict.Reason
		}
		if refuteReason == "" && inconclusiveReason == "" {
			inconclusiveReason = verdict.Reason
		}
	}
	if !impactSeen {
		// Only baseline/control evidence: nothing demonstrates the claimed impact.
		if baselineReason != "" {
			return false, false, "只有对照流量，没有能够呈现受影响内容的证明快照：" + baselineReason
		}
		return false, false, "只有对照流量，没有证明快照"
	}
	if refuteReason != "" {
		return false, true, refuteReason
	}
	// Nothing proved it and nothing disproved it: stay `verifying` for a human or the
	// retester. "Not conclusive" must never be recorded as "refuted".
	if inconclusiveReason != "" {
		return false, false, inconclusiveReason
	}
	return false, false, "绑定流量未呈现所声明的影响"
}

// corroborateFromToolOutputs checks a finding against the actual output of the
// tools that ran for its intent. Only successful tool_result rows are read, plus
// the files those rows or the finding reference, all confined to this server's
// work directory. It is the non-HTTP counterpart of the traffic and OAST paths.
func (s *Server) corroborateFromToolOutputs(ctx context.Context, taskID, explorationID, findingID int64, refs []string) (bool, string) {
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil || f == nil || f.NodeID == nil || *f.NodeID <= 0 {
		return false, ""
	}
	if explorationID <= 0 {
		_ = s.m.pg.QueryRow(`SELECT exploration_id FROM exploration_nodes WHERE id=$1`, *f.NodeID).Scan(&explorationID)
	}
	if explorationID <= 0 {
		return false, ""
	}
	if taskID <= 0 && f.TaskID != nil {
		taskID = *f.TaskID
	}
	store := s.m.pg.Exploration(explorationID)
	intentID, err := store.IntentForFindingNode(*f.NodeID)
	if err != nil {
		log.Printf("[triage] finding %d 解析 intent 失败: %v", findingID, err)
		return false, ""
	}

	allRefs := append([]string{}, refs...)
	if node, nerr := store.GetNode(*f.NodeID); nerr == nil && node != nil && len(node.Payload) > 0 {
		var payload struct {
			EvidenceRefs []string `json:"evidence_refs"`
		}
		if json.Unmarshal(node.Payload, &payload) == nil {
			allRefs = append(allRefs, payload.EvidenceRefs...)
		}
	}
	var activityIDs []int64
	var artifacts []string
	seenActivity := map[int64]bool{}
	seenArtifact := map[string]bool{}
	for _, ref := range allRefs {
		parsed, perr := db.ParseEvidenceRef(ref)
		if perr != nil {
			continue
		}
		switch parsed.Kind {
		case "activity":
			id, ierr := strconv.ParseInt(parsed.ID, 10, 64)
			if ierr == nil && id > 0 && !seenActivity[id] {
				seenActivity[id] = true
				activityIDs = append(activityIDs, id)
			}
		case "artifact":
			if !seenArtifact[parsed.ID] {
				seenArtifact[parsed.ID] = true
				artifacts = append(artifacts, parsed.ID)
			}
		}
	}

	snapshots, err := store.ToolOutputsForFindingCorroboration(intentID, activityIDs, 40)
	if err != nil {
		log.Printf("[triage] finding %d 读取工具输出失败: %v", findingID, err)
		return false, ""
	}
	var corpus []string
	for _, snap := range snapshots {
		for _, text := range []string{snap.Summary, snap.Detail} {
			if text == "" {
				continue
			}
			corpus = append(corpus, text)
			for _, p := range spillOutputPaths(text) {
				if path, ok := s.confinedFile(s.m.dir, p); ok {
					if body := readFileHead(path, 256<<10); body != "" {
						corpus = append(corpus, body)
					}
				}
			}
		}
	}

	if taskID > 0 {
		taskDir := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(taskID, 10))
		roots := []string{taskDir}
		if intentID > 0 {
			roots = append([]string{filepath.Join(taskDir, "i"+strconv.FormatInt(intentID, 10))}, roots...)
		}
		for _, rel := range artifacts {
			clean, verr := db.ValidateArtifactPath(rel)
			if verr != nil {
				continue
			}
			for _, root := range roots {
				if path, ok := s.confinedFile(root, filepath.Join(root, filepath.FromSlash(clean))); ok {
					if body := readFileHead(path, 256<<10); body != "" {
						corpus = append(corpus, body)
					}
					break
				}
			}
		}
	}

	if matched, _ := agent.MatchEvidenceInOutputs(f.VulnClass, f.Summary, f.Evidence, corpus); matched {
		return true, "证据关键输出已在真实工具执行记录或任务产物中核实"
	}
	return false, ""
}

// confinedFile resolves candidate and root through symlinks, then reports whether
// candidate is a regular file inside root.
func (s *Server) confinedFile(root, candidate string) (string, bool) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	realPath, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	info, err := os.Stat(realPath)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return realPath, true
}

func readFileHead(path string, limit int64) string {
	fh, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, limit))
	if err != nil {
		return ""
	}
	return string(b)
}

// spillOutputPaths extracts the SDK spill-file paths from a truncated tool result.
func spillOutputPaths(text string) []string {
	const (
		pathPrefix = "Full output saved to  "
		pathSuffix = " </persisted-output>"
	)
	var out []string
	for {
		i := strings.Index(text, pathPrefix)
		if i < 0 {
			break
		}
		rest := text[i+len(pathPrefix):]
		j := strings.Index(rest, pathSuffix)
		if j < 0 {
			break
		}
		if p := strings.TrimSpace(rest[:j]); p != "" {
			out = append(out, p)
		}
		text = rest[j+len(pathSuffix):]
	}
	return out
}
