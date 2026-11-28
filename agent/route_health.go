package agent

import (
	"fmt"
	"strings"
)

// suspendedRouteMessage implements the route-level autonomy guard for continuations
// of a PURE AUTONOMOUS route:
//
//   - two consecutive finished runs that produced neither a finding nor a
//     high-value ProgressEvent suspend the route unless the continuation cites
//     relevant evidence from outside the route (a credential/privilege fact or a
//     fact anchored to a shared target asset);
//   - no confirmed finding for four finished runs (or two runs and 40 minutes of
//     worker time) parks the route as parked_stagnant while the task still has
//     untested target assets: a stale route must yield capacity to uncovered
//     targets instead of consuming another run.
//
// Human-owned routes are exempt unconditionally — a human watching a route is the
// highest-priority invariant: no autonomous rule may suspend or silently kill it.
//
// (suspend bool, message string, err error): suspend=true means add_intent must
// reject the continuation with message.
func (t *ToolSet) suspendedRouteMessage(routeID int64, effort string, routeAssetIDs []int64, parents []int64) (bool, string, error) {
	if t.ts == nil || routeID <= 0 {
		return false, "", nil
	}
	health, err := t.ts.RouteHealth(routeID)
	if err != nil {
		return false, "", fmt.Errorf("检查路线健康度失败：%w", err)
	}
	// 人工路线完全豁免；MainAgent 代人类操作（t.worker == "human"）同理——它的
	// 意图本身就是人工直投，自治挂起规则不能反过来拦人的手。
	if t.worker == "human" || health.HumanInvolved {
		return false, "", nil
	}
	if health.ConsecutiveDryRuns >= dryRunSuspensionThreshold {
		outside, err := t.ts.HasRelevantOutsideEvidence(routeID, routeAssetIDs, parents)
		if err != nil {
			return false, "", fmt.Errorf("检查跨路线新证据失败：%w", err)
		}
		if outside {
			return false, "", nil // 有跨路线相关证据 → 重激活该路线
		}
		return true, fmt.Sprintf(
			"路线 #%d 已连续 %d 次跑干（既无 finding 也无高价值 ProgressEvent），本次接续的 parent_ids 也没有引用可解锁的外部证据。"+
				"挂起路线只接受两类外部证据：①来自其他路线的凭据（credential/token/secret）或提权事实；②锚定本路线同一目标资产的新外部 fact/finding。"+
				"普通无关资产的观察 fact 不能解锁。请改为："+
				"\n 1) 挂起该路线（state 记 exhausted/blocked 已满足），转派一条【机理不同】的新路线（另一入口面/另一类资产/另一条利用链）；"+
				"\n 2) 若计划用 effort=%s 在同一路线上继续，先在 parent_ids 里填上确实来自其他路线的凭据/提权节点，或同目标资产的新 fact/finding id；"+
				"\n 3) 若这是人工盯盘路线，人工可通过 Worker 消息恢复该意图——人工介入的路线不受此限制。",
			routeID, health.ConsecutiveDryRuns, strings.TrimSpace(effort)), nil
	}
	// parked_stagnant：长尾无新 finding 的路线在仍有未测目标时让位。人工路线已在
	// 上方无条件放行；这里只剩纯自治路线。
	if health.RunsSinceLastFinding >= 4 || (health.RunsSinceLastFinding >= 2 && health.WorkerSeconds >= 2400) {
		if t.as == nil || t.taskID <= 0 {
			return false, "", nil // 无资产视图时无法判断空白目标，放行
		}
		untested, untestedTotal, err := t.as.ListUntestedAssetsWithSources(t.taskID, "", 5, 0)
		if err != nil {
			return false, "", fmt.Errorf("检查未测目标资产失败：%w", err)
		}
		if untestedTotal <= 0 {
			return false, "", nil // 所有目标至少覆盖过一轮 → 放行
		}
		outside, err := t.ts.HasRelevantOutsideEvidence(routeID, routeAssetIDs, parents)
		if err != nil {
			return false, "", fmt.Errorf("检查跨路线新证据失败：%w", err)
		}
		if outside {
			return false, "", nil
		}
		labels := make([]string, 0, len(untested))
		for _, a := range untested {
			if strings.TrimSpace(a.Label) != "" {
				labels = append(labels, fmt.Sprintf("%s(%s)", a.Label, a.Type))
			} else {
				labels = append(labels, fmt.Sprintf("#%d(%s)", a.ID, a.Type))
			}
		}
		hint := ""
		if len(labels) > 0 {
			hint = "\n优先探测的空白目标样本：" + strings.Join(labels, "、") + "。"
		}
		return true, fmt.Sprintf(
			"路线 #%d 已进入 parked_stagnant 冷却让位状态：连续 %d 棒没有产出新的确认 finding（累计 %d 棒），"+
				"而任务范围内仍有 %d 个未测目标资产。该路线继续投入的边际收益低于覆盖空白目标，确定性阻断本次续派。"+
				"%s\n请改为对 untested_targets_sample 中的空白目标派新意图；若确需重新打开该路线，在 parent_ids 中引用来自该路线之外的凭据/提权事实，或同目标资产的新外部 fact/finding。"+
				"人工介入的路线不受此限制。",
			routeID, health.RunsSinceLastFinding, health.TotalRuns, untestedTotal, hint), nil
	}
	return false, "", nil
}

// dryRunSuspensionThreshold is the number of consecutive dry runs after which a
// pure-autonomous route needs outside evidence to continue.
const dryRunSuspensionThreshold = 2
