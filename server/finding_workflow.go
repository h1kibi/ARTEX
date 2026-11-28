package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) seedFindingWorkflowTools() {
	const hostSearchDescriptionFlag = "finding_workflow_tools_v3_host_search_description"
	if value, _, _ := s.m.pg.GetSetting(hostSearchDescriptionFlag); value != "true" {
		// Only replace the original built-in text. A user-edited description is
		// authoritative and must survive upgrades.
		legacy := "查询记录代理已抓取的目标流量（必须指定 host，可再按 URL 子串或正文关键词过滤）。body_contains 会在已抓取的请求/响应头与正文中做全文搜索，支持任意子串和中文（至少 3 个字符），可用来找响应里的密码、密钥、报错、内网地址等。仅返回极轻量索引(id/method/url/status/resp_len)，不含任何响应内容。默认只返回 3 条、每页最多 10 条；结果多时用 page 翻页（page=0 起）；要看某条的请求/响应原文用 traffic_get(id)。回看已访问资源、找端点先用它，避免重复 curl 同一 URL。"
		if _, err := s.m.pg.Exec(`UPDATE tools SET description=$1,updated_at=now() WHERE key='traffic_search' AND system AND description=$2`, traffic.TrafficSearchDescription, legacy); err != nil {
			// Log and leave the flag unset so the next startup retries; do not
			// return, or a transient error here would also skip the reporter
			// migration below — the two are independent.
			log.Printf("[evidence] upgrade traffic_search description: %v", err)
		} else {
			_ = s.m.pg.SetSetting(hostSearchDescriptionFlag, "true")
		}
	}
	const flag = "finding_workflow_tools_v2_reporter"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	for _, key := range []string{"report_finding", "add_hint", "add_task_hint"} {
		row, err := s.m.pg.GetTool(key)
		if err != nil {
			log.Printf("[evidence] load %s: %v", key, err)
			return
		}
		if row == nil || !row.System {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(row.Schema, &schema); err != nil {
			log.Printf("[evidence] invalid schema for %s: %v", key, err)
			return
		}
		if schema == nil {
			log.Printf("[evidence] missing object schema for %s", key)
			return
		}
		props := objectProperty(schema, "properties")
		if key == "report_finding" {
			if _, exists := props["evidence_hint_id"]; !exists {
				props["evidence_hint_id"] = map[string]any{"type": "integer", "description": "可选：本任务中对应此漏洞的 hint ID；读取该提示保存的 traffic_refs 一并绑定，无提示时省略"}
			}
		} else {
			if _, exists := props["traffic_refs"]; !exists {
				props["traffic_refs"] = agent.HintTrafficSchema()
			}
			hints := objectProperty(props, "hints")
			if _, exists := hints["type"]; !exists {
				hints["type"] = "array"
			}
			items := objectProperty(hints, "items")
			if _, ok := items["type"]; !ok {
				items["type"] = "object"
			}
			itemProps := objectProperty(items, "properties")
			for name, value := range map[string]any{"text": strParam("提示内容"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()} {
				if _, exists := itemProps[name]; !exists {
					itemProps[name] = value
				}
			}
		}
		raw, _ := json.Marshal(schema)
		result, err := s.m.pg.Exec(`UPDATE tools SET schema=$2::jsonb,updated_at=now() WHERE key=$1 AND system AND schema=$3::jsonb`, key, string(raw), string(row.Schema))
		if err != nil {
			log.Printf("[evidence] upgrade %s: %v", key, err)
			return
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return
		} // preserve concurrent user edits
	}
	// Upgrade only the original default binding. Customized lists and enabled
	// flags survive; the one-time flag also preserves future user unbinding.
	readers := `["worker","reporter"]`
	for _, key := range []string{"traffic_search", "traffic_get", "traffic_blob"} {
		if _, err := s.m.pg.Exec(`UPDATE tools SET agents=$2::jsonb WHERE key=$1 AND system AND (agents='["worker"]'::jsonb OR (agents @> '["worker","planner","mainagent","auto","pentest"]'::jsonb AND jsonb_array_length(agents)=5))`, key, readers); err != nil {
			return
		}
	}
	if _, err := s.m.pg.Exec(`UPDATE tools SET agents=$1::jsonb WHERE key='get_finding_traffic' AND system AND agents @> '["auto","reporter"]'::jsonb AND jsonb_array_length(agents)=2`, `["auto","reporter","worker","planner","mainagent","pentest"]`); err != nil {
		return
	}
	// Replace the previous code default only; preserve customized binding lists.
	if _, err := s.m.pg.Exec(`UPDATE tools SET agents='["reporter"]'::jsonb WHERE key='bind_finding_traffic' AND system AND agents @> '["worker","planner","mainagent","auto","pentest"]'::jsonb AND jsonb_array_length(agents)=5`); err != nil {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{"bind_finding_traffic"}); err != nil {
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

func objectProperty(parent map[string]any, key string) map[string]any {
	value, ok := parent[key].(map[string]any)
	if !ok {
		value = map[string]any{}
		parent[key] = value
	}
	return value
}

// agentFindingTrafficAccess authorizes an evidence tool call and returns the
// CANONICAL findings.id it resolved. id may be either number a caller holds — the
// standalone record id or the exploration node id — because report_finding prints
// both and models mix them up; failing on the distinction lost confirmed findings
// to a bookkeeping detail. A rejected call returns an error naming both accepted
// forms so the retry succeeds instead of guessing.
// idKind says which numbering the caller supplied. The two sequences are
// independent, so an explicit kind is the only unambiguous way to address a finding:
// "either sequence" resolution silently picks the record id when a node id happens to
// coincide with another finding's record id.
type idKind int

const (
	idAny  idKind = iota // legacy: resolve across both spaces (logged when ambiguous)
	idNode               // the caller holds an exploration node id
	idRec                // the caller holds a findings.id
)

// agentFindingTrafficAccessTyped resolves and authorizes one evidence tool call.
func (s *Server) agentFindingTrafficAccessTyped(ctx context.Context, id int64, kind idKind, write bool) (int64, error) {
	if id <= 0 {
		return 0, errors.New("漏洞编号必须为正整数（finding_id 为漏洞记录编号，finding_node_id 为探索节点编号）")
	}
	ri := agent.RunInfoFrom(ctx)
	// A session without a task has no authority to change evidence: without this
	// gate a platform-level conversation could rewrite any finding's report or bind
	// traffic to it. Read-only lookups (get_finding_traffic) stay available.
	if write && ri.TaskID <= 0 {
		return 0, errors.New("当前会话未绑定任务，不能修改漏洞报告或绑定流量证据；请在任务触发的会话中操作")
	}
	var findingID int64
	var err error
	switch kind {
	case idNode:
		findingID, err = s.m.pg.FindingIDByNodeIDInTask(id, ri.TaskID)
		if err == nil && findingID == 0 {
			return 0, fmt.Errorf("%w：节点 #%d 不是本任务的漏洞节点。请确认编号来源：finding_node_id 是探索节点编号，finding_id 是漏洞记录编号（两者不能互填）", db.ErrFindingNotFound, id)
		}
	case idRec:
		findingID, err = s.m.pg.FindingIDByRecordID(id, ri.TaskID)
		if err == nil && findingID == 0 {
			// Name both accepted forms: the caller may simply have used the wrong
			// parameter, and making that obvious beats sending it hunting for a third id.
			return 0, fmt.Errorf("%w：漏洞记录 #%d 不存在。请确认编号来源：finding_id 是漏洞记录编号，finding_node_id 是探索节点编号（两者不能互填）", db.ErrFindingNotFound, id)
		}
	default:
		// Legacy callers (older prompts, UI paths) still send one bare number. It is
		// resolved as before — task-scoped when a task is known — and the ambiguity is
		// logged in db.FindingIDForAnyIDInTask.
		findingID, err = s.m.pg.FindingIDForAnyIDInTask(id, ri.TaskID)
	}
	if err != nil {
		return 0, err
	}
	if findingID == 0 {
		return 0, fmt.Errorf("%w：finding_id=%d。请用 report_finding 返回的 finding_id 或 finding_node_id，或 list_task_findings / get_task_node_detail 里的编号", db.ErrFindingNotFound, id)
	}
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		return 0, err
	}
	if f == nil {
		return 0, fmt.Errorf("%w：finding_id=%d", db.ErrFindingNotFound, id)
	}
	// Task identity comes from the RUN, never from the tool arguments: a model could
	// otherwise name any task and read or overwrite that task's findings.
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
		task := s.m.ResolveTask(strconv.FormatInt(ri.TaskID, 10))
		if task == nil {
			return 0, errors.New("任务不存在")
		}
		_, inherited, allowed := findingProvenanceInTask(task, f.TaskID)
		if !allowed {
			return 0, errors.New("当前任务不可读取该漏洞")
		}
		if write && inherited {
			return 0, errors.New("继承漏洞的流量证据只读，请到来源任务修改")
		}
	}
	return findingID, nil
}

// agentFindingTrafficAccess is the legacy entry: an id of unknown kind.
func (s *Server) agentFindingTrafficAccess(ctx context.Context, id int64, write bool) (int64, error) {
	return s.agentFindingTrafficAccessTyped(ctx, id, idAny, write)
}

func (s *Server) toolBindFindingTraffic() actool.CoreTool {
	return wrTool("bind_finding_traffic", "为已登记漏洞补绑经核实的真实 HTTP 流量。漏洞编号二选一：finding_id（漏洞记录编号）或 finding_node_id（探索节点编号）；两者给哪一个就用哪一个的编号空间解析，不会互相顶替。同批引用全部成功或全部失败，重复引用不覆盖已有说明。补绑会使已有报告标记待更新；不要为补包重新探测或重复创建漏洞。",
		objSchema(map[string]any{
			"finding_id":      intParam("漏洞记录编号（findings.id，report_finding 返回的 finding_id）"),
			"finding_node_id": intParam("探索节点编号（exploration_nodes.id，report_finding 返回的 finding_node_id）"),
			"traffic_refs":    agent.HintTrafficSchema(),
		}, "traffic_refs"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			if !s.m.pg.GetBool(settingAgentTrafficBinding, false) {
				return actool.Errorf("Agent 自动绑定流量已关闭；请在系统设置开启，或使用页面人工绑定。"), nil
			}
			var args struct {
				FindingID     json.RawMessage `json:"finding_id"`
				FindingNodeID json.RawMessage `json:"finding_node_id"`
				Refs          []db.TrafficRef `json:"traffic_refs"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			id, err := s.resolveFindingArg(ctx, args.FindingID, args.FindingNodeID, true)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(args.Refs) == 0 {
				return actool.Errorf("补绑需要至少一条已核实的 traffic_refs；无流量无需调用此工具"), nil
			}
			list, err := s.evidenceStore().Bind(ctx, id, args.Refs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(trafficSummary(list))
		})
}

// resolveFindingArg turns the two optional id arguments of an evidence tool into a
// canonical findings.id, honouring which numbering the caller used. Supplying both
// is refused rather than guessed: they are different numbers for the same finding,
// so accepting both would only hide a caller bug.
//
// A READ that supplies only `finding_id` keeps the legacy resolution: older prompts
// and UI paths pass the node id there, and refusing them would break reads that have
// always worked. That path is `idAny`, so it also goes through the ambiguity warning.
// WRITES stay strict — a misaddressed write corrupts another finding's report.
func (s *Server) resolveFindingArg(ctx context.Context, recordID, nodeID json.RawMessage, write bool) (int64, error) {
	rec, node := parseProfileID(recordID), parseProfileID(nodeID)
	switch {
	case rec > 0 && node > 0:
		return 0, fmt.Errorf("finding_id 与 finding_node_id 只能给一个（finding_id=%d 是漏洞记录编号，finding_node_id=%d 是节点编号）", rec, node)
	case node > 0:
		return s.agentFindingTrafficAccessTyped(ctx, node, idNode, write)
	case rec > 0:
		kind := idRec
		if !write {
			kind = idAny
		}
		return s.agentFindingTrafficAccessTyped(ctx, rec, kind, write)
	default:
		return 0, errors.New("必须提供 finding_id 或 finding_node_id")
	}
}
