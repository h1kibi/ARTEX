package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// watchdogReadToolNames is the fixed read-only tool set the Watchdog Agent may
// use. The runner passes these instances explicitly; the tools-table binding is
// for the Agent management page, not a runtime dependency.
var watchdogReadToolNames = []string{
	"get_worker_health",
	"get_task_graph",
	"get_task_node_detail",
	"list_task_findings",
	"list_task_worker_traces",
	"get_task_worker_trace",
	"search_task_worker_traces",
}

func (s *Server) watchdogReadTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolGetWorkerHealth(),
		s.toolGetTaskGraph(),
		s.toolGetTaskNodeDetail(),
		s.toolListTaskFindings(),
		s.toolListWorkerTraces(),
		s.toolGetWorkerTrace(),
		s.toolSearchWorkerTraces(),
	}
}

// taskScopedTool pins every call's task_id to the task that owns the run. A judge
// must not be able to read another task's graph or traces, even if tool output
// injects a different id. The wrapper keeps the embedded tool's schema/prompt/
// permission behavior and only rewrites/validates the task selector.
type taskScopedTool struct {
	actool.CoreTool
	taskID string
}

func (t taskScopedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var obj map[string]json.RawMessage
	if len(in) > 0 {
		if err := json.Unmarshal(in, &obj); err != nil {
			return actool.Errorf("参数必须是 JSON 对象: " + err.Error()), nil
		}
	}
	if obj == nil {
		obj = map[string]json.RawMessage{}
	}
	requested := ""
	if raw, ok := obj["task_id"]; ok {
		_ = json.Unmarshal(raw, &requested)
		if requested == "" {
			var n int64
			if json.Unmarshal(raw, &n) == nil && n > 0 {
				requested = strconv.FormatInt(n, 10)
			}
		}
	}
	requested = strings.TrimSpace(requested)
	if requested != "" && requested != t.taskID {
		return actool.Errorf("Watchdog 只能读取当前任务数据（task_id=" + t.taskID + "）"), nil
	}
	obj["task_id"], _ = json.Marshal(t.taskID)
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return t.CoreTool.Call(ctx, rewritten, tc)
}

func scopeWatchdogTools(tools []actool.CoreTool, taskID string) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, tool := range tools {
		out = append(out, taskScopedTool{CoreTool: tool, taskID: taskID})
	}
	return out
}

// toolGetWorkerHealth returns the live phase/cycle snapshot for one task. It is
// the judge's first stop: the snapshot in the user message is what woke it, and
// this tool answers what changed since.
func (s *Server) toolGetWorkerHealth() actool.CoreTool {
	return roTool("get_worker_health",
		"读取某个任务当前运行中的 worker 健康状态：阶段、当前工具、心跳、最后事件、最后一次有效写入、周期、已写入事实/资产/漏洞数量、慢速判断状态。可按 intent_id 或 run_id 过滤。只读。",
		objSchema(map[string]any{
			"task_id":   strParam("任务 id"),
			"intent_id": map[string]any{"type": "integer", "description": "可选：只查这一条意图"},
			"run_id":    strParam("可选：只查这一次运行"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID   string `json:"task_id"`
				IntentID int64  `json:"intent_id"`
				RunID    string `json:"run_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if a.TaskID == "" {
				return actool.Errorf("task_id 为必填"), nil
			}
			var out []watchdogRunDTO
			if s.watchdog != nil && s.watchdog.monitor != nil {
				for _, snap := range s.watchdog.monitor.ListRunning(a.TaskID) {
					if a.IntentID > 0 && snap.IntentID != a.IntentID {
						continue
					}
					if a.RunID != "" && snap.RunID != a.RunID {
						continue
					}
					out = append(out, watchdogRunDTOFromSnapshot(snap))
				}
			} else if s.m != nil && s.m.pg != nil {
				rows, err := s.m.pg.ListWorkerRuns(ctx, a.TaskID, true)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				for _, row := range rows {
					if a.IntentID > 0 && row.IntentID != a.IntentID {
						continue
					}
					if a.RunID != "" && row.RunID != a.RunID {
						continue
					}
					out = append(out, watchdogRunDTOFromDB(row))
				}
			}
			return jsonResult(map[string]any{"runs": out})
		})
}
