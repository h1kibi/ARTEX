package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// sendRequest lets a worker ask another running worker in the same task to
// release/allocate a container slot. The request is delivered only at the
// receiver's next tool boundary and the requester never blocks on it.
func (t *ToolSet) sendRequest() actool.CoreTool {
	return t.writeExpTool("send_request", "向同一任务中另一条正在运行的意图(work)发起资源请求。请求不会阻塞你：立即返回 request_id，接收方在下一次工具调用前收到请求；对方的应答/释放确认同样会在你的下一次工具调用前注入。只用于容器/槽位协调，不要用它传递攻击指令。",
		obj(map[string]any{
			"to_intent_id": idp("接收方意图 id（= work 句柄）"),
			"request_type": map[string]any{
				"type": "string", "description": "请求类型",
				"enum": []string{"release_container_slot", "request_container_slot"},
			},
			"reason": str("请求原因（接收方会看到）"),
		}, "to_intent_id", "request_type", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			from, err := t.peerFrom("send_request")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				ToIntentID  json.RawMessage `json:"to_intent_id"`
				RequestType string          `json:"request_type"`
				Reason      string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			to := pid(a.ToIntentID)
			if to <= 0 {
				return actool.Errorf("to_intent_id 必填"), nil
			}
			requestID, err := t.peerOps.CreatePeerRequest(from, to, strings.TrimSpace(a.RequestType), a.Reason)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return peerResult(map[string]any{"request_id": requestID, "status": "pending"})
		})
}

// answerRequest is the receiver's reply. accepted still requires a later
// release_request once the resource is actually freed.
func (t *ToolSet) answerRequest() actool.CoreTool {
	return t.writeExpTool("answer_request", "应答一条已收到的 Worker 资源请求。accepted 表示承诺释放资源，之后还必须调用 release_request 确认实际释放；rejected 表示拒绝，请求方 10 分钟内不能再次向你请求。",
		obj(map[string]any{
			"request_id": str("请求 id（注入消息里的 request_id）"),
			"answer": map[string]any{
				"type": "string", "description": "应答",
				"enum": []string{"accepted", "rejected"},
			},
			"reason": str("可选：应答原因"),
		}, "request_id", "answer"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			receiver, err := t.peerFrom("answer_request")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				RequestID string `json:"request_id"`
				Answer    string `json:"answer"`
				Reason    string `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.RequestID) == "" {
				return actool.Errorf("request_id 必填"), nil
			}
			if err := t.peerOps.AnswerPeerRequest(receiver, a.RequestID, a.Answer, a.Reason); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return peerResult(map[string]any{"request_id": a.RequestID, "status": a.Answer})
		})
}

// cancelRequest lets the requester withdraw a request before it is answered.
func (t *ToolSet) cancelRequest() actool.CoreTool {
	return t.writeExpTool("cancel_request", "取消自己发出、尚未应答的资源请求。pending 会从接收方队列删除；delivered 会给接收方发一条取消通知；已经 accepted/rejected/released 的请求返回 too_late。取消不会触发拒绝冷却。",
		obj(map[string]any{"request_id": str("请求 id")}, "request_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			from, err := t.peerFrom("cancel_request")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				RequestID string `json:"request_id"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.RequestID) == "" {
				return actool.Errorf("request_id 必填"), nil
			}
			if err := t.peerOps.CancelPeerRequest(from, a.RequestID); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return peerResult(map[string]any{"request_id": a.RequestID, "status": "cancelled"})
		})
}

// releaseRequest is the receiver's confirmation that the resource is free.
func (t *ToolSet) releaseRequest() actool.CoreTool {
	return t.writeExpTool("release_request", "接收方在真正释放资源后确认一条 accepted 请求。请求方收到 released 后才会继续启动资源；accepted 超过 10 分钟未 released，请求方可以申请 Watchdog 仲裁。",
		obj(map[string]any{"request_id": str("请求 id")}, "request_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			receiver, err := t.peerFrom("release_request")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				RequestID string `json:"request_id"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.RequestID) == "" {
				return actool.Errorf("request_id 必填"), nil
			}
			if err := t.peerOps.ReleasePeerRequest(receiver, a.RequestID); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return peerResult(map[string]any{"request_id": a.RequestID, "status": "released"})
		})
}

// requestArbitration asks the Watchdog to judge a stuck peer request. It is
// rate-limited per requester/receiver pair.
func (t *ToolSet) requestArbitration() actool.CoreTool {
	return t.writeExpTool("request_arbitration", "当资源请求被拒绝、或 accepted 后长时间没有 released 时，申请 Watchdog 读取双方执行证据后仲裁。默认保持原状；只有请求方被阻塞、接收方没有有效推进或已空闲时才可能要求释放/终止。同一对 Worker 20 分钟内只能申请一次。",
		obj(map[string]any{
			"request_id": str("要仲裁的请求 id"),
			"reason":     str("为什么需要仲裁（会写入审计）"),
		}, "request_id", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			from, err := t.peerFrom("request_arbitration")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				RequestID string `json:"request_id"`
				Reason    string `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.RequestID) == "" {
				return actool.Errorf("request_id 必填"), nil
			}
			if err := t.peerOps.RequestPeerArbitration(from, a.RequestID, a.Reason); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return peerResult(map[string]any{"request_id": a.RequestID, "status": "requested"})
		})
}

// peerFrom resolves the current worker's intent id and checks the registry is
// actually wired. The intent is the only identity accepted from the runtime;
// model-supplied identity fields are ignored by the tool schemas.
func (t *ToolSet) peerFrom(tool string) (int64, error) {
	if t.peerOps == nil {
		return 0, fmt.Errorf("%s 当前不可用（没有接入资源请求注册表）", tool)
	}
	if t.ownerNode <= 0 {
		return 0, fmt.Errorf("%s 需要运行在一条意图(work)中", tool)
	}
	return t.ownerNode, nil
}

func peerResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}
