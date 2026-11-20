package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// ArbitrationSystemPrompt is deliberately separate from the Slow Path judge
// prompt: this run judges a RELATIONSHIP between two workers (who should keep a
// resource), not whether one worker is making progress.
const ArbitrationSystemPrompt = `你是授权渗透测试系统的资源仲裁者。你只判断两个 Worker 之间的资源请求应如何处理。你不执行探测、不修改任务图、不直接释放容器；你只输出一个 JSON 判决。

判决规则（Lazy：默认保持原状）：
- 请求方被同一个接收方阻塞，且接收方没有有效推进、已经空闲或即将结束 → 允许 release。
- 请求方和接收方都在有效推进 → keep。
- 接收方空转、循环或已经不再服务原意图，且继续占用资源阻碍请求方 → 可 terminate 接收方。
- 证据不足 → keep。
- 只有接收方可以被 terminate；target_intent_id 必须是请求的接收方。

只输出 JSON，不要输出解释或 markdown：
{"decision":"keep|release|terminate","target_intent_id":<接收方 intent id>,"reason":"一句话依据"}`

// ArbitrationReport is the only output the arbitrator may produce.
type ArbitrationReport struct {
	Decision       string `json:"decision"`
	TargetIntentID int64  `json:"target_intent_id"`
	Reason         string `json:"reason"`
}

func (r ArbitrationReport) Validate() error {
	switch r.Decision {
	case "keep", "release", "terminate":
	default:
		return fmt.Errorf("未知 decision %q", r.Decision)
	}
	if r.TargetIntentID <= 0 {
		return fmt.Errorf("target_intent_id 必须是接收方 intent id")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("reason 不能为空")
	}
	return nil
}

// ParseArbitrationReport accepts a bare JSON object or one fenced block.
func ParseArbitrationReport(text string) (ArbitrationReport, error) {
	var report ArbitrationReport
	if err := parseJSONObject(text, &report); err != nil {
		return report, err
	}
	if err := report.Validate(); err != nil {
		return report, err
	}
	return report, nil
}

// NewWatchdogWithPrompt builds a read-only judge with a fixed system prompt
// instead of the editable Slow Path prompt. Used by resource arbitration.
func NewWatchdogWithPrompt(prov llm.Provider, systemPrompt, workDir string, tools []actool.CoreTool, maxTurns int, runTimeout time.Duration, window int) *Watchdog {
	return newWatchdogRunner(prov, "watchdog", workDir, systemPrompt, tools, maxTurns, runTimeout, window)
}

// AnalyzeArbitration runs one arbitration judgment over the supplied snapshot.
func (w *Watchdog) AnalyzeArbitration(ctx context.Context, runID string, snapshot json.RawMessage) (ArbitrationReport, error) {
	var report ArbitrationReport
	if w == nil || w.prov == nil {
		return report, fmt.Errorf("仲裁 Agent 没有可用的模型配置")
	}
	if len(snapshot) == 0 {
		return report, fmt.Errorf("仲裁快照为空")
	}
	system := w.promptOverride
	if strings.TrimSpace(system) == "" {
		system = ArbitrationSystemPrompt
	}
	input := "请仲裁下面这条资源请求。只输出约定的 JSON 对象。\n\n" + string(snapshot)
	text, err := w.runJudge(ctx, "arb-"+runID, system, input)
	if err != nil {
		return report, err
	}
	report, err = ParseArbitrationReport(text)
	if err != nil {
		return report, fmt.Errorf("%w: 解析仲裁失败: %v（原文：%s）", ErrWatchdogReport, err, firstLine(text, 500))
	}
	return report, nil
}
