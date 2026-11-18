package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// ErrWatchdogReport marks a model answer that parsed or validated as the wrong
// contract. It is a failed judgment (retry), not an unavailable provider: the
// service must not open the configuration card for it.
var ErrWatchdogReport = errors.New("watchdog report invalid")

// Watchdog classification constants. The server compares these strings when it
// turns a judgment into a Fast Path action.
const (
	WatchdogContinue      = "continue"
	WatchdogTerminate     = "terminate"
	WatchdogAskUser       = "ask_user"
	WatchdogProviderError = "provider_error"

	WatchdogActionNone          = "none"
	WatchdogActionKill          = "kill"
	WatchdogActionAskUser       = "ask_user"
	WatchdogActionRetryProvider = "retry_provider"
)

// WatchdogReport is the only output the judge may produce. The runner validates
// the classification/action pair before the service sees it; an inconsistent
// answer is a failed judgment, not a silently accepted one.
type WatchdogReport struct {
	Classification    string   `json:"classification"`
	Summary           string   `json:"summary"`
	Evidence          []string `json:"evidence"`
	Confidence        string   `json:"confidence"`
	RecommendedAction string   `json:"recommended_action"`
	Reason            string   `json:"reason"`
}

// Validate enforces the contract from the施工方案 §8.1. A model that returns a
// plausible-looking but inconsistent pair must not make the Fast Path act on it.
func (r WatchdogReport) Validate() error {
	switch r.Classification {
	case WatchdogContinue:
		if r.RecommendedAction != WatchdogActionNone {
			return fmt.Errorf("continue 必须对应 recommended_action=none，实际为 %q", r.RecommendedAction)
		}
	case WatchdogTerminate:
		if r.RecommendedAction != WatchdogActionKill {
			return fmt.Errorf("terminate 必须对应 recommended_action=kill，实际为 %q", r.RecommendedAction)
		}
	case WatchdogAskUser:
		if r.RecommendedAction != WatchdogActionAskUser {
			return fmt.Errorf("ask_user 必须对应 recommended_action=ask_user，实际为 %q", r.RecommendedAction)
		}
	case WatchdogProviderError:
		if r.RecommendedAction != WatchdogActionRetryProvider {
			return fmt.Errorf("provider_error 必须对应 recommended_action=retry_provider，实际为 %q", r.RecommendedAction)
		}
	default:
		return fmt.Errorf("未知 classification %q", r.Classification)
	}
	if strings.TrimSpace(r.Summary) == "" {
		return fmt.Errorf("summary 不能为空")
	}
	switch strings.ToLower(strings.TrimSpace(r.Confidence)) {
	case "", "low", "medium", "high":
	default:
		return fmt.Errorf("confidence 只能是 low/medium/high，实际为 %q", r.Confidence)
	}
	return nil
}

// Watchdog is the read-only judge runner. It is deliberately not a ChatAgent:
// ChatAgent starts from DefaultTools (Bash/Read/Write/…), while the judge must
// see only the explicit read-only tools the Slow Path service passes in.
type Watchdog struct {
	prov       llm.Provider
	agentKey   string
	workDir    string
	tools      []actool.CoreTool
	maxTurns   int
	runTimeout time.Duration
	window     int
}

// NewWatchdog builds one judge runner. agentKey selects the editable prompt row
// (watchdog by default; a custom key can be configured) while the read-only
// tool set stays fixed. maxTurns/runTimeout are clamped here so every caller
// gets a bounded, non-runaway judge (defaults 6 turns / 120s).
func NewWatchdog(prov llm.Provider, agentKey, workDir string, tools []actool.CoreTool, maxTurns int, runTimeout time.Duration, window int) *Watchdog {
	if maxTurns <= 0 {
		maxTurns = 6
	}
	if runTimeout <= 0 {
		runTimeout = 120 * time.Second
	}
	if strings.TrimSpace(agentKey) == "" {
		agentKey = "watchdog"
	}
	return &Watchdog{prov: prov, agentKey: agentKey, workDir: workDir, tools: tools,
		maxTurns: maxTurns, runTimeout: runTimeout, window: window}
}

// Analyze runs one judgment over the supplied snapshot. The agent's final text
// must be the JSON object; anything else is returned as a parse error so the
// service can retry rather than act on prose.
func (w *Watchdog) Analyze(ctx context.Context, runID string, snapshot json.RawMessage) (WatchdogReport, error) {
	var report WatchdogReport
	if w == nil || w.prov == nil {
		return report, fmt.Errorf("Watchdog Agent 没有可用的模型配置")
	}
	if len(snapshot) == 0 {
		return report, fmt.Errorf("Watchdog 快照为空")
	}
	workdir := filepath.Join(w.workDir, "watchdog", runID)
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		return report, fmt.Errorf("创建 Watchdog 工作目录: %w", err)
	}
	// The judge has no write tools; its run directory exists only for the SDK's
	// session/tool-output plumbing. Remove it when the judgment ends so a long
	// task does not accumulate one directory per quarter-hour.
	defer os.RemoveAll(workdir)
	system := renderSystem(w.agentKey, watchdogDefaultTmpl, struct{ Now, DataDir string }{nowStr(), w.workDir})
	opts := agentcore.Options{
		Provider:       w.prov,
		SystemPrompt:   []string{system},
		Tools:          w.tools,
		PermissionMode: permission.ModeBypass,
		WorkingDir:     workdir,
		MaxTurns:       w.maxTurns,
		MaxDuration:    w.runTimeout,
		Compaction:     compactionConfig(w.window),
		ToolOutputDir:  filepath.Join(workdir, "cmd-output"),
	}
	input := "请判断下面这次运行。只输出约定的 JSON 对象。\n\n" + string(snapshot)
	text, reason, err := captureRun(ctx, opts, input, nil)
	if err != nil {
		return report, err
	}
	if reason == harness.ReasonTimeout {
		return report, fmt.Errorf("Watchdog Agent 运行超时: %w", context.DeadlineExceeded)
	}
	report, err = ParseWatchdogReport(text)
	if err != nil {
		return report, fmt.Errorf("%w: 解析 Watchdog 判断失败: %v（原文：%s）", ErrWatchdogReport, err, firstLine(text, 500))
	}
	return report, nil
}

// ParseWatchdogReport accepts a bare JSON object or one wrapped in a single
// markdown fence. It does not invent missing fields; Validate rejects them.
func ParseWatchdogReport(text string) (WatchdogReport, error) {
	var report WatchdogReport
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```JSON")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end <= start {
		return report, fmt.Errorf("没有找到 JSON 对象")
	}
	if err := json.Unmarshal([]byte(s[start:end+1]), &report); err != nil {
		return report, err
	}
	if err := report.Validate(); err != nil {
		return report, err
	}
	return report, nil
}
