package agent

import "testing"

func TestParseWatchdogReport(t *testing.T) {
	valid := `{"classification":"continue","summary":"工具仍有输出","evidence":["阶段是工具","最近两分钟有结果"],"confidence":"medium","recommended_action":"none","reason":"正常长任务"}`
	report, err := ParseWatchdogReport(valid)
	if err != nil || report.Classification != WatchdogContinue || len(report.Evidence) != 2 {
		t.Fatalf("valid report=%+v err=%v", report, err)
	}
	fenced := "```json\n" + valid + "\n```"
	if _, err := ParseWatchdogReport(fenced); err != nil {
		t.Fatalf("fenced report rejected: %v", err)
	}
	withProse := "判断如下：\n" + valid + "\n以上。"
	if _, err := ParseWatchdogReport(withProse); err != nil {
		t.Fatalf("prose-wrapped report rejected: %v", err)
	}
}

func TestParseWatchdogReportRejectsInvalidContract(t *testing.T) {
	cases := []string{
		`not json`,
		`{"classification":"continue","summary":"x","recommended_action":"kill"}`,
		`{"classification":"terminate","summary":"x","recommended_action":"none"}`,
		`{"classification":"ask_user","summary":"x","recommended_action":"ask_user","confidence":"maybe"}`,
		`{"classification":"unknown","summary":"x","recommended_action":"none"}`,
		`{"classification":"continue","summary":"","recommended_action":"none"}`,
	}
	for _, text := range cases {
		if _, err := ParseWatchdogReport(text); err == nil {
			t.Errorf("invalid report accepted: %s", text)
		}
	}
}

func TestWatchdogReportValidateAllClassifications(t *testing.T) {
	cases := []struct {
		class  string
		action string
	}{
		{WatchdogContinue, WatchdogActionNone},
		{WatchdogTerminate, WatchdogActionKill},
		{WatchdogAskUser, WatchdogActionAskUser},
		{WatchdogProviderError, WatchdogActionRetryProvider},
	}
	for _, tc := range cases {
		r := WatchdogReport{Classification: tc.class, Summary: "summary", RecommendedAction: tc.action, Confidence: "high"}
		if err := r.Validate(); err != nil {
			t.Errorf("%s/%s rejected: %v", tc.class, tc.action, err)
		}
	}
}
