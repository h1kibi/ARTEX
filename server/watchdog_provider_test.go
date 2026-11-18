package server

import (
	"errors"
	"testing"
)

func TestClassifyProviderError(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"402 Payment Required: insufficient balance", providerErrorQuota},
		{"You exceeded your current quota, please check your plan and billing details.", providerErrorQuota},
		{"status 401: invalid api key", providerErrorAuth},
		{"status 429: rate limit exceeded", providerErrorRateLimit},
		{"status 502: bad gateway", providerErrorServer},
		{"dial tcp 1.2.3.4:443: connection reset by peer", providerErrorNetwork},
		{"context deadline exceeded", providerErrorTimeout},
		{"unrelated model error", ""},
	}
	for _, tc := range cases {
		if got := classifyProviderError(errors.New(tc.msg)); got != tc.want {
			t.Errorf("classify(%q)=%q want %q", tc.msg, got, tc.want)
		}
	}
	var taskErr *taskLLMError = &taskLLMError{taskID: "1", chainExhausted: true, cause: errors.New("all failed")}
	if got := classifyProviderError(taskErr); got != providerErrorChainExhaust {
		t.Fatalf("chain exhausted classification=%q", got)
	}
}
