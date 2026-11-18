package server

import (
	"errors"
	"strings"

	"github.com/Autumn-27/artex/agent"
)

// Provider error kinds shown in the system audit. The task model chain owns the
// recovery: deterministic failures move to the next profile, transient ones
// retry and then fail over, and an exhausted chain parks the task in the
// concurrency queue. This classifier only labels the final failure for humans.
const (
	providerErrorQuota        = "quota"
	providerErrorAuth         = "auth"
	providerErrorRateLimit    = "rate_limit"
	providerErrorServer       = "server_error"
	providerErrorNetwork      = "network"
	providerErrorTimeout      = "timeout"
	providerErrorChainExhaust = "chain_exhausted"
)

// classifyProviderError unwraps the task router and recognizes only explicit
// provider signals. A generic tool timeout is not a provider error; the status
// and phrase checks below are narrow on purpose to avoid mislabeling tool output.
func classifyProviderError(err error) string {
	if err == nil {
		return ""
	}
	var taskErr *taskLLMError
	if errors.As(err, &taskErr) && taskErr.chainExhausted {
		return providerErrorChainExhaust
	}
	msg := strings.ToLower(err.Error())
	if agent.IsQuotaExhaustedMessage(msg) {
		return providerErrorQuota
	}
	switch {
	case hasAny(msg, "status 401", "status=401", " 401 ", "unauthorized", "invalid api key",
		"authentication failed", "authentication error", "invalid_api_key", "forbidden"):
		return providerErrorAuth
	case hasAny(msg, "status 402", "status=402", " 402 ", "payment required", "insufficient balance",
		"insufficient_quota", "billing", "credit"):
		return providerErrorQuota
	case hasAny(msg, "status 429", "status=429", " 429 ", "rate limit", "too many requests",
		"requests per minute", "tokens per minute", "rpm", "tpm"):
		return providerErrorRateLimit
	case hasAny(msg, "status 500", "status 502", "status 503", "status 504",
		" 500 ", " 502 ", " 503 ", " 504 ", "internal server error", "bad gateway",
		"service unavailable", "upstream error", "overloaded"):
		return providerErrorServer
	case hasAny(msg, "context deadline exceeded", "request timeout", "timed out", "timeout"):
		return providerErrorTimeout
	case hasAny(msg, "connection reset", "connection refused", "no such host", "network is unreachable",
		"tls handshake", "eof", "broken pipe", "dial tcp", "network error"):
		return providerErrorNetwork
	}
	return ""
}

func hasAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// providerErrorSummary is the human-facing one-liner for the system audit.
func providerErrorSummary(kind string) string {
	switch kind {
	case providerErrorQuota:
		return "供应商余额或额度不足"
	case providerErrorAuth:
		return "供应商鉴权失败"
	case providerErrorRateLimit:
		return "供应商限流"
	case providerErrorServer:
		return "供应商服务端错误"
	case providerErrorNetwork:
		return "与供应商的网络连接失败"
	case providerErrorTimeout:
		return "供应商请求超时"
	case providerErrorChainExhaust:
		return "任务模型配置链已耗尽"
	default:
		return "供应商错误"
	}
}
