package agent

import (
	"context"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

// bashEnv is the full BashEnv a run's tools receive: the egress proxy (tagged with
// the run's identity so recorded exchanges can be attributed — see
// traffic.ProxyURLWithTag), the CA variables that make the MITM transparent to the
// toolchains, and — on a Windows host with a WSL distro selected — the instruction
// to run every command inside that distro's native bash instead of PowerShell.
//
// taskID/intentID of 0 produce an untagged proxy URL, exactly like proxyEnv, so
// non-worker call sites keep their previous behaviour.
func bashEnv(proxyAddr, caCert string, taskID, intentID int64) []string {
	env := proxyEnv(traffic.ProxyURLWithTag(proxyAddr, taskID, intentID), caCert)
	// Three-way: a selected distro is passed through; an EXPLICIT disable is passed
	// through as the disable token so the tool layer cannot fall back to the
	// machine's default distro; "nothing configured" omits the variable entirely.
	// Omitting it on an explicit disable was the bug: the PTY backend cannot tell
	// the two apart and picked the default distro anyway.
	if distro, disabled := config.WSLBackend(); distro != "" {
		env = append(env, actool.WSLDistroEnv+"="+distro)
	} else if disabled {
		env = append(env, actool.WSLDistroEnv+"=off")
	}
	return env
}

// withTrafficScope marks ctx so traffic_search defaults to this run's task. The
// traffic package cannot import agent (agent imports traffic), so the scope rides
// on the ctx and the tool reads it back with traffic.SearchScopeFrom.
func withTrafficScope(ctx context.Context, taskID, intentID int64) context.Context {
	return traffic.TagScope(ctx, traffic.SearchScope{TaskID: taskID, IntentID: intentID})
}
