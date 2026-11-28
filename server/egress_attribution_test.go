package server

import (
	"context"
	"strings"
	"testing"

	"path/filepath"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/traffic"
)

// The egress gate resolves per-task rules from the run tag on the connection. A
// client that reaches the proxy unattributed (taskID=0) is judged by the GLOBAL
// rules only, so the task's own allow/deny list silently does not apply. The two
// non-bash clients — the browser MCP and the custom HTTP tool — must therefore
// carry the identity too.
func TestTagOwnProxyStampsPlatformProxyOnly(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	tr := openTestTraffic(t, m)
	addr := tr.ProxyAddr()

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 77, IntentID: 5})

	// The platform proxy gets the credential.
	for _, raw := range []string{addr, strings.TrimPrefix(addr, "http://")} {
		tagged, ok := m.tagOwnProxy(ctx, raw)
		if !ok {
			t.Fatalf("%q not recognized as the platform proxy", raw)
		}
		if !strings.Contains(tagged, "artex:t77_i5@") {
			t.Fatalf("tag missing from %q", tagged)
		}
	}

	// A third-party upstream proxy is left untouched: our credential would mean
	// nothing to it and would leak the run identity.
	if tagged, ok := m.tagOwnProxy(ctx, "http://proxy.corp.example:3128"); ok || tagged != "http://proxy.corp.example:3128" {
		t.Fatalf("foreign proxy was modified: %q ok=%v", tagged, ok)
	}

	// A run with no task identity cannot be attributed; leave it alone.
	anon := context.Background()
	if tagged, ok := m.tagOwnProxy(anon, addr); ok || tagged != addr {
		t.Fatalf("anonymous run modified the proxy: %q ok=%v", tagged, ok)
	}
}

// The real custom-HTTP transport must hand the tagged proxy to the request.
func TestCustomHTTPToolUsesAttributedProxy(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	tr := openTestTraffic(t, s.m)
	t.Cleanup(func() { _ = tr.Close() })

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42, IntentID: 9})
	transport := s.httpProxyTransport(ctx, httpExec{UseRecordingProxy: true})
	if transport == nil || transport.Proxy == nil {
		t.Fatal("no proxy transport built for use_recording_proxy")
	}
	req := egressReq(t, "https://target.example/api")
	u, err := transport.Proxy(req)
	if err != nil || u == nil {
		t.Fatalf("proxy resolve: %v", err)
	}
	if u.User == nil || u.User.Username() != "artex" {
		t.Fatalf("request carries no run identity: %v", u)
	}
	pass, _ := u.User.Password()
	if pass != "t42_i9" {
		t.Fatalf("credential = %q, want t42_i9", pass)
	}
	// Without a run identity it still uses the proxy, just unattributed.
	plain := s.httpProxyTransport(context.Background(), httpExec{UseRecordingProxy: true})
	u2, err := plain.Proxy(req)
	if err != nil || u2 == nil {
		t.Fatalf("proxy resolve (anonymous): %v", err)
	}
	if u2.User != nil {
		t.Fatalf("anonymous request carried credentials: %v", u2)
	}
}

// The browser MCP's --proxy-server flag must be rewritten before the process is
// dialed, in both spellings, and left alone when it points elsewhere.
func TestMCPProxyArgsCarryRunIdentity(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	tr := openTestTraffic(t, m)
	addr := tr.ProxyAddr()

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 12, IntentID: 3})
	got := tagProxyArgs(ctx, []string{"--headless", "--proxy-server", addr, "--no-sandbox"})
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "artex:t12_i3@") {
		t.Fatalf("separate-value form not tagged: %v", got)
	}
	got = tagProxyArgs(ctx, []string{"--proxy-server=" + addr})
	if !strings.Contains(got[0], "artex:t12_i3@") {
		t.Fatalf("--flag=value form not tagged: %v", got)
	}
	foreign := []string{"--proxy-server", "http://proxy.corp.example:3128"}
	if out := tagProxyArgs(ctx, foreign); strings.Join(out, " ") != strings.Join(foreign, " ") {
		t.Fatalf("foreign proxy args modified: %v", out)
	}
}

// Per-task rules must actually reach the gate for a tagged request, and the task's
// own exclusion must not appear for an untagged one — this is what "attribution"
// buys.
func TestTaskRulesApplyOnlyToAttributedRequests(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("attribution scope", "gate", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := m.assets.CreateTaskInterceptRule(taskID, "block", "fuzzy_domain", "secret.example", "test", true); err != nil {
		t.Fatalf("create task rule: %v", err)
	}

	req := egressReq(t, "https://secret.example/x")
	if ok, reason := m.checkEgressAllowed(taskID, "secret.example", req); ok {
		t.Fatalf("task exclusion not applied to an attributed request (reason=%q)", reason)
	}
	if ok, _ := m.checkEgressAllowed(0, "secret.example", req); !ok {
		t.Fatal("untagged request was judged by task rules")
	}
}

// openTestTraffic attaches a real recording proxy to the manager so ProxyAddr and
// ProxyCACert return live values.
func openTestTraffic(t *testing.T, m *Manager) *traffic.Traffic {
	t.Helper()
	if m.traffic != nil {
		return m.traffic
	}
	tr, err := traffic.Open(filepath.Join(m.dir, "traffic"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.traffic = tr
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}
