package server

import (
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

func egressReq(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{Method: http.MethodGet, URL: u, Host: u.Host}
}

// exact_url / fuzzy_url rules must be enforced at the recording proxy's egress.
// They were dead there because checkEgressAllowed dropped the request and passed
// nil for the URL list.
func TestEgressGateEnforcesURLRules(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// A global fuzzy_url block on a path segment.
	rule, err := m.pg.CreateAssetInterceptRule("fuzzy_url", "/admin/export", "禁止导出", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteAssetInterceptRule(rule.ID) })

	if allowed, _ := m.checkEgressAllowed(0, "app.example", egressReq(t, "http://app.example/admin/export?all=1")); allowed {
		t.Fatal("fuzzy_url rule not enforced at egress")
	}
	if allowed, _ := m.checkEgressAllowed(0, "app.example", egressReq(t, "http://app.example/public/index")); !allowed {
		t.Fatal("unrelated path was blocked")
	}

	// An exact_url rule matches only the full URL.
	exact, err := m.pg.CreateAssetInterceptRule("exact_url", "http://app.example/only-this", "精确拦截", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteAssetInterceptRule(exact.ID) })
	if allowed, _ := m.checkEgressAllowed(0, "app.example", egressReq(t, "http://app.example/only-this")); allowed {
		t.Fatal("exact_url rule not enforced at egress")
	}
}

// A task allow-list must restrict the egress to its own targets, and a task block
// must refuse them — both keyed off the run tag the proxy carries.
func TestEgressGateHonoursTaskRules(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("egress task rules", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskID, _ := parseTaskID(task.ID)

	allow, err := m.assets.CreateTaskInterceptRule(taskID, "allow", "fuzzy_domain", "internal.lab", "仅在范围", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.assets.DeleteTaskInterceptRule(taskID, allow.ID) })

	if allowed, _ := m.checkEgressAllowed(taskID, "app.internal.lab", egressReq(t, "http://app.internal.lab/api")); !allowed {
		t.Fatal("in-allowlist host blocked at egress")
	}
	if allowed, _ := m.checkEgressAllowed(taskID, "public.example", egressReq(t, "http://public.example/api")); allowed {
		t.Fatal("out-of-allowlist host escaped the task rule at egress")
	}
	// Another task (no tag, or an unrelated one) is not affected by that allow list.
	if allowed, _ := m.checkEgressAllowed(0, "public.example", egressReq(t, "http://public.example/api")); !allowed {
		t.Fatal("untagged request was scoped to a task's allow list")
	}
}

// A CONNECT carries no path: a hard block rule must still refuse the tunnel, a
// URL-only allow list must let the handshake through (the inner request is judged
// by its full URL), and a host-based allow list must be enforced.
func TestEgressConnectHandling(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("connect rules", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	taskID, _ := parseTaskID(task.ID)

	connectReq := func(host string) *http.Request {
		u, _ := url.Parse("https://" + host + ":443")
		return &http.Request{Method: http.MethodConnect, URL: u, Host: host + ":443"}
	}

	// Global block: the tunnel is refused outright.
	block, err := m.pg.CreateAssetInterceptRule("fuzzy_domain", ".gov.cn", "禁测", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteAssetInterceptRule(block.ID) })
	if allowed, _ := m.checkEgressAllowed(taskID, "a.gov.cn", connectReq("a.gov.cn")); allowed {
		t.Fatal("block rule did not stop the CONNECT tunnel")
	}

	// URL-only allow list: the handshake must pass (no path to judge yet).
	urlAllow, err := m.assets.CreateTaskInterceptRule(taskID, "allow", "fuzzy_url", "/allowed/only", "", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.assets.DeleteTaskInterceptRule(taskID, urlAllow.ID) })
	if allowed, _ := m.checkEgressAllowed(taskID, "secure.example", connectReq("secure.example")); !allowed {
		t.Fatal("URL-only allow list blocked the TLS handshake")
	}
	// ... but the decrypted request is then judged by its path.
	if allowed, _ := m.checkEgressAllowed(taskID, "secure.example", egressReq(t, "https://secure.example/other/path")); allowed {
		t.Fatal("inner request escaped the URL allow list")
	}
}

var _ = db.AssetInterceptRule{}

// With the proxy always in the request path, capture-off deployments keep a real
// egress point. ProxyAddr must therefore hand out the MITM address regardless of
// the capture switch, and ProxyCACert must stay set (the MITM re-signs certs either
// way). Recording is a separate signal the worker reads for its traffic_* tools.
func TestProxyStaysInPathWhenCaptureOff(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	tr, err := traffic.Open(filepath.Join(m.dir, "traffic"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.traffic = tr
	t.Cleanup(func() { _ = tr.Close() })
	// SetTrafficEnabled persists into the SHARED settings table: restore the previous
	// value or every later test in the package sees capture on.
	prevCapture := m.pg.GetBool(settingTrafficCapture, false)
	t.Cleanup(func() { _ = m.SetTrafficEnabled(prevCapture) })

	if err := m.SetTrafficEnabled(false); err != nil {
		t.Fatal(err)
	}
	if got := m.ProxyAddr(); got != tr.ProxyAddr() {
		t.Fatalf("capture off: ProxyAddr = %q, want the MITM %q", got, tr.ProxyAddr())
	}
	if m.ProxyCACert() == "" {
		t.Fatal("capture off: no CA, so HTTPS through the MITM would fail and the egress gate would never see it")
	}
	if tr.Recording() {
		t.Fatal("capture off: recording still enabled")
	}
	if err := m.SetTrafficEnabled(true); err != nil {
		t.Fatal(err)
	}
	if !tr.Recording() {
		t.Fatal("capture on: recording not enabled")
	}
	if got := m.ProxyAddr(); got != tr.ProxyAddr() {
		t.Fatalf("capture on: ProxyAddr = %q, want %q", got, tr.ProxyAddr())
	}
}
