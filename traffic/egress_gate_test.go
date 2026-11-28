package traffic

import (
	"net/http"
	"strings"
	"testing"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// The egress gate is the last line of scope enforcement: a request that reaches
// the recording proxy must be refused (synthetic 403) instead of being forwarded,
// and the gate must receive the run tag so per-task rules can apply.
func TestEgressGateBlocksOutOfScopeHost(t *testing.T) {
	tr := &Traffic{}
	var seenHost string
	var seenTask int64 = -1
	tr.SetEgressGate(func(taskID int64, host string, _ *http.Request) (bool, string) {
		seenHost, seenTask = host, taskID
		if host == "blocked.example" {
			return false, "命中资产拦截规则"
		}
		return true, ""
	})

	blocked := flowFor(t, "http://blocked.example/x")
	tr.setTag(blocked, exchangeTag{TaskID: 42, IntentID: 7})
	if !tr.gateEgress(blocked) {
		t.Fatal("gate did not refuse the out-of-scope host")
	}
	if seenHost != "blocked.example" || seenTask != 42 {
		t.Fatalf("gate saw host=%q task=%d want blocked.example/42", seenHost, seenTask)
	}
	if blocked.Response == nil || blocked.Response.StatusCode != http.StatusForbidden {
		t.Fatalf("no synthetic 403 response: %+v", blocked.Response)
	}
	if body := string(blocked.Response.Body); body == "" || !containsPlatformNotice(body) {
		t.Fatalf("refusal body does not identify the platform: %q", body)
	}
	if tr.BlockedCount() != 1 {
		t.Fatalf("blocked count=%d want 1", tr.BlockedCount())
	}

	allowed := flowFor(t, "http://ok.example/y")
	if tr.gateEgress(allowed) {
		t.Fatal("in-scope host refused")
	}
	if allowed.Response != nil {
		t.Fatalf("allowed request got a synthetic response: %+v", allowed.Response)
	}
	if tr.BlockedCount() != 1 {
		t.Fatalf("blocked count changed on an allowed request: %d", tr.BlockedCount())
	}

	// No gate installed → nothing is refused (default wiring for a bare recorder).
	bare := &Traffic{}
	if bare.gateEgress(flowFor(t, "http://blocked.example/z")) {
		t.Fatal("gate applied without being installed")
	}
}

func containsPlatformNotice(body string) bool {
	return strings.Contains(body, "ARTEX 平台管控")
}

// flowFor builds a minimal intercepted flow the addon hooks can reason about.
func flowFor(t *testing.T, rawURL string) *mproxy.Flow {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &mproxy.Flow{Request: &mproxy.Request{Method: req.Method, URL: req.URL, Header: req.Header}}
}

// The gate must receive the real request so exact_url / fuzzy_url rules can be
// decided; passing nil made every URL-shaped rule dead at the recording proxy.
func TestEgressGateSeesRequestURL(t *testing.T) {
	tr := &Traffic{}
	var gotMethod, gotURL string
	tr.SetEgressGate(func(_ int64, host string, req *http.Request) (bool, string) {
		if req != nil {
			gotMethod, gotURL = req.Method, req.URL.String()
		}
		if req != nil && strings.Contains(req.URL.Path, "/admin") {
			return false, "命中断言路径拦截"
		}
		return true, ""
	})

	blocked := flowFor(t, "http://app.example/admin/users")
	if !tr.gateEgress(blocked) {
		t.Fatal("URL-shaped rule did not block the request")
	}
	if gotMethod != http.MethodGet || gotURL != "http://app.example/admin/users" {
		t.Fatalf("gate saw method=%q url=%q", gotMethod, gotURL)
	}
	if blocked.Response == nil || blocked.Response.StatusCode != http.StatusForbidden {
		t.Fatalf("no synthetic 403: %+v", blocked.Response)
	}

	// A CONNECT flow carries no path; the gate must still be consulted with the
	// tunnelled host (and the method is CONNECT).
	connect := flowFor(t, "http://secure.example:443")
	connect.Request.Method = http.MethodConnect
	gotMethod, gotURL = "", ""
	if tr.gateEgress(connect) {
		t.Fatal("CONNECT was blocked by a path-only rule")
	}
	if gotMethod != http.MethodConnect || gotURL != "http://secure.example:443" {
		t.Fatalf("CONNECT not forwarded to the gate: method=%q url=%q", gotMethod, gotURL)
	}
}

// The gate must receive the run tag AND the request, which is what makes a
// WebFetch call (same tagged proxy URL as BashEnv) subject to the task's rules.
func TestEgressGateAppliesTaskAndURLTogether(t *testing.T) {
	tr := &Traffic{}
	var seen struct {
		task int64
		path string
	}
	tr.SetEgressGate(func(taskID int64, host string, req *http.Request) (bool, string) {
		seen.task = taskID
		if req != nil && req.Method != http.MethodConnect {
			seen.path = req.URL.Path
			if taskID == 0 {
				return true, "" // no task: only global rules would apply
			}
			if strings.HasPrefix(req.URL.Path, "/forbidden") {
				return false, "任务规则禁止该路径"
			}
		}
		return true, ""
	})

	f := flowFor(t, "http://target.example/forbidden/export")
	tr.setTag(f, exchangeTag{TaskID: 99, IntentID: 5})
	if !tr.gateEgress(f) {
		t.Fatal("task-scoped URL rule did not block the request")
	}
	if seen.task != 99 || seen.path != "/forbidden/export" {
		t.Fatalf("gate saw task=%d path=%q", seen.task, seen.path)
	}

	// An untagged flow still reaches the gate (global rules), just with task 0.
	untagged := flowFor(t, "http://target.example/forbidden/export")
	tr.gateEgress(untagged)
	if seen.task != 0 {
		t.Fatalf("untagged flow reported task=%d", seen.task)
	}
}

// The scope gate must survive capture being turned off. Recording and egress
// enforcement are independent: the proxy stays in the request path either way, so
// a capture-off deployment cannot silently lose its only enforceable exit point.
func TestEgressGateAppliesWhileRecordingOff(t *testing.T) {
	tr := &Traffic{}
	tr.SetRecording(false)
	if tr.Recording() {
		t.Fatal("recording flag did not take")
	}
	// A Traffic built directly (tests, embedders) records by default: only the host
	// opts out when the capture setting is off.
	if (&Traffic{}).Recording() == false {
		t.Fatal("zero-value Traffic should record by default")
	}
	var gated int
	tr.SetEgressGate(func(taskID int64, host string, req *http.Request) (bool, string) {
		gated++
		return false, "out of scope"
	})
	f := flowFor(t, "http://blocked.example/x")
	if !tr.gateEgress(f) {
		t.Fatal("gate did not refuse while recording was off")
	}
	if gated != 1 {
		t.Fatalf("gate called %d times, want 1", gated)
	}
	if f.Response == nil || f.Response.StatusCode != http.StatusForbidden {
		t.Fatalf("refusal did not synthesize a 403: %+v", f.Response)
	}
	// And with recording on it still refuses identically.
	tr.SetRecording(true)
	f2 := flowFor(t, "http://blocked.example/y")
	if !tr.gateEgress(f2) {
		t.Fatal("gate did not refuse while recording was on")
	}
}

// The proxy now sits in front of every request, capture on or off, so its TLS
// policy applies more broadly than before. That must be an explicit setting, not a
// hidden consequence: default off (pentest targets are self-signed) and switchable.
func TestVerifyUpstreamIsExplicit(t *testing.T) {
	tr := &Traffic{}
	if tr.VerifyUpstream() {
		t.Fatal("verification should default to off for pentest targets")
	}
	// The setting is construction-time: it is baked into the listener's TLS config.
	off, err := OpenWith(t.TempDir(), "127.0.0.1:0", Options{VerifyUpstream: false})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = off.Close() })
	if off.VerifyUpstream() {
		t.Fatal("default OpenWith verified upstream certificates")
	}
	on, err := OpenWith(t.TempDir(), "127.0.0.1:0", Options{VerifyUpstream: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = on.Close() })
	if !on.VerifyUpstream() {
		t.Fatal("Options.VerifyUpstream did not take effect")
	}
	// There is no runtime setter: the TLS config is fixed at construction, and a
	// setter could only make the reported value diverge from the live listener.
	// A nil receiver must not panic: callers treat a disabled proxy as absent.
	var nilTraffic *Traffic
	if nilTraffic.VerifyUpstream() {
		t.Fatal("nil proxy reported verification")
	}
}
