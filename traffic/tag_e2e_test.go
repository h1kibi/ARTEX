package traffic

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestProxyTagEndToEnd is the full path a worker's Bash env takes: an HTTP client
// configured with `http://artex:t42_i7@<proxy>` must (1) reach the target, (2) have
// the Proxy-Authorization header stripped before the target sees it, and (3) have
// both ids recorded in the index for that exchange.
func TestProxyTagEndToEnd(t *testing.T) {
	// Upstream target: records whether the internal header leaked.
	var gotAuth string
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		gotAuth = r.Header.Get("Proxy-Authorization")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "target-body")
	}))
	defer target.Close()

	addr := freeLoopbackAddr(t)
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()
	waitListening(t, addr)

	proxyURL, err := url.Parse("http://artex:t42_i7@" + addr)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get(target.URL + "/api/thing?x=1")
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !hit || !strings.Contains(string(body), "target-body") {
		t.Fatalf("target not reached through the proxy (hit=%v body=%q)", hit, body)
	}
	if gotAuth != "" {
		t.Fatalf("internal tag leaked to the target: %q", gotAuth)
	}

	// The exchange is recorded and attributed.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := tr.query(queryFilter{Host: "127.0.0.1", TaskID: 42}, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			if rows[0].IntentID != 7 {
				t.Fatalf("intent_id = %d, want 7", rows[0].IntentID)
			}
			if !strings.Contains(rows[0].URL, "/api/thing") {
				t.Fatalf("wrong exchange recorded: %s", rows[0].URL)
			}
			// And the recorded request headers carry no credential.
			req, _, err := tr.Get(rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(req, "Proxy-Authorization") || strings.Contains(req, "artex:t42") {
				t.Fatalf("recorded request leaks the internal credential:\n%s", req)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("exchange was not recorded with its task tag")
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proxy never started listening on %s", addr)
}
