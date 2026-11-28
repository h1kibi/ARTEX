package traffic

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mitmClient builds a client that trusts the proxy's MITM CA and routes through
// rawProxy. No credentials: this is exactly how Chromium behaves with the bridge.
func mitmClient(t *testing.T, tr *Traffic, rawProxy string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(tr.CACertPath())
	if err != nil {
		t.Fatalf("read MITM CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("MITM CA is not a valid certificate")
	}
	proxyURL, err := url.Parse(rawProxy)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfigWithRoots(pool),
		},
	}
}

// The credential-free bridge is what makes task attribution work for Chromium:
// both plain HTTP and HTTPS requests must reach the target, never leak the
// credential, and be recorded under the bridge's task. A task-scoped gate then
// blocks those requests while an untagged client keeps working.
func TestTagBridgeEndToEnd(t *testing.T) {
	var httpHits, tlsHits atomic.Int32
	var leaked atomic.Bool
	handler := func(hits *atomic.Int32) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(proxyAuthHeader) != "" {
				leaked.Store(true)
			}
			hits.Add(1)
			_, _ = io.WriteString(w, "target-body")
		}
	}
	target := httptest.NewServer(handler(&httpHits))
	defer target.Close()
	tlsTarget := httptest.NewTLSServer(handler(&tlsHits))
	defer tlsTarget.Close()

	addr := freeLoopbackAddr(t)
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()
	waitListening(t, addr)

	bridge, err := StartTagBridge(addr, 42, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	client := mitmClient(t, tr, bridge.ProxyURL())

	// The MITM certificate carries a DNS SAN (not an IP SAN), so reach the
	// loopback targets by name exactly as a browser would.
	viaLocalhost := func(rawURL string) string {
		return strings.Replace(rawURL, "127.0.0.1", "localhost", 1)
	}
	get := func(rawURL string) (int, string) {
		t.Helper()
		resp, err := client.Get(viaLocalhost(rawURL))
		if err != nil {
			t.Fatalf("GET %s: %v", rawURL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	if code, body := get(target.URL + "/ok"); code != 200 || !strings.Contains(body, "target-body") {
		t.Fatalf("HTTP through bridge: %d %q", code, body)
	}
	if code, body := get(tlsTarget.URL + "/ok"); code != 200 || !strings.Contains(body, "target-body") {
		t.Fatalf("HTTPS through bridge: %d %q", code, body)
	}
	if leaked.Load() {
		t.Fatal("bridge credential leaked to a target")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, err := tr.query(queryFilter{Host: "localhost", TaskID: 42}, 0, 20)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) >= 2 {
			for _, row := range rows {
				if row.IntentID != 7 {
					t.Fatalf("intent_id = %d, want 7", row.IntentID)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge traffic was not recorded under task 42: %d rows", len(rows))
		}
		time.Sleep(50 * time.Millisecond)
	}

	// A task-scoped rule now rejects this task's requests, on HTTP and HTTPS.
	var block atomic.Bool
	tr.SetEgressGate(func(taskID int64, _ string, _ *http.Request) (bool, string) {
		if block.Load() && taskID == 42 {
			return false, "任务私有拦截规则"
		}
		return true, ""
	})
	block.Store(true)
	beforeHTTP, beforeTLS := httpHits.Load(), tlsHits.Load()
	if code, body := get(target.URL + "/blocked"); code != http.StatusForbidden || !containsPlatformNotice(body) {
		t.Fatalf("HTTP task rule did not block: %d %q", code, body)
	}
	if code, body := get(tlsTarget.URL + "/blocked"); code != http.StatusForbidden || !containsPlatformNotice(body) {
		t.Fatalf("HTTPS task rule did not block: %d %q", code, body)
	}
	if httpHits.Load() != beforeHTTP || tlsHits.Load() != beforeTLS {
		t.Fatal("a blocked request reached the target")
	}

	// An untagged client is not subject to another task's private rule.
	plain := mitmClient(t, tr, "http://"+addr)
	resp, err := plain.Get(viaLocalhost(target.URL + "/blocked"))
	if err != nil {
		t.Fatalf("untagged GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "target-body") {
		t.Fatalf("untagged client blocked by a task rule: %d %q", resp.StatusCode, body)
	}
}

// A task-level URL allow list must see the full URL for plain HTTP and for the
// decrypted HTTPS request inside a CONNECT tunnel. The tag must reach both paths
// after the credential is stripped: the client address is the surviving identity.
func TestTagBridgeEgressURLRulesOnPlainAndInnerHTTPS(t *testing.T) {
	var deniedHits atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/denied/") {
			deniedHits.Add(1)
		}
		_, _ = io.WriteString(w, "target-body")
	})
	target := httptest.NewServer(handler)
	defer target.Close()
	tlsTarget := httptest.NewTLSServer(handler)
	defer tlsTarget.Close()

	addr := freeLoopbackAddr(t)
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()
	waitListening(t, addr)

	bridge, err := StartTagBridge(addr, 42, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	client := mitmClient(t, tr, bridge.ProxyURL())

	tr.SetEgressGate(func(taskID int64, _ string, req *http.Request) (bool, string) {
		if taskID != 42 || req.Method == http.MethodConnect {
			return true, ""
		}
		if req.URL != nil && strings.HasPrefix(req.URL.Path, "/allowed/") {
			return true, ""
		}
		return false, "任务 URL 白名单"
	})

	viaLocalhost := func(rawURL string) string {
		return strings.Replace(rawURL, "127.0.0.1", "localhost", 1)
	}
	get := func(rawURL string) (int, string) {
		t.Helper()
		resp, err := client.Get(viaLocalhost(rawURL))
		if err != nil {
			t.Fatalf("GET %s: %v", rawURL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	for _, rawURL := range []string{target.URL, tlsTarget.URL} {
		if code, body := get(rawURL + "/allowed/x"); code != http.StatusOK || !strings.Contains(body, "target-body") {
			t.Fatalf("allowed %s: %d %q", rawURL, code, body)
		}
		if code, body := get(rawURL + "/denied/x"); code != http.StatusForbidden || !containsPlatformNotice(body) {
			t.Fatalf("denied %s: %d %q", rawURL, code, body)
		}
	}
	if got := deniedHits.Load(); got != 0 {
		t.Fatalf("denied path reached the target %d times", got)
	}
}

// A host already marked passthrough must not bypass the egress gate through the
// transparent-transfer path: the refusal is enforced at the upstream dial, so the
// forbidden target sees zero TCP connections for both HTTPS and raw CONNECT.
func TestPassthroughHostStillBlockedByEgressGate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			_ = c.Close()
		}
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	targetAddr := net.JoinHostPort(host, port)

	addr := freeLoopbackAddr(t)
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()
	waitListening(t, addr)

	// Pretend a previous malformed response put this host on the transparent path.
	tr.pass.Store(host, time.Now().Add(time.Minute))
	if !tr.passing(host) {
		t.Fatal("host was not marked passthrough")
	}
	tr.SetEgressGate(func(_ int64, target string, _ *http.Request) (bool, string) {
		if target == host {
			return false, "禁测目标"
		}
		return true, ""
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustURL(t, "http://"+addr)),
			TLSClientConfig: insecureTLS(),
		},
	}
	if resp, err := client.Get("https://" + targetAddr + "/"); err == nil {
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("HTTPS request to a blocked passthrough host succeeded: %d", resp.StatusCode)
		}
	}

	// Raw CONNECT tunnel (non-TLS target): the interception path must fail at the
	// blocked upstream dial instead of direct-transferring to the target.
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "CONNECT "+targetAddr+" HTTP/1.1\r\nHost: "+targetAddr+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, _ := readResponseLine(c)
	if strings.Contains(line, "200") {
		t.Fatalf("raw CONNECT to a blocked passthrough host was established: %q", line)
	}

	time.Sleep(200 * time.Millisecond)
	if got := conns.Load(); got != 0 {
		t.Fatalf("blocked target received %d TCP connections, want 0", got)
	}
}

func tlsConfigWithRoots(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool}
}

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func readResponseLine(c net.Conn) (string, error) {
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	return string(buf[:n]), err
}

// A POST body must reach the target intact, and a request whose header names mix
// case must keep every value: the bridge parses the head with the standard
// library instead of splicing bytes, so both properties follow from it.
func TestTagBridgeForwardsPostBodyAndMixedCaseHeaders(t *testing.T) {
	var bodyGot, hdrsGot atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyGot.Store(string(b))
		hdrsGot.Store(r.Header.Values("X-Mixed-Case"))
		_, _ = io.WriteString(w, "upload-ok")
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

	bridge, err := StartTagBridge(addr, 51, 9)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(bridge.ProxyURL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	body := strings.Repeat("payload-0123456789;", 512)
	host := strings.TrimPrefix(target.URL, "http://")
	req := fmt.Sprintf("POST %s/upload HTTP/1.1\r\nHost: %s\r\nX-Mixed-Case: one\r\nx-mixed-case: two\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		target.URL, host, len(body), body)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(got) != "upload-ok" {
		t.Fatalf("POST through bridge: %d %q", resp.StatusCode, got)
	}
	if b, _ := bodyGot.Load().(string); b != body {
		t.Fatalf("target received %d body bytes, want %d", len(b), len(body))
	}
	if vals, _ := hdrsGot.Load().([]string); strings.Join(vals, ",") != "one,two" {
		t.Fatalf("mixed-case header values lost: %q", vals)
	}
}
