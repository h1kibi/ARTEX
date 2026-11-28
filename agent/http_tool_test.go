package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// callHTTPTool invokes http_request and returns the flattened result plus the
// transport error, so tests can assert the empty-input path never panics.
func callHTTPTool(t *testing.T, cfg HTTPRequestConfig, input string) (string, bool, error) {
	t.Helper()
	tool := NewHTTPRequestTool(cfg)
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	return res.Flatten(), res.IsError, err
}

func TestHTTPRequestValidation(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty object", `{}`},
		{"empty url", `{"url":""}`},
		{"ftp scheme", `{"url":"ftp://example.com/x"}`},
		{"relative url", `{"url":"/just/a/path"}`},
		{"no scheme", `{"url":"example.com"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, isErr, err := callHTTPTool(t, HTTPRequestConfig{}, tc.input)
			if err != nil {
				t.Fatalf("transport error: %v", err)
			}
			if !isErr {
				t.Fatalf("want tool error, got %q", text)
			}
			if !strings.Contains(text, "http://") {
				t.Fatalf("want the url guidance, got %q", text)
			}
		})
	}
}

func TestHTTPRequestCookieSession(t *testing.T) {
	var sawDashboard bool
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/", HttpOnly: true})
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil || c.Value != "abc123" {
			http.Error(w, "not logged in", http.StatusUnauthorized)
			return
		}
		sawDashboard = true
		io.WriteString(w, "welcome")
	})
	mux.HandleFunc("/curlcheck", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("curlsid")
		if err != nil || c.Value != "fromfile" {
			http.Error(w, "missing curl cookie", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "curl cookie received")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cookieDir := t.TempDir()
	cfg := HTTPRequestConfig{CookieDir: cookieDir}

	text, isErr, err := callHTTPTool(t, cfg, fmt.Sprintf(`{"url":%q}`, srv.URL+"/login"))
	if err != nil || isErr {
		t.Fatalf("login call failed: err=%v isErr=%v text=%s", err, isErr, text)
	}
	if !strings.Contains(text, "HTTP 302") {
		t.Fatalf("follow_redirects=false must expose 302, got %q", text)
	}
	if !strings.Contains(text, "sid") {
		t.Fatalf("want saved cookie name sid, got %q", text)
	}

	cookiePath := filepath.Join(cookieDir, "default.cookies")
	data, err := os.ReadFile(cookiePath)
	if err != nil {
		t.Fatalf("cookie file not written: %v", err)
	}
	if !strings.Contains(string(data), "# Netscape HTTP Cookie File") {
		t.Fatalf("missing Netscape header in:\n%s", data)
	}
	var found bool
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "sid") {
			continue
		}
		found = true
		if !strings.HasPrefix(line, "#HttpOnly_") {
			t.Fatalf("HttpOnly cookie row lost its prefix: %q", line)
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 7 {
			t.Fatalf("want 7 Netscape columns, got %d: %q", len(cols), line)
		}
		if cols[0] != "#HttpOnly_127.0.0.1" || cols[1] != "FALSE" || cols[2] != "/" ||
			cols[3] != "FALSE" || cols[4] != "0" || cols[5] != "sid" || cols[6] != "abc123" {
			t.Fatalf("unexpected cookie row: %q", line)
		}
	}
	if !found {
		t.Fatalf("sid row missing from:\n%s", data)
	}

	text, isErr, err = callHTTPTool(t, cfg, fmt.Sprintf(`{"url":%q}`, srv.URL+"/dashboard"))
	if err != nil || isErr {
		t.Fatalf("dashboard call failed: err=%v isErr=%v text=%s", err, isErr, text)
	}
	if !sawDashboard || !strings.Contains(text, "HTTP 200") {
		t.Fatalf("cookie not replayed, got %q", text)
	}

	// With follow_redirects the 302 is consumed and the cookie set by the
	// redirect response rides along to /dashboard.
	text, isErr, err = callHTTPTool(t, cfg, fmt.Sprintf(`{"url":%q,"follow_redirects":true}`, srv.URL+"/login"))
	if err != nil || isErr {
		t.Fatalf("redirect-following call failed: err=%v isErr=%v text=%s", err, isErr, text)
	}
	if !strings.Contains(text, "HTTP 200") || !strings.Contains(text, "welcome") {
		t.Fatalf("redirect not followed with cookies, got %q", text)
	}

	// A file written the way `curl -c` writes it must load and be sent.
	curlFile := "# Netscape HTTP Cookie File\n" +
		"127.0.0.1\tFALSE\t/\tFALSE\t0\tcurlsid\tfromfile\n"
	if err := os.WriteFile(filepath.Join(cookieDir, "fromcurl.cookies"), []byte(curlFile), 0o600); err != nil {
		t.Fatal(err)
	}
	text, isErr, err = callHTTPTool(t, cfg, fmt.Sprintf(`{"url":%q,"session":"fromcurl"}`, srv.URL+"/curlcheck"))
	if err != nil || isErr {
		t.Fatalf("curl session call failed: err=%v isErr=%v text=%s", err, isErr, text)
	}
	if !strings.Contains(text, "HTTP 200") || !strings.Contains(text, "curl cookie received") {
		t.Fatalf("curl-generated cookie file not honored, got %q", text)
	}
}

func TestHTTPRequestJSONAndQuery(t *testing.T) {
	type echo struct {
		Method      string `json:"method"`
		ContentType string `json:"content_type"`
		Query       string `json:"query"`
		Body        string `json:"body"`
		Custom      string `json:"custom"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(echo{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			Query:       r.URL.RawQuery,
			Body:        string(body),
			Custom:      r.Header.Get("X-Custom"),
		})
	}))
	defer srv.Close()

	input, _ := json.Marshal(map[string]any{
		"url":     srv.URL + "/echo",
		"method":  "post",
		"json":    map[string]any{"x": 1, "name": "测试"},
		"query":   map[string]any{"a": "b c", "n": 2},
		"headers": map[string]any{"X-Custom": "yes"},
	})
	text, isErr, err := callHTTPTool(t, HTTPRequestConfig{}, string(input))
	if err != nil || isErr {
		t.Fatalf("call failed: err=%v isErr=%v text=%s", err, isErr, text)
	}

	var got echo
	idx := strings.Index(text, "{\"")
	if idx < 0 {
		t.Fatalf("no JSON body in %q", text)
	}
	if err := json.Unmarshal([]byte(text[idx:]), &got); err != nil {
		t.Fatalf("decode echo %q: %v", text[idx:], err)
	}
	if got.Method != "POST" {
		t.Fatalf("method not uppercased: %q", got.Method)
	}
	if got.ContentType != "application/json" {
		t.Fatalf("json input must set Content-Type, got %q", got.ContentType)
	}
	if got.Custom != "yes" {
		t.Fatalf("custom header lost: %q", got.Custom)
	}
	q, err := url.ParseQuery(got.Query)
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("a") != "b c" || q.Get("n") != "2" {
		t.Fatalf("query not encoded/merged: %q", got.Query)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got.Body), &decoded); err != nil {
		t.Fatalf("body is not JSON: %q", got.Body)
	}
	if decoded["name"] != "测试" || decoded["x"] != float64(1) {
		t.Fatalf("unexpected body: %q", got.Body)
	}
}

func TestHTTPRequestProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "PROXIED")
	}))
	defer target.Close()

	var gotAuth, gotAbsURL string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Proxy-Authorization")
		gotAbsURL = r.URL.String()
		req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()

	pu, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	pu.User = url.UserPassword("user", "pass")

	cfg := HTTPRequestConfig{Proxy: pu.String()}
	text, isErr, err := callHTTPTool(t, cfg, fmt.Sprintf(`{"url":%q}`, target.URL+"/via-proxy"))
	if err != nil || isErr {
		t.Fatalf("proxied call failed: err=%v isErr=%v text=%s", err, isErr, text)
	}
	if !strings.Contains(text, "PROXIED") {
		t.Fatalf("target body missing, got %q", text)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if gotAuth != wantAuth {
		t.Fatalf("proxy auth header = %q, want %q", gotAuth, wantAuth)
	}
	if gotAbsURL != target.URL+"/via-proxy" {
		t.Fatalf("proxy did not receive absolute target URL: %q", gotAbsURL)
	}
}

// A ToolSet without per-run config must fall back to the host hook, so chat
// agents' http_request goes through the recording proxy instead of direct.
func TestHTTPRequestUsesHostConfigFallback(t *testing.T) {
	var proxied bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		io.WriteString(w, "VIA-HOST-PROXY")
	}))
	defer proxy.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "DIRECT")
	}))
	defer target.Close()

	HTTPConfigFor = func(context.Context) HTTPRequestConfig {
		return HTTPRequestConfig{Proxy: proxy.URL}
	}
	defer func() { HTTPConfigFor = nil }()

	ts := NewToolSet(nil, "")
	res, err := ts.httpRequest().Call(context.Background(),
		json.RawMessage(fmt.Sprintf(`{"url":%q}`, target.URL+"/via-host")), nil)
	if err != nil || res.IsError {
		t.Fatalf("host-config call failed: err=%v isErr=%v text=%s", err, res.IsError, res.Flatten())
	}
	if !proxied {
		t.Fatal("request did not pass through the host-configured proxy")
	}
	if !strings.Contains(res.Flatten(), "VIA-HOST-PROXY") {
		t.Fatalf("proxy response missing: %s", res.Flatten())
	}
}

func TestHTTPRequestLargeBodyArtifact(t *testing.T) {
	payload := strings.Repeat("测", 9000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, payload)
	}))
	defer srv.Close()

	artifactDir := t.TempDir()
	text, isErr, err := callHTTPTool(t, HTTPRequestConfig{ArtifactDir: artifactDir}, fmt.Sprintf(`{"url":%q}`, srv.URL+"/big"))
	if err != nil || isErr {
		t.Fatalf("call failed: err=%v isErr=%v text=%s", err, isErr, text)
	}
	if got := strings.Count(text, "测"); got != maxInlineBodyRunes {
		t.Fatalf("inline body shows %d characters, want %d", got, maxInlineBodyRunes)
	}
	const marker = "artifact_path: "
	idx := strings.Index(text, marker)
	if idx < 0 {
		t.Fatalf("artifact reference missing from output: %q", text[max(0, len(text)-300):])
	}
	name := strings.TrimSpace(text[idx+len(marker):])
	if i := strings.IndexAny(name, "\r\n"); i >= 0 {
		name = name[:i]
	}
	if !strings.HasPrefix(name, "http-") || !strings.HasSuffix(name, ".body") {
		t.Fatalf("unexpected artifact name %q", name)
	}
	full, err := os.ReadFile(filepath.Join(artifactDir, name))
	if err != nil {
		t.Fatalf("artifact file missing: %v", err)
	}
	if string(full) != payload {
		t.Fatalf("artifact holds %d bytes, want the full %d-byte body", len(full), len(payload))
	}
}

func TestHTTPRequestTimeoutAndStringifiedHeaders(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") == "fast" {
			io.WriteString(w, "FAST-OK")
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer slow.Close()

	_, isErr, err := callHTTPTool(t, HTTPRequestConfig{}, fmt.Sprintf(`{"url":%q,"timeout_sec":1}`, slow.URL))
	if err != nil || !isErr {
		t.Fatalf("expected timeout tool error, got err=%v isErr=%v", err, isErr)
	}

	text, isErr, err := callHTTPTool(t, HTTPRequestConfig{}, fmt.Sprintf(`{"url":%q,"headers":"{\"X-Test\":\"fast\"}"}`, slow.URL))
	if err != nil || isErr || !strings.Contains(text, "FAST-OK") {
		t.Fatalf("stringified headers failed: err=%v isErr=%v text=%s", err, isErr, text)
	}
}

// parseNetscapeLine accepts the variants curl and hand-edited files produce:
// mixed-case HttpOnly prefixes and rows whose empty value left six columns.
func TestParseNetscapeLineCompat(t *testing.T) {
	c, ok := parseNetscapeLine("#httponly_example.com\tTRUE\t/\tFALSE\t0\tsid")
	if !ok || !c.HTTPOnly || c.Domain != "example.com" || c.Name != "sid" || c.Value != "" {
		t.Fatalf("six-column HttpOnly row = %+v ok=%v", c, ok)
	}
	c, ok = parseNetscapeLine("#HttpOnly_example.com\tFALSE\t/\tTRUE\t1700000000\ttoken\tsecret")
	if !ok || !c.HTTPOnly || c.Value != "secret" || !c.Secure {
		t.Fatalf("seven-column HttpOnly row = %+v ok=%v", c, ok)
	}
	if _, ok := parseNetscapeLine("# a plain comment"); ok {
		t.Fatal("plain comment parsed as a cookie")
	}
}

// Repeated calls to one target reuse the cached transport's connection pool.
func TestHTTPRequestReusesTransportConnections(t *testing.T) {
	var mu sync.Mutex
	conns := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state != http.StateNew {
			return
		}
		mu.Lock()
		conns++
		mu.Unlock()
	}
	srv.Start()
	defer srv.Close()

	for i := range 2 {
		text, isErr, err := callHTTPTool(t, HTTPRequestConfig{}, fmt.Sprintf(`{"url":%q}`, srv.URL))
		if err != nil || isErr || !strings.Contains(text, "OK") {
			t.Fatalf("call %d failed: err=%v isErr=%v text=%s", i, err, isErr, text)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if conns != 1 {
		t.Fatalf("two sequential calls opened %d connections, want 1 reused", conns)
	}
}
