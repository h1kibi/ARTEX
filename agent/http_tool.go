package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/net/publicsuffix"
)

// HTTPRequestConfig tunes the in-process http_request tool. Each worker run
// supplies its own proxy tag, MITM CA and task-level cookie/artifact dirs; the
// zero value sends direct requests with no cookie persistence.
type HTTPRequestConfig struct {
	// Proxy, when set, routes requests through this http(s) proxy (typically
	// traffic.ProxyURLWithTag so :8788 records the call under the task/intent).
	Proxy string
	// CACert is a PEM CA certificate trusted in addition to the system roots,
	// so HTTPS re-signed by the MITM recorder verifies normally.
	CACert string
	// CookieDir holds one Netscape cookie file per session. Empty disables
	// persistence (memory-only jar per call).
	CookieDir string
	// ArtifactDir receives full response bodies whose inline display is truncated.
	ArtifactDir string
}

// HTTPConfigFor, when set by the host, supplies the runtime HTTP config for
// tool sets that carry no per-run config of their own (server-level domain
// tools used by chat agents). nil = direct requests, no cookie persistence.
var HTTPConfigFor func(context.Context) HTTPRequestConfig

const (
	httpToolName        = "http_request"
	maxHTTPResponseSize = 2 << 20 // 2 MiB
	maxInlineBodyRunes  = 8000
)

// NewHTTPRequestTool builds the http_request tool with a fixed configuration.
func NewHTTPRequestTool(cfg HTTPRequestConfig) actool.CoreTool {
	return newHTTPRequestTool(func(context.Context) HTTPRequestConfig { return cfg })
}

// NewHTTPRequestToolDynamic builds http_request whose proxy/cookie/artifact
// configuration is resolved per call, so the worker can tag traffic with the
// task and intent that own the current run.
func NewHTTPRequestToolDynamic(resolve func(context.Context) HTTPRequestConfig) actool.CoreTool {
	return newHTTPRequestTool(resolve)
}

func newHTTPRequestTool(resolve func(context.Context) HTTPRequestConfig) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        httpToolName,
		Description: "发送一次 HTTP(S) 请求，返回状态码、最终 URL、Location、耗时、已保存的 Cookie 名、关键响应头和响应体。支持自定义方法、请求头、查询参数、原始请求体或 JSON 请求体；会话 Cookie 写入与 curl 共用的 Netscape cookies.txt，登录态可被后续调用和 Bash 复用。follow_redirects 默认关闭，保留 301/302/307、Location 与 Set-Cookie 现场；响应体超过 8000 字符时截断展示，完整内容写入产物目录。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":              map[string]any{"type": "string", "description": "请求地址，必须以 http:// 或 https:// 开头"},
				"method":           map[string]any{"type": "string", "default": "GET", "description": "HTTP 方法：GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS"},
				"headers":          map[string]any{"type": "object", "description": "请求头；Host 会生效，Cookie 与 Authorization 按给定值发送"},
				"query":            map[string]any{"type": "object", "description": "追加到 URL 的查询参数"},
				"body":             map[string]any{"type": "string", "description": "原始请求体"},
				"json":             map[string]any{"description": "请求体 JSON，可传对象或数组；body 为空时序列化为请求体，未显式设置 Content-Type 时自动使用 application/json"},
				"session":          map[string]any{"type": "string", "default": "default", "description": "Cookie 会话名，仅支持字母、数字、下划线和连字符；传 none 表示不持久化 Cookie"},
				"follow_redirects": map[string]any{"type": "boolean", "default": false, "description": "是否跟随最多 5 次重定向；关闭时直接返回重定向响应"},
				"insecure_tls":     map[string]any{"type": "boolean", "default": false, "description": "是否跳过 TLS 证书校验"},
				"timeout_sec":      map[string]any{"type": "integer", "default": 15, "description": "请求超时秒数，取值 1 到 60"},
			},
			"required": []any{"url"},
		},
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return runHTTPRequest(ctx, in, resolve(ctx))
		},
	})
}

type httpRequestInput struct {
	URL             string          `json:"url"`
	Method          string          `json:"method"`
	Headers         json.RawMessage `json:"headers"`
	Query           json.RawMessage `json:"query"`
	Body            string          `json:"body"`
	JSON            json.RawMessage `json:"json"`
	Session         string          `json:"session"`
	FollowRedirects bool            `json:"follow_redirects"`
	InsecureTLS     bool            `json:"insecure_tls"`
	TimeoutSec      int             `json:"timeout_sec"`
}

func runHTTPRequest(ctx context.Context, raw json.RawMessage, cfg HTTPRequestConfig) (actool.Result, error) {
	var in httpRequestInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return actool.Errorf("http_request 入参不是合法 JSON: " + err.Error()), nil
	}
	u, err := parseHTTPURL(in.URL)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	method, err := httpMethod(in.Method)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	queryMap, err := parseObjectOrStringJSON(in.Query, "query")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	headerMap, err := parseObjectOrStringJSON(in.Headers, "headers")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	target := buildRequestURL(u, queryMap)
	bodyBytes, contentType, err := requestBody(&in)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	timeout := in.TimeoutSec
	if timeout <= 0 {
		timeout = 15
	}
	if timeout < 1 {
		timeout = 1
	}
	if timeout > 60 {
		timeout = 60
	}

	session := sanitizeSession(in.Session)
	cookiePath := ""
	var jar *recordingCookieJar
	var unlock func()
	if cfg.CookieDir != "" && session != "none" {
		cookiePath = filepath.Join(cfg.CookieDir, session+".cookies")
		unlock = lockCookieFile(cookiePath)
	} else {
		unlock = func() {}
	}
	defer unlock()

	jar = newRecordingCookieJar()
	if cookiePath != "" {
		if err := jar.load(cookiePath); err != nil {
			return actool.Errorf("读取 Cookie 文件失败: " + err.Error()), nil
		}
	}
	jar.beginCall()

	reqCtx, cancel := context.WithTimeout(withHTTPProxyURL(ctx, cfg.Proxy), time.Duration(timeout)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, target.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return actool.Errorf("构造请求失败: " + err.Error()), nil
	}
	applyHeaders(req, headerMap)
	if contentType != "" && !hasHeader(req.Header, "Content-Type") {
		req.Header.Set("Content-Type", contentType)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "artex-http_request/1.0")
	}

	client := newHTTPClient(cfg, in.InsecureTLS, in.FollowRedirects, jar)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return actool.Errorf("请求失败: " + err.Error()), nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseSize))
	elapsed := time.Since(start).Milliseconds()

	var saveErr error
	if cookiePath != "" {
		saveErr = jar.save(cookiePath)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	fmt.Fprintf(&b, "url: %s\n", target.String())
	if loc := resp.Header.Get("Location"); loc != "" {
		fmt.Fprintf(&b, "location: %s\n", loc)
	}
	fmt.Fprintf(&b, "elapsed_ms: %d\n", elapsed)
	saved := jar.savedNames()
	if len(saved) > 0 {
		fmt.Fprintf(&b, "cookies_saved: %s\n", strings.Join(saved, ", "))
	}
	fmt.Fprintf(&b, "response_headers:\n%s", renderKeyHeaders(resp.Header))

	runes := []rune(string(body))
	truncated := len(runes) > maxInlineBodyRunes
	shown := runes
	if truncated {
		shown = runes[:maxInlineBodyRunes]
	}
	b.WriteString("body:\n")
	b.WriteString(string(shown))
	if truncated {
		fmt.Fprintf(&b, "\n[body truncated: showing %d of %d characters]", maxInlineBodyRunes, len(runes))
		artifactName, aerr := writeHTTPArtifact(cfg.ArtifactDir, body)
		switch {
		case aerr != nil:
			fmt.Fprintf(&b, "\nartifact_error: %s", aerr.Error())
		case artifactName != "":
			// Filename relative to ArtifactDir; prefix with artifact: for evidence_refs.
			fmt.Fprintf(&b, "\nartifact_path: %s", artifactName)
		}
	}
	if saveErr != nil {
		fmt.Fprintf(&b, "\ncookie_save_error: %s", saveErr.Error())
	}
	return actool.Text(b.String()), nil
}

// parseHTTPURL rejects anything that is not an absolute http(s) URL. It runs
// before any jar or transport is touched, so empty input stays a tool error.
func parseHTTPURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("url 必填，且必须以 http:// 或 https:// 开头")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return nil, fmt.Errorf("url 必填，且必须以 http:// 或 https:// 开头")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("url 解析失败: %v", err)
	}
	return u, nil
}

var allowedHTTPMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodDelete: true, http.MethodPatch: true, http.MethodHead: true,
	http.MethodOptions: true,
}

func httpMethod(raw string) (string, error) {
	m := strings.ToUpper(strings.TrimSpace(raw))
	if m == "" {
		return http.MethodGet, nil
	}
	if !allowedHTTPMethods[m] {
		return "", fmt.Errorf("不支持的 HTTP 方法 %q（可用 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS）", raw)
	}
	return m, nil
}

func parseObjectOrStringJSON(raw json.RawMessage, field string) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj, nil
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		str = strings.TrimSpace(str)
		if str == "" {
			return nil, nil
		}
		if err := json.Unmarshal([]byte(str), &obj); err == nil {
			return obj, nil
		}
	}
	return nil, fmt.Errorf("%s 入参必须是 JSON 对象", field)
}

func buildRequestURL(u *url.URL, query map[string]any) *url.URL {
	if len(query) > 0 {
		q := u.Query()
		for k, v := range query {
			q.Add(k, scalarString(v))
		}
		u.RawQuery = q.Encode()
	}
	return u
}

// requestBody returns the body bytes and the Content-Type to apply when the
// caller did not set one explicitly.
func requestBody(in *httpRequestInput) ([]byte, string, error) {
	if in.Body != "" {
		return []byte(in.Body), "", nil
	}
	if len(in.JSON) > 0 && string(in.JSON) != "null" {
		var v any
		if err := json.Unmarshal(in.JSON, &v); err != nil {
			return nil, "", fmt.Errorf("json 入参不是合法 JSON: %v", err)
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, "", fmt.Errorf("json 入参序列化失败: %v", err)
		}
		return encoded, "application/json", nil
	}
	return nil, "", nil
}

func applyHeaders(req *http.Request, headers map[string]any) {
	for k, v := range headers {
		if k == "" {
			continue
		}
		val := scalarString(v)
		// Go ignores Header.Set("Host"); the request field is the only honored path.
		if strings.EqualFold(k, "Host") {
			req.Host = val
			continue
		}
		req.Header.Set(k, val)
	}
}

// scalarString renders a header/query value. Objects and arrays become compact
// JSON so a structured value is still transmitted predictably.
func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		enc, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(enc)
	}
}

func hasHeader(h http.Header, key string) bool {
	for k := range h {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

type httpProxyCtxKey struct{}

func withHTTPProxyURL(ctx context.Context, raw string) context.Context {
	if strings.TrimSpace(raw) == "" {
		return ctx
	}
	pu, err := url.Parse(raw)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, httpProxyCtxKey{}, pu)
}

// httpTransportKey identifies one reusable transport by its TLS verification
// policy. Per-run proxy credentials travel on the request context so finished
// intents never accumulate distinct *http.Transport instances, while Go's
// connectMethodKey still isolates pooled connections per proxy userinfo.
type httpTransportKey struct {
	caCert   string
	caMtime  int64
	insecure bool
}

var httpTransportCache sync.Map

func newHTTPClient(cfg HTTPRequestConfig, insecureTLS, followRedirects bool, jar *recordingCookieJar) *http.Client {
	tr := httpTransportFor(cfg, insecureTLS)
	c := &http.Client{Transport: tr, Jar: jar}
	if followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		}
	} else {
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

func httpTransportFor(cfg HTTPRequestConfig, insecureTLS bool) *http.Transport {
	key := httpTransportKey{caCert: cfg.CACert, insecure: insecureTLS}
	if cfg.CACert != "" {
		if fi, err := os.Stat(cfg.CACert); err == nil {
			key.caMtime = fi.ModTime().UnixNano()
		}
	}
	if cached, ok := httpTransportCache.Load(key); ok {
		return cached.(*http.Transport)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 64
	tr.MaxIdleConnsPerHost = 8
	tr.IdleConnTimeout = 60 * time.Second
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		if pu, ok := req.Context().Value(httpProxyCtxKey{}).(*url.URL); ok {
			return pu, nil
		}
		return nil, nil
	}
	switch {
	case insecureTLS:
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case cfg.CACert != "":
		if pem, err := os.ReadFile(cfg.CACert); err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	actual, _ := httpTransportCache.LoadOrStore(key, tr)
	return actual.(*http.Transport)
}

var keyResponseHeaders = []string{
	"Content-Type", "Content-Length", "Server", "Location",
	"WWW-Authenticate", "Allow", "X-Powered-By",
}

func renderKeyHeaders(h http.Header) string {
	var b strings.Builder
	for _, k := range keyResponseHeaders {
		if v := h.Values(k); len(v) > 0 {
			fmt.Fprintf(&b, "  %s: %s\n", k, strings.Join(v, ", "))
		}
	}
	return b.String()
}

func writeHTTPArtifact(dir string, body []byte) (string, error) {
	if dir == "" {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("http-%d.body", time.Now().UnixNano())
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		return "", err
	}
	return name, nil
}

// sanitizeSession keeps a session name path-safe and maps an absent/illegal
// name to "default". "none" is preserved as the stateless marker.
func sanitizeSession(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "default"
	}
	if strings.EqualFold(s, "none") {
		return "none"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

// --- Netscape cookie session ---

// netscapeCookie is one row of a curl cookies.txt file.
type netscapeCookie struct {
	Domain      string // without the leading dot; includeSubdomains says whether it applies to subdomains
	IncludeSubs bool
	Path        string
	Secure      bool
	Expires     int64 // unix seconds; 0 = session cookie
	Name        string
	Value       string
	HTTPOnly    bool
}

func (c netscapeCookie) key() string {
	return c.Domain + "\x00" + c.Path + "\x00" + c.Name
}

// recordingCookieJar wraps cookiejar (domain/path/expiry rules, public suffix
// checks) and keeps the serializable entry set so Set-Cookie results can be
// written back to a Netscape file.
type recordingCookieJar struct {
	jar     *cookiejar.Jar
	mu      sync.Mutex
	entries map[string]netscapeCookie
	touched []string
}

func newRecordingCookieJar() *recordingCookieJar {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &recordingCookieJar{jar: jar, entries: map[string]netscapeCookie{}}
}

func (j *recordingCookieJar) beginCall() {
	j.mu.Lock()
	j.touched = j.touched[:0]
	j.mu.Unlock()
}

func (j *recordingCookieJar) Cookies(u *url.URL) []*http.Cookie { return j.jar.Cookies(u) }

// accepted reports whether cookiejar kept the cookie for the request URL. It is
// the persistence filter for Set-Cookie: rejected domains never reach the file.
func (j *recordingCookieJar) accepted(u *url.URL, c *http.Cookie) bool {
	host := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
	if host == "" {
		host = u.Hostname()
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	if c.Secure {
		scheme = "https"
	}
	path := c.Path
	if path == "" {
		path = "/"
	}
	probe := &url.URL{Scheme: scheme, Host: host, Path: path}
	for _, got := range j.jar.Cookies(probe) {
		if got.Name == c.Name && got.Value == c.Value {
			return true
		}
	}
	return false
}

func (j *recordingCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.jar.SetCookies(u, cookies)
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		domain := strings.ToLower(strings.TrimSpace(c.Domain))
		includeSubs := domain != ""
		if domain == "" {
			domain = strings.ToLower(u.Hostname())
		}
		domain = strings.TrimPrefix(domain, ".")
		if domain == "" || c.Name == "" {
			continue
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		key := domain + "\x00" + path + "\x00" + c.Name
		if c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(now)) {
			delete(j.entries, key)
			continue
		}
		// Only persist what cookiejar accepted, so a public-suffix or cross-domain
		// Set-Cookie cannot be smuggled into the shared cookies.txt.
		if !j.accepted(u, c) {
			continue
		}
		var expires int64
		switch {
		case c.MaxAge > 0:
			expires = now.Add(time.Duration(c.MaxAge) * time.Second).Unix()
		case !c.Expires.IsZero():
			expires = c.Expires.Unix()
		}
		j.entries[key] = netscapeCookie{
			Domain: domain, IncludeSubs: includeSubs, Path: path,
			Secure: c.Secure, Expires: expires, Name: c.Name, Value: c.Value,
			HTTPOnly: c.HttpOnly,
		}
		j.touched = append(j.touched, c.Name)
	}
}

func (j *recordingCookieJar) savedNames() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, n := range j.touched {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func (j *recordingCookieJar) load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	now := time.Now().Unix()
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		entry, ok := parseNetscapeLine(line)
		if !ok {
			continue
		}
		if entry.Expires != 0 && entry.Expires <= now {
			continue
		}
		if entry.Path == "" {
			entry.Path = "/"
		}
		cookie := &http.Cookie{
			Name: entry.Name, Value: entry.Value, Path: entry.Path,
			Secure: entry.Secure, HttpOnly: entry.HTTPOnly,
		}
		if entry.IncludeSubs {
			cookie.Domain = entry.Domain
		}
		if entry.Expires != 0 {
			cookie.Expires = time.Unix(entry.Expires, 0)
		}
		scheme := "http"
		if entry.Secure {
			scheme = "https"
		}
		j.jar.SetCookies(&url.URL{Scheme: scheme, Host: entry.Domain}, []*http.Cookie{cookie})
		if !j.accepted(&url.URL{Scheme: scheme, Host: entry.Domain}, cookie) {
			continue
		}
		j.mu.Lock()
		j.entries[entry.key()] = entry
		j.mu.Unlock()
	}
	return nil
}

func (j *recordingCookieJar) save(path string) error {
	j.mu.Lock()
	rows := make([]netscapeCookie, 0, len(j.entries))
	for _, e := range j.entries {
		rows = append(rows, e)
	}
	j.mu.Unlock()
	sort.Slice(rows, func(a, b int) bool {
		if rows[a].Domain != rows[b].Domain {
			return rows[a].Domain < rows[b].Domain
		}
		if rows[a].Path != rows[b].Path {
			return rows[a].Path < rows[b].Path
		}
		return rows[a].Name < rows[b].Name
	})

	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	b.WriteString("# https://curl.se/docs/http-cookies.html\n")
	b.WriteString("# This file was generated by artex http_request. Edit at your own risk.\n\n")
	for _, e := range rows {
		domain := e.Domain
		if e.IncludeSubs {
			domain = "." + domain
		}
		if e.HTTPOnly {
			domain = "#HttpOnly_" + domain
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			domain, strings.ToUpper(strconv.FormatBool(e.IncludeSubs)),
			cleanCookieField(e.Path), strings.ToUpper(strconv.FormatBool(e.Secure)),
			e.Expires, cleanCookieField(e.Name), cleanCookieField(e.Value))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cookies-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// parseNetscapeLine accepts the 7-column format curl reads and writes, including
// the "#HttpOnly_" domain prefix in any letter case. A trailing empty value that
// left only six columns after the trailing tab was stripped is completed. Comment
// lines that are not HttpOnly rows are ignored.
func parseNetscapeLine(line string) (netscapeCookie, bool) {
	var e netscapeCookie
	httpOnly := false
	const httpOnlyPrefix = "#HttpOnly_"
	if len(line) >= len(httpOnlyPrefix) && strings.EqualFold(line[:len(httpOnlyPrefix)], httpOnlyPrefix) {
		httpOnly = true
		line = line[len(httpOnlyPrefix):]
	} else if strings.HasPrefix(line, "#") {
		return e, false
	}
	cols := strings.Split(line, "\t")
	if len(cols) == 6 {
		cols = append(cols, "")
	}
	if len(cols) != 7 {
		return e, false
	}
	domain := strings.TrimSpace(cols[0])
	includeSubs := strings.EqualFold(strings.TrimSpace(cols[1]), "TRUE")
	secure := strings.EqualFold(strings.TrimSpace(cols[3]), "TRUE")
	expires, err := strconv.ParseInt(strings.TrimSpace(cols[4]), 10, 64)
	if err != nil {
		return e, false
	}
	if domain == "" || cols[5] == "" {
		return e, false
	}
	e.Domain = strings.TrimPrefix(domain, ".")
	e.IncludeSubs = includeSubs || strings.HasPrefix(domain, ".")
	e.Path = cols[2]
	e.Secure = secure
	e.Expires = expires
	e.Name = cols[5]
	e.Value = cols[6]
	e.HTTPOnly = httpOnly
	return e, true
}

func cleanCookieField(s string) string {
	return strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(s)
}

var cookieFileLocks sync.Map // absolute cookie file path -> *sync.Mutex

// lockCookieFile serializes load→send→save for one cookie file so concurrent
// calls in the same session cannot overwrite each other's Set-Cookie results.
func lockCookieFile(path string) func() {
	v, _ := cookieFileLocks.LoadOrStore(filepath.Clean(path), &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
