package traffic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// TestPassthroughDoesNotBlackholeMalformed is the regression for the permanent
// blacklisting: a target that answers one malformed/fuzzed request must NOT be
// switched to unrecorded passthrough, because that is the normal reply of a
// hardened service to a fuzz payload.
func TestPassthroughDoesNotBlackholeMalformed(t *testing.T) {
	tr := &Traffic{}
	f := &mproxy.Flow{Request: &mproxy.Request{URL: &url.URL{Host: "target.test:8080"}}}
	for _, s := range []string{
		"malformed HTTP response",
		"protocol error: bogus frame",
		"protocol_error in stream",
	} {
		tr.maybePassthrough(f, errors.New(s))
		if tr.passing("target.test") {
			t.Fatalf("%q must not enable passthrough (fuzz replies are not proxy faults)", s)
		}
	}
	// The genuinely proxy-caused classes still do.
	tr.maybePassthrough(f, errors.New("protocol error: received DATA on a HEAD request"))
	if !tr.passing("target.test") {
		t.Fatal("HEAD-with-body must still fall back to passthrough")
	}
}

// TestPassthroughExpires proves the fallback is temporary: after passTTL the host
// is MITM'd and recorded again.
func TestPassthroughExpires(t *testing.T) {
	tr := &Traffic{}
	tr.pass.Store("expired.test", time.Now().Add(-time.Second))
	if tr.passing("expired.test") {
		t.Fatal("an expired mark must not tunnel")
	}
	if _, ok := tr.pass.Load("expired.test"); ok {
		t.Fatal("an expired mark must be retired on read")
	}
	tr.pass.Store("live.test", time.Now().Add(time.Minute))
	if !tr.passing("live.test") {
		t.Fatal("a live mark must tunnel")
	}
}

// TestPassthroughRenewalKeepsOriginalDeadline: repeated failures on an already
// tunneled host must not extend the window forever.
func TestPassthroughRenewalKeepsOriginalDeadline(t *testing.T) {
	tr := &Traffic{}
	exp := time.Now().Add(30 * time.Second).Truncate(time.Second)
	tr.pass.Store("once.test", exp)
	f := &mproxy.Flow{Request: &mproxy.Request{URL: &url.URL{Host: "once.test"}}}
	tr.maybePassthrough(f, errors.New("http2: server sent GOAWAY"))
	v, _ := tr.pass.Load("once.test")
	if got := v.(time.Time); !got.Equal(exp) {
		t.Fatalf("deadline moved from %v to %v", exp, got)
	}
}

// TestDeleteHostClearsPassthrough: deleting a host's traffic must also clear its
// passthrough mark, so a rebuilt target is recorded again.
func TestDeleteHostClearsPassthrough(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.pass.Store("gone.test", time.Now().Add(time.Hour))
	if _, err := tr.DeleteHost("gone.test"); err != nil {
		t.Fatal(err)
	}
	if tr.passing("gone.test") {
		t.Fatal("DeleteHost must clear the passthrough mark")
	}
}

// TestSearchMatchesOmittedDefaultPort: `https://example.com:443/api` and
// `example.com:443` must find rows recorded as `https://example.com/api`.
func TestSearchMatchesOmittedDefaultPort(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("example.com", "GET", "/api/users", nil, []byte("ok")))
	tr.record(newFlow("example.com", "GET", "/other", nil, []byte("ok")))
	tr.record(newFlow("example.com:8443", "GET", "/api/users", nil, []byte("ok")))

	for _, host := range []string{"example.com:443", "https://example.com:443/api", "example.com:80"} {
		rows, err := tr.query(queryFilter{Host: host}, 0, 10)
		if err != nil {
			t.Fatalf("query(%q): %v", host, err)
		}
		if len(rows) == 0 {
			t.Fatalf("query(%q) found nothing — the default port was not tolerated", host)
		}
		if strings.Contains(host, "/api") {
			// The URL substring lands inside the authority filter, so every row must
			// still be from the requested path.
			for _, r := range rows {
				if !strings.Contains(r.URL, "/api") {
					t.Fatalf("query(%q) returned a non-matching URL %q", host, r.URL)
				}
			}
		}
	}

	// A non-default port must still be exclusive: no 8443 row may leak into a
	// plain-host query.
	rows, err := tr.query(queryFilter{Host: "example.com:8443"}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.Contains(rows[0].URL, ":8443") {
		t.Fatalf("explicit port query returned wrong rows: %+v", rows)
	}
	rows, err = tr.query(queryFilter{Host: "example.com:443"}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.Contains(r.URL, ":8443") {
			t.Fatalf("default-port query leaked a non-default-port row: %s", r.URL)
		}
	}
}

// TestTrafficGetPaging covers the 4KB～256KB gap: a body larger than the old
// 4000-byte cut must be readable in slices, with a hint saying how to continue.
func TestTrafficGetPaging(t *testing.T) {
	tr, _ := openTraffic(t)
	body := strings.Repeat("A", trafficGetDefault) + "MARKER-B" + strings.Repeat("C", 1000)
	tr.record(newFlow("big.test", "GET", "/dump", nil, []byte(body)))

	var id string
	if err := tr.DB().QueryRow(`SELECT id FROM exchanges`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tool := findTool(t, tr, "traffic_get")
	call := func(args map[string]any) string {
		raw, _ := json.Marshal(args)
		res, err := tool.Call(t.Context(), raw, nil)
		if err != nil {
			t.Fatalf("traffic_get: %v", err)
		}
		return res.Flatten()
	}

	first := call(map[string]any{"id": id})
	if !strings.Contains(first, "[offset=0 total=") {
		t.Fatalf("first page missing the offset hint:\n%s", first)
	}
	if !strings.Contains(first, "后续用 offset=") {
		t.Fatalf("first page missing continuation guidance:\n%s", first)
	}
	if strings.Contains(first, "MARKER-B") {
		t.Fatal("first page must not already contain the tail")
	}
	second := call(map[string]any{"id": id, "offset": trafficGetDefault, "length": 4096})
	if !strings.Contains(second, "MARKER-B") {
		t.Fatalf("second page missing the tail marker:\n%s", second)
	}
	// Past the end: an explicit, non-misleading message.
	over := call(map[string]any{"id": id, "offset": len(body) + 10})
	if !strings.Contains(over, "偏移已超出正文长度") {
		t.Fatalf("out-of-range offset must say so:\n%s", over)
	}
	// A small exchange is returned whole, without paging ceremony.
	tr.record(newFlow("small.test", "GET", "/x", nil, []byte("tiny-body")))
	var smallID string
	if err := tr.DB().QueryRow(`SELECT id FROM exchanges WHERE host='small.test'`).Scan(&smallID); err != nil {
		t.Fatal(err)
	}
	small := call(map[string]any{"id": smallID})
	if !strings.Contains(small, "tiny-body") || strings.Contains(small, "[offset=") {
		t.Fatalf("small body must come back whole:\n%s", small)
	}
}

// TestTagFromProxyAuth: the credential format the host injects must round-trip,
// and anything else must be ignored as a tag (while still being stripped).
func TestTagFromProxyAuth(t *testing.T) {
	basic := func(v string) http.Header {
		return http.Header{proxyAuthHeader: []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(v))}}
	}
	cases := []struct {
		userpass string
		task     int64
		intent   int64
		ok       bool
	}{
		{"artex:t3027_i14438", 3027, 14438, true},
		{"artex:t3027_i0", 3027, 0, true},
		{"artex:t0_i14438", 0, 14438, true},
		{"artex:t0_i0", 0, 0, true},
		{"artex:nonsense", 0, 0, false},
		{"artex:t12_x99", 0, 0, false},
		{"someone:t1_i2", 0, 0, false}, // not our credential
		{"artex:t-1_i2", 0, 0, false},
	}
	for _, c := range cases {
		tag, ok := tagFromProxyAuth(basic(c.userpass))
		if ok != c.ok || tag.TaskID != c.task || tag.IntentID != c.intent {
			t.Errorf("tagFromProxyAuth(%q) = (%+v,%v), want (%d,%d,%v)",
				c.userpass, tag, ok, c.task, c.intent, c.ok)
		}
	}
	if _, ok := tagFromProxyAuth(http.Header{proxyAuthHeader: []string{"Bearer abc"}}); ok {
		t.Error("Bearer credentials must not be read as a run tag")
	}
	if _, ok := tagFromProxyAuth(nil); ok {
		t.Error("a missing header must not produce a tag")
	}
}

func TestProxyURLWithTag(t *testing.T) {
	cases := []struct {
		in           string
		task, intent int64
		want         string
	}{
		{"http://127.0.0.1:8788", 0, 0, "http://127.0.0.1:8788"},
		{"", 5, 6, ""},
		{"http://127.0.0.1:8788", 3027, 14438, "http://artex:t3027_i14438@127.0.0.1:8788"},
		{"socks5://10.0.0.1:1080", 7, 0, "socks5://artex:t7_i0@10.0.0.1:1080"},
		{"http://user:pass@127.0.0.1:8788", 7, 8, "http://artex:t7_i8@127.0.0.1:8788"},
	}
	for _, c := range cases {
		if got := ProxyURLWithTag(c.in, c.task, c.intent); got != c.want {
			t.Errorf("ProxyURLWithTag(%q,%d,%d) = %q, want %q", c.in, c.task, c.intent, got, c.want)
		}
	}
	// The rendered URL must parse back into a working credential.
	u, err := url.Parse(ProxyURLWithTag("http://127.0.0.1:8788", 3027, 14438))
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "127.0.0.1:8788" {
		t.Fatalf("host mangled: %q", u.Host)
	}
	tag, ok := parseTagCredential(u.User.String()[len(tagUser)+1:])
	if !ok || tag.TaskID != 3027 || tag.IntentID != 14438 {
		t.Fatalf("round-trip failed: %+v %v", tag, ok)
	}
}

// TestRecordStampsTagAndStripsHeader is the end-to-end attribution check: the
// credential is removed from the forwarded request (the target must never see
// it), while both ids land in the index and survive into traffic_search.
func TestRecordStampsTagAndStripsHeader(t *testing.T) {
	tr, _ := openTraffic(t)
	s := &sink{t: tr}

	f := newFlow("tagged.test", "GET", "/admin", nil, []byte("ok"))
	f.Request.Header.Set(proxyAuthHeader, "Basic "+base64.StdEncoding.EncodeToString([]byte("artex:t42_i7")))
	s.Requestheaders(f)
	if got := f.Request.Header.Get(proxyAuthHeader); got != "" {
		t.Fatalf("Proxy-Authorization must be stripped before forwarding, got %q", got)
	}
	if strings.Contains(headerString(f.Request.Header), "artex") {
		t.Fatal("internal tag leaked into the request headers")
	}
	raw := requestHeaderLines(f.Request)
	if strings.Contains(raw, "Proxy-Authorization") || strings.Contains(raw, "artex:") {
		t.Fatalf("recorded request headers carry the internal tag:\n%s", raw)
	}

	s.Response(f)
	var taskID, intentID int64
	if err := tr.DB().QueryRow(`SELECT task_id, intent_id FROM exchanges WHERE host='tagged.test'`).Scan(&taskID, &intentID); err != nil {
		t.Fatal(err)
	}
	if taskID != 42 || intentID != 7 {
		t.Fatalf("recorded tag = (%d,%d), want (42,7)", taskID, intentID)
	}

	rows, err := tr.query(queryFilter{Host: "tagged.test", TaskID: 42}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("task filter returned %d rows, want 1", len(rows))
	}
	rows, err = tr.query(queryFilter{Host: "tagged.test", TaskID: 99}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("an unrelated task must not see this exchange, got %d rows", len(rows))
	}
}

// TestRecordCarriesConnectionTag: an HTTPS tunnel sends the credential on CONNECT
// only, so the tag must be remembered per connection and re-applied.
func TestRecordCarriesConnectionTag(t *testing.T) {
	tr, _ := openTraffic(t)
	s := &sink{t: tr}

	conn := &mproxy.ConnContext{}
	connect := newFlow("tls.test", "CONNECT", "/", nil, nil)
	connect.ConnContext = conn
	connect.Request.Header.Set(proxyAuthHeader, "Basic "+base64.StdEncoding.EncodeToString([]byte("artex:t9_i3")))
	s.Requestheaders(connect)

	inner := newFlow("tls.test", "GET", "/inside", nil, []byte("ok"))
	inner.ConnContext = conn // same tunnel, no credential of its own
	s.Response(inner)

	var taskID, intentID int64
	if err := tr.DB().QueryRow(`SELECT task_id, intent_id FROM exchanges WHERE url LIKE '%/inside%'`).Scan(&taskID, &intentID); err != nil {
		t.Fatal(err)
	}
	if taskID != 9 || intentID != 3 {
		t.Fatalf("connection tag not applied: (%d,%d), want (9,3)", taskID, intentID)
	}
}

// TestUntaggedRecordIsZero: without credentials the exchange is unattributed (0),
// which is also what every historical row reads as after the migration.
func TestUntaggedRecordIsZero(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("plain.test", "GET", "/", nil, []byte("ok")))
	var taskID, intentID int64
	if err := tr.DB().QueryRow(`SELECT task_id, intent_id FROM exchanges WHERE host='plain.test'`).Scan(&taskID, &intentID); err != nil {
		t.Fatal(err)
	}
	if taskID != 0 || intentID != 0 {
		t.Fatalf("untagged exchange stamped (%d,%d)", taskID, intentID)
	}
}

// TestTagColumnMigrationIsIdempotent: an index created before the columns existed
// must gain them in place, keeping its rows readable, and a second migration must
// be a no-op.
func TestTagColumnMigrationIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	tr, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`DROP INDEX IF EXISTS idx_ex_task`); err != nil {
		t.Fatal(err)
	}
	// Simulate an old index by recreating the table without the new columns.
	for _, q := range []string{
		`CREATE TABLE exchanges_old AS SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path FROM exchanges`,
		`DROP TABLE exchanges`,
		`ALTER TABLE exchanges_old RENAME TO exchanges`,
	} {
		if _, err := tr.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES('legacy-1',1,'old.test','GET','/','http://old.test/',200,'text/plain',0,2,'')`)
	tr.Close()

	tr2, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("migration must resurrect an old index: %v", err)
	}
	defer tr2.Close()
	var taskID, intentID int64
	if err := tr2.DB().QueryRow(`SELECT task_id, intent_id FROM exchanges WHERE id='legacy-1'`).Scan(&taskID, &intentID); err != nil {
		t.Fatalf("legacy row unreadable after migration: %v", err)
	}
	if taskID != 0 || intentID != 0 {
		t.Fatalf("legacy row tagged (%d,%d), want (0,0)", taskID, intentID)
	}
	tr3, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("second migration must be a no-op: %v", err)
	}
	tr3.Close()
}

// findTool returns one of the traffic tools by name.
func findTool(t *testing.T, tr *Traffic, name string) actool.CoreTool {
	t.Helper()
	for _, tl := range tr.Tools() {
		if tl.Name() == name {
			return tl
		}
	}
	t.Fatalf("tool %q not found", name)
	return nil
}

// headerString flattens a header map for substring assertions.
func headerString(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	return b.String()
}

// TestSearchScopeDefaultsToTask: a worker run's traffic_search is implicitly
// limited to its own task, and an explicit id still wins.
func TestSearchScopeDefaultsToTask(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("shared.test", "GET", "/mine", nil, []byte("a")))
	if _, err := tr.DB().Exec(`UPDATE exchanges SET task_id=11, intent_id=111 WHERE url LIKE '%/mine%'`); err != nil {
		t.Fatal(err)
	}
	tr.record(newFlow("shared.test", "GET", "/theirs", nil, []byte("b")))
	if _, err := tr.DB().Exec(`UPDATE exchanges SET task_id=22 WHERE url LIKE '%/theirs%'`); err != nil {
		t.Fatal(err)
	}

	tool := findTool(t, tr, "traffic_search")
	call := func(ctx context.Context, args map[string]any) string {
		raw, _ := json.Marshal(args)
		res, err := tool.Call(ctx, raw, nil)
		if err != nil {
			t.Fatalf("traffic_search: %v", err)
		}
		return res.Flatten()
	}

	scoped := TagScope(context.Background(), SearchScope{TaskID: 11})
	out := call(scoped, map[string]any{"host": "shared.test"})
	if !strings.Contains(out, "/mine") || strings.Contains(out, "/theirs") {
		t.Fatalf("scoped search returned the wrong rows: %s", out)
	}
	// An explicit task_id overrides the scope.
	out = call(scoped, map[string]any{"host": "shared.test", "task_id": 22})
	if !strings.Contains(out, "/theirs") || strings.Contains(out, "/mine") {
		t.Fatalf("explicit task_id must win over the run scope: %s", out)
	}
	// No scope (planner-side call): everything is visible, as before.
	out = call(context.Background(), map[string]any{"host": "shared.test"})
	if !strings.Contains(out, "/mine") || !strings.Contains(out, "/theirs") {
		t.Fatalf("unscoped search must return both tasks: %s", out)
	}
}
