package oast

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/miekg/dns"
)

// hitOnce delivers one plain callback to a token URL and closes the body.
func hitOnce(t *testing.T, url string) error {
	t.Helper()
	resp, err := http.Get(url + "/probe")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func startTestServer(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:0"
	}
	s := New(opts)
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func callTool(t *testing.T, tool actool.CoreTool, input any, wantErr bool) map[string]any {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("%s: %v", tool.Name(), err)
	}
	if res.IsError != wantErr {
		t.Fatalf("%s: isError=%v want %v: %s", tool.Name(), res.IsError, wantErr, res.Flatten())
	}
	if wantErr {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("%s: decode %q: %v", tool.Name(), res.Flatten(), err)
	}
	return out
}

// The two tools must be reachable end to end: generate a token bound to the run,
// deliver a real HTTP callback to the listener, then read it back through
// oast_poll with an `oast:<id>` evidence reference.
func TestGeneratePollEndToEnd(t *testing.T) {
	s := startTestServer(t, Options{PublicURL: ""})
	tools := s.Tools(func(context.Context) (int64, int64) { return 42, 7 })
	gen, poll := tools[0], tools[1]
	if gen.Name() != "oast_generate" || poll.Name() != "oast_poll" {
		t.Fatalf("unexpected tool names %s / %s", gen.Name(), poll.Name())
	}

	out := callTool(t, gen, map[string]any{"memo": "blind ssrf on /fetch"}, false)
	token, _ := out["token"].(string)
	url, _ := out["callback_url"].(string)
	curl, _ := out["curl_example"].(string)
	if token == "" || !strings.HasSuffix(url, "/o/"+token) {
		t.Fatalf("bad token/url: %+v", out)
	}
	if !strings.Contains(curl, url) {
		t.Fatalf("curl example does not use the callback url: %q", curl)
	}
	if !strings.Contains(url, s.Addr()) {
		t.Fatalf("callback url %q not reachable via bound addr %q", url, s.Addr())
	}

	// Empty poll is a normal answer, not an error.
	empty := callTool(t, poll, map[string]any{"token": token}, false)
	if empty["count"] != float64(0) {
		t.Fatalf("expected no interactions yet, got %+v", empty)
	}

	// Deliver a callback with a query string, custom header and a body.
	req, err := http.NewRequest(http.MethodPost, url+"/ssrf?u=http%3A%2F%2F169.254.169.254%2Flatest", strings.NewReader("payload=xxe"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Oast-Probe", "yes")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	got := callTool(t, poll, map[string]any{"token": token}, false)
	if got["count"] != float64(1) {
		t.Fatalf("count=%v want 1 (%+v)", got["count"], got)
	}
	list, _ := got["interactions"].([]any)
	if len(list) != 1 {
		t.Fatalf("interactions=%v", got["interactions"])
	}
	ev, _ := list[0].(map[string]any)
	if ev["method"] != "POST" {
		t.Fatalf("method=%v", ev["method"])
	}
	if ev["path"] != "/ssrf" {
		t.Fatalf("path=%v", ev["path"])
	}
	if q, _ := ev["query"].(string); !strings.Contains(q, "169.254.169.254") {
		t.Fatalf("query lost: %v", ev["query"])
	}
	if ip, _ := ev["remote_ip"].(string); ip == "" || strings.Contains(ip, ":") {
		t.Fatalf("remote ip not normalized: %v", ev["remote_ip"])
	}
	if ev["body_preview"] != "payload=xxe" {
		t.Fatalf("body preview=%v", ev["body_preview"])
	}
	if ev["task_id"] != float64(42) || ev["intent_id"] != float64(7) {
		t.Fatalf("token binding lost: %+v", ev)
	}
	ref, _ := ev["evidence_ref"].(string)
	if !strings.HasPrefix(ref, "oast:") {
		t.Fatalf("evidence ref=%v", ref)
	}
	headers, _ := ev["headers"].(map[string]any)
	if v, _ := headers["X-Oast-Probe"].([]any); len(v) != 1 || v[0] != "yes" {
		t.Fatalf("headers=%v", ev["headers"])
	}
	// The recorded interaction must resolve for evidence validation.
	if !s.Has(strings.TrimPrefix(ref, "oast:")) {
		t.Fatalf("interaction %s not resolvable", ref)
	}
}

// A token nobody issued must be rejected instead of silently returning "no hits"
// — a typo would otherwise read as "the target is not vulnerable".
func TestPollRejectsUnknownToken(t *testing.T) {
	s := startTestServer(t, Options{})
	tools := s.Tools(nil)
	callTool(t, tools[1], map[string]any{"token": "deadbeef"}, true)
	callTool(t, tools[1], map[string]any{}, true)
	if s.Known("deadbeef") {
		t.Fatal("unknown token reported as known")
	}
}

// Without a bound listener the generator must fail loudly rather than hand the
// model a URL that can never receive a callback.
func TestGenerateWithoutListenerFails(t *testing.T) {
	s := New(Options{})
	tools := s.Tools(nil)
	callTool(t, tools[0], map[string]any{"memo": "x"}, true)
}

// Both ring buffers must bound memory: per-token eviction keeps the newest hits
// and reports how many were dropped, and the global buffer stays capped.
func TestRingBuffersBoundMemory(t *testing.T) {
	s := startTestServer(t, Options{MaxPerToken: 3, MaxTotal: 5})
	gen, poll := s.Tools(nil)[0], s.Tools(nil)[1]
	out := callTool(t, gen, map[string]any{}, false)
	token, _ := out["token"].(string)
	url, _ := out["callback_url"].(string)

	for i := range 8 {
		resp, err := http.Get(fmt.Sprintf("%s/hit?i=%d", url, i))
		if err != nil {
			t.Fatalf("callback %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	got := callTool(t, poll, map[string]any{"token": token}, false)
	if got["count"] != float64(3) {
		t.Fatalf("per-token cap not enforced: %v", got["count"])
	}
	if got["dropped"] != float64(5) {
		t.Fatalf("dropped=%v want 5", got["dropped"])
	}
	if n := s.InteractionCount(); n != 5 {
		t.Fatalf("global cap not enforced: %d", n)
	}
	list, _ := got["interactions"].([]any)
	last, _ := list[len(list)-1].(map[string]any)
	if q, _ := last["query"].(string); q != "i=7" {
		t.Fatalf("ring kept the wrong (oldest) entries, last query=%v", q)
	}
}

// Tokens are capped too: an agent looping oast_generate must not grow the map.
func TestTokenRingEvictsOldest(t *testing.T) {
	s := startTestServer(t, Options{MaxTokens: 2})
	var issued []Token
	for i := range 3 {
		issued = append(issued, s.Generate("", 1, int64(i)))
	}
	if s.Known(issued[0].Value) {
		t.Fatal("oldest token should have been evicted")
	}
	if !s.Known(issued[2].Value) {
		t.Fatal("newest token missing")
	}
}

// Body previews are capped so a target answering a callback with megabytes cannot
// push them into the graph.
func TestBodyPreviewTruncated(t *testing.T) {
	s := startTestServer(t, Options{})
	tok := s.Generate("", 0, 0)
	big := strings.Repeat("A", maxBodyPreview*3)
	resp, err := http.Post(tok.CallbackURL, "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	events, _, known := s.Poll(tok.Value)
	if !known || len(events) != 1 {
		t.Fatalf("events=%d known=%v", len(events), known)
	}
	ev := events[0]
	if len(ev.BodyPreview) != maxBodyPreview || !ev.BodyTruncated {
		t.Fatalf("preview len=%d truncated=%v", len(ev.BodyPreview), ev.BodyTruncated)
	}
}

// Nil receiver safety: the server is optional wiring, so a nil instance must not
// panic and must report "no callback service" through the tool.
func TestNilServerIsSafe(t *testing.T) {
	var s *Server
	if s.PublicURL() != "" || s.Addr() != "" {
		t.Fatal("nil server reported an address")
	}
	if s.Known("x") || s.Has("1") {
		t.Fatal("nil server claimed knowledge")
	}
	if err := s.Start(); err != nil {
		t.Fatalf("nil start: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
	callTool(t, s.Tools(nil)[0], map[string]any{}, true)
}

func TestSplitToken(t *testing.T) {
	for _, tc := range []struct{ path, tok, rest string }{
		{"/o/abc", "abc", ""},
		{"/o/abc/x/y/z", "abc", "/x/y/z"},
		{"/abc", "abc", ""},
		{"/", "", ""},
	} {
		tok, rest := splitToken(tc.path)
		if tok != tc.tok || rest != tc.rest {
			t.Errorf("splitToken(%q)=(%q,%q) want (%q,%q)", tc.path, tok, rest, tc.tok, tc.rest)
		}
	}
}

// The in-process ring dies with the process, so an `oast:<id>` reference that
// outlives a restart must still resolve. SetPersist is the durable half; this
// asserts the hook receives the recorded callback, attribution included, and that
// a failing sink does not prevent the callback from being answered.
func TestPersistHookReceivesCallback(t *testing.T) {
	s := startTestServer(t, Options{})
	var got []Interaction
	s.SetPersist(func(ev Interaction) error {
		got = append(got, ev)
		return nil
	})
	tok := s.Generate("durable proof", 42, 7)
	if err := hitOnce(t, tok.CallbackURL); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("persist hook saw %d callbacks, want 1", len(got))
	}
	if got[0].TaskID != 42 || got[0].IntentID != 7 {
		t.Fatalf("persisted attribution = (%d,%d), want (42,7)", got[0].TaskID, got[0].IntentID)
	}
	if got[0].EvidenceRef != "oast:"+fmt.Sprint(got[0].ID) {
		t.Fatalf("evidence ref = %q for id %d", got[0].EvidenceRef, got[0].ID)
	}
	// Lookup is the read half the host uses before falling back to the database.
	if ev, ok := s.Lookup(got[0].ID); !ok || ev.TaskID != 42 {
		t.Fatalf("Lookup(%d) = %+v ok=%v", got[0].ID, ev, ok)
	}
	if _, ok := s.Lookup(got[0].ID + 1000); ok {
		t.Fatal("Lookup reported an id that was never recorded")
	}
}

// A failing sink must not break the callback: the ring still answers the target,
// and the failure is only logged.
func TestPersistFailureKeepsCallbackWorking(t *testing.T) {
	s := startTestServer(t, Options{})
	s.SetPersist(func(Interaction) error { return fmt.Errorf("db down") })
	tok := s.Generate("best effort", 1, 0)
	if err := hitOnce(t, tok.CallbackURL); err != nil {
		t.Fatalf("callback failed while the sink was down: %v", err)
	}
	if events, _, known := s.Poll(tok.Value); !known || len(events) != 1 {
		t.Fatalf("callback not retained in the ring: %v", events)
	}
}

// References must stay resolvable even when the durable sink never received the id.
// The old counter restarted at 1 (or at MAX(id)), so a callback whose persist failed
// — and therefore never appeared in MAX(id) — was re-minted after a restart, and the
// old reference silently changed meaning.
func TestIDsUniqueWithoutPersistedFloor(t *testing.T) {
	// Process A: persist always fails, so nothing reaches the durable store.
	a := New(Options{Addr: "127.0.0.1:0"})
	if err := a.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetPersist(func(Interaction) error { return fmt.Errorf("db down") })
	tokA := a.Generate("persist will fail", 5, 0)
	if err := hitOnce(t, tokA.CallbackURL); err != nil {
		t.Fatal(err)
	}
	evA, _, _ := a.Poll(tokA.Value)
	if len(evA) != 1 {
		t.Fatalf("process A recorded %d events", len(evA))
	}

	// Process B: nothing was persisted, so any sequence-based scheme would restart at
	// the same place. Random ids do not.
	b := New(Options{Addr: "127.0.0.1:0"})
	if err := b.Start(); err != nil {
		t.Fatalf("start B: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	tokB := b.Generate("second process", 5, 0)
	if err := hitOnce(t, tokB.CallbackURL); err != nil {
		t.Fatal(err)
	}
	evB, _, _ := b.Poll(tokB.Value)
	if len(evB) != 1 {
		t.Fatalf("process B recorded %d events", len(evB))
	}
	if evB[0].ID == evA[0].ID {
		t.Fatalf("id %d re-minted across processes with no persisted floor", evA[0].ID)
	}
	if evA[0].EvidenceRef == evB[0].EvidenceRef {
		t.Fatalf("both processes minted %s", evA[0].EvidenceRef)
	}
}

// Two instances must not share an id — including when they start at the same
// instant. A time-based base overlapped there; random 62-bit ids cannot.
func TestIDsUniqueAcrossConcurrentInstances(t *testing.T) {
	a := New(Options{Addr: "127.0.0.1:0"})
	c := New(Options{Addr: "127.0.0.1:0"})
	for _, s := range []*Server{a, c} {
		if err := s.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
	}
	tokA := a.Generate("instance A", 1, 0)
	tokC := c.Generate("instance C", 1, 0)
	for _, pair := range []*struct {
		s   *Server
		tok Token
	}{{a, tokA}, {c, tokC}} {
		if err := hitOnce(t, pair.tok.CallbackURL); err != nil {
			t.Fatal(err)
		}
	}
	evA, _, _ := a.Poll(tokA.Value)
	evC, _, _ := c.Poll(tokC.Value)
	if len(evA) != 1 || len(evC) != 1 {
		t.Fatalf("callbacks not recorded: A=%v C=%v", evA, evC)
	}
	if evA[0].ID == evC[0].ID {
		t.Fatalf("two instances minted the same id %d", evA[0].ID)
	}
	if evA[0].ID <= 0 || evC[0].ID <= 0 {
		t.Fatalf("ids must be positive: A=%d C=%d", evA[0].ID, evC[0].ID)
	}
	if evA[0].ID>>62 != 0 || evC[0].ID>>62 != 0 {
		t.Fatalf("ids must stay positive int64 (BIGINT-safe): A=%d C=%d", evA[0].ID, evC[0].ID)
	}
}

// A durable id conflict must NOT publish the event: the reference already exists and
// means the old callback, so serving the new one from memory would make the same id
// resolve differently depending on which store answers.
func TestConflictDoesNotPublishEvent(t *testing.T) {
	s := startTestServer(t, Options{})
	s.SetPersist(func(Interaction) error { return NewConflictError(fmt.Errorf("id taken")) })
	tok := s.Generate("conflict", 1, 0)

	req, err := http.NewRequest(http.MethodGet, tok.CallbackURL+"/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("callback request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("conflict answered %d, want 503 (no reference handed out)", resp.StatusCode)
	}
	if events, _, known := s.Poll(tok.Value); !known || len(events) != 0 {
		t.Fatalf("conflicting event was published: %v", events)
	}
	// The id set must not keep the abandoned id.
	if n := len(s.ids); n != 0 {
		t.Fatalf("abandoned id retained in the dedup set: %d", n)
	}
}

// An ordinary write failure still records the callback in memory: durability is lost,
// availability is not.
func TestOrdinaryPersistFailureStillPublishes(t *testing.T) {
	s := startTestServer(t, Options{})
	s.SetPersist(func(Interaction) error { return fmt.Errorf("db down") })
	tok := s.Generate("best effort", 1, 0)
	if err := hitOnce(t, tok.CallbackURL); err != nil {
		t.Fatal(err)
	}
	if events, _, known := s.Poll(tok.Value); !known || len(events) != 1 {
		t.Fatalf("callback lost on a plain write failure: %v", events)
	}
}

// The process-wide id set must follow the rings exactly: every id still answerable
// through Poll (the per-token ring) or Lookup (the global ring) keeps a positive
// reference count, and an id evicted from every ring is forgotten. The old
// "delete arbitrary map keys" pruning could drop a live id and let the next draw
// reuse it, re-pointing `oast:<id>` evidence at a different callback.
func TestIDRefcountsTrackRingEviction(t *testing.T) {
	s := startTestServer(t, Options{MaxTotal: 4, MaxPerToken: 2, MaxTokens: 2})

	// The third token evicts the first, which by then owns no callback.
	var tokens []Token
	for i := range 3 {
		tokens = append(tokens, s.Generate("", 1, int64(i)))
	}
	if s.Known(tokens[0].Value) {
		t.Fatal("setup: oldest token should have been evicted")
	}

	// A callback to the evicted token reaches only the global ring: it must be
	// forgotten when the global ring drops it, with a single reference to lose.
	if err := hitOnce(t, tokens[0].CallbackURL); err != nil {
		t.Fatal(err)
	}
	ever := map[int64]bool{}
	record := func() {
		for _, tok := range tokens[1:] {
			events, _, _ := s.Poll(tok.Value)
			for _, ev := range events {
				ever[ev.ID] = true
			}
		}
		for _, ev := range s.snapshotEvents() {
			ever[ev.ID] = true
		}
	}
	record()
	for round := range 3 {
		for _, tok := range tokens[1:] {
			if err := hitOnce(t, tok.CallbackURL); err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		record()
	}

	retained := map[int64]bool{}
	for _, tok := range tokens[1:] {
		events, _, known := s.Poll(tok.Value)
		if !known {
			t.Fatalf("token %s lost from the token ring", tok.Value)
		}
		if len(events) != s.opts.MaxPerToken {
			t.Fatalf("per-token ring holds %d, want %d", len(events), s.opts.MaxPerToken)
		}
		for _, ev := range events {
			retained[ev.ID] = true
		}
	}
	for _, ev := range s.snapshotEvents() {
		retained[ev.ID] = true
	}

	counts := s.idRefCounts()
	for id := range retained {
		if counts[id] <= 0 {
			t.Fatalf("retained interaction %d has no id reference", id)
		}
	}
	for id := range ever {
		if retained[id] {
			continue
		}
		if _, still := counts[id]; still {
			t.Fatalf("evicted id %d still occupies the dedup set", id)
		}
		if _, ok := s.Lookup(id); ok {
			t.Fatalf("evicted id %d is still lookupable", id)
		}
	}
	if n := len(counts); n > s.opts.MaxTotal {
		t.Fatalf("id set unbounded: %d entries for MaxTotal=%d", n, s.opts.MaxTotal)
	}
	if len(ever) <= len(retained) {
		t.Fatalf("eviction did not happen: %d ids seen, %d retained", len(ever), len(retained))
	}
}

// idRefCounts copies the reference counts for white-box assertions.
func (s *Server) idRefCounts() map[int64]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int64]int, len(s.ids))
	for id, n := range s.ids {
		out[id] = n
	}
	return out
}

// snapshotEvents copies the global ring under the lock for white-box assertions.
func (s *Server) snapshotEvents() []*Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Interaction(nil), s.events...)
}

// Adapter names and address ranges that cannot carry a callback from a remote
// target must be recognised before one is advertised.
func TestVirtualInterfaceSelection(t *testing.T) {
	cases := []struct {
		name string
		mac  net.HardwareAddr
		ip   string
		want bool
	}{
		{"VirtualBox Host-Only Network", nil, "192.168.56.1", true},
		{"vEthernet (WSL)", nil, "172.20.16.1", true},
		{"br-1a2b3c", nil, "10.0.0.5", true},
		{"docker0", nil, "172.17.0.1", true},
		{"Ethernet", nil, "10.10.20.5", false},
		{"Wi-Fi", nil, "198.18.0.7", true},
		{"Ethernet 2", nil, "169.254.3.4", true},
		// Chinese Windows names the host-only adapter "以太网 2"; the
		// VirtualBox locally administered MAC prefix identifies it.
		{"以太网 2", net.HardwareAddr{0x0a, 0x00, 0x27, 0x00, 0x00, 0x04}, "192.168.56.1", true},
		// A VM guest adapter (08:00:27) inside the tested host is physical.
		{"eth0", net.HardwareAddr{0x08, 0x00, 0x27, 0x12, 0x34, 0x56}, "10.0.2.15", false},
	}
	for _, c := range cases {
		if got := isVirtualInterface(c.name, c.mac, net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isVirtualInterface(%q, %v, %q) = %v, want %v", c.name, c.mac, c.ip, got, c.want)
		}
	}
}

func TestTargetIPv4(t *testing.T) {
	cases := map[string]string{
		"10.1.2.3":                   "10.1.2.3",
		"10.1.2.3:443":               "10.1.2.3",
		"http://10.1.2.3:8080/x?y=1": "10.1.2.3",
		"https://127.0.0.1/probe":    "127.0.0.1",
		"example.internal":           "",
		"":                           "",
	}
	for in, want := range cases {
		if got := targetIPv4(in); got != want {
			t.Errorf("targetIPv4(%q) = %q, want %q", in, got, want)
		}
	}
}

// The embedded DNS responder must record queries and answer them, on UDP and TCP:
// a blind payload that resolves through DNS proves the same outbound behaviour an
// HTTP callback does.
func TestDNSInteractionEndToEnd(t *testing.T) {
	s := startTestServer(t, Options{})
	tok := s.Generate("dns callback", 9, 5)
	if tok.DNSAddr == "" || tok.DNSDomain != tok.Value+"."+oastDomain {
		t.Fatalf("token lacks DNS identity: %+v", tok)
	}
	if !strings.Contains(tok.DNSExample, tok.DNSDomain) {
		t.Fatalf("dns example does not name the domain: %q", tok.DNSExample)
	}

	qname := strings.ToUpper(tok.Value) + "." + strings.ToUpper(oastDomain) + "."
	for i, network := range []string{"udp", "tcp"} {
		m := new(dns.Msg)
		m.SetQuestion(qname, dns.TypeA)
		resp, _, err := (&dns.Client{Net: network, Timeout: 5 * time.Second}).Exchange(m, tok.DNSAddr)
		if err != nil {
			t.Fatalf("%s query: %v", network, err)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("%s answer = %+v", network, resp)
		}
		if a, ok := resp.Answer[0].(*dns.A); !ok || a.A == nil || a.A.To4() == nil {
			t.Fatalf("%s answer is not an A record: %v", network, resp.Answer[0])
		}
		if i == 1 {
			break
		}
	}

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeTXT)
	resp, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(m, tok.DNSAddr)
	if err != nil {
		t.Fatalf("TXT query: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("TXT answer = %+v", resp)
	}
	if txt, ok := resp.Answer[0].(*dns.TXT); !ok || len(txt.Txt) != 1 || txt.Txt[0] != "oast:"+tok.Value {
		t.Fatalf("TXT answer = %v", resp.Answer[0])
	}

	events, _, known := s.Poll(tok.Value)
	if !known || len(events) != 3 {
		t.Fatalf("DNS interactions recorded = %d (known=%v), want 3", len(events), known)
	}
	for _, ev := range events {
		if ev.Protocol != "dns" || ev.EvidenceRef != fmt.Sprintf("oast:%d", ev.ID) {
			t.Fatalf("bad DNS interaction: %+v", ev)
		}
		if ev.TaskID != 9 || ev.IntentID != 5 {
			t.Fatalf("DNS attribution = (%d,%d)", ev.TaskID, ev.IntentID)
		}
		if !strings.EqualFold(ev.Path, strings.TrimSuffix(qname, ".")) {
			t.Fatalf("DNS path = %q", ev.Path)
		}
		switch ev.Method {
		case "DNS:A", "DNS:TXT":
		default:
			t.Fatalf("DNS method = %q", ev.Method)
		}
	}
}

// An external interactsh server supplies both the generated domain and the
// interactions. The real client performs registration, polling and deregistering;
// the fake server returns the plaintext Extra list the client already accepts.
func TestExternalInteractshRelay(t *testing.T) {
	var unique atomic.Value
	var delivered atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"message":"registration successful"}`)
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		uid, _ := unique.Load().(string)
		if uid == "" || !delivered.CompareAndSwap(false, true) {
			_, _ = io.WriteString(w, `{"extra":[]}`)
			return
		}
		dnsEvent, _ := json.Marshal(map[string]any{
			"protocol": "dns", "unique-id": uid, "full-id": uid + ".probe." + oastDomain,
			"q-type": "A", "remote-address": "203.0.113.9:5353", "raw-request": "question",
		})
		httpEvent, _ := json.Marshal(map[string]any{
			"protocol": "http", "unique-id": strings.ToUpper(uid), "full-id": uid + "/x",
			"remote-address": "203.0.113.10:44321", "raw-request": "GET /x HTTP/1.1",
		})
		_ = json.NewEncoder(w).Encode(map[string]any{"extra": []string{string(dnsEvent), string(httpEvent)}})
	})
	mux.HandleFunc("/deregister", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	// Standard interactsh configuration names a bare host with no scheme. The
	// client prepends https:// and registers against the TLS server; the
	// advertised host comes from the successful registration, not url.Parse(raw).
	bareHost := strings.TrimPrefix(srv.URL, "https://")
	s := New(Options{InteractshURL: bareHost, PollInterval: 20 * time.Millisecond})
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.PublicURL() == "" {
		t.Fatal("external relay must still report a public URL")
	}
	tok := s.Generate("relay", 11, 22)
	if tok.Value == "" || tok.CallbackURL != "http://"+tok.DNSDomain || !strings.HasPrefix(tok.DNSDomain, tok.Value+".") {
		t.Fatalf("external token = %+v", tok)
	}
	unique.Store(tok.Value)

	deadline := time.Now().Add(10 * time.Second)
	var events []Interaction
	for time.Now().Before(deadline) {
		events, _, _ = s.Poll(tok.Value)
		if len(events) == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(events) != 2 {
		t.Fatalf("relayed interactions = %d, want 2", len(events))
	}
	protocols := map[string]string{}
	for _, ev := range events {
		protocols[ev.Protocol] = ev.Method
		if ev.TaskID != 11 || ev.IntentID != 22 {
			t.Fatalf("relayed attribution = (%d,%d)", ev.TaskID, ev.IntentID)
		}
		if ev.EvidenceRef == "" || !s.Has(strings.TrimPrefix(ev.EvidenceRef, "oast:")) {
			t.Fatalf("relayed interaction has no resolvable reference: %+v", ev)
		}
	}
	if protocols["dns"] != "DNS:A" || protocols["http"] != "HTTP" {
		t.Fatalf("relayed protocols = %v", protocols)
	}
	if events[0].RemoteIP != "203.0.113.9" || events[1].RemoteIP != "203.0.113.10" {
		t.Fatalf("relayed remote addresses = %q / %q", events[0].RemoteIP, events[1].RemoteIP)
	}
}

// An implicit DNS bind that fails must not take the HTTP listener down: the
// callback service stays usable and reports no DNS address.
func TestImplicitDNSBindFailureKeepsHTTP(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0"})
	s.opts.DNSAddr = "127.0.0.1:99999"
	if err := s.Start(); err != nil {
		t.Fatalf("HTTP listener should survive a failed implicit DNS bind: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.Addr() == "" {
		t.Fatal("HTTP listener not bound")
	}
	if s.dnsConn != nil || s.dnsAddr != "" {
		t.Fatalf("DNS listener reported as bound: conn=%v addr=%q", s.dnsConn, s.dnsAddr)
	}
	tok := s.Generate("http only", 1, 0)
	if tok.DNSAddr != "" || tok.DNSDomain != "" {
		t.Fatalf("token advertises an absent DNS listener: %+v", tok)
	}
	if err := hitOnce(t, tok.CallbackURL); err != nil {
		t.Fatalf("HTTP callback: %v", err)
	}
	if events, _, known := s.Poll(tok.Value); !known || len(events) != 1 {
		t.Fatalf("callback not recorded: %v", events)
	}
}

// A DNS address the operator named explicitly is part of the requested service:
// a bind failure stops startup instead of silently serving HTTP alone.
func TestExplicitDNSBindFailureStopsStart(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0", DNSAddr: "127.0.0.1:99999"})
	if err := s.Start(); err == nil {
		t.Fatal("explicit DNS bind failure should be reported")
	}
	if s.Addr() != "" || s.ln != nil {
		t.Fatalf("HTTP listener left behind after failed start: addr=%q ln=%v", s.Addr(), s.ln)
	}
}

// A busy TCP port next to the UDP DNS listener only removes the TCP half; UDP
// keeps answering instead of the whole DNS service failing.
func TestDNSTCPConflictKeepsUDP(t *testing.T) {
	for range 5 {
		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcpLn.Addr().(*net.TCPAddr).Port
		probe, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			_ = tcpLn.Close()
			continue
		}
		_ = probe.Close()

		s := New(Options{Addr: "127.0.0.1:0", DNSAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})
		if err := s.startDNS(); err != nil {
			_ = tcpLn.Close()
			t.Fatalf("UDP DNS should start despite the TCP conflict: %v", err)
		}
		if s.dnsConn == nil || s.dnsTCPSrv != nil || s.dnsTCP != nil {
			_ = tcpLn.Close()
			_ = s.Close()
			t.Fatalf("TCP half not degraded: conn=%v tcp=%v tcpSrv=%v", s.dnsConn, s.dnsTCP, s.dnsTCPSrv)
		}
		tok := s.Generate("udp only", 3, 4)
		m := new(dns.Msg)
		m.SetQuestion(tok.DNSDomain+".", dns.TypeA)
		resp, _, qerr := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(m, tok.DNSAddr)
		_ = tcpLn.Close()
		_ = s.Close()
		if qerr != nil || resp == nil || len(resp.Answer) != 1 {
			t.Fatalf("UDP DNS answer = %+v err=%v", resp, qerr)
		}
		return
	}
	t.Fatal("could not reserve a port free for UDP and busy for TCP")
}
