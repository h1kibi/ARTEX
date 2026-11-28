// Package oast implements the built-in out-of-band application security testing
// (OAST) subsystem: a small HTTP listener that hands out unique callback URLs and
// records every hit on them, so a blind SSRF / XXE / async RCE / Log4j / blind XSS
// can be proven by an outbound callback instead of a visible response body.
//
// Design constraints (docs §4.3 WP6):
//   - three callback sources share one recording path: a local HTTP listener, a
//     local DNS responder and an optional external interactsh relay. The package
//     never imports other artex packages, so it can be embedded by the server and
//     unit-tested in isolation.
//   - every interaction is bounded by ring buffers (per token AND globally) so a
//     noisy target cannot exhaust process memory.
//   - each interaction is addressable as an evidence pointer `oast:<id>`, the same
//     way traffic records are `traffic:<id>`.
package oast

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/miekg/dns"
	ishclient "github.com/projectdiscovery/interactsh/pkg/client"
)

// Defaults bound the memory footprint of one embedded OAST server.
const (
	DefaultMaxPerToken = 200  // interactions kept per token
	DefaultMaxTotal    = 5000 // interactions kept across all tokens
	DefaultMaxTokens   = 2000 // live tokens (oldest evicted first)
	maxHeaderFields    = 40   // header name/value pairs kept per interaction
	maxHeaderValueLen  = 512
	maxBodyRead        = 4096 // bytes read off the wire (drained, then discarded)
	maxBodyPreview     = 1024 // bytes of body kept for the preview
	// Default listens on every interface with an OS-assigned port: a blind SSRF
	// payload is sent by the TARGET, which usually lives on another host, so a
	// loopback-only listener would never see the callback. resolvePublicURL picks
	// the machine's route-selected IPv4 for the advertised URL.
	defaultListenAddress = "0.0.0.0:0"
	// Default DNS listener: same availability as HTTP, OS-assigned port.
	defaultDNSListenAddress = "0.0.0.0:0"
	// oastDomain is the wildcard domain the local DNS listener answers for.
	oastDomain = "oast.local"
)

// Options configures one OAST server.
type Options struct {
	// Addr is the local listen address ("127.0.0.1:0", ":8081", …). Empty means
	// loopback with an OS-assigned port.
	Addr string
	// PublicURL is the base URL a target can reach this listener on (an address
	// inside the tested network, e.g. "http://10.0.0.7:8081"). Empty = derive from
	// the listener: the route-selected IPv4 when listening on all interfaces,
	// otherwise the loopback address.
	PublicURL string
	// DNSAddr is the local DNS listen address. Empty means the same interface as
	// Addr with an OS-assigned port. "off"/"disabled" turns the DNS listener off.
	DNSAddr string
	// InteractshURL points at an external (public or self-hosted) interactsh
	// server. When set, the embedded listeners stay off and callbacks come from
	// that server's polling API.
	InteractshURL   string
	InteractshToken string
	// PollInterval is the interactsh polling cadence (0 = 5s).
	PollInterval time.Duration
	// MaxPerToken / MaxTotal / MaxTokens override the ring capacities (0 = default).
	MaxPerToken int
	MaxTotal    int
	MaxTokens   int
}

// Token is one generated callback identity, bound to the (task, intent) that
// created it so the planner can attribute a callback to the intent that caused it.
type Token struct {
	Value       string `json:"token"`
	CallbackURL string `json:"callback_url"`
	CurlExample string `json:"curl_example"`
	DNSAddr     string `json:"dns_addr,omitempty"`
	DNSDomain   string `json:"dns_domain,omitempty"`
	DNSExample  string `json:"dns_example,omitempty"`
	Memo        string `json:"memo,omitempty"`
	TaskID      int64  `json:"task_id,omitempty"`
	IntentID    int64  `json:"intent_id,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// Interaction is one recorded callback (one HTTP request or DNS query that hit a
// token's identity).
type Interaction struct {
	ID            int64               `json:"id"`
	EvidenceRef   string              `json:"evidence_ref"` // "oast:<id>"
	Token         string              `json:"token"`
	Protocol      string              `json:"protocol,omitempty"` // http / dns / smtp / ldap / …
	At            string              `json:"at"`
	RemoteIP      string              `json:"remote_ip"`
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	Query         string              `json:"query,omitempty"`
	Host          string              `json:"host,omitempty"`
	Headers       map[string][]string `json:"headers,omitempty"`
	BodyPreview   string              `json:"body_preview,omitempty"`
	BodyTruncated bool                `json:"body_truncated,omitempty"`
	TaskID        int64               `json:"task_id,omitempty"`
	IntentID      int64               `json:"intent_id,omitempty"`
}

type tokenState struct {
	token     Token
	events    []*Interaction // bounded by maxPerToken
	dropped   int            // interactions evicted by the per-token ring
	lastEvent time.Time
}

// Server is the embedded OAST listener. Safe for concurrent use; a nil *Server is
// a no-op (every method returns zero values), so callers can leave it unwired.
type Server struct {
	mu      sync.Mutex
	tokens  map[string]*tokenState
	order   []string // token creation order (ring eviction)
	events  []*Interaction
	evicted int
	// ids counts, per id minted by this process, how many in-memory rings still
	// hold the interaction. A random draw cannot repeat an id while its count is
	// above zero; an entry is removed when the last ring reference is evicted. A
	// freshly minted id sits at zero until one of the rings retains it.
	ids  map[int64]int
	opts Options
	// dnsExplicit means the operator named DNSAddr, so a bind failure fails
	// Start instead of degrading to HTTP-only.
	dnsExplicit bool
	public      string
	addr        string
	ln          net.Listener
	httpSrv     *http.Server
	dnsConn     net.PacketConn
	dnsTCP      net.Listener
	dnsSrv      *dns.Server
	dnsTCPSrv   *dns.Server
	dnsAddr     string
	ish         *ishclient.Client
	startErr    error
	started     bool
	// persist, when set by the host, durably records every callback so an
	// `oast:<id>` reference stays resolvable across a restart. nil = memory only.
	persist atomic.Pointer[func(Interaction) error]
}

// SetPersist installs the durable sink for recorded callbacks. Nil clears it.
func (s *Server) SetPersist(fn func(Interaction) error) {
	if s == nil {
		return
	}
	if fn == nil {
		s.persist.Store(nil)
		return
	}
	s.persist.Store(&fn)
}

// Lookup returns the retained in-memory interaction for id, and whether it is
// still in the ring. The host falls back to its durable store when this reports
// false (a callback from before a restart).
func (s *Server) Lookup(id int64) (Interaction, bool) {
	if s == nil {
		return Interaction{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range s.events {
		if ev.ID == id {
			return *ev, true
		}
	}
	return Interaction{}, false
}

// New builds a server. Call Start to bind the listener.
func New(opts Options) *Server {
	dnsExplicit := strings.TrimSpace(opts.DNSAddr) != ""
	if opts.MaxPerToken <= 0 {
		opts.MaxPerToken = DefaultMaxPerToken
	}
	if opts.MaxTotal <= 0 {
		opts.MaxTotal = DefaultMaxTotal
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = DefaultMaxTokens
	}
	if strings.TrimSpace(opts.Addr) == "" {
		opts.Addr = defaultListenAddress
	}
	if strings.TrimSpace(opts.DNSAddr) == "" {
		opts.DNSAddr = defaultDNSAddrFor(opts.Addr)
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	return &Server{tokens: map[string]*tokenState{}, opts: opts, ids: map[int64]int{}, dnsExplicit: dnsExplicit}
}

// defaultDNSAddrFor mirrors the HTTP bind scope. A loopback HTTP listener gets a
// loopback DNS listener too: binding 0.0.0.0 there would trip the Windows
// firewall prompt for a service the caller deliberately kept local.
func defaultDNSAddrFor(httpAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(httpAddr))
	if err == nil {
		host = strings.ToLower(strings.Trim(host, "[]"))
		if host == "localhost" {
			return "127.0.0.1:0"
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return net.JoinHostPort(host, "0")
		}
	}
	return defaultDNSListenAddress
}

// idSpaceBits is the width of the random id space: 62 bits keeps every value a
// positive int64 (BIGINT-safe) while making a collision between independent
// processes negligible — 2^62 ≈ 4.6e18, so two processes minting a million callbacks
// each collide with probability below 1e-7.
const idSpaceBits = 62

// nextID mints an interaction id.
//
// An `oast:<id>` reference is evidence: once written into a checkpoint or finding it
// must keep pointing at the same callback forever. Every counter-based scheme failed
// that promise in some corner: a 1..N counter repeats after a restart; a persisted
// MAX(id) floor misses callbacks whose persist failed; a process-start-time base
// still overlaps when two instances start in the same nanosecond or when a clock
// steps backwards. A random 62-bit value has no shared sequence to collide on, which
// is why uniqueness does not depend on the database, the clock or coordination.
//
// The in-process set makes a repeat within one process impossible as well; the
// durable table's ON CONFLICT then becomes a belt-and-braces check that REPORTs a
// conflict instead of silently keeping two meanings for one id.
func (s *Server) nextID() int64 {
	for attempt := 0; attempt < 8; attempt++ {
		id := randomID()
		s.mu.Lock()
		_, seen := s.ids[id]
		if !seen {
			// Zero references: minted but not yet published into a ring.
			s.ids[id] = 0
		}
		s.mu.Unlock()
		if !seen {
			return id
		}
	}
	// Eight collisions in a 2^62 space means the CSPRNG is broken. A repeated id
	// would silently re-point an existing evidence reference, so refuse to mint.
	return 0
}

// ConflictError marks a durable-write failure caused by an id ALREADY existing —
// i.e. the reference would silently change meaning. The OAST server distinguishes it
// from an ordinary write failure (database down) and refuses to publish the event.
type ConflictError struct{ Err error }

func (e *ConflictError) Error() string { return e.Err.Error() }
func (e *ConflictError) Unwrap() error { return e.Err }

// NewConflictError wraps a durable-write error as an id conflict.
func NewConflictError(err error) error { return &ConflictError{Err: err} }

func isIDConflict(err error) bool {
	var ce *ConflictError
	return errors.As(err, &ce)
}

// releaseID forgets an id that was minted but never published, so the set stays in
// step with what the rings actually serve.
func (s *Server) releaseID(id int64) {
	if s == nil || id == 0 {
		return
	}
	s.mu.Lock()
	delete(s.ids, id)
	s.mu.Unlock()
}

// retainID records that one more ring now holds the id. Caller holds s.mu.
func (s *Server) retainID(id int64) {
	s.ids[id]++
}

// releaseRefs drops one reference per interaction in events and forgets an id once
// its last ring reference is gone. Caller holds s.mu.
func (s *Server) releaseRefs(events []*Interaction) {
	for _, ev := range events {
		if n := s.ids[ev.ID]; n > 1 {
			s.ids[ev.ID] = n - 1
		} else {
			delete(s.ids, ev.ID)
		}
	}
}

func randomID() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG must not fall back to a predictable sequence: clock-derived
		// ids are exactly what collides across processes.
		return 0
	}
	v := int64(binary.BigEndian.Uint64(b[:]))
	v &= (1 << idSpaceBits) - 1
	if v <= 0 {
		v = 1
	}
	return v
}

// Start binds the listeners (or registers with the interactsh server) and serves
// in the background. It is idempotent.
func (s *Server) Start() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.started {
		err := s.startErr
		s.mu.Unlock()
		return err
	}
	s.started = true
	s.mu.Unlock()

	err := s.startListeners()

	s.mu.Lock()
	s.startErr = err
	s.mu.Unlock()
	return err
}

// startListeners brings up exactly one callback source: an external interactsh
// server when configured, otherwise the embedded HTTP and DNS listeners.
func (s *Server) startListeners() error {
	if raw := strings.TrimSpace(s.opts.InteractshURL); raw != "" {
		return s.startInteractsh(raw)
	}

	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	public := resolvePublicURL(s.opts.PublicURL, ln.Addr())
	if err := s.startDNS(); err != nil {
		if s.dnsExplicit {
			_ = ln.Close()
			return err
		}
		log.Printf("[oast] DNS 监听未启动，HTTP 回调继续提供: %v", err)
	}
	s.mu.Lock()
	s.ln = ln
	s.addr = ln.Addr().String()
	s.public = public
	s.httpSrv = srv
	s.mu.Unlock()

	go func(srv *http.Server) {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("[oast] listener stopped: %v", serveErr)
		}
	}(srv)
	log.Printf("[oast] 带外回调监听 %s (回调基址 %s)", ln.Addr(), public)
	return nil
}

// Addr returns the bound listen address ("" before Start).
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// PublicURL returns the callback base URL handed to targets ("" before Start).
func (s *Server) PublicURL() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.public
}

// Close stops every listener and the interactsh polling loop. Safe on nil /
// not-started servers.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	srv := s.httpSrv
	udpSrv, tcpSrv := s.dnsSrv, s.dnsTCPSrv
	pc, tcpLn := s.dnsConn, s.dnsTCP
	ish := s.ish
	s.httpSrv, s.dnsSrv, s.dnsTCPSrv = nil, nil, nil
	s.dnsConn, s.dnsTCP, s.ish = nil, nil, nil
	s.dnsAddr = ""
	s.started = false
	s.mu.Unlock()

	if ish != nil {
		_ = ish.StopPolling()
		_ = ish.Close()
	}
	for _, ds := range []*dns.Server{udpSrv, tcpSrv} {
		if ds != nil {
			_ = ds.Shutdown()
		}
	}
	if pc != nil {
		_ = pc.Close()
	}
	if tcpLn != nil {
		_ = tcpLn.Close()
	}
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// Generate allocates a fresh token bound to (taskID, intentID) and returns its
// callback identity. memo is free-form model context (never executed, only echoed).
func (s *Server) Generate(memo string, taskID, intentID int64) Token {
	return s.GenerateForTarget(memo, "", taskID, intentID)
}

// GenerateForTarget is Generate with a target hint: on a host with several
// adapters the advertised callback address comes from the route table entry that
// reaches target, so a target on a bridged VM network does not receive an address
// from an unrelated adapter.
func (s *Server) GenerateForTarget(memo, target string, taskID, intentID int64) Token {
	if s == nil {
		return Token{}
	}
	s.mu.Lock()
	if s.ish != nil {
		ish := s.ish
		s.mu.Unlock()
		return s.generateInteractsh(ish, memo, taskID, intentID)
	}
	tok := newToken()
	now := time.Now().UTC()
	base := s.baseForTargetLocked(target)
	if base == "" {
		base = strings.TrimRight(s.opts.PublicURL, "/")
	}
	dnsAddr, dnsDomain, dnsExample := s.dnsTokenFieldsLocked(base, tok)
	s.addTokenLocked(Token{
		Value: tok, Memo: strings.TrimSpace(memo), TaskID: taskID, IntentID: intentID,
		CreatedAt: now.Format(time.RFC3339),
		DNSAddr:   dnsAddr, DNSDomain: dnsDomain, DNSExample: dnsExample,
	})
	st := s.tokens[tok]
	url := base + "/o/" + tok
	st.token.CallbackURL = url
	st.token.CurlExample = "curl -sS -i '" + url + "/probe?src=oast'"
	out := st.token
	s.mu.Unlock()
	return out
}

// baseForTargetLocked picks this token's callback base. An operator-fixed
// PublicURL and a concrete bind address stay authoritative; only a wildcard bind
// with no fixed URL consults the target's route.
func (s *Server) baseForTargetLocked(target string) string {
	if strings.TrimSpace(s.opts.PublicURL) != "" {
		return s.public
	}
	host, port, err := net.SplitHostPort(s.addr)
	if err != nil {
		return s.public
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
		return s.public
	}
	if h := callbackHostForTarget(target); h != "" {
		return "http://" + net.JoinHostPort(h, port)
	}
	return s.public
}

// dnsTokenFieldsLocked describes where to send a DNS query for tok. The host is
// the DNS listener's reachable address, which under a wildcard bind follows the
// same route-selected address as the HTTP callback.
func (s *Server) dnsTokenFieldsLocked(base, tok string) (addr, domain, example string) {
	if s.dnsAddr == "" {
		return "", "", ""
	}
	host, port, err := net.SplitHostPort(s.dnsAddr)
	if err != nil {
		return "", "", ""
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		if u, uerr := url.Parse(base); uerr == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
	}
	domain = tok + "." + oastDomain
	if port == "53" {
		example = "nslookup " + domain + " " + host
	} else {
		example = "dig @" + host + " -p " + port + " " + domain
	}
	return net.JoinHostPort(host, port), domain, example
}

// addTokenLocked registers one token and evicts the oldest beyond the capacity.
func (s *Server) addTokenLocked(t Token) {
	s.tokens[t.Value] = &tokenState{token: t}
	s.order = append(s.order, t.Value)
	for len(s.order) > s.opts.MaxTokens {
		oldest := s.order[0]
		s.order = s.order[1:]
		if dropped, ok := s.tokens[oldest]; ok {
			// The token's callbacks leave every ring with it: their ids stop being
			// addressable, so their references go too.
			s.releaseRefs(dropped.events)
		}
		delete(s.tokens, oldest)
	}
}

// Poll returns every interaction recorded for token, oldest first. known reports
// whether the token exists (false for a typo or an evicted token). Non-blocking.
func (s *Server) Poll(token string) (events []Interaction, dropped int, known bool) {
	if s == nil {
		return nil, 0, false
	}
	token = strings.TrimSpace(token)
	s.mu.Lock()
	st, ok := s.tokens[token]
	if !ok {
		s.mu.Unlock()
		return nil, 0, false
	}
	out := make([]Interaction, 0, len(st.events))
	for _, ev := range st.events {
		out = append(out, *ev)
	}
	dropped = st.dropped
	s.mu.Unlock()
	return out, dropped, true
}

// Known reports whether token was issued by this server and is still retained.
func (s *Server) Known(token string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	_, ok := s.tokens[strings.TrimSpace(token)]
	s.mu.Unlock()
	return ok
}

// Has reports whether the interaction id (the numeric part of `oast:<id>`) is
// retained. Evidence validation uses it to reject references nobody can resolve.
func (s *Server) Has(id string) bool {
	if s == nil {
		return false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range s.events {
		if fmt.Sprint(ev.ID) == id {
			return true
		}
	}
	return false
}

// InteractionCount reports how many interactions are retained (tests/diagnostics).
func (s *Server) InteractionCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// Tokens returns the retained tokens, newest last (diagnostics/tests).
func (s *Server) Tokens() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// handle records one callback. Every method and path is accepted: a blind payload
// may be issued as GET, POST, DNS-over-HTTP, WebDAV or anything else, and the
// callback shape itself is evidence.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	token, rest := splitToken(r.URL.Path)
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyRead+1))
	if err != nil {
		body = nil
	}

	remote := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(remote); splitErr == nil {
		remote = host
	}
	ev := &Interaction{
		Token:    token,
		At:       time.Now().UTC().Format(time.RFC3339),
		RemoteIP: remote,
		Method:   r.Method,
		Path:     rest,
		Query:    r.URL.RawQuery,
		Host:     r.Host,
		Headers:  pickHeaders(r.Header),
		TaskID:   -1,
	}
	if len(body) > maxBodyPreview {
		ev.BodyPreview = string(body[:maxBodyPreview])
		ev.BodyTruncated = true
	} else {
		ev.BodyPreview = string(body)
	}

	if s.publishInteraction(ev) == nil {
		// No id, or a durable id conflict: answering with a callback the platform
		// cannot address would hand out a dangling pointer.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "oast: unavailable\n")
		return
	}

	// Answer with the token so a human probing by hand sees the callback landed;
	// the body is irrelevant to the target's exploit chain.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "oast:"+ev.Token+"\n")
}

// publishInteraction is the single recording path shared by HTTP, DNS and
// interactsh callbacks. It assigns an evidence id, resolves attribution, persists
// the row, then appends it to both rings. nil means the callback was not
// recorded: no id could be minted, or the durable store already owns that id.
func (s *Server) publishInteraction(ev *Interaction) *Interaction {
	ev.ID = s.nextID()
	if ev.ID == 0 {
		return nil
	}
	ev.EvidenceRef = fmt.Sprintf("oast:%d", ev.ID)

	// Resolve attribution BEFORE persisting: the durable row records who the callback
	// belongs to, and an untracked token must stay visibly unattributed (-1) so the
	// evidence validator can refuse it.
	s.mu.Lock()
	if st, ok := s.tokens[strings.ToLower(ev.Token)]; ok {
		ev.TaskID, ev.IntentID = st.token.TaskID, st.token.IntentID
		ev.Token = st.token.Value
	}
	s.mu.Unlock()

	// Persist BEFORE publishing to the in-memory rings.
	//
	// Order matters: if the durable row already holds this id (a conflict), the
	// reference must keep meaning the OLD event. Publishing first left the memory
	// serving the new callback while the database kept the old one, so the same
	// `oast:<id>` resolved differently depending on which store answered. Persisting
	// first makes a conflict a clean failure: nothing is published.
	if persist := s.persist.Load(); persist != nil {
		if err := (*persist)(*ev); err != nil {
			if isIDConflict(err) {
				log.Printf("[oast] 回调 id %d 与已持久化记录冲突，未发布（证据引用保持原义）: %v", ev.ID, err)
				s.releaseID(ev.ID)
				return nil
			}
			// A plain write failure is not fatal: the callback is still recorded in
			// memory so the agent can poll it now; only durability is lost.
			log.Printf("[oast] 回调 %d 持久化失败（仅保留在内存环形缓冲）: %v", ev.ID, err)
		}
	}

	s.mu.Lock()
	if st, ok := s.tokens[ev.Token]; ok {
		st.lastEvent = time.Now()
		st.events = append(st.events, ev)
		s.retainID(ev.ID)
		if len(st.events) > s.opts.MaxPerToken {
			cut := len(st.events) - s.opts.MaxPerToken
			s.releaseRefs(st.events[:cut])
			st.events = append([]*Interaction(nil), st.events[cut:]...)
			st.dropped += cut
		}
	}
	s.events = append(s.events, ev)
	s.retainID(ev.ID)
	if len(s.events) > s.opts.MaxTotal {
		cut := len(s.events) - s.opts.MaxTotal
		s.releaseRefs(s.events[:cut])
		s.events = append([]*Interaction(nil), s.events[cut:]...)
		s.evicted += cut
	}
	s.mu.Unlock()
	return ev
}

// remoteHost strips a port from a remote address.
func remoteHost(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// truncate caps s at n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// newToken mints an unguessable lowercase token. crypto/rand keeps two tokens from
// colliding across restarts and keeps a target from enumerating other runs' tokens.
func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG is fatal for a security tool's identifiers; fall back to
		// the clock rather than emitting a predictable constant.
		return fmt.Sprintf("t%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// splitToken extracts the token from /o/<token>/<rest>.
func splitToken(path string) (token, rest string) {
	p := strings.TrimPrefix(path, "/")
	if head, tail, ok := strings.Cut(p, "/"); ok {
		if strings.HasPrefix(p, "o/") {
			head, tail, ok = strings.Cut(tail, "/")
			if !ok {
				return head, ""
			}
			return head, "/" + tail
		}
		return head, "/" + tail
	}
	return p, ""
}

func pickHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string][]string, min(len(keys), maxHeaderFields))
	for i, k := range keys {
		if i >= maxHeaderFields {
			out["x-oast-more-headers"] = []string{fmt.Sprintf("%d field(s) omitted", len(keys)-maxHeaderFields)}
			break
		}
		vals := h[k]
		kept := make([]string, 0, len(vals))
		for _, v := range vals {
			if len(v) > maxHeaderValueLen {
				v = v[:maxHeaderValueLen] + "…"
			}
			kept = append(kept, v)
		}
		out[k] = kept
	}
	return out
}

// Tools builds the two agent-facing tools (oast_generate / oast_poll). run supplies
// the caller's (task_id, intent_id) so a generated token is attributable; nil run
// leaves both zero.
func (s *Server) Tools(run func(ctx context.Context) (taskID, intentID int64)) []actool.CoreTool {
	generate := actool.Build(actool.Spec{
		Name: "oast_generate",
		Description: "生成一个唯一带外回调地址（OAST token），用于验证【无回显】漏洞：盲 SSRF、盲 XXE、盲 RCE / 反序列化、Log4j JNDI、盲 XSS、" +
			"服务端请求伪造等。返回字段同时包含 HTTP callback_url 与 DNS dns_domain/dns_example：把 callback_url（或其变体，如 http://<token>@host、URL 编码形式）" +
			"注入 payload，或让目标解析 dns_domain，再用 oast_poll(token) 查是否收到回连。" +
			"token 绑定当前 (task, intent)，回调命中记录可直接以 evidence_refs 里的 oast:<id> 作为漏洞证据。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"memo":   map[string]any{"type": "string", "description": "可选：这个回调要验证什么（写入记录便于复盘，不执行）"},
				"target": map[string]any{"type": "string", "description": "可选：正在测试的目标 IP、主机或 URL。多网卡主机按路由表选择目标可达的本机回调网卡地址"},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Memo   string `json:"memo"`
				Target string `json:"target"`
			}
			_ = json.Unmarshal(in, &a)
			var taskID, intentID int64
			if run != nil {
				taskID, intentID = run(ctx)
			}
			if s == nil || s.PublicURL() == "" {
				return actool.Errorf("OAST 回调服务未启用：请在内置 OAST 未启动时先在配置/环境变量里开启（ARTEX_OAST_ADDR）或改用外部带外验证"), nil
			}
			tok := s.GenerateForTarget(a.Memo, a.Target, taskID, intentID)
			return jsonResult(tok)
		},
	})
	poll := actool.Build(actool.Spec{
		Name: "oast_poll",
		Description: "非阻塞查询某个 OAST token 收到的全部回连交互（时间、远端 IP、HTTP 方法、路径/查询、请求头、截断安全的 Body 预览）。" +
			"返回条目的 evidence_ref 形如 oast:<id>，可作为 report_finding / record_fact 的 evidence_refs 直接引用；空列表说明尚未回连（不代表漏洞不存在，可稍后再查）。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"token": map[string]any{"type": "string", "description": "oast_generate 返回的 token"},
			},
			"required": []any{"token"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Token string `json:"token"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Token) == "" {
				return actool.Errorf("token 不能为空（用 oast_generate 生成）"), nil
			}
			events, dropped, known := s.Poll(a.Token)
			if !known {
				return actool.Errorf("未知或已过期的 OAST token（服务重启/OAST 关闭会丢失未使用的 token）：" + a.Token), nil
			}
			if events == nil {
				events = []Interaction{}
			}
			return jsonResult(map[string]any{
				"token":        a.Token,
				"count":        len(events),
				"dropped":      dropped,
				"interactions": events,
				"hint":         "空 count 表示尚无回连；命中条目的 evidence_ref 可直接写进 evidence_refs",
			})
		},
	})
	return []actool.CoreTool{generate, poll}
}

func jsonResult(v any) (actool.Result, error) {
	b, mErr := json.Marshal(v)
	if mErr != nil {
		return actool.Errorf(mErr.Error()), nil
	}
	return actool.Text(string(b)), nil
}
