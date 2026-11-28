package traffic

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
)

// Zero-extra-port attribution: instead of one proxy port per (task, intent), the
// host puts the identity into the proxy credentials —
// `http://artex:t<taskID>_i<intentID>@127.0.0.1:8788`. The addon reads it once
// per connection, strips the header before forwarding, and stamps every exchange
// recorded on that connection with the ids. traffic_search can then scope a query
// to one task without any extra listener, process or port.

// proxyAuthHeader is the hop-by-hop header carrying the credential. It is deleted
// on the way in (sink.Requestheaders) so targets never see it.
const proxyAuthHeader = "Proxy-Authorization"

// tagUser is the proxy username the host uses for its own credential. Any other
// username means an operator's own proxy auth (an upstream egress proxy, a
// debugging session), which must not be interpreted as run attribution.
const tagUser = "artex"

// exchangeTag is the run identity stamped onto recorded exchanges. Zero values
// mean "unknown" and are stored as 0.
type exchangeTag struct {
	TaskID   int64
	IntentID int64
}

func (t exchangeTag) zero() bool { return t.TaskID == 0 && t.IntentID == 0 }

// tagFromProxyAuth parses `Proxy-Authorization: Basic base64(artex:t<int>_i<int>)`.
// Anything else (Basic with another username, Bearer tokens, junk) is not a tag
// and reports false — the header is still stripped by the caller, because no
// target server has any use for it.
func tagFromProxyAuth(h http.Header) (exchangeTag, bool) {
	raw := strings.TrimSpace(h.Get(proxyAuthHeader))
	if raw == "" {
		return exchangeTag{}, false
	}
	scheme, cred, ok := strings.Cut(raw, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return exchangeTag{}, false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return exchangeTag{}, false
	}
	user, pass, ok := strings.Cut(string(dec), ":")
	if !ok || !strings.EqualFold(user, tagUser) {
		return exchangeTag{}, false
	}
	return parseTagCredential(pass)
}

// parseTagCredential parses the password half of the credential: t<task>_i<intent>,
// with either component optional (t12_i0 for a planner-driven run, t0_i34 for a
// worker whose task id is unknown). An unparseable value yields no tag rather
// than a wrong one.
func parseTagCredential(pass string) (exchangeTag, bool) {
	pass = strings.TrimSpace(pass)
	if pass == "" {
		return exchangeTag{}, false
	}
	var tag exchangeTag
	seen := false
	for _, part := range strings.Split(pass, "_") {
		part = strings.TrimSpace(part)
		if len(part) < 2 {
			continue
		}
		n, err := strconv.ParseInt(part[1:], 10, 64)
		if err != nil || n < 0 {
			return exchangeTag{}, false
		}
		switch part[0] {
		case 't', 'T':
			tag.TaskID, seen = n, true
		case 'i', 'I':
			tag.IntentID, seen = n, true
		default:
			return exchangeTag{}, false
		}
	}
	if !seen {
		return exchangeTag{}, false
	}
	return tag, true
}

// ProxyURLWithTag renders the per-run proxy URL the host injects into BashEnv.
// taskID/intentID of 0 leave the corresponding component out; both 0 returns the
// plain proxy URL unchanged (no credential, no attribution).
func ProxyURLWithTag(proxyURL string, taskID, intentID int64) string {
	if proxyURL == "" || (taskID == 0 && intentID == 0) {
		return proxyURL
	}
	scheme, rest, ok := strings.Cut(proxyURL, "://")
	if !ok {
		return proxyURL
	}
	// Drop any credentials an upstream-configured value may already carry; the
	// host's tag replaces them (the MITM itself has no upstream auth to pass).
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	cred := tagUser + ":" + TagCredential(taskID, intentID)
	return scheme + "://" + cred + "@" + rest
}

// TagCredential formats the proxy password for a run: t<task>_i<intent>. Both
// ids are always emitted (0 = unknown) so the value is easy to read in logs and
// impossible to confuse with a user's own credentials.
func TagCredential(taskID, intentID int64) string {
	return "t" + strconv.FormatInt(taskID, 10) + "_i" + strconv.FormatInt(intentID, 10)
}

// --- per-connection tag storage ---

// zeroUUID is uuid.Nil, compared by its string form to avoid another import.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// tagKey names the storage slot for a request's tag. A tunnel is the important
// case: an HTTPS request sends the credential once, on CONNECT, and every later
// request on the same connection must inherit it — so the connection id wins
// whenever one is attached. Otherwise the flow itself is the scope (a plain
// HTTP proxy request: credential and request are one message, and the same *Flow
// is what record() later sees).
func tagKey(f *proxy.Flow) string {
	if f.ConnContext != nil {
		if f.ConnContext.ClientConn != nil {
			return "c:" + f.ConnContext.Id().String()
		}
		// Synthetic connection (tests): its pointer is still the tunnel's identity.
		return fmt.Sprintf("c:%p", f.ConnContext)
	}
	if id := f.Id.String(); id != "" && id != zeroUUID {
		return "f:" + id
	}
	// No ids at all (a synthetic flow, e.g. in a test): pointer identity still
	// scopes the tag to exactly this message.
	return fmt.Sprintf("p:%p", f)
}

// setTag records the tag for this request's connection/flow.
func (t *Traffic) setTag(f *proxy.Flow, tag exchangeTag) {
	if tag.zero() {
		return
	}
	if k := tagKey(f); k != "" {
		t.tags.Store(k, tag)
	}
}

// tagFor returns the tag to stamp on the exchange being recorded. For an
// uncaptured (tunneled) connection the CONNECT request carried the credential, so
// the flow has no header of its own and the stored connection tag is used.
func (t *Traffic) tagFor(f *proxy.Flow) exchangeTag {
	if f == nil {
		return exchangeTag{}
	}
	if f.Request != nil {
		if tag, ok := tagFromProxyAuth(f.Request.Header); ok {
			return tag
		}
	}
	if k := tagKey(f); k != "" {
		if v, ok := t.tags.Load(k); ok {
			return v.(exchangeTag)
		}
	}
	return exchangeTag{}
}

// --- client-address tag storage ---
//
// The CONNECT request carries the credential, but by the time the proxy dials the
// target (including the raw TCP and WebSocket fallbacks) the addon has already
// stripped it. The client address is the only identity that survives into that
// dial, so the CONNECT-time tag is also remembered by RemoteAddr and released
// when the connection closes.

func addrTagKey(addr string) string { return "r:" + addr }

func (t *Traffic) setAddrTag(addr string, tag exchangeTag) {
	if addr == "" || tag.zero() {
		return
	}
	t.tags.Store(addrTagKey(addr), tag)
}

func (t *Traffic) addrTag(addr string) exchangeTag {
	if addr == "" {
		return exchangeTag{}
	}
	if v, ok := t.tags.Load(addrTagKey(addr)); ok {
		return v.(exchangeTag)
	}
	return exchangeTag{}
}

// flowRemoteAddr returns the client address that survives into the upstream dial.
func flowRemoteAddr(f *proxy.Flow) string {
	if f == nil {
		return ""
	}
	if f.Request != nil {
		if raw := f.Request.Raw(); raw != nil && raw.RemoteAddr != "" {
			return raw.RemoteAddr
		}
	}
	if f.ConnContext != nil && f.ConnContext.ClientConn != nil && f.ConnContext.ClientConn.Conn != nil {
		return f.ConnContext.ClientConn.Conn.RemoteAddr().String()
	}
	return ""
}

// tagForRequest resolves the tag of an inbound request: the credential it carries
// wins, otherwise the tag remembered for its client connection.
func (t *Traffic) tagForRequest(req *http.Request) exchangeTag {
	if req == nil {
		return exchangeTag{}
	}
	if tag, ok := tagFromProxyAuth(req.Header); ok {
		return tag
	}
	return t.addrTag(req.RemoteAddr)
}

// ClientDisconnected releases the tags a closed connection may still hold.
func (s *sink) ClientDisconnected(c *proxy.ClientConn) {
	if c == nil {
		return
	}
	s.t.tags.Delete("c:" + c.Id.String())
	if c.Conn != nil {
		s.t.tags.Delete(addrTagKey(c.Conn.RemoteAddr().String()))
	}
}

// tagCount exposes the live tag-entry count for tests and diagnostics.
func (t *Traffic) tagCount() int {
	n := 0
	t.tags.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}

// --- search scoping ---

// SearchScope is the (task, intent) a traffic_search call is implicitly limited
// to. The traffic package cannot import the agent package (agent already imports
// traffic), so the host attaches the scope to the tool ctx with TagScope and the
// tools read it back here.
type SearchScope struct {
	TaskID   int64
	IntentID int64
}

type scopeKey struct{}

// TagScope attaches a search scope to ctx.
func TagScope(ctx context.Context, s SearchScope) context.Context {
	if s.TaskID == 0 && s.IntentID == 0 {
		return ctx
	}
	return context.WithValue(ctx, scopeKey{}, s)
}

// SearchScopeFrom reads the scope attached by TagScope.
func SearchScopeFrom(ctx context.Context) (SearchScope, bool) {
	v, ok := ctx.Value(scopeKey{}).(SearchScope)
	return v, ok
}
