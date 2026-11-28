package traffic

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// TagBridge is a local TCP forwarder that injects the run's Proxy-Authorization
// credential into a client that cannot send one itself.
//
// Playwright's Chromium ignores the userinfo of --proxy-server (and some
// @playwright/mcp versions drop it while parsing), so browser traffic reached the
// recording proxy with taskID=0 and task-scoped allow/deny rules never applied.
// The bridge listens on 127.0.0.1, dials the platform proxy, adds the credential to
// the first CONNECT/HTTP request, then forwards the untouched byte stream. An
// HTTPS tunnel inherits the tag for its whole life; a plain HTTP request is sent
// with Connection: close so each request gets its own tagged connection.
type TagBridge struct {
	ln       net.Listener
	upstream string
	auth     string

	closeOnce sync.Once
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

const tagBridgeMaxHeader = 64 << 10

// StartTagBridge listens on 127.0.0.1:0 and forwards to upstreamProxyAddr. It
// returns nil, nil when both ids are zero: there is nothing to attribute.
func StartTagBridge(upstreamProxyAddr string, taskID, intentID int64) (*TagBridge, error) {
	if taskID <= 0 && intentID <= 0 {
		return nil, nil
	}
	addr := strings.TrimSpace(upstreamProxyAddr)
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	if addr == "" {
		return nil, errors.New("上游代理地址为空")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	raw := tagUser + ":" + TagCredential(taskID, intentID)
	b := &TagBridge{
		ln:       ln,
		upstream: addr,
		auth:     "Basic " + base64.StdEncoding.EncodeToString([]byte(raw)),
		conns:    map[net.Conn]struct{}{},
	}
	go b.serve()
	return b, nil
}

// ProxyURL is the credential-free proxy URL the client is configured with.
func (b *TagBridge) ProxyURL() string {
	if b == nil || b.ln == nil {
		return ""
	}
	return "http://" + b.ln.Addr().String()
}

// Close stops the listener and every forwarded connection. Idempotent.
func (b *TagBridge) Close() error {
	if b == nil {
		return nil
	}
	var err error
	b.closeOnce.Do(func() {
		err = b.ln.Close()
		b.mu.Lock()
		for c := range b.conns {
			_ = c.Close()
		}
		b.mu.Unlock()
	})
	return err
}

func (b *TagBridge) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handle(c)
	}
}

func (b *TagBridge) track(c net.Conn) {
	b.mu.Lock()
	b.conns[c] = struct{}{}
	b.mu.Unlock()
}

func (b *TagBridge) untrack(c net.Conn) {
	b.mu.Lock()
	delete(b.conns, c)
	b.mu.Unlock()
}

func (b *TagBridge) handle(client net.Conn) {
	defer client.Close()
	upstream, err := net.Dial("tcp", b.upstream)
	if err != nil {
		return
	}
	defer upstream.Close()
	b.track(client)
	b.track(upstream)
	defer b.untrack(client)
	defer b.untrack(upstream)

	// Only the first request's head is bounded. Body and tunnel bytes must flow
	// unbounded afterwards: a limit left in place would truncate uploads and the
	// TLS stream inside a CONNECT tunnel.
	lim := &headerCapReader{r: client, left: tagBridgeMaxHeader}
	br := bufio.NewReader(lim)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	lim.lift()
	if b.auth != "" {
		req.Header.Set("Proxy-Authorization", b.auth)
	}

	if req.Method == http.MethodConnect {
		target := req.RequestURI
		if target == "" {
			target = req.Host
		}
		if _, err := io.WriteString(upstream, "CONNECT "+target+" HTTP/1.1\r\n"); err != nil {
			return
		}
		if req.Host != "" {
			if _, err := io.WriteString(upstream, "Host: "+req.Host+"\r\n"); err != nil {
				return
			}
		}
		if err := req.Header.Write(upstream); err != nil {
			return
		}
		if _, err := io.WriteString(upstream, "\r\n"); err != nil {
			return
		}
		b.pipe(client, upstream, br)
		return
	}

	if isUpgradeRequest(req) {
		// A protocol upgrade turns into an opaque two-way stream after the 101;
		// the head must reach the upstream verbatim.
		req.Close = false
		if err := req.WriteProxy(upstream); err != nil {
			return
		}
		b.pipe(client, upstream, br)
		return
	}

	// A plain HTTP request is answered by the upstream proxy itself. Forcing
	// close keeps one tagged upstream connection per request, so a keep-alive
	// client cannot send a second, differently-attributed request over it.
	req.Close = true
	req.Header.Set("Connection", "close")
	req.Header.Del("Proxy-Connection")
	if err := req.WriteProxy(upstream); err != nil {
		return
	}
	_, _ = io.Copy(client, upstream)
}

// isUpgradeRequest reports whether the client asked to leave HTTP.
func isUpgradeRequest(req *http.Request) bool {
	if req.Header.Get("Upgrade") != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(req.Header.Get("Connection")), "upgrade")
}

// pipe relays bytes in both directions until both halves are done. src is the
// buffered client reader, so bytes the parser already pulled off the socket are
// forwarded before any further read.
func (b *TagBridge) pipe(client, upstream net.Conn, src io.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, src)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

// headerCapReader bounds how much of the client stream the request parser may
// read. The cap is lifted once the head is parsed.
type headerCapReader struct {
	r    io.Reader
	left int
}

func (h *headerCapReader) Read(p []byte) (int, error) {
	if h.left <= 0 {
		return 0, errors.New("请求头过长")
	}
	if len(p) > h.left {
		p = p[:h.left]
	}
	n, err := h.r.Read(p)
	h.left -= n
	return n, err
}

func (h *headerCapReader) lift() { h.left = int(^uint(0) >> 1) }

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}
