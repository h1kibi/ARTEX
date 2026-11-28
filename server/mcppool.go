package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/mcp"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// Session-level MCP connection pool.
//
// A stateful MCP server — @playwright/mcp being the one this platform ships — is
// a browser: its tabs, cookies and logged-in sessions ARE the state the agent
// needs across turns. Building it per Chat/Plan/Execute call (connect + defer
// Close, which is what AugmentTools did) throws that state away every round, so
// the model must re-login and re-navigate in every turn.
//
// The pool keys a live client by (sessionKey, mcpServerID):
//
//	sessionKey = "task:<taskID>"        planner / mainagent / every worker of a task
//	           | "session:<sessionID>" chat conversation
//	           | "agent:<agentKey>"     no run identity in ctx (non-task callers)
//
// Entries are reused across runs and reclaimed when idle past mcpPoolIdle, when
// their task ends (CloseMCPSession from the task teardown path) or at shutdown. A
// second caller for the same key while a connect is in flight waits for that
// connect instead of spawning a second process.

const (
	// mcpPoolIdle is how long an unused client survives. Long enough for a human
	// to read a report between turns; short enough that a finished task's spawned
	// npx tree does not linger for hours.
	mcpPoolIdle = 15 * time.Minute
	// mcpPoolSweep is the reaper interval.
	mcpPoolSweep = time.Minute
	// mcpDialTimeout bounds the connect handshake + tools/list. Generous because a
	// cold npx/playwright start downloads nothing but still takes seconds.
	mcpDialTimeout = 90 * time.Second
)

// mcpPoolKey identifies one pooled client.
type mcpPoolKey struct {
	Session  string
	ServerID int64
}

// mcpPoolEntry is one live (or being-connected) client.
type mcpPoolEntry struct {
	key     mcpPoolKey
	client  mcpClient
	tools   []actool.CoreTool
	toolsBy map[string]actool.CoreTool
	lastUse time.Time
	err     error
	// closer releases resources the dial created for this entry (the local tag
	// bridge that attributes a browser's traffic). Closed with the client.
	closer io.Closer
	// ready is closed once the in-flight connect finishes; later callers wait on
	// it instead of starting a second connect.
	ready chan struct{}
}

// mcpPool owns every pooled MCP client of the process.
type mcpPool struct {
	mu      sync.Mutex
	entries map[mcpPoolKey]*mcpPoolEntry
	idle    time.Duration
	done    chan struct{}
	// connect is injectable for tests; nil means connectMCP.
	connect func(ctx context.Context, m *db.MCPServer) (mcpClient, error)
}

var (
	mcpPoolOnce sync.Once
	mcpPoolInst *mcpPool
	// mcpProxyTagger, when set by the host, stamps the run's identity onto an MCP
	// server's own --proxy-server argument. The seeded browser MCP is dialed per
	// TASK but its configuration row is global, so without this every browser
	// request reaches the egress gate with taskID=0 and only the global rules are
	// applied — the task's allow/deny rules would silently not participate.
	mcpProxyTagger func(ctx context.Context, raw string) (string, bool)
	// mcpProxyBridge, when set by the host, replaces a platform-proxy URL with a
	// local credential-injecting bridge for task-scoped runs. Chromium (and some
	// @playwright/mcp builds) drops userinfo from --proxy-server, so the credential
	// must be injected by a forwarder instead of relying on the URL.
	mcpProxyBridge func(ctx context.Context, raw string) (string, io.Closer, bool, error)
)

// SetMCPProxyTagger installs the host's proxy-attribution hook (see mcpProxyTagger).
func SetMCPProxyTagger(fn func(ctx context.Context, raw string) (string, bool)) {
	mcpProxyTagger = fn
}

// SetMCPProxyBridge installs the host's credential-injection bridge hook. It is
// tried before the URL tagger, because a URL credential is lost on the client.
func SetMCPProxyBridge(fn func(ctx context.Context, raw string) (string, io.Closer, bool, error)) {
	mcpProxyBridge = fn
}

// bridgeProxyArgs rewrites one server's proxy argument through the bridge hook,
// returning the closers created for this dial. False means "not our proxy" or no
// task identity, and the argument is left for the tagger. A bridge failure aborts
// the dial: falling back to the untagged address would bypass the task's rules.
func bridgeProxyArgs(ctx context.Context, args []string) ([]string, []io.Closer, error) {
	if mcpProxyBridge == nil || len(args) == 0 {
		return args, nil, nil
	}
	out := append([]string(nil), args...)
	var closers []io.Closer
	closeAll := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
	for i := 0; i < len(out); i++ {
		var raw string
		switch {
		case out[i] == "--proxy-server" && i+1 < len(out):
			raw = out[i+1]
		case strings.HasPrefix(out[i], "--proxy-server="):
			raw = strings.TrimPrefix(out[i], "--proxy-server=")
		default:
			continue
		}
		bridged, closer, ok, err := mcpProxyBridge(ctx, raw)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		if !ok {
			continue
		}
		if closer != nil {
			closers = append(closers, closer)
		}
		if out[i] == "--proxy-server" {
			out[i+1] = bridged
			i++
		} else {
			out[i] = "--proxy-server=" + bridged
		}
	}
	return out, closers, nil
}

// closeMCPEntry releases a pooled entry's client and any dial-created resources.
func closeMCPEntry(e *mcpPoolEntry) {
	if e == nil {
		return
	}
	if e.client != nil {
		_ = e.client.Close()
	}
	if e.closer != nil {
		_ = e.closer.Close()
	}
}

// mustMarshalArgs encodes args back into the JSON column shape. A marshal failure is
// impossible for []string and would only mean "leave the args alone".
func mustMarshalArgs(args []string) json.RawMessage {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil
	}
	return raw
}

// tagProxyArgs rewrites the --proxy-server/--proxy-server= value of one server's
// args with the current run's identity, when the host recognizes it as its own
// proxy. Any other proxy (a corporate upstream) is left untouched.
func tagProxyArgs(ctx context.Context, args []string) []string {
	if mcpProxyTagger == nil || len(args) == 0 {
		return args
	}
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		switch {
		case out[i] == "--proxy-server" && i+1 < len(out):
			if tagged, ok := mcpProxyTagger(ctx, out[i+1]); ok {
				out[i+1] = tagged
				i++
			}
		case strings.HasPrefix(out[i], "--proxy-server="):
			raw := strings.TrimPrefix(out[i], "--proxy-server=")
			if tagged, ok := mcpProxyTagger(ctx, raw); ok {
				out[i] = "--proxy-server=" + tagged
			}
		}
	}
	return out
}

// mcpPoolInstance returns the process-wide pool, starting its reaper once.
func mcpPoolInstance() *mcpPool {
	mcpPoolOnce.Do(func() {
		p := &mcpPool{entries: map[mcpPoolKey]*mcpPoolEntry{}, idle: mcpPoolIdle, done: make(chan struct{})}
		mcpPoolInst = p
		go p.sweep()
	})
	return mcpPoolInst
}

// mcpSessionKey derives the pooling key from the run identity attached to ctx.
// The task id (not the intent id) is the unit: every worker of one task explores
// a related surface, and a shared browser session there is a feature.
func mcpSessionKey(ctx context.Context, agentKey string) string {
	ri := agent.RunInfoFrom(ctx)
	switch {
	case ri.TaskID != 0:
		return fmt.Sprintf("task:%d", ri.TaskID)
	case ri.SessionID != "":
		return "session:" + ri.SessionID
	default:
		return "agent:" + agentKey
	}
}

// acquire returns a connected client plus its tools for (session, m), dialing once
// per key and reusing the live process afterwards.
func (p *mcpPool) acquire(ctx context.Context, session string, m *db.MCPServer) (*mcpPoolEntry, error) {
	key := mcpPoolKey{Session: session, ServerID: m.ID}
	for {
		p.mu.Lock()
		e, ok := p.entries[key]
		if ok {
			select {
			case <-e.ready:
				if e.err == nil {
					e.lastUse = time.Now()
					p.mu.Unlock()
					return e, nil
				}
				delete(p.entries, key) // failed dial: retry on this call
				p.mu.Unlock()
				continue
			default:
				ready := e.ready
				p.mu.Unlock()
				select {
				case <-ready:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				continue
			}
		}
		e = &mcpPoolEntry{key: key, lastUse: time.Now(), ready: make(chan struct{})}
		p.entries[key] = e
		p.mu.Unlock()

		cl, tools, closer, err := p.dial(ctx, m)

		p.mu.Lock()
		e.err, e.client, e.tools, e.closer = err, cl, tools, closer
		if err == nil {
			e.toolsBy = make(map[string]actool.CoreTool, len(tools))
			for _, t := range tools {
				e.toolsBy[t.Name()] = t
			}
		}
		if err != nil {
			delete(p.entries, key)
		}
		close(e.ready)
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return e, nil
	}
}

// dial connects one server and lists its tools.
//
// The caller's ctx must NOT reach the client. An http/sse transport captures it
// for the life of the connection (mcphttp's SSE client derives its stream ctx
// from the one it is handed), so a per-run cancel — or even a handshake deadline
// cancelled by its own defer — would silently kill a client the pool keeps
// serving for the next 15 minutes. So the client is dialed on
// context.WithoutCancel(ctx) (value chain intact: ids an MCP server may read stay
// visible; cancellation and deadlines are dropped) and the HANDSHAKE is bounded
// by the pool's own timer instead of a derived deadline.
func (p *mcpPool) dial(ctx context.Context, m *db.MCPServer) (mcpClient, []actool.CoreTool, io.Closer, error) {
	connect := p.connect
	if connect == nil {
		connect = connectMCP
	}
	base := context.WithoutCancel(ctx)
	type result struct {
		cl  mcpClient
		ts  []actool.CoreTool
		err error
	}
	ch := make(chan result, 1)
	// Rewrite the server's own proxy argument before the process starts: playwright
	// reads --proxy-server once at launch. A task-scoped run gets a local bridge
	// (the credential is injected per connection, since Chromium drops userinfo);
	// otherwise the URL tagger stamps what it can.
	args, closers, err := bridgeProxyArgs(ctx, decodeStrSlice(m.Args))
	if err != nil {
		return nil, nil, nil, err
	}
	closer := combineClosers(closers)
	dialed := *m
	dialed.Args = mustMarshalArgs(tagProxyArgs(ctx, args))
	go func() {
		cl, err := connect(base, &dialed)
		if err != nil {
			if closer != nil {
				_ = closer.Close()
			}
			ch <- result{err: err}
			return
		}
		ts, err := cl.Tools(base)
		if err != nil {
			_ = cl.Close()
			if closer != nil {
				_ = closer.Close()
			}
			ch <- result{err: err}
			return
		}
		ch <- result{cl: cl, ts: ts}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, nil, nil, r.err
		}
		return r.cl, r.ts, closer, nil
	case <-time.After(mcpDialTimeout):
		// The dial may still complete; reap its client so nothing leaks.
		go func() {
			if r := <-ch; r.cl != nil {
				_ = r.cl.Close()
			}
			if closer != nil {
				_ = closer.Close()
			}
		}()
		return nil, nil, nil, fmt.Errorf("MCP %s 连接超过 %s 未完成", m.Name, mcpDialTimeout)
	}
}

// onceCloser makes a bridge's Close idempotent across the dial goroutine and the
// timeout reaper, both of which may release the same entry.
type onceCloser struct {
	once sync.Once
	c    io.Closer
}

func (o *onceCloser) Close() error {
	var err error
	o.once.Do(func() { err = o.c.Close() })
	return err
}

func combineClosers(closers []io.Closer) io.Closer {
	switch len(closers) {
	case 0:
		return nil
	case 1:
		return &onceCloser{c: closers[0]}
	}
	list := make([]io.Closer, 0, len(closers))
	for _, c := range closers {
		list = append(list, &onceCloser{c: c})
	}
	return &multiCloser{list: list}
}

type multiCloser struct{ list []io.Closer }

func (m *multiCloser) Close() error {
	var first error
	for _, c := range m.list {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// CloseSession closes (and forgets) every client bound to a session key (exact
// match) — called when a task ends so its browsers and npx trees stop now rather
// than after the idle timeout.
func (p *mcpPool) CloseSession(session string) {
	var closing []*mcpPoolEntry
	p.mu.Lock()
	for k, e := range p.entries {
		if k.Session != session {
			continue
		}
		select {
		case <-e.ready:
			closing = append(closing, e)
		default:
			// Still connecting: it will find its entry gone and be closed by the
			// dialer (see acquire's error path) or reclaimed on the next sweep.
		}
		delete(p.entries, k)
	}
	p.mu.Unlock()
	for _, e := range closing {
		closeMCPEntry(e)
	}
}

// CloseTaskSession closes every client pooled under a task id.
func (p *mcpPool) CloseTaskSession(taskID int64) {
	p.CloseSession(fmt.Sprintf("task:%d", taskID))
}

// CloseServer closes every pooled client of one server, in every session. Called
// after the server's configuration is rewritten (args, env, URL, key): a pooled
// client carries the configuration it was dialed with, so keeping it would run
// the old proxy/token until the idle sweep.
func (p *mcpPool) CloseServer(serverID int64) {
	var closing []*mcpPoolEntry
	p.mu.Lock()
	for k, e := range p.entries {
		if k.ServerID != serverID {
			continue
		}
		closing = append(closing, e)
		delete(p.entries, k)
	}
	p.mu.Unlock()
	for _, e := range closing {
		closeMCPEntry(e)
	}
}

// CloseAll closes every pooled client (shutdown / test teardown).
func (p *mcpPool) CloseAll() {
	p.mu.Lock()
	entries := p.entries
	p.entries = map[mcpPoolKey]*mcpPoolEntry{}
	p.mu.Unlock()
	for _, e := range entries {
		closeMCPEntry(e)
	}
}

// sweep reclaims clients idle past the pool's TTL.
func (p *mcpPool) sweep() {
	t := time.NewTicker(mcpPoolSweep)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case now := <-t.C:
			var closing []*mcpPoolEntry
			p.mu.Lock()
			for k, e := range p.entries {
				select {
				case <-e.ready:
				default:
					continue // mid-dial; judged on the next sweep
				}
				if now.Sub(e.lastUse) <= p.idle {
					continue
				}
				closing = append(closing, e)
				delete(p.entries, k)
			}
			p.mu.Unlock()
			for _, e := range closing {
				closeMCPEntry(e)
			}
			if len(closing) > 0 {
				log.Printf("[mcp] 回收 %d 个空闲 MCP 连接", len(closing))
			}
		}
	}
}

// len reports the pooled entry count (tests / diagnostics).
func (p *mcpPool) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// lazyTool returns a stand-in for one tool of a server that is only reachable
// through a skill. Nothing is spawned at assembly time: the first actual call
// connects the server through the pool and forwards the arguments. The schema is
// deliberately permissive — the real one lives on the server and is validated
// there — because these tools are always deferred (schema withheld from the
// prompt), so a placeholder costs no context and never blocks a legitimate call.
func lazyTool(pool *mcpPool, session string, m *db.MCPServer, name, desc string) actool.CoreTool {
	short := strings.TrimPrefix(name, "mcp__"+m.Name+"__")
	return actool.Build(actool.Spec{
		Name:        name,
		Description: desc + "\n（该 MCP 未连接：首次调用时才启动子进程，之后在同一次任务/会话内复用。参数按服务器实际 schema 传。）",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			e, err := pool.acquire(ctx, session, m)
			if err != nil {
				return actool.Errorf("MCP " + m.Name + " 连接失败: " + err.Error()), nil
			}
			inner, ok := e.toolsBy[name]
			if !ok {
				// The server's tool list can change between discovery and the call;
				// retry once by short name so a renamed prefix cannot silently break
				// an otherwise valid call.
				inner, ok = e.toolsBy[mcp.ToolName(m.Name, short)]
			}
			if !ok {
				return actool.Errorf("MCP " + m.Name + " 未提供工具 " + short), nil
			}
			return inner.Call(ctx, in, tc)
		},
	})
}

// closeMCPForServer invalidates a server's pooled clients after its configuration
// changed. Safe on a nil entry set (tests create servers without a pool).
func closeMCPForServer(id int64) {
	if id == 0 {
		return
	}
	mcpPoolInstance().CloseServer(id)
}
