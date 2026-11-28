package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// fakeMCPClient records calls and counts closes, so pool lifetime is observable.
type fakeMCPClient struct {
	mu       sync.Mutex
	closed   int
	calls    []string
	closeErr error
}

func (f *fakeMCPClient) Tools(context.Context) ([]actool.CoreTool, error) {
	return []actool.CoreTool{echoTool("ping")}, nil
}

func (f *fakeMCPClient) Close() error {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
	return f.closeErr
}

func (f *fakeMCPClient) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// echoTool is a minimal CoreTool standing in for one MCP tool.
func echoTool(name string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: "echo",
		Schema: map[string]any{"type": "object"},
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return actool.Text("echo:" + string(in)), nil
		},
	})
}

// newTestPool builds an isolated pool whose dialer returns fake clients.
func newTestPool(t *testing.T) (*mcpPool, *atomic.Int32) {
	t.Helper()
	var dials atomic.Int32
	p := &mcpPool{entries: map[mcpPoolKey]*mcpPoolEntry{}, idle: mcpPoolIdle, done: make(chan struct{})}
	p.connect = func(context.Context, *db.MCPServer) (mcpClient, error) {
		dials.Add(1)
		return &fakeMCPClient{}, nil
	}
	t.Cleanup(func() { close(p.done); p.CloseAll() })
	return p, &dials
}

// TestMCPPoolReusesAcrossRuns is the core fix: two consecutive runs in one task
// must hit the SAME client, so a browser keeps its tabs and cookies.
func TestMCPPoolReusesAcrossRuns(t *testing.T) {
	p, dials := newTestPool(t)
	srv := &db.MCPServer{ID: 1, Name: "browser", Transport: "stdio"}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 3027})

	first, err := p.acquire(ctx, mcpSessionKey(ctx, "worker"), srv)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.acquire(ctx, mcpSessionKey(ctx, "worker"), srv)
	if err != nil {
		t.Fatal(err)
	}
	if first.client != second.client {
		t.Fatal("a second run got a fresh client — the browser would lose its state")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialed %d times, want 1 (reuse across runs)", n)
	}
}

// TestMCPPoolSeparatesSessions: different tasks (and chat sessions) must not share
// a browser session.
func TestMCPPoolSeparatesSessions(t *testing.T) {
	p, dials := newTestPool(t)
	srv := &db.MCPServer{ID: 1, Name: "browser"}

	ctxA := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 1})
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 2})
	ctxC := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: "chat-7"})

	for _, ctx := range []context.Context{ctxA, ctxB, ctxC} {
		if _, err := p.acquire(ctx, mcpSessionKey(ctx, "worker"), srv); err != nil {
			t.Fatal(err)
		}
	}
	if n := dials.Load(); n != 3 {
		t.Fatalf("dialed %d times, want one per session (3)", n)
	}
	if n := p.len(); n != 3 {
		t.Fatalf("pool holds %d entries, want 3", n)
	}
}

// TestMCPPoolConcurrentAcquireDialsOnce: assembly runs concurrently for several
// workers of one task; they must not each spawn a browser.
func TestMCPPoolConcurrentAcquireDialsOnce(t *testing.T) {
	p, dials := newTestPool(t)
	p.connect = func(context.Context, *db.MCPServer) (mcpClient, error) {
		dials.Add(1)
		time.Sleep(20 * time.Millisecond) // widen the window
		return &fakeMCPClient{}, nil
	}
	srv := &db.MCPServer{ID: 1, Name: "browser"}
	session := "task:9"

	var wg sync.WaitGroup
	clients := make([]mcpClient, 8)
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e, err := p.acquire(context.Background(), session, srv)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			clients[i] = e.client
		}(i)
	}
	wg.Wait()
	if n := dials.Load(); n != 1 {
		t.Fatalf("concurrent acquires dialed %d times, want 1", n)
	}
	for i, c := range clients {
		if c != clients[0] {
			t.Fatalf("client %d differs from client 0: %v vs %v", i, c, clients[0])
		}
	}
}

// TestMCPPoolCloseTaskSession: task teardown must close the client immediately.
func TestMCPPoolCloseTaskSession(t *testing.T) {
	p, _ := newTestPool(t)
	srv := &db.MCPServer{ID: 1, Name: "browser"}
	e, err := p.acquire(context.Background(), "task:77", srv)
	if err != nil {
		t.Fatal(err)
	}
	fc := e.client.(*fakeMCPClient)

	p.CloseTaskSession(77)
	if n := fc.closeCount(); n != 1 {
		t.Fatalf("client closed %d times, want 1", n)
	}
	if n := p.len(); n != 0 {
		t.Fatalf("pool still holds %d entries", n)
	}
	// A different task's client must survive.
	e2, err := p.acquire(context.Background(), "task:78", srv)
	if err != nil {
		t.Fatal(err)
	}
	p.CloseTaskSession(77)
	if n := e2.client.(*fakeMCPClient).closeCount(); n != 0 {
		t.Fatal("closing task 77 touched task 78's client")
	}
}

// TestMCPPoolIdleSweepReclaims: an idle client is closed by the reaper.
func TestMCPPoolIdleSweepReclaims(t *testing.T) {
	p, _ := newTestPool(t)
	p.idle = time.Millisecond
	srv := &db.MCPServer{ID: 1, Name: "browser"}
	e, err := p.acquire(context.Background(), "task:5", srv)
	if err != nil {
		t.Fatal(err)
	}
	fc := e.client.(*fakeMCPClient)
	time.Sleep(5 * time.Millisecond)

	// Drive one sweep iteration directly (the ticker is minute-scale in prod).
	now := time.Now().Add(2 * time.Millisecond)
	var closing []mcpClient
	p.mu.Lock()
	for k, en := range p.entries {
		select {
		case <-en.ready:
		default:
			continue
		}
		if now.Sub(en.lastUse) > p.idle {
			closing = append(closing, en.client)
			delete(p.entries, k)
		}
	}
	p.mu.Unlock()
	for _, c := range closing {
		_ = c.Close()
	}
	if fc.closeCount() != 1 || p.len() != 0 {
		t.Fatalf("idle client not reclaimed (closed=%d, entries=%d)", fc.closeCount(), p.len())
	}
}

// TestMCPPoolRetriesAfterFailedDial: a transient failure must not poison the key.
func TestMCPPoolRetriesAfterFailedDial(t *testing.T) {
	p, dials := newTestPool(t)
	var fail atomic.Bool
	fail.Store(true)
	p.connect = func(context.Context, *db.MCPServer) (mcpClient, error) {
		dials.Add(1)
		if fail.Load() {
			return nil, errors.New("npx not found")
		}
		return &fakeMCPClient{}, nil
	}
	srv := &db.MCPServer{ID: 1, Name: "browser"}
	if _, err := p.acquire(context.Background(), "task:1", srv); err == nil {
		t.Fatal("expected the first dial to fail")
	}
	fail.Store(false)
	if _, err := p.acquire(context.Background(), "task:1", srv); err != nil {
		t.Fatalf("retry after a failed dial must succeed: %v", err)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("dialed %d times, want 2", n)
	}
}

// TestLazyToolConnectsOnFirstCall: a skill-gated server must not be spawned during
// assembly; the first real call dials it and later calls reuse the client.
func TestLazyToolConnectsOnFirstCall(t *testing.T) {
	p, dials := newTestPool(t)
	p.connect = func(context.Context, *db.MCPServer) (mcpClient, error) {
		dials.Add(1)
		return &fakeMCPClient{}, nil
	}
	srv := &db.MCPServer{ID: 3, Name: "ScopeSentry"}
	tool := lazyTool(p, "task:12", srv, "mcp__ScopeSentry__list_projects", "list projects")

	if n := dials.Load(); n != 0 {
		t.Fatalf("lazy tool dialed during construction (%d)", n)
	}
	raw, _ := json.Marshal(map[string]any{"page": 1})
	if _, err := tool.Call(context.Background(), raw, nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("first call dialed %d times, want 1", n)
	}
	if _, err := tool.Call(context.Background(), raw, nil); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("second call re-dialed (%d)", n)
	}
	if tool.Name() != "mcp__ScopeSentry__list_projects" {
		t.Fatalf("lazy tool name = %q", tool.Name())
	}
	if tool.CheckPermissions(context.Background(), nil, permission.Context{}).Behavior != permission.Allow {
		t.Fatal("lazy tools must not prompt: they are gated by the unlock set already")
	}
}

// TestLazyToolUnknownNameReportsClearly: a tool the server no longer offers must
// produce an actionable error, not a panic or a silent success.
func TestLazyToolUnknownNameReportsClearly(t *testing.T) {
	p, _ := newTestPool(t)
	srv := &db.MCPServer{ID: 3, Name: "ScopeSentry"}
	tool := lazyTool(p, "task:1", srv, "mcp__ScopeSentry__gone", "gone")
	res, err := tool.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || res.Flatten() == "" {
		t.Fatalf("expected an explanatory error, got %+v", res)
	}
}

// TestMCPSessionKey: the pooling unit is the task, then the chat session, then the
// agent key for callers with no run identity.
func TestMCPSessionKey(t *testing.T) {
	cases := []struct {
		ri   agent.RunInfo
		want string
	}{
		{agent.RunInfo{TaskID: 42, IntentID: 7}, "task:42"},
		{agent.RunInfo{SessionID: "chat-3"}, "session:chat-3"},
		{agent.RunInfo{}, "agent:worker"},
	}
	for _, c := range cases {
		ctx := agent.WithRunInfo(context.Background(), c.ri)
		if got := mcpSessionKey(ctx, "worker"); got != c.want {
			t.Errorf("mcpSessionKey(%+v) = %q, want %q", c.ri, got, c.want)
		}
	}
}

// TestResolveMCPsDirectVisibleIsPooledAndGlobal: a directly visible server is
// connected at assembly time, its tools are global (unlocked from turn one), and a
// second assembly reuses the same client.
func TestResolveMCPsDirectVisibleIsPooledAndGlobal(t *testing.T) {
	p, dials := newTestPool(t)
	srv := &db.MCPServer{ID: 5, Name: "browser", Enabled: true}
	servers := []*db.MCPServer{srv}
	visible := map[int64]bool{5: true}
	cached := func(int64) ([]db.MCPTool, error) { return nil, nil }

	r1 := resolveMCPs(context.Background(), p, "task:1", servers, visible, nil, cached)
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialed %d times at assembly, want 1", n)
	}
	if len(r1.Tools) != 1 || len(r1.GlobalNames) != 1 || len(r1.AllNames) != 1 {
		t.Fatalf("direct-visible resolution wrong: %+v", r1)
	}
	if r1.GlobalNames[0] != r1.AllNames[0] {
		t.Fatalf("a directly visible, ungated tool must be global: %+v", r1)
	}

	r2 := resolveMCPs(context.Background(), p, "task:1", servers, visible, nil, cached)
	if n := dials.Load(); n != 1 {
		t.Fatalf("second assembly re-dialed (%d) — the pool must be reused", n)
	}
	if r2.Tools[0].Name() != r1.Tools[0].Name() {
		t.Fatalf("tool set changed between assemblies: %v vs %v", r2.Tools[0].Name(), r1.Tools[0].Name())
	}
}

// TestResolveMCPsSkillGatedIsLazyAndDeferred: a server reachable only through a
// skill must NOT be spawned at assembly time, its names must stay out of the
// global block, and the tools must be callable (lazily) once unlocked.
func TestResolveMCPsSkillGatedIsLazyAndDeferred(t *testing.T) {
	p, dials := newTestPool(t)
	srv := &db.MCPServer{ID: 6, Name: "ScopeSentry", Enabled: true}
	cached := func(int64) ([]db.MCPTool, error) {
		return []db.MCPTool{{Name: "list_projects", Description: "list projects"}}, nil
	}
	r := resolveMCPs(context.Background(), p, "task:1", []*db.MCPServer{srv}, nil,
		map[string]bool{"ScopeSentry": true}, cached)

	if n := dials.Load(); n != 0 {
		t.Fatalf("skill-gated server dialed at assembly (%d) — must be lazy", n)
	}
	if len(r.Tools) != 1 {
		t.Fatalf("skill-gated tools not advertised: %+v", r)
	}
	if len(r.GlobalNames) != 0 {
		t.Fatalf("skill-gated tools must not be global: %v", r.GlobalNames)
	}
	if got := r.ServerTools["ScopeSentry"]; len(got) != 1 || got[0] != "mcp__ScopeSentry__list_projects" {
		t.Fatalf("server→tools index wrong: %v", r.ServerTools)
	}
	// The advertised tool is a working stand-in, not a dead name.
	if _, err := r.Tools[0].Call(context.Background(), json.RawMessage(`{}`), nil); err != nil {
		t.Fatalf("lazy tool call: %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("lazy call dialed %d times, want 1", n)
	}
}

// TestResolveMCPsSkipsUnreachable: a server that is neither visible nor gated, or
// disabled, produces nothing at all.
func TestResolveMCPsSkipsUnreachable(t *testing.T) {
	p, dials := newTestPool(t)
	servers := []*db.MCPServer{
		{ID: 1, Name: "hidden", Enabled: true},
		{ID: 2, Name: "disabled", Enabled: false},
	}
	r := resolveMCPs(context.Background(), p, "task:1", servers, nil, nil,
		func(int64) ([]db.MCPTool, error) { return []db.MCPTool{{Name: "x"}}, nil })
	if len(r.Tools) != 0 || len(r.AllNames) != 0 || dials.Load() != 0 {
		t.Fatalf("unreachable servers produced tools: %+v (dials=%d)", r, dials.Load())
	}
}

// TestMCPPoolCloseServer: rewriting a server's configuration must invalidate its
// pooled clients in every session, so the next use replays the new args/env.
func TestMCPPoolCloseServer(t *testing.T) {
	p, _ := newTestPool(t)
	srv := &db.MCPServer{ID: 4, Name: "browser"}
	eA, _ := p.acquire(context.Background(), "task:1", srv)
	eB, _ := p.acquire(context.Background(), "task:2", srv)
	fcA := eA.client.(*fakeMCPClient)
	fcB := eB.client.(*fakeMCPClient)

	p.CloseServer(4)
	if fcA.closeCount() != 1 || fcB.closeCount() != 1 {
		t.Fatalf("both sessions must be closed (A=%d B=%d)", fcA.closeCount(), fcB.closeCount())
	}
	if p.len() != 0 {
		t.Fatalf("pool still holds %d entries", p.len())
	}
	// An unrelated server is untouched.
	other := &db.MCPServer{ID: 9, Name: "other"}
	eC, _ := p.acquire(context.Background(), "task:1", other)
	p.CloseServer(4)
	if eC.client.(*fakeMCPClient).closeCount() != 0 {
		t.Fatal("closing server 4 touched server 9")
	}
}

// TestMCPPoolWiredIntoAssembly is a static guard on the wiring: the augment must
// route MCP resolution through resolveMCPs (so lifetime rules cannot silently
// drift back to per-run connect+Close).
func TestMCPPoolWiredIntoAssembly(t *testing.T) {
	src, err := os.ReadFile("assembly.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, "resolveMCPs(ctx, pool, session") {
		t.Fatal("assembly no longer resolves MCPs through the shared pool")
	}
	if strings.Contains(body, "closers = append(closers, cl)") {
		t.Fatal("assembly still collects per-run closers (the per-turn kill would be back)")
	}
	if !strings.Contains(body, "cleanup := func() {}") {
		t.Fatal("per-run cleanup must not close pooled clients")
	}
}

// TestResolveMCPsSkillGateWinsOverDirectVisibility is the gate-precedence
// regression: a server both directly visible AND named by a visible skill's
// `mcps:` must stay deferred — no eager process, no global tool names.
func TestResolveMCPsSkillGateWinsOverDirectVisibility(t *testing.T) {
	p, dials := newTestPool(t)
	srv := &db.MCPServer{ID: 11, Name: "browser", Enabled: true}
	cached := func(int64) ([]db.MCPTool, error) {
		return []db.MCPTool{{Name: "navigate", Description: "go"}}, nil
	}
	r := resolveMCPs(context.Background(), p, "task:1",
		[]*db.MCPServer{srv},
		map[int64]bool{11: true},         // directly visible …
		map[string]bool{"browser": true}, // … AND skill-gated
		cached)

	if n := dials.Load(); n != 0 {
		t.Fatalf("skill-gated server dialed at assembly (%d) despite the gate", n)
	}
	if len(r.GlobalNames) != 0 {
		t.Fatalf("gated tools leaked into the global block: %v", r.GlobalNames)
	}
	if len(r.Tools) != 1 || r.AllNames[0] != "mcp__browser__navigate" {
		t.Fatalf("gated tools must still be advertised as deferred: %+v", r)
	}
	if got := r.ServerTools["browser"]; len(got) != 1 {
		t.Fatalf("server→tools index missing the gated tools: %v", r.ServerTools)
	}
}

// TestResolveMCPsGatedWithoutCacheStillExposesTools: a skill-gated server whose
// tools were never cached (fresh install / failed discovery) must still yield
// callable tools, otherwise Skill() would unlock names that do not exist.
func TestResolveMCPsGatedWithoutCacheStillExposesTools(t *testing.T) {
	p, dials := newTestPool(t)
	// A real MCP client hands back fully-qualified names; mirror that here.
	p.connect = func(context.Context, *db.MCPServer) (mcpClient, error) {
		dials.Add(1)
		return &namedMCPClient{name: "mcp__ScopeSentry__ping"}, nil
	}
	srv := &db.MCPServer{ID: 12, Name: "ScopeSentry", Enabled: true}
	cached := func(int64) ([]db.MCPTool, error) { return nil, nil } // empty cache

	r := resolveMCPs(context.Background(), p, "task:1",
		[]*db.MCPServer{srv}, nil, map[string]bool{"ScopeSentry": true}, cached)

	if n := dials.Load(); n != 1 {
		t.Fatalf("empty-cache gated server must be dialed once to learn its tools, got %d", n)
	}
	if len(r.Tools) != 1 || r.AllNames[0] != "mcp__ScopeSentry__ping" {
		t.Fatalf("tools not exposed for the skill to unlock: %+v", r)
	}
	if len(r.GlobalNames) != 0 {
		t.Fatalf("gated tools leaked into the global block: %v", r.GlobalNames)
	}
	// The published tools are lazy stand-ins: calling one reuses the pooled client.
	if _, err := r.Tools[0].Call(context.Background(), json.RawMessage(`{}`), nil); err != nil {
		t.Fatalf("lazy tool call: %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("the lazy call re-dialed (%d) instead of reusing the pooled client", n)
	}
}

// TestPooledClientSurvivesRunCancel is the connection-pool regression: an http/sse
// MCP captures the ctx it was dialed with, so a per-run cancel must not reach it.
func TestPooledClientSurvivesRunCancel(t *testing.T) {
	p := &mcpPool{entries: map[mcpPoolKey]*mcpPoolEntry{}, idle: mcpPoolIdle, done: make(chan struct{})}
	t.Cleanup(func() { close(p.done); p.CloseAll() })

	var ctxSeen atomic.Value
	p.connect = func(ctx context.Context, _ *db.MCPServer) (mcpClient, error) {
		ctxSeen.Store(ctx)
		return &ctxAwareClient{ctx: ctx}, nil
	}
	srv := &db.MCPServer{ID: 21, Name: "remote", Transport: "http"}

	runCtx, cancelRun := context.WithCancelCause(context.Background())
	e, err := p.acquire(runCtx, "task:1", srv)
	if err != nil {
		t.Fatal(err)
	}
	cancelRun(errors.New("run finished"))

	// The ctx the client holds must not be cancelled by the run ending.
	held := ctxSeen.Load().(context.Context)
	if held.Err() != nil {
		t.Fatalf("pooled client's ctx was killed by the run cancel: %v", held.Err())
	}
	// And the next run reuses the same live client.
	e2, err := p.acquire(context.Background(), "task:1", srv)
	if err != nil {
		t.Fatal(err)
	}
	if e2.client != e.client {
		t.Fatal("second run got a different client after the first run was cancelled")
	}
	if err := e2.client.(*ctxAwareClient).Call(); err != nil {
		t.Fatalf("reused client is dead: %v", err)
	}
}

// ctxAwareClient simulates an http/sse MCP client whose transport is bound to the
// context it was created with.
type ctxAwareClient struct{ ctx context.Context }

func (c *ctxAwareClient) Tools(context.Context) ([]actool.CoreTool, error) {
	return []actool.CoreTool{echoTool("remote_tool")}, nil
}

func (c *ctxAwareClient) Close() error { return nil }

// Call fails when the captured ctx has been cancelled — exactly how an http MCP
// behaves when its run-scoped ctx dies.
func (c *ctxAwareClient) Call() error {
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	default:
		return nil
	}
}

// TestDialDoesNotInheritRunCtx: a run whose ctx is already dead must still
// populate the pool, and the client it hands back must not inherit that ctx.
func TestDialDoesNotInheritRunCtx(t *testing.T) {
	p := &mcpPool{entries: map[mcpPoolKey]*mcpPoolEntry{}, idle: mcpPoolIdle, done: make(chan struct{})}
	t.Cleanup(func() { close(p.done); p.CloseAll() })
	var inheritedCancel bool
	p.connect = func(ctx context.Context, _ *db.MCPServer) (mcpClient, error) {
		select {
		case <-ctx.Done():
			inheritedCancel = true
		default:
		}
		return &ctxAwareClient{ctx: ctx}, nil
	}
	srv := &db.MCPServer{ID: 22, Name: "remote", Transport: "http"}
	dead, cancel := context.WithCancel(context.Background())
	cancel()

	e, err := p.acquire(dead, "task:1", srv)
	if err != nil {
		t.Fatalf("acquire with a cancelled run ctx must still connect: %v", err)
	}
	if inheritedCancel {
		t.Fatal("the client inherited the caller's cancelled ctx")
	}
	if err := e.client.(*ctxAwareClient).Call(); err != nil {
		t.Fatalf("handed-back client is already dead: %v", err)
	}
}

// countCloser records how many times a dial-created resource was released.
type countCloser struct{ n atomic.Int32 }

func (c *countCloser) Close() error {
	c.n.Add(1)
	return nil
}

// A task-scoped browser dial must replace the platform proxy URL with a local
// bridge and release that bridge when the pooled entry closes; a run without a
// task id keeps the URL (the bridge hook declines).
func TestMCPPoolBridgesBrowserProxyForTask(t *testing.T) {
	p, _ := newTestPool(t)
	var gotArgs []string
	p.connect = func(_ context.Context, m *db.MCPServer) (mcpClient, error) {
		gotArgs = decodeStrSlice(m.Args)
		return &fakeMCPClient{}, nil
	}
	closer := &countCloser{}
	prevBridge := mcpProxyBridge
	mcpProxyBridge = func(_ context.Context, raw string) (string, io.Closer, bool, error) {
		if raw != "http://127.0.0.1:8788" {
			return raw, nil, false, nil
		}
		return "http://127.0.0.1:9999", closer, true, nil
	}
	t.Cleanup(func() { mcpProxyBridge = prevBridge })

	srv := &db.MCPServer{ID: 1, Name: "browser", Args: mustMarshalArgs([]string{
		"--proxy-server", "http://127.0.0.1:8788",
	})}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42, IntentID: 7})
	if _, err := p.acquire(ctx, mcpSessionKey(ctx, "worker"), srv); err != nil {
		t.Fatal(err)
	}
	want := []string{"--proxy-server", "http://127.0.0.1:9999"}
	if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Fatalf("dialed args = %v, want %v", gotArgs, want)
	}

	p.CloseAll()
	if n := closer.n.Load(); n != 1 {
		t.Fatalf("bridge was closed %d times, want 1", n)
	}
}

// A bridge failure aborts the dial instead of silently launching the browser
// against the untagged address, which would bypass the task's egress rules.
func TestMCPPoolProxyBridgeFailureAbortsDial(t *testing.T) {
	p, _ := newTestPool(t)
	connectCalled := false
	p.connect = func(_ context.Context, _ *db.MCPServer) (mcpClient, error) {
		connectCalled = true
		return &fakeMCPClient{}, nil
	}
	closer := &countCloser{}
	prevBridge := mcpProxyBridge
	mcpProxyBridge = func(_ context.Context, raw string) (string, io.Closer, bool, error) {
		if raw == "http://127.0.0.1:8788" {
			return "http://127.0.0.1:9999", closer, true, nil
		}
		return "", nil, false, errors.New("bridge listen failed")
	}
	t.Cleanup(func() { mcpProxyBridge = prevBridge })

	srv := &db.MCPServer{ID: 1, Name: "browser", Args: mustMarshalArgs([]string{
		"--proxy-server", "http://127.0.0.1:8788",
		"--proxy-server", "http://127.0.0.1:8789",
	})}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42, IntentID: 7})
	_, err := p.acquire(ctx, mcpSessionKey(ctx, "worker"), srv)
	if err == nil || !strings.Contains(err.Error(), "bridge listen failed") {
		t.Fatalf("acquire error=%v, want the bridge failure", err)
	}
	if connectCalled {
		t.Fatal("the MCP process was started after the bridge failed")
	}
	if n := closer.n.Load(); n != 1 {
		t.Fatalf("earlier bridge closed %d times, want 1", n)
	}
}

// namedMCPClient serves exactly one tool under a fully-qualified MCP name, as a
// real MCP client does.
type namedMCPClient struct{ name string }

func (c *namedMCPClient) Tools(context.Context) ([]actool.CoreTool, error) {
	return []actool.CoreTool{echoTool(c.name)}, nil
}

func (c *namedMCPClient) Close() error { return nil }
