package server

import (
	"context"
	"log"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// mcpResolution is what resolving one agent's MCP servers yields for tool
// assembly: the tools to add, every tool name (deferred wiring), the subset that
// belongs in the global block, and a server→tool-names index the skill gate uses
// to unlock a named server's tools.
type mcpResolution struct {
	Tools       []actool.CoreTool
	AllNames    []string
	GlobalNames []string
	ServerTools map[string][]string
}

// resolveMCPs turns (visible servers, skill gates, cached tool lists) into tools.
// Pure apart from the pool, so the lifetime rules below are testable without a
// database.
//
// Two deliberately different lifetimes:
//   - directly visible → connect NOW through the session pool, so its tools are in
//     the model's list from the first turn.
//   - skill-gated only → do NOT connect. Its tool names come from the cached
//     tools/list and the tools are lazy stand-ins that connect on first real call.
//     Otherwise every ordinary intent of an agent that merely *could* load a
//     browser skill pays to spawn npx/playwright it never uses.
func resolveMCPs(
	ctx context.Context,
	pool *mcpPool,
	session string,
	servers []*db.MCPServer,
	visible map[int64]bool,
	gated map[string]bool,
	cachedTools func(serverID int64) ([]db.MCPTool, error),
) mcpResolution {
	res := mcpResolution{ServerTools: map[string][]string{}}
	for _, m := range servers {
		if m == nil || !m.Enabled {
			continue
		}
		directVisible := visible[m.ID]
		skillGated := gated[m.Name]
		if !directVisible && !skillGated {
			continue // neither directly visible nor referenced by a visible skill
		}
		// Precedence: the skill gate WINS. A server named by any visible skill's
		// `mcps:` stays deferred + locked even when it is also directly visible —
		// that is the whole contract of the gate (its tools appear only after the
		// skill is invoked). Eagerly connecting it here would both spawn a process
		// the run may never use and leak locked tools into the global block.
		if directVisible && !skillGated {
			e, err := pool.acquire(ctx, session, m)
			if err != nil {
				log.Printf("[mcp] %s 连接失败: %v", m.Name, err)
				continue
			}
			for _, t := range e.tools {
				res.Tools = append(res.Tools, t)
				res.AllNames = append(res.AllNames, t.Name())
				res.ServerTools[m.Name] = append(res.ServerTools[m.Name], t.Name())
				res.GlobalNames = append(res.GlobalNames, t.Name())
			}
			continue
		}
		// Skill-gated: never global. Prefer the cached tools/list so nothing is
		// spawned; a server with no cache yet (fresh install, discovery failed)
		// must still expose its tools, or invoking the skill would unlock names the
		// session has never heard of. That one case connects through the pool and
		// publishes the tools as lazy stand-ins (never as global names).
		entries, err := cachedTools(m.ID)
		if err != nil || len(entries) == 0 {
			e, aerr := pool.acquire(ctx, session, m)
			if aerr != nil {
				log.Printf("[mcp] %s 仅被 skill 门控且无工具缓存，连接获取工具列表失败: %v", m.Name, aerr)
				continue
			}
			for _, t := range e.tools {
				full := t.Name()
				res.Tools = append(res.Tools, lazyTool(pool, session, m, full, t.Description()))
				res.AllNames = append(res.AllNames, full)
				res.ServerTools[m.Name] = append(res.ServerTools[m.Name], full)
			}
			continue
		}
		for _, ct := range entries {
			full := mcpToolName(m.Name, ct.Name)
			res.Tools = append(res.Tools, lazyTool(pool, session, m, full, ct.Description))
			res.AllNames = append(res.AllNames, full)
			res.ServerTools[m.Name] = append(res.ServerTools[m.Name], full)
			// stays out of GlobalNames; unlocked when the skill loads
		}
	}
	return res
}
