package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

// hasSkillTool reports whether the packed tool set contains the Skill meta-tool.
func hasSkillTool(tools []actool.CoreTool) bool {
	for _, t := range tools {
		if t.Name() == "Skill" {
			return true
		}
	}
	return false
}

// TestAssembleVisibleSkill verifies a filesystem skill made visible to an agent is
// packed into that agent's tool set (as the single Skill meta-tool) via the wired
// ToolAugment hook. Skills live on disk under skillDir; visibility is a per-agent
// (agent × skill_name) row keyed by the skill's directory name.
func TestAssembleVisibleSkill(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// Filesystem skill fixture: <skillDir>/t-assemble/SKILL.md. The directory name
	// (t-assemble) is the visibility key matched against AgentSkillNames.
	skillDir := t.TempDir()
	const skillName = "t-assemble"
	if err := os.MkdirAll(filepath.Join(skillDir, skillName), 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: t-assemble\ndescription: do the thing\n---\ndo the thing"
	if err := os.WriteFile(filepath.Join(skillDir, skillName, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	wireAgentAugment(pg, skillDir, nil)
	t.Cleanup(func() { agent.ToolAugment = nil })

	ag, _ := pg.GetAgentByKey("planner")
	if ag == nil {
		t.Fatal("planner agent missing")
	}

	// Isolate this test from whatever skill visibility the planner already has in the
	// shared DB: clear it now, restore it on cleanup.
	orig, _ := pg.AgentSkillNames(ag.ID)
	if err := pg.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.SetAgentSkillVisibility(ag.ID, orig) })

	// before: skill not visible → no Skill meta-tool
	extra, _, cleanup := agent.ToolAugment(context.Background(), "planner")
	cleanup()
	if hasSkillTool(extra) {
		t.Fatalf("expected no Skill meta-tool before the skill is made visible")
	}

	// make the skill visible to planner
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.ToggleSkillVisibility(ag.ID, skillName, false) })

	// after: the Skill meta-tool is packed in
	extra, _, cleanup = agent.ToolAugment(context.Background(), "planner")
	defer cleanup()
	if !hasSkillTool(extra) {
		t.Fatalf("expected the Skill meta-tool after making the skill visible")
	}

	// AugmentTools appends extra to base without filtering base
	combined, _, c2 := agent.AugmentTools(context.Background(), "planner", nil)
	defer c2()
	if !hasSkillTool(combined) {
		t.Fatalf("AugmentTools should surface the Skill meta-tool")
	}
}

// TestSkillFrontmatterScopesentry: the shipped ScopeSentry skill must parse with a
// real name, description and mcps gate — the broken header used to lose all three
// plus the first 40 lines of body.
func TestSkillFrontmatterScopesentry(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	var found bool
	for _, s := range reg.List() {
		if filepath.Base(s.Dir) != "scopesentry" {
			continue
		}
		found = true
		if s.Name != "scopesentry-mcp" {
			t.Errorf("name = %q, want scopesentry-mcp", s.Name)
		}
		if !strings.Contains(s.Description, "ScopeSentry") {
			t.Errorf("description lost: %q", s.Description)
		}
		if len(s.MCPs) != 1 || s.MCPs[0] != "ScopeSentry" {
			t.Errorf("mcps = %v, want [ScopeSentry]", s.MCPs)
		}
		// The body must still carry its first sections — a mangled frontmatter
		// swallowed them along with the header.
		for _, want := range []string{"ScopeSentry MCP 使用指南", "## 1. 准备工作", "1.3 配置 Cursor MCP"} {
			if !strings.Contains(s.Instructions, want) {
				t.Errorf("instructions lost %q", want)
			}
		}
		if strings.Contains(s.Instructions, "## name:") {
			t.Error("the broken header line is still inside the body")
		}
	}
	if !found {
		t.Fatal("scopesentry skill not loaded")
	}
}

// TestSkillFrontmatterPlaywright: playwright-cli keeps parsing cleanly and needs no
// mcp gate of its own (it drives the browser-cli directly).
func TestSkillFrontmatterPlaywright(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	for _, s := range reg.List() {
		if filepath.Base(s.Dir) != "playwright-cli" {
			continue
		}
		if s.Name != "playwright-cli" || s.Description == "" || s.Instructions == "" {
			t.Fatalf("playwright-cli frontmatter broken: %+v", s)
		}
		return
	}
	t.Fatal("playwright-cli skill not loaded")
}
