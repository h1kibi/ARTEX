package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresDSNPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","port":6000,"user":"u","password":"p","dbname":"d","sslmode":"require"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)

	// no env DSN → built from config file fields
	t.Setenv("ARTEX_PG_DSN", "")
	got, _, err := PostgresDSN()
	want := "postgres://u:p@10.1.2.3:6000/d?sslmode=require"
	if err != nil || got != want {
		t.Fatalf("from file: got %q err %v want %q", got, err, want)
	}

	// env wins over config file
	t.Setenv("ARTEX_PG_DSN", "postgres://envwins/x")
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://envwins/x" {
		t.Fatalf("env should win, got %q err %v", got, err)
	}

	// no env, no file → error (no built-in default)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "nope.json"))
	if got, _, err := PostgresDSN(); err == nil {
		t.Fatalf("missing config should error, got %q", got)
	}

	// full dsn in config file is used verbatim
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://full/dsn" {
		t.Fatalf("file dsn verbatim, got %q err %v", got, err)
	}
}

// The OAST listener resolves env over file, and ARTEX_OAST_DISABLED wins over both.
func TestOASTListenPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"oast":{"addr":"10.1.1.1:9000","public_url":"http://cb.internal:9000"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfg)
	t.Setenv("ARTEX_OAST_ADDR", "")
	t.Setenv("ARTEX_OAST_PUBLIC_URL", "")
	t.Setenv("ARTEX_OAST_DISABLED", "")

	addr, public, enabled := OASTListen()
	if addr != "10.1.1.1:9000" || public != "http://cb.internal:9000" || !enabled {
		t.Fatalf("file config: addr=%q public=%q enabled=%v", addr, public, enabled)
	}
	t.Setenv("ARTEX_OAST_ADDR", "0.0.0.0:8081")
	t.Setenv("ARTEX_OAST_PUBLIC_URL", "http://10.9.9.9:8081")
	addr, public, _ = OASTListen()
	if addr != "0.0.0.0:8081" || public != "http://10.9.9.9:8081" {
		t.Fatalf("env should win: addr=%q public=%q", addr, public)
	}
	t.Setenv("ARTEX_OAST_DISABLED", "1")
	if _, _, enabled = OASTListen(); enabled {
		t.Fatal("ARTEX_OAST_DISABLED=1 did not disable the listener")
	}
}
