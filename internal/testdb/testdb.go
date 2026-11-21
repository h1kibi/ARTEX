package testdb

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Run executes one package's tests inside a dedicated PostgreSQL schema. The
// schema is dropped before and after m.Run, so test-created tasks, templates,
// settings, and assets never enter the application's public schema. A schema
// left behind by an interrupted test run is dropped and recreated on the next
// run.
func Run(m *testing.M, name string) int {
	dsn, _, err := config.PostgresDSN()
	if err != nil {
		return m.Run() // tests that need PG skip themselves
	}
	u, err := url.Parse(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "testdb: invalid PostgreSQL URL: %v\n", err)
		return 1
	}
	schema := "artex_test_" + sanitize(name)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		return m.Run()
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return m.Run()
	}
	drop := func() error {
		_, err := admin.Exec(`DROP SCHEMA IF EXISTS "` + schema + `" CASCADE`)
		return err
	}
	if err := drop(); err != nil {
		fmt.Fprintf(os.Stderr, "testdb: drop schema %s: %v\n", schema, err)
		return 1
	}
	if _, err := admin.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		fmt.Fprintf(os.Stderr, "testdb: create schema %s: %v\n", schema, err)
		return 1
	}
	testURL := *u
	query := testURL.Query()
	query.Set("options", "-c search_path="+schema)
	testURL.RawQuery = query.Encode()
	if err := os.Setenv("ARTEX_PG_DSN", testURL.String()); err != nil {
		fmt.Fprintf(os.Stderr, "testdb: set test DSN: %v\n", err)
		return 1
	}

	code := m.Run()
	if err := drop(); err != nil {
		fmt.Fprintf(os.Stderr, "testdb: cleanup schema %s: %v\n", schema, err)
		return 1
	}
	return code
}

func sanitize(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "suite"
	}
	if b.Len() > 48 {
		return b.String()[:48]
	}
	return b.String()
}
