package db

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// Two different callbacks under one id would make `oast:<id>` ambiguous, and the
// reference was already handed to an agent. The second insert must report the
// collision instead of silently keeping the first row.
func TestOASTInsertReportsIDConflict(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	if err := d.EnsureOASTTable(); err != nil {
		t.Fatal(err)
	}
	// A per-run id keeps the row from colliding with an earlier test's.
	base := time.Now().UnixNano() % 1_000_000_000
	first := OASTInteraction{ID: base, Token: "tok-a", TaskID: 1, At: "2026-11-27T00:00:00Z", Method: "GET", Path: "/probe"}
	if err := d.InsertOASTInteraction(first); err != nil {
		t.Fatal(err)
	}
	second := OASTInteraction{ID: base, Token: "tok-b", TaskID: 2, At: "2026-11-27T00:00:01Z", Method: "GET", Path: "/other"}
	dupErr := d.InsertOASTInteraction(second)
	if dupErr == nil {
		t.Fatal("duplicate id accepted silently")
	}
	if !strings.Contains(dupErr.Error(), strconv.FormatInt(base, 10)) {
		t.Fatalf("conflict error does not name the id: %v", dupErr)
	}
	// The original row is what an existing reference resolves to.
	owner, found, qerr := d.OASTInteractionTask(base)
	if qerr != nil || !found || owner != 1 {
		t.Fatalf("owner=%d found=%v err=%v, want 1/true", owner, found, qerr)
	}
}
