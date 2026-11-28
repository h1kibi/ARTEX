package db

import "testing"

func TestNormalizeEvidenceRefsRejectsBlankAndTraversal(t *testing.T) {
	if _, err := NormalizeEvidenceRefs([]string{"traffic:1", "  "}); err == nil {
		t.Fatal("blank evidence ref was accepted")
	}
	if _, err := NormalizeEvidenceRefs([]string{"artifact:../secret.txt"}); err == nil {
		t.Fatal("artifact traversal was accepted")
	}
	if _, err := NormalizeEvidenceRefs([]string{"artifact:/etc/passwd"}); err == nil {
		t.Fatal("absolute artifact path was accepted")
	}
	got, err := NormalizeEvidenceRefs([]string{" traffic:1 ", "traffic:1", "artifact:out.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "traffic:1" || got[1] != "artifact:out.txt" {
		t.Fatalf("normalized refs=%v", got)
	}
}

// OAST callbacks are addressable evidence: oast:<id> must parse, normalize and
// dedupe like every other pointer, and a non-numeric id must be rejected so a
// reference nobody can resolve never reaches the graph.
func TestNormalizeEvidenceRefsAcceptsOAST(t *testing.T) {
	got, err := NormalizeEvidenceRefs([]string{" oast:17 ", "oast:17", "traffic:3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "oast:17" || got[1] != "traffic:3" {
		t.Fatalf("normalized refs=%v", got)
	}
	for _, bad := range []string{"oast:", "oast:abc", "oast:../x"} {
		if _, err := ParseEvidenceRef(bad); err == nil {
			t.Fatalf("malformed oast ref %q was accepted", bad)
		}
	}
}
