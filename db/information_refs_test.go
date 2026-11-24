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
