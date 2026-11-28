package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/oast"
)

// An oast:<id> reference proves reachability of the target that issued the token.
// A callback owned by ANOTHER task therefore cannot prove this task's finding —
// the previous validator only checked that the id was still in the ring, so a
// worker could borrow a neighbour's evidence.
func TestOASTEvidenceRejectsOtherTasksCallback(t *testing.T) {
	s, _, taskID := findingFixture(t, "oast attribution")
	srv := oast.New(oast.Options{Addr: "127.0.0.1:0"})
	if err := srv.Start(); err != nil {
		t.Fatalf("start oast: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	s.m.oast = srv

	mine := srv.Generate("my blind SSRF", taskID, 0)
	if err := hitCallback(t, mine.CallbackURL); err != nil {
		t.Fatal(err)
	}
	theirs := srv.Generate("another task's blind SSRF", taskID+9999, 0)
	if err := hitCallback(t, theirs.CallbackURL); err != nil {
		t.Fatal(err)
	}
	mineEvents, _, _ := srv.Poll(mine.Value)
	theirEvents, _, _ := srv.Poll(theirs.Value)
	if len(mineEvents) != 1 || len(theirEvents) != 1 {
		t.Fatalf("callbacks not recorded: mine=%v theirs=%v", mineEvents, theirEvents)
	}

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})
	if err := s.m.validateOASTEvidence(ctx, strings.TrimPrefix(mineEvents[0].EvidenceRef, "oast:")); err != nil {
		t.Fatalf("own callback rejected: %v", err)
	}
	err := s.m.validateOASTEvidence(ctx, strings.TrimPrefix(theirEvents[0].EvidenceRef, "oast:"))
	if err == nil {
		t.Fatal("another task's callback accepted as this task's evidence")
	}
	if !strings.Contains(err.Error(), "其他任务") {
		t.Fatalf("rejection did not name the ownership problem: %v", err)
	}

	// An id nobody ever issued is rejected outright.
	if err := s.m.validateOASTEvidence(ctx, "999999999"); err == nil {
		t.Fatal("fabricated oast id accepted")
	}
}
