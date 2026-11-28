package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/oast"
)

// An `oast:<id>` reference must keep pointing at the same event across a restart.
// The previous implementation restarted the in-memory counter at 0, so the new
// process's first callback reused id 1 and the reference silently came to mean a
// different event (different content, possibly a different task).
//
// This simulates two processes against ONE database: record via the first, then
// start a second OAST server whose floor comes from the persisted table, exactly
// as Manager does at startup.
func TestOASTIDsSurviveRestartViaSequenceFloor(t *testing.T) {
	s, _, taskID := findingFixture(t, "oast restart")
	if s.m.pg == nil {
		t.Skip("postgres unavailable")
	}

	// --- process 1 ---
	first := oast.New(oast.Options{Addr: "127.0.0.1:0"})
	if err := first.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	first.SetPersist(func(ev oast.Interaction) error {
		return s.m.pg.InsertOASTInteraction(db.OASTInteraction{
			ID: ev.ID, Token: ev.Token, TaskID: ev.TaskID, IntentID: ev.IntentID,
			At: ev.At, RemoteIP: ev.RemoteIP, Method: ev.Method, Path: ev.Path,
			Query: ev.Query, Host: ev.Host, Headers: ev.Headers,
			BodyPreview: ev.BodyPreview, BodyTruncated: ev.BodyTruncated,
		})
	})
	tok := first.Generate("process one", taskID, 0)
	if err := hitCallback(t, tok.CallbackURL); err != nil {
		t.Fatal(err)
	}
	oldEvents, _, _ := first.Poll(tok.Value)
	if len(oldEvents) != 1 {
		t.Fatalf("first process recorded %d events", len(oldEvents))
	}
	oldID := oldEvents[0].EvidenceRef
	_ = first.Close()

	persisted, found, err := s.m.pg.OASTInteractionTask(oldEvents[0].ID)
	if err != nil || !found {
		t.Fatalf("first callback not persisted: found=%v err=%v", found, err)
	}
	if persisted != taskID {
		t.Fatalf("persisted owner = %d, want %d", persisted, taskID)
	}

	// --- process 2 (same database, fresh memory) ---
	// Ids are random 62-bit values, so a restart cannot re-mint one regardless of
	// what reached the database.
	second := oast.New(oast.Options{Addr: "127.0.0.1:0"})
	if err := second.Start(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	second.SetPersist(func(ev oast.Interaction) error {
		return s.m.pg.InsertOASTInteraction(db.OASTInteraction{
			ID: ev.ID, Token: ev.Token, TaskID: ev.TaskID, IntentID: ev.IntentID,
			At: ev.At, RemoteIP: ev.RemoteIP, Method: ev.Method, Path: ev.Path,
			Query: ev.Query, Host: ev.Host, Headers: ev.Headers,
			BodyPreview: ev.BodyPreview, BodyTruncated: ev.BodyTruncated,
		})
	})
	tok2 := second.Generate("process two", taskID, 0)
	if err := hitCallback(t, tok2.CallbackURL); err != nil {
		t.Fatal(err)
	}
	newEvents, _, _ := second.Poll(tok2.Value)
	if len(newEvents) != 1 {
		t.Fatalf("second process recorded %d events", len(newEvents))
	}
	if newEvents[0].ID <= 0 {
		t.Fatalf("restarted process minted an invalid id %d", newEvents[0].ID)
	}
	if newEvents[0].EvidenceRef == oldID {
		t.Fatalf("both processes minted the same evidence id %s", oldID)
	}

	// The old reference must still resolve to the OLD event and its task.
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})
	if err := s.m.validateOASTEvidence(ctx, strings.TrimPrefix(oldID, "oast:")); err != nil {
		t.Fatalf("old reference no longer resolves: %v", err)
	}
	owner, found, err := s.m.pg.OASTInteractionTask(parseID(strings.TrimPrefix(oldID, "oast:")))
	if err != nil || !found || owner != taskID {
		t.Fatalf("old reference owner = %d found=%v err=%v, want %d", owner, found, err, taskID)
	}
	// The new event is a different row, not an overwrite of the old one.
	if owner2, found2, err := s.m.pg.OASTInteractionTask(newEvents[0].ID); err != nil || !found2 || owner2 != taskID {
		t.Fatalf("new reference owner = %d found=%v err=%v", owner2, found2, err)
	}
	if newEvents[0].ID == oldEvents[0].ID {
		t.Fatal("the persisted rows collide")
	}
}
