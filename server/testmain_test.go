package server

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/internal/testdb"
)

func TestMain(m *testing.M) {
	os.Exit(testdb.Run(m, "server"))
}

// stopAllServerTasks stops task loops loaded from the shared test DB. A test
// server starts loops for every persisted task; without this, an unrelated
// task's transcript write can race that test's TempDir cleanup on Windows.
func stopAllServerTasks(s *Server, m *Manager) {
	if s == nil || m == nil {
		return
	}
	for _, t := range m.List() {
		s.engine.StopTask(t.ID)
	}
}
