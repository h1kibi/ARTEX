package evidence

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/internal/testdb"
)

// TestMain runs the evidence suite in its own PostgreSQL schema. db.Open
// applies the schema there, and testdb removes the whole schema after m.Run,
// so fixtures cannot leak into the application's public schema.
func TestMain(m *testing.M) {
	os.Exit(testdb.Run(m, "evidence"))
}
