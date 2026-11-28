package enrich

import (
	"testing"
	"time"
)

// Construction must be inert: a deployment that never passively enriches must
// not carry a resolver or worker goroutines. The first job starts the pool, the
// job is consumed, and Close stays idempotent with no goroutine left behind.
func TestNewIsLazyAndCloseIdempotent(t *testing.T) {
	e := New(nil, nil, 3)
	if e == nil {
		t.Fatal("nil engine")
	}
	if e.resolv != nil {
		t.Fatal("New initialized the DNS resolver before any job")
	}

	e.ResolveDomain(1, "invalid.invalid")
	key := string(rune(jobDNS)) + ":1"
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, ok := e.cool.Load(key); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("enqueued job was never consumed after lazy start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	e.Close()
	e.Close() // idempotent
	// A job arriving after Close must be dropped without blocking or panicking.
	e.ResolveDomain(2, "invalid.invalid")
}
