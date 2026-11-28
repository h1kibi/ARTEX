package agent

import (
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 并发安全红线回归：一个 *Worker 被多个 worker goroutine 共享，per-intent 的
// effort 轮数必须只活在本次 run 的局部变量里。这个测试用 -race 跑大量并发
// resolveTurnBudget 调用并断言每个 goroutine 拿到自己档位的值——若实现改成写
// w.maxTurns，会在此处数据竞争或被串档。
func TestResolveTurnBudgetConcurrentIsolation(t *testing.T) {
	w := NewWorker(nil, "test-model", t.TempDir(), nil, 200000, 0)
	cases := []struct {
		effort      string
		adminMax    int
		wantTurns   int
		wantCycles  int
		description string
	}{
		{db.EffortProbe, 0, 35, 0, "probe"},
		{db.EffortStandard, 0, 80, 1, "standard"},
		{db.EffortDeep, 0, 130, 2, "deep"},
		{db.EffortDeep, 60, 60, 2, "deep clamped by admin cap"},
		{db.EffortProbe, 100, 35, 0, "probe under a larger admin cap"},
		{"", 0, 80, 1, "unset → standard"},
	}

	var wg sync.WaitGroup
	errs := make(chan string, 512)
	for range 50 {
		for _, tc := range cases {
			wg.Add(1)
			go func(tc struct {
				effort      string
				adminMax    int
				wantTurns   int
				wantCycles  int
				description string
			}) {
				defer wg.Done()
				if w.maxTurns != 0 {
					errs <- "shared Worker.maxTurns was mutated: " + tc.description
					return
				}
				if got := resolveTurnBudget(tc.effort, tc.adminMax); got != tc.wantTurns {
					errs <- tc.description + ": turns mismatch"
					return
				}
				if got := db.EffortRuntimeLimits(tc.effort).MaxAutoCycles; got != tc.wantCycles {
					errs <- tc.description + ": cycles mismatch"
				}
			}(tc)
		}
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
	if w.maxTurns != 0 {
		t.Fatalf("shared Worker.maxTurns changed to %d", w.maxTurns)
	}
}

// The same isolation, but through the full per-run path: two workers built with
// different admin caps must resolve independently of each other's runs.
func TestResolveTurnBudgetPerWorkerCaps(t *testing.T) {
	unbounded := NewWorker(nil, "m", t.TempDir(), nil, 200000, 0)
	capped := NewWorker(nil, "m", t.TempDir(), nil, 200000, 40)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got := resolveTurnBudget(db.EffortDeep, unbounded.maxTurns); got != 130 {
				t.Errorf("unbounded deep=%d want 130", got)
			}
		}()
		go func() {
			defer wg.Done()
			if got := resolveTurnBudget(db.EffortDeep, capped.maxTurns); got != 40 {
				t.Errorf("capped deep=%d want 40", got)
			}
			if got := resolveTurnBudget(db.EffortProbe, capped.maxTurns); got != 35 {
				t.Errorf("capped probe=%d want 35", got)
			}
		}()
	}
	wg.Wait()
}
