package e2e

// 连接池吞吐诊断（二期阶段 5）：共享单 Session（同 origin 一条 h2 连接，
// 真 Chrome 形态）vs 每 worker 一个 Session（各自池化连接）的吞吐对照。
// 数字登记在 docs/benchmarks.md。

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geektls/core/engine"
	"github.com/geektls/core/profiles"
)

func benchVariant(t *testing.T, base string, concurrency int, dur time.Duration, shared bool) (int64, int64) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	var sharedS *engine.Session
	if shared {
		sharedS, err = engine.NewSession(p, engine.SessionOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	var reqs, errs int64
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := sharedS
			if s == nil {
				var err error
				s, err = engine.NewSession(p, engine.SessionOptions{InsecureSkipVerify: true})
				if err != nil {
					atomic.AddInt64(&errs, 1)
					return
				}
			}
			for time.Now().Before(deadline) {
				resp, err := s.Do(&engine.Request{Method: "GET", URL: base + "/echo"})
				if err != nil {
					atomic.AddInt64(&errs, 1)
					continue
				}
				resp.Body.Close()
				atomic.AddInt64(&reqs, 1)
			}
		}()
	}
	wg.Wait()
	return reqs, errs
}

func TestBenchDiag(t *testing.T) {
	if os.Getenv("GEEDTLS_BENCH") == "" {
		t.Skip("set GEDTLS_BENCH=1")
	}
	base := startEchoBinary(t)
	for _, c := range []int{100} {
		start := time.Now()
		reqs, errs := benchVariant(t, base, c, 5*time.Second, true)
		t.Logf("shared-session  c=%d: %.0f req/s (errs %d)", c, float64(reqs)/time.Since(start).Seconds(), errs)
		start = time.Now()
		reqs, errs = benchVariant(t, base, c, 5*time.Second, false)
		t.Logf("per-worker-sess c=%d: %.0f req/s (errs %d)", c, float64(reqs)/time.Since(start).Seconds(), errs)
	}
}
