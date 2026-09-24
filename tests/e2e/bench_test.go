package e2e

// P7-T4 性能基准（Go 直用链路）：并发 10/50/100 打本地 echo，统计 req/s。
// 注意：P3 起 engine 每请求一条新连接（含完整 TLS 握手），握手成本即
// 吞吐上限——这是设计现状的如实测量，不是瓶颈掩盖。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geektls/core/engine"
	"github.com/geektls/core/profiles"
)

func benchThroughput(t *testing.T, base string, concurrency int, dur time.Duration) (reqs int64, errs int64) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	s, err := engine.NewSession(p, engine.SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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

func TestBenchThroughput(t *testing.T) {
	if os.Getenv("GEEDTLS_BENCH") == "" {
		t.Skip("set GEDTLS_BENCH=1 to run benchmarks")
	}
	base := startEchoBinary(t)
	t.Logf("env: %s", benchEnv())
	for _, c := range []int{10, 50, 100} {
		start := time.Now()
		reqs, errs := benchThroughput(t, base, c, 10*time.Second)
		elapsed := time.Since(start).Seconds()
		t.Logf("go-direct concurrency=%3d: %d reqs in %.1fs = %.0f req/s (errors: %d)",
			c, reqs, elapsed, float64(reqs)/elapsed, errs)
	}
}

func benchEnv() string {
	out, _ := exec.Command("go", "version").Output()
	return strings.TrimSpace(string(out)) + " / " + filepath.Base(os.Getenv("OS"))
}
