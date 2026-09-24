package e2e

import (
	"testing"
	"time"

	"github.com/geektls/core/engine"
	"github.com/geektls/core/profiles"
)

func TestZZLatency(t *testing.T) {
	base := startEchoBinary(t)
	p, _ := profiles.Get("chrome_133")
	s, _ := engine.NewSession(p, engine.SessionOptions{InsecureSkipVerify: true})
	for i := 0; i < 8; i++ {
		t0 := time.Now()
		resp, err := s.Do(&engine.Request{Method: "GET", URL: base + "/echo"})
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		resp.Body.Close()
		t.Logf("#%d: %v", i, time.Since(t0))
	}
}
