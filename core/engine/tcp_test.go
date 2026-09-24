package engine

// engine × profile.tcp 集成：tcp 节驱动的 setsockopt 不应破坏请求链路，
// 且带 raw 档字段的 profile 走降级 warning（不报错）。

import (
	"io"
	"testing"

	"github.com/geektls/core/profiles"
)

func TestEngineTCPProfile(t *testing.T) {
	echo := startEchoServer(t)

	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.TCP = &profiles.TCPProfile{
		TTL:          64,
		MSS:          1300, // Windows 降级为 skip+warning
		WindowSize:   65535,
		WindowScale:  8,
		OptionsOrder: []string{"mss", "sack", "ts", "nop", "ws"},
	}
	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Do(&Request{Method: "GET", URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatalf("Do with tcp profile: %v", err)
	}
	defer resp.Body.Close()
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	io.Copy(io.Discard, resp.Body)
	t.Logf("engine with tcp profile OK (proto=%s)", resp.UsedProtocol)
}
