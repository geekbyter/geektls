package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/geekbyter/geektls/core/profiles"
)

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) // echo
		}
	}()
	return ln.Addr().String()
}

// TestDialerSockopts setsockopt 档：设置 + 读回一致（本机可验证的边界；
// 线上 pcap 验证随 P6-T3/nginx 环境）。
func TestDialerSockopts(t *testing.T) {
	addr := startTCPEcho(t)
	cfg := &profiles.TCPProfile{TTL: 77, MSS: 1300}

	d, warnings, err := NewDialer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		t.Logf("warning: %s: %s", w.Code, w.Message)
	}

	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ttl, mss, err := ReadBack(conn)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	t.Logf("readback ttl=%d mss=%d", ttl, mss)
	if ttl != 77 {
		t.Errorf("TTL readback = %d, want 77", ttl)
	}
	// MSS：Windows 不支持 TCP_MAXSEG（降级跳过，读回 0）；unix 读回为协商值
	if runtime.GOOS != "windows" && mss <= 0 {
		t.Errorf("MSS readback = %d, want negotiated value > 0", mss)
	}

	// 连接可用性冒烟
	fmt.Fprint(conn, "ping")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Errorf("echo: %v %q", err, buf)
	}
}

// TestDialerWarnings raw 档字段触发降级 warning。
func TestDialerWarnings(t *testing.T) {
	cfg := &profiles.TCPProfile{TTL: 64, WindowSize: 65535, WindowScale: 8,
		OptionsOrder: []string{"mss", "sack", "ts", "nop", "ws"}}
	_, warnings, err := NewDialer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) == 0 {
		t.Error("raw-tier fields should produce a downgrade warning")
	}
}

// TestDialerNil 空配置直通。
func TestDialerNil(t *testing.T) {
	addr := startTCPEcho(t)
	d, warnings, err := NewDialer(&profiles.TCPProfile{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("empty profile should not warn: %v", warnings)
	}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
