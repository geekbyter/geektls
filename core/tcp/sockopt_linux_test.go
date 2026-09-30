//go:build linux

package tcp

// T1 setsockopt 档增强的 Linux 读回验证（WSL 可跑）：
// window 夹击法（SO_RCVBUF×4 + TCP_WINDOW_CLAMP）与 DF 位。

import (
	"context"
	"net"
	"testing"

	"github.com/geekbyter/geektls/core/profiles"
)

func readBackFd(t *testing.T, conn net.Conn, fn func(fd uintptr)) {
	t.Helper()
	tc := conn.(*net.TCPConn)
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(fn); err != nil {
		t.Fatal(err)
	}
}

// TestSockoptWindowClamp：夹击法——SO_RCVBUF=win*4 + TCP_WINDOW_CLAMP=win，
// 读回 clamp == 设定值；rcvbuf 读回为内核翻倍后的值（>=win*2 即生效）。
func TestSockoptWindowClamp(t *testing.T) {
	addr := startTCPEcho(t)
	cfg := &profiles.TCPProfile{TTL: 64, WindowSize: 65535}

	d, warnings, err := NewDialer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		t.Logf("warning: %s: %s", w.Code, w.Message)
	}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var clamp, rcvbuf int
	readBackFd(t, conn, func(fd uintptr) {
		var err error
		clamp, err = ReadBackWindow(fd)
		if err != nil {
			t.Errorf("read TCP_WINDOW_CLAMP: %v", err)
		}
		rcvbuf, _ = getsockoptRcvbuf(fd)
	})
	t.Logf("window=65535 → clamp=%d rcvbuf=%d", clamp, rcvbuf)
	if clamp != 65535 {
		t.Errorf("TCP_WINDOW_CLAMP = %d, want 65535", clamp)
	}
	if rcvbuf < 65535*2 {
		t.Errorf("SO_RCVBUF readback = %d, want >= %d（夹击下限）", rcvbuf, 65535*2)
	}
}

// TestSockoptDF：DF 位（IP_MTU_DISCOVER=DO）读回。
func TestSockoptDF(t *testing.T) {
	addr := startTCPEcho(t)
	cfg := &profiles.TCPProfile{DF: true}

	d, _, err := NewDialer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var df int
	readBackFd(t, conn, func(fd uintptr) {
		var err error
		df, err = ReadBackDF(fd)
		if err != nil {
			t.Errorf("read IP_MTU_DISCOVER: %v", err)
		}
	})
	t.Logf("IP_MTU_DISCOVER = %d (2=DO 即 DF=1)", df)
	if df != 2 {
		t.Errorf("IP_MTU_DISCOVER = %d, want 2 (IP_PMTUDISC_DO)", df)
	}
}

// TestSockoptDualStackHops：IPv6 socket 上 IPV6_UNICAST_HOPS 同设。
func TestSockoptDualStackHops(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	cfg := &profiles.TCPProfile{TTL: 42}
	d, _, err := NewDialer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp6", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var hops int
	readBackFd(t, conn, func(fd uintptr) {
		hops, _ = getsockoptHopsV6(fd)
	})
	t.Logf("IPV6_UNICAST_HOPS = %d", hops)
	if hops != 42 {
		t.Errorf("IPV6_UNICAST_HOPS = %d, want 42", hops)
	}
}
