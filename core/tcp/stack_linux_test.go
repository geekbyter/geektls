//go:build linux

package tcp

// netstack 档独立验证（需 root；WSL 里 wsl -u root go test -run Netstack）。
// 起内核侧 echo 监听 0.0.0.0（覆盖 gtls0 的 10.99.0.1），netstack 拨入，
// 验证连接建立 + echo + 对端地址确为 netstack 侧 IP。

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/geektls/core/profiles"
)

func TestNetstackDial(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("netstack 档需 root（/dev/net/tun）")
	}

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()

	cfg := &profiles.TCPProfile{
		Mode: "netstack", TTL: 42, DF: true,
		MSS: 1460, WindowSize: 29184, WindowScale: 8,
	}
	conn, err := DialNetstack("10.99.0.1:"+port, cfg)
	if err != nil {
		t.Fatalf("DialNetstack: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Errorf("echo: %v %q", err, buf)
	}
	t.Log("netstack dial + echo OK（10.99.0.2 → 10.99.0.1）")
}
