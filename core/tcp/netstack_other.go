//go:build !linux

package tcp

// netstack 档非 Linux 平台：结构化报"linux-only"。

import (
	"fmt"
	"net"

	"github.com/geekbyter/geektls/core/profiles"
)

// DialNetstack 非 Linux：netstack 档不可用。
func DialNetstack(addr string, cfg *profiles.TCPProfile) (net.Conn, error) {
	return nil, fmt.Errorf("tcp netstack: linux-only（gVisor netstack over AF_PACKET；当前平台不支持）")
}

// CloseNetstack 非 Linux 为空操作。
func CloseNetstack() {}
