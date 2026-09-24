// Package tcp 实现 TCP 指纹的 setsockopt 档（P6-T1）。
//
// 两档模型（docs/01-fingerprint-dimensions.md §4）：
//   - setsockopt 档：TTL / MSS（本包 Dialer，三平台）
//   - raw socket 档：window/WS/options 序（raw_linux.go，仅 Linux，见
//     docs/tcp-platform-matrix.md 的边界声明）
//
// 关键时序：TTL/MSS 必须在 connect 之前落在 socket 上才影响 SYN——
// 因此挂在 net.Dialer.Control 钩子（socket 创建后、connect 前）而非事后补设。
package tcp

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/geektls/core/profiles"
)

// Dialer 按 profile.tcp 应用 socket 选项后拨号。
type Dialer struct {
	base net.Dialer
	cfg  *profiles.TCPProfile
}

// SYNProbeResult 是 raw 档探测（ProbeSYN）的结果；定义在共享文件以
// 保证非 Linux 平台编译通过（实现见 raw_linux.go / raw_other.go）。
type SYNProbeResult struct {
	SentBytes  int           // 发出的 SYN 字节数
	GotSynAck  bool          // 是否收到 SYN-ACK
	PeerWindow uint16        // 对端窗口（解析自 SYN-ACK）
	RTT        time.Duration // SYN → SYN-ACK 耗时
}

// NewDialer 创建 Dialer；返回的 warnings 列出本平台被降级/忽略的字段。
func NewDialer(cfg *profiles.TCPProfile, base *net.Dialer) (*Dialer, []profiles.Warning, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("tcp: nil profile")
	}
	if base == nil {
		base = &net.Dialer{}
	}
	d := &Dialer{cfg: cfg}
	baseCopy := *base
	baseCopy.Control = d.control // socket 创建后、connect 前
	d.base = baseCopy

	var warnings []profiles.Warning
	warnings = append(warnings, platformWarnings(cfg)...)
	return d, warnings, nil
}

// DialContext 拨 TCP 并应用 profile 选项。
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("tcp: network %q unsupported", network)
	}
	return d.base.DialContext(ctx, network, addr)
}

// Configure 在既有 net.Dialer 上挂 profile 的 socket 选项（Control 钩子，
// socket 创建后、connect 前生效）。返回降级 warning。
// 与 NewDialer 二选一：engine 这类需要代理分支的调用方用它复用拨号路径。
func Configure(base *net.Dialer, cfg *profiles.TCPProfile) []profiles.Warning {
	d := &Dialer{cfg: cfg}
	base.Control = d.control
	return platformWarnings(cfg)
}

// control 是 net.Dialer.Control 钩子：在 fd 上应用选项。
func (d *Dialer) control(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = applySockopts(fd, d.cfg)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// ReadBack 读回已连接 socket 上的 TTL/MSS 实际值（测试/自校验用）。
func ReadBack(conn net.Conn) (ttl, mss int, err error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, 0, fmt.Errorf("tcp: not a *net.TCPConn")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var readErr error
	err = raw.Control(func(fd uintptr) {
		ttl, mss, readErr = readBackSockopts(fd)
	})
	if err != nil {
		return 0, 0, err
	}
	return ttl, mss, readErr
}
