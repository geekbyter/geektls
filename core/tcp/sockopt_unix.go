//go:build !linux && !darwin && !windows

// 其它 Unix（FreeBSD / OpenBSD / NetBSD / DragonFly / Solaris 等）：
// 只承诺 **TTL 与 MSS** 两项——这两个常量在 x/sys/unix 的各 BSD 实现里都稳定存在；
// DF（IP_DONTFRAG 各家取值不一致）、window/window_scale/options_order（只有 Linux
// netstack 档能做）统一降级为 warning，不做"半对半错"的设置。
//
// 2026-09-30：本文件是补回那次改名的漏。原先只有一份 sockopt_unix.go（约束 !windows）
// 覆盖全部 Unix；后来 darwin 被单独拆成 sockopt_darwin.go（TTL/MSS/DF）时，
// 原来那份没有同步收窄约束 —— 结果 mac 上两份同时参与编译、符号重名，云编译直接红
// （只有 darwin 会撞；linux/windows 各自独占，所以本地与 linux runner 都是绿的）。
// 这里把"darwin 之外的 Unix"重新填上，约束与另外三个平台文件互斥且完备：
//   linux ← sockopt_linux.go ｜ darwin ← sockopt_darwin.go ｜ windows ← sockopt_windows.go
//   ｜ 其余 Unix ← 本文件
// 平台差异的完整表格见 docs/tcp-platform-matrix.md。
package tcp

import (
	"strings"

	"github.com/geektls/core/profiles"
	"golang.org/x/sys/unix"
)

// applySockopts BSD：TTL / MSS（TCP_MAXSEG 在 BSD 上只在**未连接**的 socket 上生效，
// 我们正是在 connect 之前调用，符合该前置条件）。
func applySockopts(fd uintptr, cfg *profiles.TCPProfile, network string) error {
	if cfg.TTL > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, cfg.TTL); err != nil {
			return err
		}
		if strings.HasSuffix(network, "6") {
			// best-effort：与 darwin 档同口径，失败不中止（各家对 v6 hops 的支持面不同）
			unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, cfg.TTL)
		}
	}
	if cfg.MSS > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, cfg.MSS); err != nil {
			return err
		}
	}
	return nil
}

func readBackSockopts(fd uintptr) (ttl, mss int, err error) {
	ttl, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	if err != nil {
		return 0, 0, err
	}
	mss, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	if err != nil {
		return ttl, 0, nil // MSS 读不回来不影响 TTL 的结论（与 darwin 档一致）
	}
	return ttl, mss, nil
}

// platformWarnings BSD：DF 与 raw 档项如实告警，不静默。
func platformWarnings(cfg *profiles.TCPProfile) []profiles.Warning {
	var w []profiles.Warning
	if cfg.DF {
		w = append(w, profiles.Warning{
			Code:    "tcp_df_unsupported",
			Message: "DF (don't fragment) is not set on this platform: IP_DONTFRAG differs per BSD and is not portable",
		})
	}
	if cfg.WindowSize > 0 || cfg.WindowScale > 0 || len(cfg.OptionsOrder) > 0 {
		w = append(w, profiles.Warning{
			Code:    "tcp_raw_tier",
			Message: "window_size/window_scale/options_order need the netstack tier (mode:\"netstack\", Linux root only)",
		})
	}
	return w
}
