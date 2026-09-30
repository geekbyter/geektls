//go:build darwin

package tcp

import (
	"strings"

	"github.com/geekbyter/geektls/core/profiles"
	"golang.org/x/sys/unix"
)

// ipDontFrag darwin：IP_DONTFRAG（osx 私有常量，x/sys/unix 未导出）。
const ipDontFrag = 28

// applySockopts darwin：TTL / MSS / DF（IP_DONTFRAG）。
func applySockopts(fd uintptr, cfg *profiles.TCPProfile, network string) error {
	if cfg.TTL > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, cfg.TTL); err != nil {
			return err
		}
		if strings.HasSuffix(network, "6") {
			unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, cfg.TTL)
		}
	}
	if cfg.MSS > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, cfg.MSS); err != nil {
			return err
		}
	}
	if cfg.DF {
		// best-effort：老 macOS 上可能 ENOPROTOOPT，不中止
		unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipDontFrag, 1)
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
		return ttl, 0, nil
	}
	return ttl, mss, nil
}

// platformWarnings darwin：window/ws/options 仅 netstack 档（Linux-only）。
func platformWarnings(cfg *profiles.TCPProfile) []profiles.Warning {
	var w []profiles.Warning
	if cfg.WindowSize > 0 || cfg.WindowScale > 0 || len(cfg.OptionsOrder) > 0 {
		w = append(w, profiles.Warning{
			Code:    "tcp_raw_tier",
			Message: "window_size/window_scale/options_order need the netstack tier (mode:\"netstack\", Linux root only)",
		})
	}
	return w
}
