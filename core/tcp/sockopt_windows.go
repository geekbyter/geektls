//go:build windows

package tcp

import (
	"github.com/geekbyter/geektls/core/profiles"
	"golang.org/x/sys/windows"
)

const (
	ipprotoIP = 0
	ipTTL     = 4
	// ipDontFragment Windows：IP_DONTFRAGMENT（winsock 常量，x/sys 未导出）。
	ipDontFragment = 14
)

// applySockopts 在 connect 前应用 TTL/MSS。
// Windows 实测：IP_TTL 可用；TCP_MAXSEG 返回 WSAENOPROTOOPT（不支持）——
// MSS 在 Windows 降级为跳过+warning（见 platformWarnings）。
// DF：IP_DONTFRAGMENT best-effort（老系统 ENOPROTOOPT 不中止）。
func applySockopts(fd uintptr, cfg *profiles.TCPProfile, network string) error {
	h := windows.Handle(fd)
	if cfg.TTL > 0 {
		if err := windows.SetsockoptInt(h, ipprotoIP, ipTTL, cfg.TTL); err != nil {
			return err
		}
	}
	if cfg.DF {
		windows.SetsockoptInt(h, ipprotoIP, ipDontFragment, 1) // best-effort
	}
	return nil
}

func readBackSockopts(fd uintptr) (ttl, mss int, err error) {
	h := windows.Handle(fd)
	ttl, err = windows.GetsockoptInt(h, ipprotoIP, ipTTL)
	if err != nil {
		return 0, 0, err
	}
	// Windows 不支持 TCP_MAXSEG：MSS 读回恒 0（不代表失败）
	return ttl, 0, nil
}

// platformWarnings Windows 降级说明：MSS 不支持（WSAENOPROTOOPT 实测）；
// raw socket 档全不可用。
func platformWarnings(cfg *profiles.TCPProfile) []profiles.Warning {
	var w []profiles.Warning
	if cfg.MSS > 0 {
		w = append(w, profiles.Warning{
			Code:    "tcp_mss_unsupported",
			Message: "TCP_MAXSEG is not supported on Windows (WSAENOPROTOOPT); MSS setting skipped",
		})
	}
	if cfg.WindowSize > 0 || cfg.WindowScale > 0 || len(cfg.OptionsOrder) > 0 {
		w = append(w, profiles.Warning{
			Code:    "tcp_raw_unavailable",
			Message: "window_size/window_scale/options_order need the raw-socket tier, unavailable on Windows (P6 design boundary)",
		})
	}
	return w
}
