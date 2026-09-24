//go:build linux || darwin

package tcp

import (
	"github.com/geektls/core/profiles"
	"golang.org/x/sys/unix"
)

// applySockopts 在 connect 前应用 TTL/MSS。
func applySockopts(fd uintptr, cfg *profiles.TCPProfile) error {
	if cfg.TTL > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, cfg.TTL); err != nil {
			return err
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
		return ttl, 0, nil
	}
	return ttl, mss, nil
}

// platformWarnings unix：setsockopt 档全可用；raw 档字段在 Linux 上见
// raw_linux.go（探测模式），darwin 提示受限。
func platformWarnings(cfg *profiles.TCPProfile) []profiles.Warning {
	var w []profiles.Warning
	if cfg.WindowSize > 0 || cfg.WindowScale > 0 || len(cfg.OptionsOrder) > 0 {
		w = append(w, profiles.Warning{
			Code:    "tcp_raw_tier",
			Message: "window_size/window_scale/options_order use the raw-socket tier (Linux probe mode only this phase; see docs/tcp-platform-matrix.md)",
		})
	}
	return w
}
