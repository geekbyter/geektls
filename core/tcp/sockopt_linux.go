//go:build linux

package tcp

import (
	"os"
	"strconv"
	"strings"

	"github.com/geekbyter/geektls/core/profiles"
	"golang.org/x/sys/unix"
)

// Linux 专有常量（TCP_WINDOW_CLAMP x/sys/unix 未导出，按内核值硬编码）。
const tcpWindowClamp = 10 // TCP_WINDOW_CLAMP（linux/in.h）

// applySockopts 在 connect 前应用 profile 选项（T1 增强版）：
// TTL（双栈同设）/ MSS / DF / window（夹击法）。
func applySockopts(fd uintptr, cfg *profiles.TCPProfile, network string) error {
	if cfg.TTL > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, cfg.TTL); err != nil {
			return err
		}
		// 双栈同设：IPv6 单栈 socket 上补 IPV6_UNICAST_HOPS；单边失败无害。
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
		applyDF(fd, network)
	}
	if cfg.WindowSize > 0 {
		applyWindowLinux(fd, cfg.WindowSize)
	}
	return nil
}

// applyDF Linux：IP_MTU_DISCOVER=IP_PMTUDISC_DO ⇒ DF=1（IPv6 用
// IPV6_MTU_DISCOVER；失败无害）。
func applyDF(fd uintptr, network string) {
	unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	if strings.HasSuffix(network, "6") {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}
}

// applyWindowLinux 夹击法（借鉴 httpcloak，MIT）：SO_RCVBUF = window*4 抬高
// 接收缓冲（内核公告窗口受 rcvbuf 钳制），TCP_WINDOW_CLAMP = window 把
// 公告窗口钉死在目标值。超 rmem_max 上限时内核静默钳制——告警在
// platformWarnings 里读 /proc 判定。
func applyWindowLinux(fd uintptr, window int) {
	unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, window*4)
	unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, tcpWindowClamp, window)
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

// ReadBackWindow 读回 TCP_WINDOW_CLAMP（夹击法验证用）。
func ReadBackWindow(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, tcpWindowClamp)
}

// ReadBackDF 读回 IP_MTU_DISCOVER（2=PMTUDISC_DO 即 DF=1）。
func ReadBackDF(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
}

func getsockoptRcvbuf(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func getsockoptHopsV6(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
}

// rmemMaxLinux 读内核接收缓冲上限（钳制预警用）。
func rmemMaxLinux() int {
	b, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// platformWarnings Linux：window 夹击法的 rmem_max 钳制预警；netstack 档
// 字段提示；其余字段 setsockopt 档全覆盖。
func platformWarnings(cfg *profiles.TCPProfile) []profiles.Warning {
	var w []profiles.Warning
	if cfg.Mode == "netstack" {
		return w // netstack 档的校验在 stack_linux.go
	}
	if cfg.WindowSize > 0 {
		if max := rmemMaxLinux(); max > 0 && cfg.WindowSize*4 > max {
			w = append(w, profiles.Warning{
				Code:    "tcp_window_clamped",
				Message: "window_size*4 exceeds kernel rmem_max; SO_RCVBUF will be clamped by the kernel（公告窗口可能小于设定值）",
			})
		}
	}
	if cfg.WindowScale > 0 || len(cfg.OptionsOrder) > 0 {
		w = append(w, profiles.Warning{
			Code:    "tcp_raw_tier",
			Message: "window_scale/options_order need the netstack tier (mode:\"netstack\", Linux root only)；setsockopt 档忽略这两项",
		})
	}
	return w
}
