package engine

// 目标地址控制（A9）：DNS 钉位、源地址绑定、协议族偏好。
//
// 三项都只改"连到哪 / 从哪出去"，不改线上指纹字节——SNI、Host、伪头、
// ClientHello 全部沿用 URL 里的原域名。也正因如此它们不属于 profile：
// profile 描述"伪装成谁"，这三项描述"这次跑在哪台机器上"。
//
// 生效范围（与 curl --resolve / --interface 的语义对齐）：
//
//	直连（H1/H2）、netstack 档      —— 三项全部生效
//	socks5 / socks4（本地解析）     —— 三项全部生效
//	CONNECT / socks5h / socks4a     —— 域名交给代理解析，resolve 与 ip_version
//	                                  不参与（否则等于偷偷把"远端 DNS"换成"本地
//	                                  DNS"，那是另一种泄漏形态）；local_address
//	                                  仍生效，因为它绑的是到代理这条 socket
//
// 刻意不支持的两件事，写清楚而不是留成静默死角：
//   - resolve 的键不做通配/后缀匹配：钉 `example.com` 不会连带钉 `cdn.example.com`。
//   - local_address 不接受网卡名（Go 的 net.Dialer.LocalAddr 只认地址；
//     按网卡绑要 SO_BINDTODEVICE，跨平台不对齐）。

import (
	"fmt"
	"net"
	"strings"
)

// netControl 是 SessionOptions 里三项地址控制的归一化形态（建会话时算好）。
type netControl struct {
	resolve map[string]string // 归一键 → IP 字面量
	family  string            // "" | "4" | "6"
	localIP net.IP            // nil = 不绑定
}

// normalizeIPVersion 接受 curl 风格的几种写法（4 / v4 / ipv4，6 同理，
// 空或 any = 不限）。
func normalizeIPVersion(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(v, "ipv"), "ip"), "v")
	switch v {
	case "", "0", "any":
		return "", nil
	case "4":
		return "4", nil
	case "6":
		return "6", nil
	default:
		return "", fmt.Errorf("engine: ip_version %q 未知（want 4/6/空）", v)
	}
}

// resolveKey 归一化"host"或"host:port"形态的键。
func resolveKey(host, port string) string {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	host = strings.TrimSuffix(host, ".")
	if port == "" {
		return host
	}
	return host + ":" + port
}

// normalizeNetControl 校验并归一化地址控制项。
func normalizeNetControl(o *SessionOptions) (*netControl, error) {
	nc := &netControl{}
	fam, err := normalizeIPVersion(o.IPVersion)
	if err != nil {
		return nil, err
	}
	nc.family = fam

	if s := strings.TrimSpace(o.LocalAddress); s != "" {
		ip := net.ParseIP(strings.Trim(s, "[]"))
		if ip == nil {
			return nil, fmt.Errorf("engine: local_address %q 不是 IP 字面量（网卡名不支持，见 proxy/target 文档）", s)
		}
		nc.localIP = ip
		if fam != "" { // 显式族偏好必须与绑定地址同族，否则每次拨号必失败
			is4 := ip.To4() != nil
			if (fam == "4") != is4 {
				return nil, fmt.Errorf("engine: local_address %s 与 ip_version=%s 冲突", s, fam)
			}
		}
	}

	if len(o.Resolve) > 0 {
		nc.resolve = make(map[string]string, len(o.Resolve))
		for k, v := range o.Resolve {
			host, port := k, ""
			if h, p, err := net.SplitHostPort(strings.Trim(k, "[]")); err == nil {
				host, port = h, p
			}
			ip := net.ParseIP(strings.Trim(strings.TrimSpace(v), "[]"))
			if ip == nil {
				return nil, fmt.Errorf("engine: resolve[%q]=%q 不是 IP 字面量（只接受地址，不再做一次 DNS）", k, v)
			}
			if fam != "" && (fam == "4") != (ip.To4() != nil) {
				return nil, fmt.Errorf("engine: resolve[%q]=%s 与 ip_version=%s 冲突", k, v, fam)
			}
			key := resolveKey(host, port)
			if _, dup := nc.resolve[key]; dup {
				return nil, fmt.Errorf("engine: resolve 键 %q 重复（host 与 host:port 归一后同名）", key)
			}
			nc.resolve[key] = ip.String()
		}
	}
	return nc, nil
}

// pinned 返回该 host[:port] 的钉位地址（"" = 未钉）。先查 host:port，再查 host。
func (nc *netControl) pinned(host, port string) string {
	if nc == nil || len(nc.resolve) == 0 {
		return ""
	}
	if ip := nc.resolve[resolveKey(host, port)]; ip != "" {
		return ip
	}
	return nc.resolve[resolveKey(host, "")]
}

// dialTarget 给出本次实际拨号用的 (host, host:port)：钉位命中时换成 IP 字面量
// （本地 DNS 被跳过），SNI / Host / ClientHello 仍用 URL 里的原域名。
func (s *Session) dialTarget(host, port string) (string, string) {
	if ip := s.netctl.pinned(host, port); ip != "" {
		return ip, net.JoinHostPort(ip, port)
	}
	return host, net.JoinHostPort(host, port)
}

// usesRemoteDNS 报告这个代理形态是否把目标名字交给代理去解析。
// 是 ⇒ resolve / ip_version 不参与（拨号地址保持域名形态，见文件头的生效范围表）；
// local_address 不受影响，它绑的是到代理这条 socket。
func usesRemoteDNS(proxySpec string) bool {
	if proxySpec == "" {
		return false
	}
	pu, _, err := parseProxySpec(proxySpec)
	if err != nil { // 交给拨号去报错
		return false
	}
	switch pu.Scheme {
	case "http", "https", "socks5h", "socks4a":
		return true
	}
	return false
}

// network 按"钉位/绑定地址/族偏好"收窄拨号族。目标是 IP 字面量时族已定，
// 与 ip_version 冲突要报错而不是挑一个能连的（那会把"我要 v6"变成静默 v4）。
func (s *Session) network(host string) (string, error) {
	fam := s.netctl.family
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		is4 := ip.To4() != nil
		if fam != "" && (fam == "4") != is4 {
			return "", fmt.Errorf("engine: 目标 %s 与 ip_version=%s 不是同族", host, fam)
		}
		if !is4 && fam == "" {
			return "tcp6", nil
		}
		if is4 && fam == "" && s.netctl.localIP != nil && s.netctl.localIP.To4() == nil {
			// 绑了 v6 源地址却打 v4 目标：Go 会报 mismatched local address type，
			// 这里提前给出可读错误。
			return "", fmt.Errorf("engine: local_address=%s 是 IPv6，目标是 IPv4 (%s)", s.netctl.localIP, host)
		}
		return "tcp4", nil
	}
	if fam != "" {
		return "tcp" + fam, nil
	}
	if s.netctl.localIP != nil { // 绑定地址隐含族（不隐含也没关系：Go 自己会挑）
		if s.netctl.localIP.To4() == nil {
			return "tcp6", nil
		}
		return "tcp4", nil
	}
	return "tcp", nil
}

// localTCPAddr 是 net.Dialer.LocalAddr（未绑定返回 nil）。
func (s *Session) localTCPAddr() net.Addr {
	if s.netctl.localIP == nil {
		return nil
	}
	return &net.TCPAddr{IP: s.netctl.localIP}
}

// h3NetBlocked 报告地址控制项是否与 H3 路径冲突（h3core 走 quic-go 内部解析，
// 本库没有把这三项接进去 ⇒ 按 A8 的口径：宁可不用 H3，也不发一条没按用户
// 要求走的连接）。
func (s *Session) h3NetBlocked() (bool, string) {
	if s.netctl.localIP != nil {
		return true, "local_address"
	}
	if s.netctl.family != "" {
		return true, "ip_version"
	}
	if len(s.netctl.resolve) > 0 {
		return true, "resolve"
	}
	return false, ""
}
