package engine

// 代理形态（A8）。
//
// 支持六种 proxy URL：http / https（CONNECT 隧道）、socks5 / socks5h、
// socks4 / socks4a。语义与 curl 对齐：
//
//	socks5   本地解析目标域名，代理只看到 IP
//	socks5h  域名交给代理解析（远端 DNS）
//	socks4   同 socks5，但协议本身只承载 IPv4
//	socks4a  域名交给代理解析（DSTIP=0.0.0.1 + HOST 字段）
//
// 环境变量：显式 proxy 优先；都没给时按**目标 scheme** 取变量（curl/requests
// 同语义）——https/wss 读 HTTPS_PROXY，http/ws 读 HTTP_PROXY，都没命中再退
// 到 ALL_PROXY，并查 NO_PROXY 例外表。刻意**不跨 scheme 取**：用 http_proxy
// 代理 https（或反过来）是 curl/requests 都拒绝的误配面。
// （G5 明文支持前引擎只走 https/wss，那时 HTTP_PROXY 与引擎无关；现在 http://
// 目标认它，https:// 目标仍不认——这与 curl 的 `http_proxy` 分工一致。）

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// proxyDefaultPorts 是各 scheme 缺端口时的默认值。
var proxyDefaultPorts = map[string]string{
	"http":    "8080",
	"https":   "8080",
	"socks5":  "1080",
	"socks5h": "1080",
	"socks4":  "1080",
	"socks4a": "1080",
}

// parseProxySpec 校验代理 URL 并补默认端口，返回 (解析结果, 代理 host:port)。
func parseProxySpec(spec string) (*url.URL, string, error) {
	pu, err := url.Parse(strings.TrimSpace(spec))
	if err != nil {
		return nil, "", fmt.Errorf("engine: bad proxy url %q: %w", spec, err)
	}
	defPort, ok := proxyDefaultPorts[pu.Scheme]
	if !ok {
		return nil, "", fmt.Errorf("engine: unsupported proxy scheme %q (want http/https/socks5/socks5h/socks4/socks4a)", pu.Scheme)
	}
	if pu.Host == "" {
		return nil, "", fmt.Errorf("engine: proxy %q 缺主机名", spec)
	}
	// SOCKS4 线上没有口令位（只有 NUL 结尾的 USERID）。静默丢掉会让用户以为
	// 鉴权过了，实际代理侧看到的是匿名请求 ⇒ 在这里就拒绝（curl 同样不支持）。
	if pu.User != nil && strings.HasPrefix(pu.Scheme, "socks4") {
		if _, has := pu.User.Password(); has {
			return nil, "", fmt.Errorf("engine: %s 代理无法承载口令（协议只有 USERID 位）；用 user@host 形态或换 socks5h", pu.Scheme)
		}
	}
	addr := pu.Host
	if pu.Port() == "" {
		addr = net.JoinHostPort(pu.Hostname(), defPort)
	}
	return pu, addr, nil
}

// proxySpecFor 给出本次请求实际生效的代理 URL（"" = 直连）。
//
// 拨号、池键、H3 判定三处都必须走它：池键与实拨代理不一致会让不同代理下的
// 连接互相复用（同一 origin 经两个代理是两条完全不同的指纹路径）。
//
// 优先级：请求级 proxy > 会话 proxy > 环境变量。显式给出的代理**不受
// NO_PROXY 影响**（curl 语义：-x 就是硬要求）；只有环境变量派生的代理才查
// 例外表。
func (s *Session) proxySpecFor(req *Request, scheme, host, port string) (string, error) {
	spec := ""
	if req != nil {
		spec = req.Proxy
	}
	if spec == "" {
		spec = s.opts.Proxy
	}
	if spec == "" {
		if s.opts.ProxyFromEnv != nil && !*s.opts.ProxyFromEnv {
			return "", nil
		}
		spec = proxyFromEnv(scheme, host, port)
		if spec == "" {
			return "", nil
		}
	}
	if _, _, err := parseProxySpec(spec); err != nil {
		return "", err
	}
	return spec, nil
}

// proxyFromEnv 按目标 scheme 给出代理：https/wss 走 HTTPS_PROXY，
// http/ws 走 HTTP_PROXY，未命中再退 ALL_PROXY；命中 NO_PROXY 则返回空。
//
// 回环目标永不走环境变量派生的代理（Go 的 http.ProxyFromEnvironment 与 Chrome
// 同规则，且这里只做字面判定、不查 DNS）：本机回环是最常见的调试形态，
// 开发机 shell 里挂着 ALL_PROXY 不该把回环测试变成"经代理测试"。
// 显式给出的 proxy 不受此限——socks4a://127.0.0.1:1080 就是要代理它。
func proxyFromEnv(scheme, host, port string) string {
	if h := strings.Trim(strings.TrimSpace(host), "[]"); h != "" {
		if strings.EqualFold(h, "localhost") {
			return ""
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return ""
		}
	}
	if noProxyBypass(envAny("NO_PROXY", "no_proxy"), host, port) {
		return ""
	}
	if scheme == "http" || scheme == "ws" {
		if v := envAny("HTTP_PROXY", "http_proxy"); v != "" {
			return v
		}
		return envAny("ALL_PROXY", "all_proxy")
	}
	if v := envAny("HTTPS_PROXY", "https_proxy"); v != "" {
		return v
	}
	return envAny("ALL_PROXY", "all_proxy")
}

func envAny(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// noProxyBypass 判定目标是否在 NO_PROXY 例外表里。**纯字面匹配、不做 DNS**：
// Go 的 http.ProxyFromEnvironment 会先解析目标、且"解析失败=直连"，那会让
// "本来就指望代理解析"的用法反向泄漏。
//
// 条目形态（curl/requests 的交集）：
//
//   - 全部直连
//     example.com   自身 + 所有子域（前导点形态 .example.com 同义）
//     foo:8080      带端口时端口也必须匹配
//     10.0.0.0/8    CIDR（仅当目标是 IP 字面量时可判定）
//
// 目标是 IP 字面量时只做精确/CIDR 匹配，不走后缀规则——否则 "0.0.1" 这种
// 条目会把 127.0.0.1 后缀匹配上。
func noProxyBypass(list, host, port string) bool {
	list = strings.TrimSpace(list)
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	h = strings.TrimSuffix(h, ".")
	if list == "" || h == "" {
		return false
	}
	ip := net.ParseIP(h)

	for _, raw := range strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		pat := strings.ToLower(raw)
		if pat == "*" {
			return true
		}
		if ph, pp, err := net.SplitHostPort(pat); err == nil && pp != "" {
			if port != pp {
				continue
			}
			pat = ph
		}
		pat = strings.Trim(pat, "[]")
		pat = strings.TrimPrefix(strings.TrimSuffix(pat, "."), ".") // ".example.com" ≡ "example.com"，FQDN 尾点同理
		if pat == "" {
			continue
		}
		if ip != nil {
			if strings.Contains(pat, "/") {
				if _, netw, err := net.ParseCIDR(pat); err == nil && netw.Contains(ip) {
					return true
				}
				continue
			}
			if h == pat {
				return true
			}
			continue
		}
		if strings.Contains(pat, "/") {
			continue
		}
		if h == pat || strings.HasSuffix(h, "."+pat) {
			return true
		}
	}
	return false
}

// localResolve 是"我们自己在本地解析目标"的统一入口（A9）：`resolve` 钉位与
// `ip_version` 收窄都只从这里生效——远端解析的那几档（CONNECT / socks5h /
// socks4a）本来就是把名字交出去，本地钉位参与进去等于偷偷换了 DNS 落点。
// v4Only 用于 socks4（报文里目标只有 4 字节）。
func (s *Session) localResolve(host, port string, deadline time.Time, v4Only bool) (net.IP, error) {
	if ip := s.netctl.pinned(host, port); ip != "" {
		parsed := net.ParseIP(ip)
		if v4Only && parsed.To4() == nil {
			return nil, fmt.Errorf("resolve[%q]=%s 是 IPv6，socks4 承载不了", host, ip)
		}
		return parsed, nil
	}
	ctx := context.Background()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	fam := ""
	if s != nil && s.netctl != nil {
		fam = s.netctl.family
	}
	var picked net.IP
	for _, a := range ips {
		if fam == "4" && a.IP.To4() == nil {
			continue
		}
		if fam == "6" && a.IP.To4() != nil {
			continue
		}
		if v4Only && a.IP.To4() == nil {
			continue
		}
		picked = a.IP
		if fam != "" || picked.To4() != nil {
			break // 族已定 ⇒ 取第一个合格的；否则沿用"优先 IPv4"
		}
	}
	if picked == nil {
		if fam != "" {
			return nil, fmt.Errorf("engine: %s 没有 ip_version=%s 的地址（%d 条结果全被过滤）", host, fam, len(ips))
		}
		return nil, fmt.Errorf("engine: %s 解析结果无法使用（%d 条）", host, len(ips))
	}
	return picked, nil
}

// socks5Target 给出交给代理的目标地址："socks5" 时本地解析（走 localResolve，
// 因而 resolve/ip_version 在这一档生效）后只发 IP；"socks5h" 时原样发域名。
// 解析失败即报错——不回落到"发域名"，
// 因为那会让 socks5 静默变成 socks5h（DNS 落点变了，正是这一档要区分的唯一东西）。
func (s *Session) socks5Target(scheme, targetAddr string, deadline time.Time) (string, error) {
	if scheme != "socks5" {
		return targetAddr, nil
	}
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return "", fmt.Errorf("engine: proxy target %q: %w", targetAddr, err)
	}
	if net.ParseIP(host) != nil {
		return targetAddr, nil
	}
	ip, err := s.localResolve(host, port, deadline, false)
	if err != nil {
		return "", fmt.Errorf("engine: socks5 需要本地解析目标（要远端解析用 socks5h）: %w", err)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// socks4Connect 在已连到代理的 conn 上完成 SOCKS4 / SOCKS4A CONNECT。
//
// SOCKS4 报文里目标只有 4 字节 IP，**没有 IPv6 位置**；SOCKS4A 用
// DSTIP=0.0.0.x（约定 0.0.0.1）+ USERID 之后的 HOST 字段把解析交给代理。
// 认证位只有明文 USERID，所以 socks4://user@host 的 user 会发出，
// 密码无法承载（parseProxySpec 对带口令的 socks4 直接报错）。
func (s *Session) socks4Connect(conn net.Conn, targetAddr string, fourA bool, userid string, deadline time.Time) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("engine: proxy target %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("engine: proxy target port %q 非法", portStr)
	}
	host = strings.Trim(host, "[]")

	var ip net.IP
	if literal := net.ParseIP(host); literal != nil {
		if literal.To4() == nil {
			return fmt.Errorf("engine: socks4/socks4a 只承载 IPv4（目标是 %s）；IPv6 用 socks5", host)
		}
		ip = literal.To4()
	} else if !fourA {
		// socks4 报文里没有 HOST 字段，必须本地拿到 IPv4（走 localResolve ⇒
		// resolve 钉位与 ip_version 偏好在这一档生效）
		resolved, err := s.localResolve(host, portStr, deadline, true)
		if err != nil {
			return fmt.Errorf("engine: socks4 无法得到 %s 的 IPv4（要代理侧解析用 socks4a）: %w", host, err)
		}
		ip = resolved.To4()
	}

	req := make([]byte, 0, 9+len(userid)+len(host)+1)
	req = append(req, 0x04, 0x01) // VN=4, CD=CONNECT
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	sendHost := fourA && ip == nil
	if sendHost {
		req = append(req, 0, 0, 0, 1) // SOCKS4A 约定：0.0.0.x = "代理解析"
	} else {
		req = append(req, ip...)
	}
	req = append(req, userid...)
	req = append(req, 0)
	if sendHost {
		req = append(req, host...)
		req = append(req, 0)
	}

	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("engine: socks4 deadline: %w", err)
		}
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("engine: socks4 connect write: %w", err)
	}
	var rep [8]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		return fmt.Errorf("engine: socks4 connect reply: %w", err)
	}
	// 回复：VN(应为 0x00) | CD | DSTPORT(2) | DSTIP(4)
	if rep[1] != 90 {
		return fmt.Errorf("engine: socks4 proxy refused (code %d: %s)", rep[1], socks4Code(rep[1]))
	}
	return nil
}

func socks4Code(cd byte) string {
	switch cd {
	case 91:
		return "request rejected or failed"
	case 92:
		return "rejected because identd connection failed"
	case 93:
		return "rejected because client identd not running"
	default:
		return "unknown status"
	}
}
