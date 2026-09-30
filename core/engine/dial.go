package engine

// 拨号与 TLS：代理（HTTP CONNECT / SOCKS5）→ tlscore 握手 → 协议分发。

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"

	"github.com/geektls/core/profiles"
	tcp "github.com/geektls/core/tcp"
	tlscore "github.com/geektls/core/tls"
)

// transportConn 是一次请求的完整连接产物。
// sc 在握手完成时算好（selfcheck 随连接走：连接池复用时不发新
// ClientHello，复用方报告的就是这条连接建立时的指纹）。
// uconn 是写读这条连接的句柄：TLS 档是 *utls.UConn，明文档（http:// / ws://）
// 就是裸 TCP——两条路径只用到 net.Conn 的读写面，故此处收成接口（G5）。
type transportConn struct {
	conn  net.Conn
	uconn net.Conn
	spec  *utls.ClientHelloSpec
	proto string // 协商出的 ALPN（明文档为空）
	sc    SelfCheck
	plain bool // 明文档：无 TLS、无指纹、SelfCheck 恒为零值
}

// connect 完成 dial（可选代理）+ uTLS 握手，返回可用于 H1/H2 分发的连接。
// deadline 是整体硬超时（P3 简化：connect+TLS+响应头共用一个 deadline）。
// 明文档（http://）走 connectPlain：不握手，故 proto 为空、SelfCheck 零值。
func (s *Session) connect(req *Request, u *url.URL) (*transportConn, error) {
	if u.Scheme == "http" {
		return s.connectPlain(req, u)
	}
	return s.connectALPN(req, u, nil, nil)
}

// connectPlain 是明文档（http:// 与 ws://）：只做 TCP（可经代理、可带 TCP
// 指纹与地址控制），不发 ClientHello。`SelfCheck` 保持零值——TLS 层不存在，
// 就不报任何"看起来像 TLS"的东西（绑定层据此判空，见 README）。
func (s *Session) connectPlain(req *Request, u *url.URL) (*transportConn, error) {
	p, err := s.planDial(req, u)
	if err != nil {
		return nil, err
	}
	raw, err := s.dialTCPOnly(p)
	if err != nil {
		return nil, err
	}
	return &transportConn{conn: raw, uconn: raw, plain: true}, nil
}

// dialPlan 是一次拨号所需的全部决策（目标 / 代理 / 地址控制 / 超时 / 拨号器）。
// TLS 档与明文档共用同一份决策（G5），避免两条路径的代理与地址控制行为分叉。
type dialPlan struct {
	d        *net.Dialer
	proxyURL string
	network  string
	dialAddr string
	host     string
	deadline time.Time
}

// defaultPort 给出 scheme 的缺省端口：明文 http/ws 为 80，其余 443。
func defaultPort(scheme string) string {
	if scheme == "http" || scheme == "ws" {
		return "80"
	}
	return "443"
}

// portOrDefault 给出 URL 的端口，省略时按 scheme 缺省（NO_PROXY 带端口的
// 条目需要它才能匹配 `https://example.com` 这种写法）。
func portOrDefault(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return defaultPort(u.Scheme)
}

// planDial 解析"这一次请求该怎么拨"：端口缺省、生效代理、地址控制（A9）、
// 拨号器（含 P6 的 TCP 指纹 setsockopt）。
func (s *Session) planDial(req *Request, u *url.URL) (*dialPlan, error) {
	host := u.Hostname()
	port := portOrDefault(u)

	timeout := time.Duration(s.opts.TimeoutMs) * time.Millisecond
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	p := &dialPlan{host: host, deadline: time.Now().Add(timeout)}

	proxyURL, perr := s.proxySpecFor(req, u.Scheme, host, port)
	if perr != nil {
		return nil, perr
	}
	p.proxyURL = proxyURL

	// A9：钉位 / 族收窄只作用于"我们自己本地解析"的档位；把名字交给代理的
	// 档位（CONNECT / socks5h / socks4a）保持域名形态。local_address 两边都绑，
	// 它绑的是这条出网 socket（代理场景就是到代理那一条）。
	p.dialAddr, p.network = net.JoinHostPort(host, port), "tcp"
	if !usesRemoteDNS(proxyURL) {
		dialHost, dialAddr := s.dialTarget(host, port)
		nw, err := s.network(dialHost)
		if err != nil {
			return nil, err
		}
		p.dialAddr, p.network = dialAddr, nw
	}

	p.d = &net.Dialer{Timeout: time.Until(p.deadline), LocalAddr: s.localTCPAddr()}
	// P6：profile.tcp 非空时给拨号器挂 setsockopt（对代理场景，
	// 选项落在到代理的这条 TCP 上——这正是承载指纹的流）。
	// netstack 档不走 net.Dialer（见 dialTCPOnly 分支）。
	if s.profile.TCP != nil && s.profile.TCP.Mode != "netstack" {
		tcp.Configure(p.d, s.profile.TCP)
	}
	return p, nil
}

// connectALPN：alpn 非 nil 时覆盖 profile 的 ALPN 列表（WS 握手强制 http/1.1，
// 避免服务端协商出 h2 后 Upgrade 路径失效）；detail 非 nil 时替代 profile 的
// tls.detail 参与编译（WS 用它把 ALPN 扩展内容收窄到 http/1.1——只改
// cfg.NextProtos 没用，uTLS 线上发的是扩展里的协议列表）。
func (s *Session) connectALPN(req *Request, u *url.URL, alpn []string, detail *profiles.Detail) (*transportConn, error) {
	plan, err := s.planDial(req, u)
	if err != nil {
		return nil, err
	}

	// 本次握手是否会带票据（缓存里有该 SNI 的票据即会）：仅用于决定失败后是否
	// 值得丢票重试（见下）。缓存键就是 SNI（实测）。
	hadTicket := false
	if s.sessionCache != nil {
		if _, ok := s.sessionCache.Get(plan.host); ok {
			hadTicket = true
		}
	}

	tc, err := s.dialAndHandshake(plan, alpn, detail)
	if err == nil {
		return tc, nil
	}
	// 会话复用手握失败（对端不接受我们的 PSK binder，如 Go std 服务端——实测）。
	// 浏览器同款行为：丢掉这张票据、改用全新握手重试一次。丢掉后 Get 必然 miss，
	// 因此重试不会再带 PSK。
	if !hadTicket {
		return nil, err
	}
	if s.sessionCache != nil {
		s.sessionCache.Put(plan.host, nil) // uTLS 语义：Put(nil) = 删除该键
	}
	if tc, retryErr := s.dialAndHandshake(plan, alpn, detail); retryErr == nil {
		return tc, nil
	} else {
		return nil, fmt.Errorf("%w（丢票回退后仍失败: %v）", err, retryErr)
	}
}

// dialTCPOnly 完成一次"TCP（可经代理）"：TLS 档与明文档共用（G5）。
// 目标地址、代理与拨号器来自 planDial 的决策（A9 / P6）。
func (s *Session) dialTCPOnly(p *dialPlan) (net.Conn, error) {
	switch {
	case s.profile.TCP != nil && s.profile.TCP.Mode == "netstack":
		// netstack 档（Linux root，gVisor 用户态栈）：指纹落在到目标的
		// 这条 TCP 上，与代理不兼容（代理场景指纹本就该落在到代理的
		// 连接上，netstack 直发目标语义矛盾——拒绝）。
		if p.proxyURL != "" {
			return nil, fmt.Errorf("engine: tcp.mode=netstack 与代理不兼容（netstack 直发目标）")
		}
		// 源地址由 TUN 拓扑固定（栈内 Bind 到 nsNetstackIP），local_address 绑不上。
		if s.netctl.localIP != nil {
			return nil, fmt.Errorf("engine: tcp.mode=netstack 不支持 local_address（用户态栈的源地址固定为 TUN 侧地址）；要绑网卡用 tcp.mode=setsockopt")
		}
		return tcp.DialNetstack(p.dialAddr, s.profile.TCP)
	case s.profile.TCP != nil && s.profile.TCP.Mode != "" && s.profile.TCP.Mode != "setsockopt":
		return nil, fmt.Errorf("engine: tcp.mode %q 未知（want setsockopt/netstack）", s.profile.TCP.Mode)
	case p.proxyURL == "":
		return p.d.Dial(p.network, p.dialAddr)
	default:
		return s.dialViaProxy(p.d, p.proxyURL, p.dialAddr, p.deadline)
	}
}

// dialAndHandshake 完成一次"TCP（可经代理）+ 编译 spec + TLS 握手"。
// spec 每次重新编译——它不可跨连接复用（见 tlscore.Handshake 文档）。
func (s *Session) dialAndHandshake(p *dialPlan, alpn []string, detail *profiles.Detail) (*transportConn, error) {
	raw, err := s.dialTCPOnly(p)
	if err != nil {
		return nil, err
	}

	if detail == nil {
		detail = s.profile.TLS.Detail
	}
	// 协议选择（G8）：按会话允许集合收窄 ALPN。默认集合（h1.1+h2）时 narrowALPN
	// 原样返回 profile 的 detail ⇒ 线上逐字节不变；只有用户显式收窄（如只要
	// h1.1 / 只要 h2）才会改写扩展里的协议列表。
	if alpn == nil {
		narrowed, list, _ := narrowALPN(detail, s.protos, s.protoCustom)
		detail = narrowed
		alpn = list
	}
	spec, err := tlscore.CompileDetail(detail)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("engine: compile tls detail: %w", err)
	}
	cfg := &utls.Config{
		ServerName:         p.host, // sni:"auto" 的解析点
		InsecureSkipVerify: s.opts.InsecureSkipVerify,
		RootCAs:            s.certs.rootPool(), // nil = 系统信任库
		Certificates:       s.certs.tcpCerts(), // mTLS：服务端索要证书时用
		NextProtos:         alpn,               // 收窄后的集合；nil = profile 不发 ALPN
		ClientSessionCache: s.sessionCache,     // P7-T2：nil 时 uTLS 不复用
		OmitEmptyPsk:       true,               // 无票据时线上省略空 PSK 扩展（不报错）
	}
	// 真 ECH：detail 里 mode=real 的 ECH 扩展注入 ECHConfigList。
	if echList, err := realECHConfigList(detail); err != nil {
		raw.Close()
		return nil, fmt.Errorf("engine: ech config_list_hex: %w", err)
	} else if echList != nil {
		cfg.EncryptedClientHelloConfigList = echList
	}
	uconn, err := tlscore.Handshake(raw, cfg, spec)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("engine: tls handshake with %s: %w", p.dialAddr, err)
	}

	return &transportConn{
		conn:  raw,
		uconn: uconn,
		spec:  spec,
		proto: uconn.ConnectionState().NegotiatedProtocol,
		sc:    selfCheck(s.profile, spec, p.host, uconn),
	}, nil
}

// alpnProtocols 取 detail 里 ALPN 扩展的协议列表（cfg.NextProtos 用；
// 线上内容由扩展本身决定）。
func alpnProtocols(d *profiles.Detail) []string {
	for _, e := range d.Extensions {
		if e.Type == 16 && len(e.ALPN) > 0 {
			return e.ALPN
		}
	}
	return nil
}

// dialViaProxy 建立经代理的 TCP 通道（HTTP CONNECT / SOCKS5(+h) / SOCKS4(A)）。
// deadline 只覆盖"代理握手"这一段（握手完即撤销，不会变成连接的读超时——
// body 的空闲上限是 read_timeout_ms 的职责，见 A6）。
func (s *Session) dialViaProxy(d *net.Dialer, proxySpec, targetAddr string, deadline time.Time) (net.Conn, error) {
	pu, proxyAddr, err := parseProxySpec(proxySpec)
	if err != nil {
		return nil, err
	}

	switch pu.Scheme {
	case "http", "https":
		conn, err := d.Dial("tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("engine: dial proxy %s: %w", proxyAddr, err)
		}
		if err := httpConnect(conn, targetAddr, pu.User, deadline); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "socks5", "socks5h":
		// socks5 = 本地解析后把 IP 交给代理；socks5h = 域名交给代理（远端 DNS）。
		target, err := s.socks5Target(pu.Scheme, targetAddr, deadline)
		if err != nil {
			return nil, err
		}
		var auth *proxy.Auth
		if pu.User != nil {
			password, _ := pu.User.Password()
			auth = &proxy.Auth{User: pu.User.Username(), Password: password}
		}
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, d)
		if err != nil {
			return nil, fmt.Errorf("engine: socks5 proxy: %w", err)
		}
		return dialer.Dial("tcp", target)

	default: // socks4 / socks4a —— parseProxySpec 已保证 scheme 合法且无口令
		userid := ""
		if pu.User != nil {
			userid = pu.User.Username() // socks4 只有明文 USERID 位，密码无法承载（curl 同）
		}
		conn, err := d.Dial("tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("engine: dial proxy %s: %w", proxyAddr, err)
		}
		if err := s.socks4Connect(conn, targetAddr, pu.Scheme == "socks4a", userid, deadline); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// httpConnect 在已连通的代理连接上发 CONNECT 并校验 200。
func httpConnect(conn net.Conn, targetAddr string, user *url.Userinfo, deadline time.Time) error {
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("engine: connect deadline: %w", err)
		}
		defer conn.SetDeadline(time.Time{})
	}
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: http.Header{},
	}
	if user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password) // Proxy-Authorization 由调用方改成 proxy 头
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("engine: CONNECT write: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("engine: CONNECT response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("engine: CONNECT to %s via proxy: status %d", targetAddr, resp.StatusCode)
	}
	return nil
}

// realECHConfigList 取 detail 里首个 mode=real 的 ECH 配置的 ECHConfigList
// 字节；无 real ECH 返回 nil,nil。
func realECHConfigList(d *profiles.Detail) ([]byte, error) {
	if d == nil {
		return nil, nil
	}
	for _, e := range d.Extensions {
		if e.Type == 65037 && e.ECH != nil && e.ECH.Mode == "real" {
			return profiles.ParseHexBytes(e.ECH.ConfigListHex)
		}
	}
	return nil, nil
}
