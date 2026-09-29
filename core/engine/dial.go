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
type transportConn struct {
	conn  net.Conn
	uconn *utls.UConn
	spec  *utls.ClientHelloSpec
	proto string // 协商出的 ALPN
	sc    SelfCheck
}

// connect 完成 dial（可选代理）+ uTLS 握手，返回可用于 H1/H2 分发的连接。
// deadline 是整体硬超时（P3 简化：connect+TLS+响应头共用一个 deadline）。
func (s *Session) connect(req *Request, u *url.URL) (*transportConn, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	timeout := time.Duration(s.opts.TimeoutMs) * time.Millisecond
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	deadline := time.Now().Add(timeout)

	proxyURL := req.Proxy
	if proxyURL == "" {
		proxyURL = s.opts.Proxy
	}

	d := net.Dialer{Timeout: time.Until(deadline)}
	// P6：profile.tcp 非空时给拨号器挂 setsockopt（对代理场景，
	// 选项落在到代理的这条 TCP 上——这正是承载指纹的流）。
	if s.profile.TCP != nil {
		tcp.Configure(&d, s.profile.TCP)
	}

	// 本次握手是否会带票据（缓存里有该 SNI 的票据即会）：仅用于决定失败后是否
	// 值得丢票重试（见下）。缓存键就是 SNI（实测）。
	hadTicket := false
	if s.sessionCache != nil {
		if _, ok := s.sessionCache.Get(host); ok {
			hadTicket = true
		}
	}

	tc, err := s.dialAndHandshake(&d, proxyURL, addr, host)
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
		s.sessionCache.Put(host, nil) // uTLS 语义：Put(nil) = 删除该键
	}
	if tc, retryErr := s.dialAndHandshake(&d, proxyURL, addr, host); retryErr == nil {
		return tc, nil
	} else {
		return nil, fmt.Errorf("%w（丢票回退后仍失败: %v）", err, retryErr)
	}
}

// dialAndHandshake 完成一次"TCP（可经代理）+ 编译 spec + TLS 握手"。
// spec 每次重新编译——它不可跨连接复用（见 tlscore.Handshake 文档）。
func (s *Session) dialAndHandshake(d *net.Dialer, proxyURL, addr, host string) (*transportConn, error) {
	var raw net.Conn
	var err error
	if proxyURL == "" {
		raw, err = d.Dial("tcp", addr)
	} else {
		raw, err = dialViaProxy(d, proxyURL, addr)
	}
	if err != nil {
		return nil, err
	}

	spec, err := tlscore.CompileDetail(s.profile.TLS.Detail)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("engine: compile tls detail: %w", err)
	}

	cfg := &utls.Config{
		ServerName:         host, // sni:"auto" 的解析点
		InsecureSkipVerify: s.opts.InsecureSkipVerify,
		NextProtos:         alpnProtocols(s.profile.TLS.Detail),
		ClientSessionCache: s.sessionCache, // P7-T2：nil 时 uTLS 不复用
		OmitEmptyPsk:       true,           // 无票据时线上省略空 PSK 扩展（不报错）
	}
	// 真 ECH：detail 里 mode=real 的 ECH 扩展注入 ECHConfigList。
	if echList, err := realECHConfigList(s.profile.TLS.Detail); err != nil {
		raw.Close()
		return nil, fmt.Errorf("engine: ech config_list_hex: %w", err)
	} else if echList != nil {
		cfg.EncryptedClientHelloConfigList = echList
	}
	uconn, err := tlscore.Handshake(raw, cfg, spec)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("engine: tls handshake with %s: %w", addr, err)
	}

	return &transportConn{
		conn:  raw,
		uconn: uconn,
		spec:  spec,
		proto: uconn.ConnectionState().NegotiatedProtocol,
		sc:    selfCheck(s.profile, spec, host, uconn),
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

// dialViaProxy 建立经代理的 TCP 通道（HTTP CONNECT / SOCKS5，均支持账号密码）。
func dialViaProxy(d *net.Dialer, proxySpec, targetAddr string) (net.Conn, error) {
	pu, err := url.Parse(proxySpec)
	if err != nil {
		return nil, fmt.Errorf("engine: bad proxy url: %w", err)
	}
	proxyAddr := pu.Host
	if pu.Port() == "" {
		switch pu.Scheme {
		case "http", "https":
			proxyAddr = net.JoinHostPort(pu.Hostname(), "8080")
		case "socks5", "socks5h":
			proxyAddr = net.JoinHostPort(pu.Hostname(), "1080")
		}
	}

	switch pu.Scheme {
	case "http", "https":
		conn, err := d.Dial("tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("engine: dial proxy %s: %w", proxyAddr, err)
		}
		if err := httpConnect(conn, targetAddr, pu.User); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "socks5", "socks5h":
		var auth *proxy.Auth
		if pu.User != nil {
			password, _ := pu.User.Password()
			auth = &proxy.Auth{User: pu.User.Username(), Password: password}
		}
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, d)
		if err != nil {
			return nil, fmt.Errorf("engine: socks5 proxy: %w", err)
		}
		return dialer.Dial("tcp", targetAddr)

	default:
		return nil, fmt.Errorf("engine: unsupported proxy scheme %q (want http/socks5)", pu.Scheme)
	}
}

// httpConnect 在已连通的代理连接上发 CONNECT 并校验 200。
func httpConnect(conn net.Conn, targetAddr string, user *url.Userinfo) error {
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
