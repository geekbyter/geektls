package engine

// 单次请求执行：connect → 协议分发（h2/h1）→ 响应头到达即返回。

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	utls "github.com/refraction-networking/utls"

	h2core "github.com/geektls/core/h2"
	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// doSingle 执行一跳请求（不含重定向）。
func (s *Session) doSingle(req *Request) (*Response, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("engine: bad url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("engine: only https is supported in P3 (got %q)", u.Scheme)
	}

	// 身份注入（T2-1）：profile.identity 的缺省头补齐用户未提供的头部，
	// 再注入 Cookie（请求头里显式给的 Cookie 优先）
	headers := s.appendCookieHeader(u, s.applyIdentity(req.Headers))

	var resp *Response
	switch {
	case req.ForceHTTP3:
		// 强制 H3：失败不回落（调用方明确要 H3）
		resp, err = s.doH3(req, headers)
	case s.profile.HTTP3 != nil && s.profile.HTTP3.Enabled && s.profile.HTTP3.H2RaceMs > 0:
		// 竞速模式：H3 先跑，超时并发 H2
		resp, err = s.raceH3H2(req, u, headers)
	case s.h3Eligible(req, u.Host):
		// Alt-Svc 已知 H3 能力：H3 优先，失败负缓存该主机并落 H2
		resp, err = s.doH3(req, headers)
		if err != nil {
			s.altSvcH3.Store(u.Host, false)
			resp, err = s.doTCPLegacy(req, u, headers)
		}
	default:
		resp, err = s.doTCPLegacy(req, u, headers)
	}
	if err != nil {
		return nil, err
	}

	s.absorbResponseMeta(u, resp)
	return resp, nil
}

// absorbResponseMeta 收取响应的 Set-Cookie 进 jar、从响应头学习 Alt-Svc
//（普通请求与流式上传共用）。
func (s *Session) absorbResponseMeta(u *url.URL, resp *Response) {
	if s.jar != nil {
		var setCookies []string
		for _, kv := range resp.Headers {
			if equalFoldASCII(kv[0], "set-cookie") {
				setCookies = append(setCookies, kv[1])
			}
		}
		if len(setCookies) > 0 {
			h := http.Header{}
			for _, c := range setCookies {
				h.Add("Set-Cookie", c)
			}
			s.jar.SetCookies(u, (&http.Response{Header: h}).Cookies())
		}
	}
	s.learnAltSvc(u.Host, resp.Headers)
}

// doTCPLegacy 是 TCP 上的 h2/h1 路径（原 doSingle 主体）。
// 连接池（默认开）：先试同键的共享 h2 连接 / 空闲 h1 连接，失败落新拨号
// 重试一次（请求体在内存中可重放；静默死连接上的写对端未处理，重试安全）。
func (s *Session) doTCPLegacy(req *Request, u *url.URL, headers [][2]string) (*Response, error) {
	key := s.poolKey(req, u.Host)
	if s.poolOn() {
		if e := s.pool.getH2(key); e != nil {
			if e.cc.CanTakeNewRequest() {
				if resp, err := s.doH2(e, req, headers); err == nil {
					return resp, nil
				}
			}
			// 死连接或 RoundTrip 失败：摘除并落新拨号
			s.pool.removeH2(key, e)
			e.tc.uconn.Close()
		}
		if e := s.pool.popH1(key); e != nil {
			if e.br != nil && e.br.Buffered() > 0 {
				// 空闲连接上有未读字节 = 协议脱同步，不复用
				e.tc.uconn.Close()
			} else if resp, err := s.doH1(e, req, u, headers); err == nil {
				return resp, nil
			} else {
				e.tc.uconn.Close()
			}
			// 池化连接失效 → 落新拨号
		}
	}

	tc, err := s.connect(req, u)
	if err != nil {
		return nil, err
	}

	var resp *Response
	if tc.proto == "h2" {
		var e *poolEntry
		e, err = s.newH2Entry(key, tc)
		if err == nil {
			resp, err = s.doH2(e, req, headers)
		}
	} else {
		resp, err = s.doH1(&poolEntry{key: key, tc: tc}, req, u, headers)
	}
	if err != nil {
		tc.uconn.Close()
		return nil, err
	}
	return resp, nil
}

// applyIdentity 把 profile.identity 的缺省请求头补齐到用户头部之前：
// 用户请求里同名头（大小写不敏感）优先，不覆盖；identity 表内顺序即线上顺序。
// 无 identity 节时原样返回，行为与注入前完全一致（冻结面安全）。
func (s *Session) applyIdentity(headers [][2]string) [][2]string {
	id := s.profile.Identity
	if id == nil || len(id.Headers) == 0 {
		return headers
	}
	present := make(map[string]bool, len(headers))
	for _, kv := range headers {
		present[strings.ToLower(kv[0])] = true
	}
	out := make([][2]string, 0, len(id.Headers)+len(headers))
	for _, kv := range id.Headers {
		if !present[strings.ToLower(kv[0])] {
			out = append(out, kv)
		}
	}
	return append(out, headers...)
}

// appendCookieHeader 注入 Cookie 头；显式 Cookie 头优先（不覆盖）。
func (s *Session) appendCookieHeader(u *url.URL, headers [][2]string) [][2]string {
	if s.jar == nil {
		return headers
	}
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "cookie") {
			return headers
		}
	}
	cookies := s.jar.Cookies(u)
	if len(cookies) == 0 {
		return headers
	}
	val := ""
	for i, c := range cookies {
		if i > 0 {
			val += "; "
		}
		val += c.Name + "=" + c.Value
	}
	out := make([][2]string, 0, len(headers)+1)
	out = append(out, headers...)
	return append(out, [2]string{"cookie", val})
}

// newH2Entry 在新握手的连接上建 h2 ClientConn 并尝试登记为池内共享连接
// （并发撞车时本连接作孤儿：服务完当前请求后随 body 关闭）。
func (s *Session) newH2Entry(key string, tc *transportConn) (*poolEntry, error) {
	cc, err := h2core.NewClientConn(tc.uconn, s.profile.HTTP2)
	if err != nil {
		return nil, fmt.Errorf("engine: h2 client conn: %w", err)
	}
	e := &poolEntry{key: key, tc: tc, cc: cc}
	if s.poolOn() {
		s.pool.putH2(key, e)
	}
	return e, nil
}

// doH2 走 fhttp 帧层。SelfCheck 报告本连接握手时的指纹（池化复用不发新
// ClientHello）；共享连接的 body 关闭只收尾当前流，孤儿/无池连接随 body
// 关闭（旧行为）。
func (s *Session) doH2(e *poolEntry, req *Request, headers [][2]string) (*Response, error) {
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	resp, err := h2core.Do(e.cc, req.Method, req.URL, headers, body)
	if err != nil {
		return nil, fmt.Errorf("engine: h2 request: %w", err)
	}
	var rc io.ReadCloser = resp.Body
	if !e.shared {
		rc = &connClosingReader{ReadCloser: resp.Body, onClose: func() { e.tc.uconn.Close() }}
	}
	out := &Response{
		Status:       resp.StatusCode,
		UsedProtocol: "h2",
		Body:         rc,
		SelfCheck:    e.tc.sc,
	}
	for name, vals := range resp.Header {
		for _, v := range vals {
			out.Headers = append(out.Headers, [2]string{name, v})
		}
	}
	return out, nil
}

// connClosingReader：body 关闭时连带关连接（P3 每请求一连接）。
type connClosingReader struct {
	io.ReadCloser
	onClose func()
}

func (r *connClosingReader) Close() error {
	err := r.ReadCloser.Close()
	if r.onClose != nil {
		r.onClose()
	}
	return err
}

// selfCheck 用本次握手实际发出的 spec 自算 JA3/JA4；profile 来自 JA3/JA4R
// 入口时与期望指纹比对。host 是本次拨号目标：IP 字面量（含 IPv6）时 uTLS
// 与真 Chrome 一样在线上省略 SNI 扩展，而 spec 里的 SNI 只是 "auto" 占位，
// 自算前从 spec 副本剔除，让 JA4 的 d/i 标志与扩展计数（及 JA3 扩展段）
// 反映线上实情。uconn 非 nil 时附协商结果（cipher/版本/ALPN）。
// 本函数在握手完成时调用一次，结果随连接走（连接池复用不重算）。
func selfCheck(p *profiles.Profile, spec *utls.ClientHelloSpec, host string, uconn *utls.UConn) SelfCheck {
	sniInSpec := false
	for _, e := range spec.Extensions {
		if _, ok := e.(*utls.SNIExtension); ok {
			sniInSpec = true
			break
		}
	}
	sniSent := sniInSpec && net.ParseIP(host) == nil
	calc := spec
	if sniInSpec && !sniSent {
		calc = tlscore.SpecWithoutSNI(spec)
	}

	ja3 := tlscore.ComputeJA3(calc)
	wireExts, plainExts, grease := tlscore.WireView(calc)
	sc := SelfCheck{
		JA3:           ja3,
		JA3Hash:       tlscore.JA3Hash(ja3),
		JA3FullString: ja3,
		JA4:           tlscore.ComputeJA4(calc),
		SNISent:       sniSent,
		Extensions:    plainExts,
		WireExts:      wireExts,
		Grease:        grease,
	}
	if uconn != nil {
		st := uconn.ConnectionState()
		sc.Negotiated = &NegotiatedInfo{
			Cipher:  fmt.Sprintf("0x%04x", st.CipherSuite),
			Version: fmt.Sprintf("0x%04x", st.Version),
			ALPN:    st.NegotiatedProtocol,
		}
	}
	if p.TLS.JA3 != "" {
		match := tlscore.JA3Hash(p.TLS.JA3) == sc.JA3Hash
		sc.JA3Match = &match
	}
	if p.TLS.JA4R != "" {
		if want, err := tlscore.HashJA4R(p.TLS.JA4R); err == nil {
			match := want == sc.JA4
			sc.JA4Match = &match
		}
	}
	return sc
}
