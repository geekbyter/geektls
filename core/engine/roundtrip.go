package engine

// 单次请求执行：connect → 协议分发（h2/h1）→ 响应头到达即返回。

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"

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

	// cookie 注入（请求头里显式给的 Cookie 优先）
	headers := s.appendCookieHeader(u, req.Headers)

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

	// 收取 Set-Cookie / 学习 Alt-Svc
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
	return resp, nil
}

// doTCPLegacy 是 TCP 上的 h2/h1 路径（原 doSingle 主体）。
func (s *Session) doTCPLegacy(req *Request, u *url.URL, headers [][2]string) (*Response, error) {
	tc, err := s.connect(req, u)
	if err != nil {
		return nil, err
	}

	var resp *Response
	if tc.proto == "h2" {
		resp, err = s.doH2(tc, req, headers)
	} else {
		resp, err = s.doH1(tc, req, u, headers)
	}
	if err != nil {
		tc.uconn.Close()
		return nil, err
	}
	resp.SelfCheck = selfCheck(s.profile, tc.spec)
	return resp, nil
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

// doH2 走 fhttp 帧层。
func (s *Session) doH2(tc *transportConn, req *Request, headers [][2]string) (*Response, error) {
	cc, err := h2core.NewClientConn(tc.uconn, s.profile.HTTP2)
	if err != nil {
		return nil, fmt.Errorf("engine: h2 client conn: %w", err)
	}
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	resp, err := h2core.Do(cc, req.Method, req.URL, headers, body)
	if err != nil {
		return nil, fmt.Errorf("engine: h2 request: %w", err)
	}
	out := &Response{
		Status:       resp.StatusCode,
		UsedProtocol: "h2",
		Body:         &connClosingReader{ReadCloser: resp.Body, onClose: func() { tc.uconn.Close() }},
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
// 入口时与期望指纹比对。
func selfCheck(p *profiles.Profile, spec *utls.ClientHelloSpec) SelfCheck {
	ja3 := tlscore.ComputeJA3(spec)
	sc := SelfCheck{
		JA3:     ja3,
		JA3Hash: tlscore.JA3Hash(ja3),
		JA4:     tlscore.ComputeJA4(spec),
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
