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
	"time"

	utls "github.com/refraction-networking/utls"

	h2core "github.com/geekbyter/geektls/core/h2"
	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

// doSingle 执行一跳请求（不含重定向）。
func (s *Session) doSingle(req *Request) (*Response, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("engine: bad url: %w", err)
	}
	switch u.Scheme {
	case "https", "http":
	default:
		return nil, fmt.Errorf("engine: unsupported scheme %q (want https/http)", u.Scheme)
	}
	// 明文档（G5）：只走 H1（h2c 不在承诺面内），不握手、不发 ClientHello
	// ⇒ SelfCheck 恒为零值、UsedProtocol 恒为 http/1.1。H3 只在 TLS 之上，
	// 所以明文一律不走 H3（下面 h3ok=false 就落到 doTCPLegacy）。
	plain := u.Scheme == "http"
	if plain && req.ForceHTTP3 {
		return nil, fmt.Errorf("engine: force_http3 需要 https（明文 http:// 没有 QUIC 承载）")
	}
	// 协议选择（G8）：请求级 force_http3 是**显式**选择，默认会话下照旧可用（老行为
	// 不变）；但用户显式给了 protocols 且不含 h3 时冲突 —— 显式配置优先，报错而不是
	// 静默降级。会话级"只允许 h3"（protocols=["h3"]）在 resolveProtocols 里已校验。
	if req.ForceHTTP3 && s.protoCustom && !s.protos.h3 {
		return nil, fmt.Errorf("engine: force_http3 与本会话 protocols=%s 冲突（显式限定了协议集合）：把 \"h3\" 加进 protocols 或去掉 force_http3", s.protos)
	}
	if plain && !s.protos.h1 {
		return nil, fmt.Errorf("engine: http:// 只能走 h1.1（明文没有 h2c / QUIC 承载）：protocols=%s 需保留 \"h1.1\"", s.protos)
	}

	// 身份注入（T2-1）：profile.identity 的缺省头补齐用户未提供的头部，
	// 再注入 Cookie（请求头里显式给的 Cookie 优先）
	identHeaders, idWarns := s.applyIdentity(req.Headers)
	headers := s.appendCookieHeader(u, identHeaders)

	// 生效代理（请求级 > 会话级 > 环境变量 + NO_PROXY）。这里先算一次只为
	// 判定 H3 可用性：QUIC 过代理需要 CONNECT-UDP（RFC 9298），本库未实现，
	// 而"以为走了代理、其实 UDP 直发"是最坏的一种泄漏，所以有代理时一律不走
	// H3；显式 force_http3 则直接报错（A8）。拨号与池键各自再取一次同值
	// （proxySpecFor 只做字符串匹配、不发 DNS 查询，重复调用是幂等的）。
	proxySpec, err := s.proxySpecFor(req, u.Scheme, u.Hostname(), portOrDefault(u))
	if err != nil {
		return nil, err
	}
	h3ok := proxySpec == "" && !plain
	if blocked, field := s.h3NetBlocked(); blocked {
		if req.ForceHTTP3 {
			// 地址控制（resolve / local_address / ip_version）没有接进 QUIC 拨号，
			// H3 走的是另一套解析路径。让 force_http3 报错而不是偷偷绕过用户点名的
			// 那一项（与代理同口径，A8/A9）。
			return nil, fmt.Errorf("engine: force_http3 与 %s 不兼容（QUIC 拨号不认地址控制项；要该行为请走 H2/H1）", field)
		}
		h3ok = false // profile 开着 H3 也只是"优先尝试"，这里静默让位给 H2 是安全的
	}

	var resp *Response
	switch {
	case req.ForceHTTP3 || s.protos.h3Only():
		if !h3ok {
			if req.ForceHTTP3 {
				return nil, fmt.Errorf("engine: force_http3 与代理不兼容（QUIC 过代理需 CONNECT-UDP/RFC 9298，未实现；要经代理请用 H2/H1，或去掉 proxy）")
			}
			return nil, fmt.Errorf("engine: H3 与代理不兼容（protocols 只允许 h3；QUIC 过代理需 CONNECT-UDP/RFC 9298，未实现；要经代理请把 h2/h1.1 加进 protocols，或去掉 proxy）")
		}
		// 强制 H3（请求级 force_http3 或会话级"只允许 h3"）：失败不回落
		resp, err = s.doH3(req, headers)
	case s.protos.h3 && s.profile.HTTP3 != nil && s.profile.HTTP3.Enabled && s.profile.HTTP3.H2RaceMs > 0 && h3ok:
		// 竞速模式：H3 先跑，超时并发 TCP（h2/h1.1 按 ALPN 收窄结果）
		resp, err = s.raceH3H2(req, u, headers)
	case h3ok && s.h3Eligible(req, u.Host):
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

	// 读超时先包住协议层 body（这样才认得出它的 abort 入口），再叠透明解压。
	resp.Body = newTimeoutReader(resp.Body, s.readTimeout(req))
	// 透明解压（T-DECOMP）：按 Content-Encoding 包装 body；headers 不动。
	s.applyDecompression(req, resp)
	// G9：身份自洽的告警与解压告警同路（都走 resp.Warnings → 绑定层 r.warnings）
	resp.Warnings = append(resp.Warnings, idWarns...)
	s.absorbResponseMeta(u, resp)
	return resp, nil
}

// readTimeout 取本次请求的 body 读取超时（请求级覆盖会话级；都没设则 0 = 不限）。
func (s *Session) readTimeout(req *Request) time.Duration {
	ms := s.opts.ReadTimeoutMs
	if req != nil && req.ReadTimeoutMs > 0 {
		ms = req.ReadTimeoutMs
	}
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// absorbResponseMeta 收取响应的 Set-Cookie 进 jar、从响应头学习 Alt-Svc
// （普通请求与流式上传共用）。
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
	key, err := s.poolKey(req, u.Scheme, u.Host)
	if err != nil {
		return nil, err
	}
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
//
// G9：调用方自带 `user-agent` 且与预设身份不一致时，按 IdentitySync 策略把
// **客户端提示**（sec-ch-ua / sec-ch-ua-platform / sec-ch-ua-mobile）校正到该 UA，
// 并把"TLS/H2 仍是该预设"如实写进返回的 warnings（调用方挂到响应上）。
func (s *Session) applyIdentity(headers [][2]string) ([][2]string, []string) {
	id := s.profile.Identity
	if id == nil || len(id.Headers) == 0 {
		return headers, nil
	}
	present := make(map[string]bool, len(headers))
	for _, kv := range headers {
		present[strings.ToLower(kv[0])] = true
	}
	injected := make([][2]string, 0, len(id.Headers))
	for _, kv := range id.Headers {
		if !present[strings.ToLower(kv[0])] {
			injected = append(injected, kv)
		}
	}

	var warns []string
	if s.idSync == identitySyncAuto {
		if presetUA, userUA, conflict := identityUAConflict(id.Headers, headers); conflict {
			if changed := syncClientHints(injected, parseUA(userUA)); len(changed) > 0 {
				warns = append(warns, fmt.Sprintf(
					"identity_sync: 调用方 user-agent 与预设身份不一致（预设 %q）：已把 %s 校正为调用方 UA；TLS/JA3/JA4/H2 仍为该预设（要字节级一致请改用同平台变体预设）",
					presetUA, strings.Join(changed, ", ")))
			}
		}
	}
	return append(injected, headers...), warns
}

// orderForWire 按会话头序策略处理"将要上线的头顺序"（H2/H3 用；H1 走
// orderH1Headers 一族，见 headerorder.go）。input 档在这里是 no-op —— H2/H3 的
// 切片顺序本来就是调用方给的顺序。
func (s *Session) orderForWire(headers [][2]string) [][2]string {
	if s.hdrOrder == headerOrderRandom {
		return randomizeHeaderOrder(headers)
	}
	return headers
}

// appendCookieHeader 注入 Cookie 头；显式 Cookie 头优先（不覆盖）。
func (s *Session) appendCookieHeader(u *url.URL, headers [][2]string) [][2]string {
	if s.jar == nil {
		return headers
	}
	// 显式 Cookie 头里的名字优先；引擎 jar 只补它没有的名字（**合并**而不是
	// 整段让位）。让位会把"重定向中间跳设置的 cookie"静默丢掉（最终响应里
	// 看不到它们，Python 绑定的会话级 jar 也就补不上），合并既不会双份同名，
	// 也保住了 jar 的补全。
	have := make(map[string]bool)
	for _, kv := range headers {
		if !equalFoldASCII(kv[0], "cookie") {
			continue
		}
		for _, pair := range strings.Split(kv[1], ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(pair), "=")
			if name != "" {
				have[strings.ToLower(name)] = true
			}
		}
	}
	var parts []string
	for _, c := range s.jar.Cookies(u) {
		if have[strings.ToLower(c.Name)] {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	if len(parts) == 0 {
		return headers
	}
	val := strings.Join(parts, "; ")
	out := make([][2]string, 0, len(headers)+1)
	merged := false
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "cookie") && !merged {
			out = append(out, [2]string{kv[0], kv[1] + "; " + val})
			merged = true
			continue
		}
		out = append(out, kv)
	}
	if !merged {
		out = append(out, [2]string{"cookie", val})
	}
	return out
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
	resp, err := h2core.Do(e.cc, req.Method, req.URL, s.orderForWire(headers), body)
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

// abort 是读超时的取消入口：内层若支持作废就用它，然后照样把连接关掉。
func (r *connClosingReader) abort() error {
	if ab, ok := r.ReadCloser.(interface{ abort() error }); ok {
		if err := ab.abort(); err != nil {
			return err
		}
	} else if err := r.ReadCloser.Close(); err != nil {
		return err
	}
	if r.onClose != nil {
		r.onClose()
	}
	return nil
}

// selfCheck 是 TCP 面入口：用本次握手实际发出的 spec 自算 JA3/JA4；profile
// 来自 JA3/JA4R 入口时与期望指纹比对。host 是本次拨号目标：IP 字面量（含
// IPv6）时 uTLS 与真 Chrome 一样在线上省略 SNI 扩展，而 spec 里的 SNI 只是
// "auto" 占位，自算前从 spec 副本剔除，让 JA4 的 d/i 标志与扩展计数（及 JA3
// 扩展段）反映线上实情。uconn 非 nil 时附协商结果（cipher/版本/ALPN）。
// 本函数在握手完成时调用一次，结果随连接走（连接池复用不重算）。
func selfCheck(p *profiles.Profile, spec *utls.ClientHelloSpec, host string, uconn *utls.UConn) SelfCheck {
	return buildSelfCheck(p, spec, host, uconn, false)
}

// selfCheckQUIC 是 H3/QUIC 面入口（T2.1）：同一套 spec 语义（SNI 归一 /
// GREASE 标记 / 扩展序两份），JA4 换 QUIC 变体（首字符 q）。两处如实差异：
//   - Negotiated 不填：QUIC 握手状态在 quic-go-utls 内部，无导出面；
//   - JA3Match/JA4Match 不算：内层形态经 clampSpecForQUIC 裁剪，与 profile
//     的 TCP 期望值本就不同，填 false 是误导（缺省即"不适用"）。
//
// 调用语义：每次 H3 请求按当次 host 计算（共享 transport 跨请求复用，但 SNI
// 的 d/i 位与目标相关；纯 spec 计算，微秒级）。
func selfCheckQUIC(p *profiles.Profile, spec *utls.ClientHelloSpec, host string) SelfCheck {
	return buildSelfCheck(p, spec, host, nil, true)
}

func buildSelfCheck(p *profiles.Profile, spec *utls.ClientHelloSpec, host string, uconn *utls.UConn, quic bool) SelfCheck {
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

	ja4 := tlscore.ComputeJA4(calc)
	if quic {
		ja4 = tlscore.ComputeJA4QUIC(calc)
	}
	ja3 := tlscore.ComputeJA3(calc)
	wireExts, plainExts, grease := tlscore.WireView(calc)
	sc := SelfCheck{
		JA3:           ja3,
		JA3Hash:       tlscore.JA3Hash(ja3),
		JA3FullString: ja3,
		JA4:           ja4,
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
	if !quic { // QUIC 面不比对（见 selfCheckQUIC 注释）
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
	}
	return sc
}
