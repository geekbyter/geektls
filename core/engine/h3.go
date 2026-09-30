package engine

// H3 路径：profile.http3.enabled 驱动；Alt-Svc 学习；H2/H3 竞速。

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/quic-go-utls/http3"

	h3core "github.com/geektls/core/h3"
)

// learnAltSvc 从响应头学习 Alt-Svc（h3/h3-29 广告）。显式负缓存优先：
// H3 失败过的主机不再被广告覆盖（否则每次响应都会复活 H3 尝试，实测坑）。
func (s *Session) learnAltSvc(host string, headers [][2]string) {
	for _, kv := range headers {
		if !equalFoldASCII(kv[0], "alt-svc") {
			continue
		}
		if strings.Contains(kv[1], "h3=") || strings.Contains(kv[1], "h3-") {
			if v, ok := s.altSvcH3.Load(host); ok && !v.(bool) {
				return
			}
			s.altSvcH3.Store(host, true)
		}
	}
}

// h3Eligible 判定本次请求是否走 H3。
func (s *Session) h3Eligible(req *Request, host string) bool {
	if req.ForceHTTP3 {
		return true
	}
	if s.profile.HTTP3 == nil || !s.profile.HTTP3.Enabled {
		return false
	}
	v, known := s.altSvcH3.Load(host)
	return known && v.(bool)
}

// doH3 单次 H3 请求。池开启时用 Session 级共享 transport（quic-go 内部按
// host 复用 QUIC 连接——真 Chrome 的同 origin 单 QUIC 连接形态）；池关闭时
// 维持旧行为：每请求新 transport，随 body 关闭。
func (s *Session) doH3(req *Request, headers [][2]string) (*Response, error) {
	shared := s.poolOn()
	var tr *http3.Transport
	var err error
	if shared {
		tr, err = s.sharedH3Transport()
	} else {
		tr, err = h3core.NewTransport(s.profile, s.h3TLSSettings())
	}
	if err != nil {
		return nil, err
	}
	// transport 不能在这里 Close：QUIC 连接必须活到 body 流读完。

	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	freq, err := fhttp.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	order := make([]string, 0, len(headers))
	for _, kv := range headers {
		freq.Header.Set(kv[0], kv[1])
		order = append(order, kv[0])
	}
	if len(order) > 0 {
		freq.Header[fhttp.HeaderOrderKey] = order
	}

	resp, err := tr.RoundTrip(freq)
	if err != nil {
		if !shared {
			tr.Close()
		}
		return nil, fmt.Errorf("engine: h3 request: %w", err)
	}
	out := &Response{
		Status:       resp.StatusCode,
		UsedProtocol: "h3",
	}
	if shared {
		out.Body = resp.Body // 共享 transport 留在池里，body 关闭只收尾当前流
	} else {
		out.Body = &connClosingReader{ReadCloser: resp.Body, onClose: func() {
			tr.Close()
		}}
	}
	for name, vals := range resp.Header {
		for _, v := range vals {
			out.Headers = append(out.Headers, [2]string{name, v})
		}
	}
	return out, nil
}

// sharedH3Transport 懒建并返回 Session 级共享 H3 transport（并发安全）。
// Session.Close 时随池排空。
func (s *Session) sharedH3Transport() (*http3.Transport, error) {
	s.h3mu.Lock()
	defer s.h3mu.Unlock()
	if s.h3tr != nil {
		return s.h3tr, nil
	}
	tr, err := h3core.NewTransport(s.profile, s.h3TLSSettings())
	if err != nil {
		return nil, err
	}
	s.h3tr = tr
	return tr, nil
}

// h3TLSSettings 把会话的证书材料映射到 H3 侧参数（QUIC 内层 TLS 用的是
// bogdanfinn/utls 类型，与 TCP 侧同一份 PEM 解析结果）。
func (s *Session) h3TLSSettings() h3core.TLSSettings {
	return h3core.TLSSettings{
		InsecureSkipVerify: s.opts.InsecureSkipVerify,
		RootCAs:            s.certs.rootPool(),
		Certificates:       s.certs.quicCerts(),
	}
}

// raceH3H2 实现 Chrome 式 H2/H3 竞速：H3 先跑，h2_race_ms 内没拿到响应头
// 就并发发 H2（/H1），先到先得；败者连接关闭。
func (s *Session) raceH3H2(req *Request, u *url.URL, headers [][2]string) (*Response, error) {
	raceMs := 300
	if s.profile.HTTP3 != nil && s.profile.HTTP3.H2RaceMs > 0 {
		raceMs = s.profile.HTTP3.H2RaceMs
	}

	type result struct {
		resp *Response
		err  error
	}
	h3ch := make(chan result, 1)
	go func() {
		r, err := s.doH3(req, headers)
		h3ch <- result{r, err}
	}()

	select {
	case r := <-h3ch:
		if r.err == nil {
			return r.resp, nil
		}
		// H3 快速失败 → 直接落 H2
	case <-time.After(time.Duration(raceMs) * time.Millisecond):
		// 超时未决 → 并发 H2
	}

	h2ch := make(chan result, 1)
	go func() {
		r, err := s.doTCPLegacy(req, u, headers)
		h2ch <- result{r, err}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case r := <-h3ch:
			if r.err == nil {
				return r.resp, nil
			}
			firstErr = r.err
		case r := <-h2ch:
			if r.err == nil {
				return r.resp, nil
			}
			firstErr = r.err
		}
	}
	return nil, fmt.Errorf("engine: h2/h3 race both failed: %v", firstErr)
}
