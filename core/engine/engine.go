// Package engine 是 geektls 的会话引擎（P3）：cookie jar、重定向、超时、
// 代理（HTTP CONNECT / SOCKS5）、协议分发（h2/h1）、响应流式。
//
// 连接模型：P3 每请求一条新连接（连接池/复用是 P7 性能项）。响应头到达
// 即返回，body 以 io.ReadCloser 流式暴露。
package engine

import (
	"fmt"
	"io"
	"net/http/cookiejar"
	"net/url"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/publicsuffix"

	"github.com/geektls/core/profiles"
)

// SessionOptions 是会话级配置。
type SessionOptions struct {
	Proxy              string `json:"proxy,omitempty"`                // http://user:pass@host:port / socks5://...
	TimeoutMs          int    `json:"timeout_ms,omitempty"`           // 整体硬超时（dial+TLS+响应头），默认 30000
	RedirectMax        int    `json:"redirect_max,omitempty"`         // 默认 10；<0 = 不跟随（Go RoundTripper 用）
	CookieJar          *bool  `json:"cookie_jar,omitempty"`           // 默认 true
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"` // 跳过证书校验（测试/自签场景）
}

// Request 是一次请求（FFI 的 request_json 映射到它）。
type Request struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Headers    [][2]string `json:"headers,omitempty"`
	Body       []byte      `json:"-"` // FFI 层从 body_b64 解码
	BodyB64    string      `json:"body_b64,omitempty"`
	TimeoutMs  int         `json:"timeout_ms,omitempty"`  // 覆盖会话默认
	Proxy      string      `json:"proxy,omitempty"`       // 覆盖会话默认
	Stream     bool        `json:"stream,omitempty"`      // 预留；P3 响应恒流式
	ForceHTTP3 bool        `json:"force_http3,omitempty"` // P4 生效
}

// SelfCheck 是"实际发出 vs 期望"的自校验结果（02 文档 §1）。
type SelfCheck struct {
	JA3      string `json:"ja3"`
	JA3Hash  string `json:"ja3_hash"`
	JA4      string `json:"ja4"`
	JA3Match *bool  `json:"ja3_match,omitempty"` // 仅当 profile 来自 JA3 入口时有期望值
	JA4Match *bool  `json:"ja4_match,omitempty"` // 仅当来自 JA4R 入口时
}

// Response 是响应头到达时刻的视图；Body 流式。
//
// 便捷读取（Bytes/Text/JSON/OK/Reason/HeaderValues）见 response.go，
// 与 Python/Node 绑定保持同一套语义。
type Response struct {
	Status       int
	Headers      [][2]string
	UsedProtocol string
	SelfCheck    SelfCheck
	Body         io.ReadCloser

	body []byte // Bytes() 读完后的缓存（Body 随之消费）
}

// Header 取首个同名响应头（大小写不敏感）。
func (r *Response) Header(name string) string {
	for _, kv := range r.Headers {
		if equalFoldASCII(kv[0], name) {
			return kv[1]
		}
	}
	return ""
}

// Session 是带状态的会话：cookie jar + 默认配置 + profile + Alt-Svc 缓存 +
// TLS 会话票据缓存（P7-T2 复用/PSK）。
type Session struct {
	profile      *profiles.Profile
	opts         SessionOptions
	jar          *cookiejar.Jar // nil = 禁用 cookie
	altSvcH3     sync.Map       // host:port → 已知广告 H3
	sessionCache utls.ClientSessionCache
	closed       bool
}

// NewSession 基于 profile 建会话。profile 必须有可编译的 tls.detail。
func NewSession(p *profiles.Profile, opts SessionOptions) (*Session, error) {
	if p == nil || p.TLS == nil || p.TLS.Detail == nil {
		return nil, fmt.Errorf("engine: profile has no tls.detail")
	}
	if opts.TimeoutMs <= 0 {
		opts.TimeoutMs = 30000
	}
	if opts.RedirectMax == 0 {
		opts.RedirectMax = 10
	}
	s := &Session{profile: p, opts: opts}
	jarEnabled := opts.CookieJar == nil || *opts.CookieJar
	if jarEnabled {
		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			return nil, fmt.Errorf("engine: cookie jar: %w", err)
		}
		s.jar = jar
	}
	// TLS 会话复用：behavior.session_resumption=false 时禁用，默认开启。
	// 共享 cache 让同 Session 的后续握手发带 PSK 的 ClientHello。
	if p.Behavior == nil || p.Behavior.SessionResumption {
		s.sessionCache = utls.NewLRUClientSessionCache(64)
	}
	return s, nil
}

// Profile 返回会话的 profile（供 selfcheck 等读取）。
func (s *Session) Profile() *profiles.Profile { return s.profile }

// Close 释放会话持有的缓存（TLS 票据 / cookie / Alt-Svc 记忆）。
// 与 Python/Node 绑定的 s.close() 对称；调用后 Do 返回错误。
func (s *Session) Close() {
	s.closed = true
	s.jar = nil
	s.sessionCache = nil
	s.altSvcH3 = sync.Map{}
}

// Do 执行请求（含重定向链），阻塞到最终响应头到达。
func (s *Session) Do(req *Request) (*Response, error) {
	if s.closed {
		return nil, fmt.Errorf("engine: session closed")
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	if _, err := url.Parse(req.URL); err != nil {
		return nil, fmt.Errorf("engine: bad url: %w", err)
	}

	current := *req
	for redirects := 0; ; redirects++ {
		resp, err := s.doSingle(&current)
		if err != nil {
			return nil, err
		}
		location, isRedirect := redirectTarget(resp)
		if !isRedirect || s.opts.RedirectMax < 0 {
			return resp, nil
		}
		if redirects >= s.opts.RedirectMax {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("engine: too many redirects (max %d)", s.opts.RedirectMax)
		}
		// 排空并关闭当前 body 后跟随重定向
		io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()

		next, err := url.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("engine: bad redirect location %q: %w", location, err)
		}
		base, _ := url.Parse(current.URL)
		current.URL = base.ResolveReference(next).String()
		// 301/302/303 改写为 GET 并丢弃 body；307/308 保留
		if resp.Status == 301 || resp.Status == 302 || resp.Status == 303 {
			current.Method = "GET"
			current.Body = nil
		}
	}
}

func redirectTarget(resp *Response) (string, bool) {
	switch resp.Status {
	case 301, 302, 303, 307, 308:
		loc := resp.Header("Location")
		return loc, loc != ""
	}
	return "", false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
