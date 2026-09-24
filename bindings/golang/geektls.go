// Package geektls 是 core 的 Go 薄封装（不走 FFI，直接 import core）。
//
// 两种用法：
//   - Session：完整控制（selfcheck/流式 body/协议断言）
//   - NewRoundTripper：http.RoundTripper 兼容，直接挂 http.Client
package geektls

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/geektls/core/engine"
	"github.com/geektls/core/profiles"
	"github.com/geektls/core/version"
)

// ABI / Core re-export 自 core/version（单一事实源）。
const (
	ABI  = version.ABI
	Core = version.Core
)

// Version 返回与 gtls_version() 一致的版本 JSON。
func Version() string {
	b, _ := json.Marshal(struct {
		ABI  int    `json:"abi"`
		Core string `json:"core"`
		UTLS string `json:"utls"`
	}{ABI, Core, version.UTLS})
	return string(b)
}

// Options 是 Session/RoundTripper 的配置。
type Options struct {
	Proxy              string // http://user:pass@host:port / socks5://...
	TimeoutMs          int
	InsecureSkipVerify bool
	// RoundTripper 模式下重定向与 cookie 由 net/http.Client 管理，自动关闭 engine 侧。
}

// Session 是指纹会话（engine.Session 的薄封装）。
type Session struct {
	eng *engine.Session
}

// NewSession 以预设名建会话（如 "chrome_133"，见 gtls_list_presets）。
func NewSession(preset string, opts *Options) (*Session, error) {
	p, err := profiles.Get(preset)
	if err != nil {
		return nil, err
	}
	return NewSessionFromProfile(p, opts)
}

// NewSessionFromProfile 以完整 profile 建会话。
func NewSessionFromProfile(p *profiles.Profile, opts *Options) (*Session, error) {
	eng, err := engine.NewSession(p, engineOpts(opts, false))
	if err != nil {
		return nil, err
	}
	return &Session{eng: eng}, nil
}

func engineOpts(o *Options, forRoundTripper bool) engine.SessionOptions {
	var out engine.SessionOptions
	if o != nil {
		out.Proxy = o.Proxy
		out.TimeoutMs = o.TimeoutMs
		out.InsecureSkipVerify = o.InsecureSkipVerify
	}
	if forRoundTripper {
		out.RedirectMax = -1 // 重定向交给 http.Client
		disabled := false    // cookie 交给 http.Client.Jar
		out.CookieJar = &disabled
	}
	return out
}

// Response 是响应头到达时刻的视图；Body 流式。
type Response = engine.Response

// Do 执行请求（含重定向链），阻塞到响应头。
func (s *Session) Do(req *engine.Request) (*Response, error) { return s.eng.Do(req) }

// Get 是 GET 便捷方法。
func (s *Session) Get(url string) (*Response, error) {
	return s.eng.Do(&engine.Request{Method: "GET", URL: url})
}

// roundTripper 适配 http.RoundTripper。
type roundTripper struct {
	s *Session
}

// NewRoundTripper 返回 http.RoundTripper 兼容的指纹 Transport：
//
//	client := &http.Client{Transport: rt}
//
// 注意：请求头顺序/大小写经 http.Header（map）会丢失——指纹级 header 序
// 控制请用 Session + http1 节；RoundTripper 面向"拿来即用"的兼容场景。
func NewRoundTripper(preset string, opts *Options) (http.RoundTripper, error) {
	p, err := profiles.Get(preset)
	if err != nil {
		return nil, err
	}
	eng, err := engine.NewSession(p, engineOpts(opts, true))
	if err != nil {
		return nil, err
	}
	return &roundTripper{s: &Session{eng: eng}}, nil
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	er := &engine.Request{Method: req.Method, URL: req.URL.String()}
	for name, vals := range req.Header {
		for _, v := range vals {
			er.Headers = append(er.Headers, [2]string{name, v})
		}
	}
	if req.Body != nil {
		// engine P3 为整体 body；RoundTripper 场景缓冲读全（流式上传用 Session）
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		er.Body = body
	}

	resp, err := rt.s.eng.Do(er)
	if err != nil {
		return nil, err
	}

	hdr := http.Header{}
	for _, kv := range resp.Headers {
		hdr.Add(kv[0], kv[1])
	}
	major, minor := 1, 1
	proto := "HTTP/1.1"
	switch resp.UsedProtocol {
	case "h2":
		major, minor, proto = 2, 0, "HTTP/2.0"
	case "h3":
		major, minor, proto = 3, 0, "HTTP/3.0"
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", resp.Status, http.StatusText(resp.Status)),
		StatusCode:    resp.Status,
		Proto:         proto,
		ProtoMajor:    major,
		ProtoMinor:    minor,
		Header:        hdr,
		Body:          resp.Body,
		Request:       req,
		ContentLength: -1,
	}, nil
}
