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
	"os"
	"path/filepath"

	"github.com/geekbyter/geektls/core/engine"
	pcapimport "github.com/geekbyter/geektls/core/pcapimport"
	"github.com/geekbyter/geektls/core/profiles"
	"github.com/geekbyter/geektls/core/version"
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
	}{ABI, Core, version.UTLSVersion()}) // utls 字段：指纹栈版本（build info 推导）
	return string(b)
}

// Options 是 Session/RoundTripper 的配置。
type Options struct {
	// Proxy 支持 http/https（CONNECT 隧道）、socks5、socks5h、socks4、socks4a。
	// socks5 在本地解析域名，socks5h 交代理解析；socks4 只承载 IPv4。
	Proxy     string // http://user:pass@host:port / socks5://...
	TimeoutMs int
	// ReadTimeoutMs 是每次读响应 body 的空闲超时（0 = 不设限）。TimeoutMs 只管到
	// dial+TLS+响应头，body 慢速/挂死要靠它兜；触发时 Read 返回 engine.ErrReadTimeout。
	ReadTimeoutMs      int
	InsecureSkipVerify bool
	// CABundle 是自持信任库：CA 文件路径、含 .pem/.crt/.cer 的目录、或内联 PEM
	// 文本。空 = 用系统信任库。给了它就等于**替换**系统根（与 requests 的
	// verify=<path> 语义一致），配错的 CA 会在建会话时报错而不是静默忽略。
	CABundle string
	// ClientCert / ClientKey 用于 mTLS。ClientCert 可以是"证书+私钥同文件"的
	// PEM（此时 ClientKey 留空）。
	ClientCert string
	ClientKey  string
	// ProxyFromEnv 控制"没显式给 Proxy 时是否读 HTTPS_PROXY / ALL_PROXY（并查
	// NO_PROXY）"。nil = 读；指向 false = 只认 Proxy。指纹调试要可复计时可关掉。
	ProxyFromEnv *bool
	// Resolve 把域名钉到固定 IP（curl --resolve 的形状：键是 "host" 或
	// "host:port"，值必须是 IP 字面量）。只改"连到哪"，SNI / Host / 指纹字节
	// 仍是原域名。键不做通配——钉 example.com 不会连带钉 cdn.example.com。
	Resolve map[string]string
	// LocalAddress 是出网 socket 的源 IP（curl --interface 的 IP 形态；网卡名
	// 不支持）。代理场景它绑的是到代理那一条。
	LocalAddress string
	// IPVersion 收窄协议族："4" / "6"（也接受 v4/ipv4 写法），空 = 不限。
	// 与 Proxy 同用时应选 socks5/socks4 这类本地解析档，socks5h/socks4a/CONNECT
	// 由代理解析、这一项不参与。
	IPVersion string
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
		out.ReadTimeoutMs = o.ReadTimeoutMs
		out.InsecureSkipVerify = o.InsecureSkipVerify
		out.CaBundle = o.CABundle
		out.ClientCert = o.ClientCert
		out.ClientKey = o.ClientKey
		out.ProxyFromEnv = o.ProxyFromEnv
		out.Resolve = o.Resolve
		out.LocalAddress = o.LocalAddress
		out.IPVersion = o.IPVersion
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

// WSRequest / WSConn 直接 re-export engine 的类型：绑定层不再包一层，
// 因为 engine 的形状就是 FFI url_json 的形状，多一层只会与 core 漂移。
type (
	WSRequest = engine.WSRequest
	WSConn    = engine.WSConn
)

// WebSocket opcode（RFC 6455 §5.2）。
const (
	WSOpContinuation = engine.WSOpContinuation
	WSOpText         = engine.WSOpText
	WSOpBinary       = engine.WSOpBinary
	WSOpClose        = engine.WSOpClose
	WSOpPing         = engine.WSOpPing
	WSOpPong         = engine.WSOpPong
)

// DialWS 建立 wss:// 连接：握手走本会话的拨号 + TLS 指纹链路（ALPN 收窄
// http/1.1，Upgrade 头序受控）。帧层拉模型：Send / Recv / Close。
// WSRequest.Compress=true 时握手 offer permessage-deflate（RFC 7692），只有
// 真的协商成功才压缩，Send/Recv 收发的仍是明文。
func (s *Session) DialWS(wr *WSRequest) (*WSConn, error) {
	return s.eng.DialWS(wr)
}

// Close 释放会话（连接池与 H3 transport）。薄封装必须给：eng 字段是非导出的，
// 没有它调用方就没办法回收长期运行的进程里的这些连接。
func (s *Session) Close() { s.eng.Close() }

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

// --- pcap 直导入（v0.2.0：与 CLI import-pcap / Python / Node 同一解析核） ---

// PcapOptions 控制 ImportPcap/ImportPcapBytes。零值合法（Stream=1）。
type PcapOptions struct {
	// Name 是记录名；空 = 文件名去扩展（Bytes 入口 = SourceBase，再空 = "pcap"）。
	Name string
	// UA 由调用方补（HTTP 头在 TLS 隧道内，pcap 明文看不到）。给了它，记录带
	// http2.regular_headers 的 user-agent，可直接喂 tests/e2e/cmd/gen-profiles。
	UA string
	// Stream 取第几条可导出的流（1-based；All=true 时忽略）。
	Stream int
	// All 导出全部可导出的流。
	All bool
	// TCPOnly 不要求 ClientHello，只导 TCP 形态（SYN/TTL/窗口/选项序）。
	TCPOnly bool
}

// ImportPcap 读取 pcap/pcapng 文件并提取 E1p 指纹记录。Records 为空时
// Skipped 说明每条流被拒的原因（resumption / 缺 SYN / 抓包缺口 / 无 CH）。
// 记录的 name/source 默认取文件名（与 CLI 同口径）；Record.ClientHelloHex
// 可直接喂 NewSessionFromClientHelloHex。
func ImportPcap(path string, opts *PcapOptions) (*pcapimport.Result, error) {
	if path == "" {
		return nil, fmt.Errorf("pcap path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ImportPcapBytes(data, opts, filepath.Base(path))
}

// ImportPcapBytes 是 ImportPcap 的字节版（抓包不落盘的场景，如从网络/内存来）。
// sourceBase 为 source 字段用的文件基名（空 = "pcap"）。
func ImportPcapBytes(data []byte, opts *PcapOptions, sourceBase string) (*pcapimport.Result, error) {
	o := pcapimport.Options{SourceBase: sourceBase}
	if opts != nil {
		o.Name = opts.Name
		o.UA = opts.UA
		o.Stream = opts.Stream
		o.All = opts.All
		o.TCPOnly = opts.TCPOnly
	}
	return pcapimport.Import(data, o)
}

// NewSessionFromClientHelloHex 以 ClientHello record 原始字节的 hex 建会话
// （无损路径：扩展按线上顺序保留、未知扩展透传；随机项经 NormalizeForReplay
// 按浏览器语义重生成——不会把"那一次"冻进会话）。TLS 面复现；TCP 面要用
// profile/预设路径（tcp 节）。
func NewSessionFromClientHelloHex(hex string, opts *Options) (*Session, []profiles.Warning, error) {
	p, warns, err := profiles.FromClientHelloHex(hex)
	if err != nil {
		return nil, warns, err
	}
	s, err := NewSessionFromProfile(p, opts)
	return s, warns, err
}

// NewSessionFromJA3 以 JA3 串建会话（语义同 CLI --ja3）。
func NewSessionFromJA3(ja3 string, opts *Options) (*Session, []profiles.Warning, error) {
	p, warns, err := profiles.FromJA3(ja3)
	if err != nil {
		return nil, warns, err
	}
	s, err := NewSessionFromProfile(p, opts)
	return s, warns, err
}

// NewSessionFromJA4R 以 JA4R 串建会话（语义同 CLI --ja4r）。
func NewSessionFromJA4R(ja4r string, opts *Options) (*Session, []profiles.Warning, error) {
	p, warns, err := profiles.FromJA4R(ja4r)
	if err != nil {
		return nil, warns, err
	}
	s, err := NewSessionFromProfile(p, opts)
	return s, warns, err
}
