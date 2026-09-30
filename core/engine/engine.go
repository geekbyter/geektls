// Package engine 是 geektls 的会话引擎（P3）：cookie jar、重定向、超时、
// 代理（HTTP CONNECT / SOCKS5）、协议分发（h2/h1）、响应流式。
//
// 连接模型（二期阶段 5 起）：默认 per-origin 连接池——H2 同 origin 单连接
// 多路复用，H1 keep-alive 空闲连接复用；profile.behavior.connection_pool=false
// 回到"每请求一条新连接"的旧默认（CONTRACT-FREEZE #5 的解除开关）。
// 响应头到达即返回，body 以 io.ReadCloser 流式暴露。
//
// 并发：同一 Session 可被多 goroutine 并发 Do（池/缓存均加锁）；
// Close 与并发中的 Do 安全（进行中的请求用完各自连接，池即时排空）。
package engine

import (
	"fmt"
	"io"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"sync/atomic"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/publicsuffix"

	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/http3"
	utlsb "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"

	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

// SessionOptions 是会话级配置。
type SessionOptions struct {
	// Proxy 支持 http / https（CONNECT 隧道）、socks5、socks5h、socks4、socks4a。
	// socks5 本地解析、socks5h 交代理解析；socks4 只承载 IPv4（详见 proxy.go）。
	Proxy     string `json:"proxy,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"` // 整体硬超时（dial+TLS+响应头），默认 30000
	// ProxyFromEnv 控制"未显式给 proxy 时是否读 HTTPS_PROXY / ALL_PROXY（并查
	// NO_PROXY）"。nil/true = 读（requests 的 trust_env、curl 的默认行为）；
	// false = 只在显式给 proxy 时经代理。指纹调试要可复计时可关掉。
	ProxyFromEnv       *bool `json:"proxy_from_env,omitempty"`
	RedirectMax        int   `json:"redirect_max,omitempty"`         // 默认 10；<0 = 不跟随（Go RoundTripper 用）
	CookieJar          *bool `json:"cookie_jar,omitempty"`           // 默认 true
	InsecureSkipVerify bool  `json:"insecure_skip_verify,omitempty"` // 跳过证书校验（测试/自签场景）
	AutoDecompress     *bool `json:"auto_decompress,omitempty"`      // 响应透明解压，默认 true
	// ReadTimeoutMs 是**每次读取响应 body** 的空闲超时（0 = 不设限）。
	// TimeoutMs 只管到"dial+TLS+响应头"，body 慢速/挂死要靠它兜（A6）。
	ReadTimeoutMs int `json:"read_timeout_ms,omitempty"`

	// CaBundle：自持信任库（requests 的 verify=<path>）。PEM 文本、证书文件路径
	// 或证书目录皆可；**替换**系统根证书池（与 requests 一致，不叠加）。
	// 空 = 用系统信任库。与 InsecureSkipVerify 同时给出时后者优先（跳过校验）。
	CaBundle string `json:"ca_bundle,omitempty"`
	// ClientCert / ClientKey：mTLS 客户端证书（requests 的 cert=(crt,key) 或
	// cert=<同文件>）。私钥可随 ClientCert 一起给（同文件形态），此时
	// ClientKey 留空。带口令的加密私钥不支持。
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`

	// --- 目标地址控制（A9，详见 target.go 的生效范围表）---
	// Resolve 把域名钉到固定 IP（curl 的 --resolve）：键是 "host" 或 "host:port"，
	// 值必须是 IP 字面量。只改"连到哪"——SNI / Host / 伪头 / ClientHello 全部
	// 沿用 URL 里的原域名，因此指纹字节不受影响。
	Resolve map[string]string `json:"resolve,omitempty"`
	// LocalAddress 绑定出网源地址（curl 的 --interface、httpx 的 local_address）。
	// 只接受 IP 字面量（网卡名不支持），并隐含协议族。
	LocalAddress string `json:"local_address,omitempty"`
	// IPVersion 是 "4" / "6"（curl 的 --ipv4 / --ipv6）；空 = 不限。
	// 与 local_address、resolve 的取值冲突时建会话即报错。
	IPVersion string `json:"ip_version,omitempty"`

	// --- 协议选择（G8，详见 protocols.go）---
	// Protocols 是**允许的 HTTP 协议集合**（顺序无关）："h1.1" / "h2" / "h3"。
	// 默认（省略）= ["h1.1","h2"]：只走 TCP，**不参与 H3**——与 curl / curl_cffi
	// 一致（哪怕预设声明了 http3 节，也要用户显式点头才走 QUIC）。
	// 不含 "h2" ⇒ ALPN 收窄到 http/1.1；只有 "h3" ⇒ 会话级强制 H3（失败不回落）。
	Protocols []string `json:"protocols,omitempty"`
	// H3 是 Protocols 的便捷写法：true = 在默认集合上追加 "h3"。
	// 与 Protocols 同时给出时**报错**（不静默取其一）。
	H3 *bool `json:"h3,omitempty"`

	// --- 头序与身份自洽（G9，详见 headerorder.go / identitysync.go）---
	// HeaderOrder：请求头顺序策略，preserve（默认，按 profile 声明序）/ input（按
	// 调用方传入序）/ random（打乱，Host 仍最前）。默认 preserve = 与改动前逐字节相同。
	HeaderOrder string `json:"header_order,omitempty"`
	// IdentitySync：调用方自带 user-agent 与预设身份不一致时，是否把客户端提示
	//（sec-ch-ua / sec-ch-ua-platform / sec-ch-ua-mobile）校正到该 UA（默认 auto）。
	// 注意：**TLS/JA3/JA4/H2 不会因此改变**——那需要换同平台变体预设，本库如实告警。
	IdentitySync string `json:"identity_sync,omitempty"`
}

// Request 是一次请求（FFI 的 request_json 映射到它）。
type Request struct {
	Method        string      `json:"method"`
	URL           string      `json:"url"`
	Headers       [][2]string `json:"headers,omitempty"`
	Body          []byte      `json:"-"` // FFI 层从 body_b64 解码
	BodyB64       string      `json:"body_b64,omitempty"`
	TimeoutMs     int         `json:"timeout_ms,omitempty"`      // 覆盖会话默认
	Proxy         string      `json:"proxy,omitempty"`           // 覆盖会话默认
	ReadTimeoutMs int         `json:"read_timeout_ms,omitempty"` // 覆盖会话的 body 读取空闲超时
	Stream        bool        `json:"stream,omitempty"`          // 预留；P3 响应恒流式
	ForceHTTP3    bool        `json:"force_http3,omitempty"`     // P4 生效
	// RedirectMax 覆盖会话级重定向上限（nil = 跟随会话；<0 = 不跟随）。
	// requests 的 allow_redirects=False / max_redirects=N 映射到它。
	RedirectMax *int `json:"redirect_max,omitempty"`
	// AutoDecompress 覆盖会话级开关（nil = 跟随会话；会话默认 true）。
	AutoDecompress *bool `json:"auto_decompress,omitempty"`
}

// SelfCheck 是"实际发出 vs 期望"的自校验结果（02 文档 §1）。
// 连接池下语义不变：报告的是本请求所用连接握手时的指纹（复用连接不发新
// ClientHello，报告建立该连接时的记录）。
type SelfCheck struct {
	JA3      string `json:"ja3"`
	JA3Hash  string `json:"ja3_hash"`
	JA4      string `json:"ja4"`
	JA3Match *bool  `json:"ja3_match,omitempty"` // 仅当 profile 来自 JA3 入口时有期望值
	JA4Match *bool  `json:"ja4_match,omitempty"` // 仅当来自 JA4R 入口时

	// --- 深化字段（二期 T3；纯记录，不新增线上行为） ---
	JA3FullString string               `json:"ja3_fullstring"`  // 与 ja3 同值（显式名）
	SNISent       bool                 `json:"sni_sent"`        // SNI 实际上链与否（IP 字面量目标线上省略）
	Extensions    []uint16             `json:"extensions"`      // 线上扩展序（剔 GREASE）
	WireExts      []uint16             `json:"wire_extensions"` // 线上扩展序（含 GREASE 实际值）
	Grease        []tlscore.GreaseMark `json:"grease,omitempty"`
	Negotiated    *NegotiatedInfo      `json:"negotiated,omitempty"` // 握手协商结果
}

// NegotiatedInfo 是握手协商出的 cipher/版本/ALPN（uConn ConnectionState）。
type NegotiatedInfo struct {
	Cipher  string `json:"cipher"`  // "0x1301"
	Version string `json:"version"` // "0x0304"
	ALPN    string `json:"alpn"`
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

	// 解压语义（T-DECOMP）：ContentEncoding 是线上 Content-Encoding 原值
	//（headers 不篡改）；Decoded=true 表示 Body 是解压后字节；Warnings 记
	// 未知编码透传等告警。
	ContentEncoding string   `json:"content_encoding"`
	Decoded         bool     `json:"decoded"`
	Warnings        []string `json:"warnings,omitempty"`

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
// TLS 会话票据缓存（P7-T2 复用/PSK）+ per-origin 连接池（阶段 5）。
// jar/sessionCache 创建后不再替换（cookiejar 与 uTLS LRU cache 均自带锁），
// 因此 Do 并发安全；Close 只翻 closed 标志并排池，不置空字段（避免与
// 进行中的请求竞争）。
type Session struct {
	profile      *profiles.Profile
	opts         SessionOptions
	protos       protocolSet    // 归一化后的协议允许集合（G8；建会话时算好）
	protoCustom  bool           // 用户是否显式指定过 protocols/h3（决定 ALPN 收窄是否"补位"）
	hdrOrder     string         // 头序策略（G9；preserve / input / random）
	idSync       string         // 身份自洽策略（G9；auto / off）
	certs        *certMaterial  // 自持信任库 / mTLS 客户端证书（nil = 系统默认）
	netctl       *netControl    // 地址钉位 / 源绑定 / 族偏好（A9；nil = 全默认）
	jar          *cookiejar.Jar // nil = 禁用 cookie
	altSvcH3     sync.Map       // host:port → 已知广告 H3
	sessionCache utls.ClientSessionCache
	// h3SessionCache 是 QUIC/H3 侧的票据缓存（bogdanfinn/utls 类型；与 TCP 侧
	// sessionCache 同一开关）。0-RTT 链路见 third_party/utls-bogdanfinn patch。
	h3SessionCache utlsb.ClientSessionCache
	pool           *connPool
	h3tr           *http3.Transport // 池开启时的共享 H3 transport（懒建；quic-go 内部按 host 复用 QUIC 连接）
	h3mu           sync.Mutex
	closed         atomic.Bool
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
	// 代理配置错误在建会话时即失败（与证书材料同口径），不要等到第一次拨号。
	if opts.Proxy != "" {
		if _, _, err := parseProxySpec(opts.Proxy); err != nil {
			return nil, err
		}
	}
	// 地址控制三项同样在建会话时校验+归一化（A9）：非法取值到这里就挡住，
	// 不等第一次拨号才报"连不上"——那看起来像目标挂了，其实是配置写错。
	netctl, err := normalizeNetControl(&opts)
	if err != nil {
		return nil, err
	}
	opts.IPVersion = netctl.family
	// 协议允许集合（G8）：建会话时归一化 + 校验，非法值/非法组合在这里就报错。
	protos, err := resolveProtocols(opts, p)
	if err != nil {
		return nil, err
	}
	hdrOrder, err := normalizeHeaderOrder(opts.HeaderOrder)
	if err != nil {
		return nil, err
	}
	idSync, err := normalizeIdentitySync(opts.IdentitySync)
	if err != nil {
		return nil, err
	}
	s := &Session{
		profile: p, opts: opts, netctl: netctl,
		protos:      protos,
		protoCustom: len(opts.Protocols) > 0 || opts.H3 != nil,
		hdrOrder:    hdrOrder,
		idSync:      idSync,
	}
	certs, err := loadCertMaterial(opts)
	if err != nil {
		return nil, err
	}
	s.certs = certs
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
		s.h3SessionCache = utlsb.NewLRUClientSessionCache(64) // QUIC 侧同一开关（T1）
	}
	s.pool = newConnPool()
	return s, nil
}

// poolOn 报告连接池是否启用（默认开；behavior.connection_pool=false 关闭）。
func (s *Session) poolOn() bool {
	b := s.profile.Behavior
	return b == nil || b.ConnectionPool == nil || *b.ConnectionPool
}

// Profile 返回会话的 profile（供 selfcheck 等读取）。
func (s *Session) Profile() *profiles.Profile { return s.profile }

// Close 释放会话持有的缓存（TLS 票据 / cookie / Alt-Svc 记忆）。
// 与 Python/Node 绑定的 s.close() 对称；调用后 Do 返回错误。
func (s *Session) Close() {
	if s.closed.CompareAndSwap(false, true) {
		s.pool.drain()
		s.h3mu.Lock()
		if s.h3tr != nil {
			s.h3tr.Close()
			s.h3tr = nil
		}
		s.h3mu.Unlock()
	}
}

// Do 执行请求（含重定向链），阻塞到最终响应头到达。
func (s *Session) Do(req *Request) (*Response, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("engine: session closed")
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	if _, err := url.Parse(req.URL); err != nil {
		return nil, fmt.Errorf("engine: bad url: %w", err)
	}

	// 重定向上限：请求级覆盖会话级（allow_redirects=False / max_redirects=N）。
	redirectMax := s.opts.RedirectMax
	if req.RedirectMax != nil {
		redirectMax = *req.RedirectMax
	}

	current := *req
	for redirects := 0; ; redirects++ {
		resp, err := s.doSingle(&current)
		if err != nil {
			return nil, err
		}
		location, isRedirect := redirectTarget(resp)
		if !isRedirect || redirectMax < 0 {
			return resp, nil
		}
		if redirects >= redirectMax {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("engine: too many redirects (max %d)", redirectMax)
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
