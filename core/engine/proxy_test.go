package engine

// A8 代理形态测试：SOCKS4/4A 的报文形状、SOCKS5 的"本地解析 vs 代理解析"、
// NO_PROXY 与环境变量优先级、H3 + 代理的拒绝路径。
//
// 假服务端在 proxytest_test.go。

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/geektls/core/profiles"
)

func proxySession(t *testing.T, opts SessionOptions) *Session {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	opts.InsecureSkipVerify = true
	s, err := NewSession(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// localEcho 返回 (127.0.0.1 形态 URL, localhost 形态 URL)。
func localEcho(t *testing.T) (string, string) {
	t.Helper()
	echo := startEchoServer(t)
	return echo.URL, strings.Replace(echo.URL, "127.0.0.1", "localhost", 1)
}

func getAndCheck(t *testing.T, s *Session, url string) {
	t.Helper()
	resp, err := s.Do(&Request{Method: "GET", URL: url + "/echo"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body := readBody(t, resp)
	if resp.Status != 200 || !strings.Contains(body, `"path":"/echo"`) {
		t.Fatalf("status=%d body=%s", resp.Status, body)
	}
	// h2 说明隧道里真的完成了一次带 ALPN 的 TLS 握手（不是"连上了但降级"）。
	if resp.UsedProtocol != "h2" {
		t.Errorf("UsedProtocol = %q, want h2", resp.UsedProtocol)
	}
}

func TestParseProxySpec(t *testing.T) {
	cases := []struct {
		spec     string
		wantAddr string
		wantErr  bool
	}{
		{"http://p.example:3128", "p.example:3128", false},
		{"http://p.example", "p.example:8080", false},
		{"https://p.example", "p.example:8080", false},
		{"socks5://p.example", "p.example:1080", false},
		{"socks5h://p.example:1", "p.example:1", false},
		{"socks4://p.example", "p.example:1080", false},
		{"socks4a://user@p.example:1080", "p.example:1080", false},
		{"socks5://user:pw@p.example:1080", "p.example:1080", false},
		// SOCKS4 线上没有口令位：给了就必须拒绝，不能静默丢掉当成匿名请求
		{"socks4://user:pw@p.example:1080", "", true},
		{"socks4a://user:pw@p.example:1080", "", true},
		{"ftp://p.example:21", "", true}, // 未实现的 scheme 必须报错，不能静默直连
		{"p.example:1080", "", true},     // 缺 scheme
		{"socks5://", "", true},          // 缺主机名
	}
	for _, tc := range cases {
		_, addr, err := parseProxySpec(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseProxySpec(%q) 应报错，实际 addr=%q", tc.spec, addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseProxySpec(%q): %v", tc.spec, err)
			continue
		}
		if addr != tc.wantAddr {
			t.Errorf("parseProxySpec(%q) addr = %q, want %q", tc.spec, addr, tc.wantAddr)
		}
	}
}

func TestNewSessionRejectsBadProxy(t *testing.T) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSession(p, SessionOptions{Proxy: "socks6://x:1"}); err == nil {
		t.Fatal("会话创建时应拒绝未知代理 scheme（等到拨号才发现就晚了）")
	}
}

func TestNoProxyBypass(t *testing.T) {
	cases := []struct {
		list, host, port string
		want             bool
	}{
		{"", "example.com", "443", false},
		{"example.com", "example.com", "443", true},
		{".example.com", "example.com", "443", true},    // 前导点形态
		{"example.com", "sub.example.com", "443", true}, // 子域
		{"example.com", "notexample.com", "443", false}, // 不是后缀巧合
		{"example.com", "example.com.evil.net", "443", false},
		{"*", "anything", "443", true},
		{"intranet.local:8443", "intranet.local", "8443", true},
		{"intranet.local:8443", "intranet.local", "443", false}, // 带端口条目要求端口也匹配
		{"127.0.0.1", "127.0.0.1", "443", true},
		{"0.0.1", "127.0.0.1", "443", false}, // IP 目标不走后缀规则
		{"10.0.0.0/8", "10.1.2.3", "443", true},
		{"10.0.0.0/8", "11.1.2.3", "443", false},
		{"10.0.0.0/8", "some.example", "443", false}, // 域名目标无从判定 CIDR
		{"a.example , b.example;c.example", "c.example", "443", true},
		{"[::1]", "::1", "443", true},
		{"LOCAL", "local", "443", true}, // 大小写无关
	}
	for _, tc := range cases {
		if got := noProxyBypass(tc.list, tc.host, tc.port); got != tc.want {
			t.Errorf("noProxyBypass(%q, %q, %q) = %v, want %v", tc.list, tc.host, tc.port, got, tc.want)
		}
	}
}

func TestProxySpecPrecedence(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	s := proxySession(t, SessionOptions{})

	// 都没给 ⇒ 直连
	got, err := s.proxySpecFor(&Request{}, "https", "a.example", "443")
	if err != nil || got != "" {
		t.Fatalf("无 proxy 无 env: got %q err %v", got, err)
	}

	// ALL_PROXY 生效（HTTPS_PROXY 优先于它）
	t.Setenv("ALL_PROXY", "socks5h://env-all:1080")
	if got, _ := s.proxySpecFor(&Request{}, "https", "a.example", "443"); got != "socks5h://env-all:1080" {
		t.Errorf("ALL_PROXY 未生效: %q", got)
	}
	t.Setenv("HTTPS_PROXY", "socks5://env-https:1080")
	if got, _ := s.proxySpecFor(&Request{}, "https", "a.example", "443"); got != "socks5://env-https:1080" {
		t.Errorf("HTTPS_PROXY 应压过 ALL_PROXY: %q", got)
	}

	// NO_PROXY 只作用于环境变量派生的代理
	t.Setenv("NO_PROXY", "b.example")
	if got, _ := s.proxySpecFor(&Request{}, "https", "b.example", "443"); got != "" {
		t.Errorf("NO_PROXY 命中时应直连: %q", got)
	}
	if got, _ := s.proxySpecFor(&Request{}, "https", "a.example", "443"); got == "" {
		t.Error("NO_PROXY 不该波及未列出的主机")
	}

	// 回环目标不吃 env 派生的代理（Chrome / Go ProxyFromEnvironment 同规则），
	// 否则开发机挂上 ALL_PROXY 后连本地测试服务都会被塞进代理
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if got, err := s.proxySpecFor(&Request{}, "https", h, "8443"); err != nil || got != "" {
			t.Errorf("回环目标 %s 应由 env 直连: got %q err %v", h, got, err)
		}
	}

	// 池键必须与实拨代理同源：env 命中时键里带上代理，NO_PROXY 命中时不带
	if k, err := s.poolKey(&Request{}, "https", net.JoinHostPort("a.example", "443")); err != nil || !strings.HasSuffix(k, "|proxy=socks5://env-https:1080") {
		t.Errorf("poolKey = %q, err %v", k, err)
	}
	if k, err := s.poolKey(&Request{}, "https", net.JoinHostPort("b.example", "443")); err != nil || !strings.HasSuffix(k, "|proxy=") {
		t.Errorf("NO_PROXY 主机的池键不该带代理: %q err %v", k, err)
	}

	sessExplicit := proxySession(t, SessionOptions{Proxy: "http://explicit:8080"})
	t.Setenv("NO_PROXY", "a.example")
	if got, err := sessExplicit.proxySpecFor(&Request{}, "https", "a.example", "443"); err != nil || got != "http://explicit:8080" {
		t.Errorf("显式 proxy 不受 NO_PROXY 影响（curl 语义）: got %q err %v", got, err)
	}
	// 显式 proxy 同样不受回环豁免影响（测试里代理与被连目标常同为 127.0.0.1）
	if got, err := sessExplicit.proxySpecFor(&Request{}, "https", "127.0.0.1", "8443"); err != nil || got != "http://explicit:8080" {
		t.Errorf("显式 proxy 对回环目标仍应生效: got %q err %v", got, err)
	}

	// 请求级压过会话级
	if got, _ := sessExplicit.proxySpecFor(&Request{Proxy: "socks4a://req:1080"}, "https", "a.example", "443"); got != "socks4a://req:1080" {
		t.Errorf("请求级 proxy 应覆盖会话级: %q", got)
	}

	// ProxyFromEnv=false ⇒ 完全不看环境
	off := false
	strict := proxySession(t, SessionOptions{ProxyFromEnv: &off})
	if got, _ := strict.proxySpecFor(&Request{}, "https", "a.example", "443"); got != "" {
		t.Errorf("proxy_from_env=false 应直连: %q", got)
	}

	// 非法代理 URL 要在这里报错，而不是拿去拨号
	if _, err := s.proxySpecFor(&Request{Proxy: "socks9://x"}, "https", "a.example", "443"); err == nil {
		t.Error("未知 scheme 应报错")
	}
}

// SOCKS4：目标是 IP 字面量 ⇒ 报文里直接给 4 字节 IP；目标是域名 ⇒ 本地解析后给 IP。
func TestSocks4EndToEnd(t *testing.T) {
	ipURL, hostURL := localEcho(t)
	px := startSOCKSProxy(t)

	s := proxySession(t, SessionOptions{Proxy: "socks4://" + px.addr})
	getAndCheck(t, s, ipURL)
	h := px.lastHello(t)
	if h.vn != 4 || h.cd != 1 {
		t.Fatalf("握手头 = %+v", h)
	}
	if h.ip != "127.0.0.1" || h.host != "" {
		t.Errorf("socks4 目标是 IP 字面量时应直发 IP: %+v", h)
	}

	s2 := proxySession(t, SessionOptions{Proxy: "socks4://tester@" + px.addr})
	getAndCheck(t, s2, hostURL)
	h = px.lastHello(t)
	if h.host != "" {
		t.Errorf("socks4 没有 HOST 字段，域名必须本地解析: %+v", h)
	}
	if h.ip != "127.0.0.1" {
		t.Errorf("localhost 应本地解析成 127.0.0.1 后发给 socks4 代理: %+v", h)
	}
	if h.userid != "tester" {
		t.Errorf("USERID = %q, want tester", h.userid)
	}
}

// SOCKS4A：域名交给代理解析（DSTIP=0.0.0.1 + HOST 段）。
func TestSocks4ARemoteResolve(t *testing.T) {
	_, hostURL := localEcho(t)
	px := startSOCKSProxy(t)

	s := proxySession(t, SessionOptions{Proxy: "socks4a://" + px.addr})
	getAndCheck(t, s, hostURL)
	h := px.lastHello(t)
	if h.ip != "0.0.0.1" || h.host != "localhost" {
		t.Errorf("socks4a 应把域名交给代理: %+v", h)
	}
}

// SOCKS5 两档的差别就在 DNS 落点：socks5 本地解析（代理只见 IP），
// socks5h 交给代理（代理见域名）。此前两档同义，这一档是回归门。
func TestSocks5LocalVsRemoteDNS(t *testing.T) {
	_, hostURL := localEcho(t)

	px := startSOCKSProxy(t)
	defer px.logNotes(t)
	s := proxySession(t, SessionOptions{Proxy: "socks5://" + px.addr})
	getAndCheck(t, s, hostURL)
	h := px.lastHello(t)
	if h.vn != 5 || h.atyp != 1 {
		t.Fatalf("socks5 应发 IPv4 ATYP: %+v", h)
	}
	if h.ip != "127.0.0.1" || h.host != "" {
		t.Errorf("socks5 = 本地解析: %+v", h)
	}

	px2 := startSOCKSProxy(t)
	defer px2.logNotes(t)
	s2 := proxySession(t, SessionOptions{Proxy: "socks5h://" + px2.addr})
	getAndCheck(t, s2, hostURL)
	h2 := px2.lastHello(t)
	if h2.atyp != 3 || h2.host != "localhost" {
		t.Errorf("socks5h = 域名交给代理: %+v", h2)
	}
}

// HTTP CONNECT 是既有主路径，此前无覆盖：断言目标形态与 Proxy-Authorization。
func TestHTTPConnectEndToEnd(t *testing.T) {
	ipURL, _ := localEcho(t)
	px := startConnectProxy(t)

	s := proxySession(t, SessionOptions{Proxy: "http://usr:pwd@" + px.addr})
	getAndCheck(t, s, ipURL)

	hosts, auths := px.recorded()
	if len(hosts) != 1 || hosts[0] != strings.TrimPrefix(ipURL, "https://") {
		t.Errorf("CONNECT 目标 = %v", hosts)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("usr:pwd"))
	if len(auths) != 1 || auths[0] != want {
		t.Errorf("Proxy-Authorization = %v, want %q", auths, want)
	}
}

// 有代理时 H3 不参与：QUIC 过代理要 CONNECT-UDP（RFC 9298），没实现时
// 最坏的情况是"以为在代理里、其实 UDP 直发"。
func TestH3RefusedWithProxy(t *testing.T) {
	echo := startEchoServer(t)
	px := startSOCKSProxy(t)

	s := proxySession(t, SessionOptions{Proxy: "socks5h://" + px.addr})
	_, err := s.Do(&Request{Method: "GET", URL: echo.URL + "/echo", ForceHTTP3: true})
	if err == nil || !strings.Contains(err.Error(), "force_http3") {
		t.Fatalf("force_http3 + proxy 应明确报错，实际: %v", err)
	}
	if strings.Contains(err.Error(), "h3 request") {
		t.Fatalf("不该真的尝试 H3: %v", err)
	}
	// 直连路径仍可用（去掉 proxy）
	s2 := proxySession(t, SessionOptions{})
	if _, err := s2.Do(&Request{Method: "GET", URL: echo.URL + "/echo", ForceHTTP3: true}); err == nil {
		t.Fatal("回环服务没有 H3，force_http3 应失败")
	} else if strings.Contains(err.Error(), "force_http3 与代理不兼容") {
		t.Fatalf("无代理时不该报代理不兼容: %v", err)
	}
}
