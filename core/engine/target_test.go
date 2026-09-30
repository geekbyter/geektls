package engine

// A9 地址控制测试：resolve 钉位 / local_address 源绑定 / ip_version 族偏好的
// 校验、生效边界（哪几档代理吃 resolve），以及一条不能破的不变量——
// 钉位只改"连到哪"，SNI 与 Host 仍是 URL 里的原域名。

import (
	"net"
	"strings"
	"testing"

	"github.com/geekbyter/geektls/core/profiles"
)

func TestNormalizeNetControl(t *testing.T) {
	cases := []struct {
		name    string
		opts    SessionOptions
		family  string
		local   string
		pins    map[string]string
		wantErr string
	}{
		{name: "全空"},
		{name: "ip_version 数字", opts: SessionOptions{IPVersion: "6"}, family: "6"},
		{name: "ip_version v4 别名", opts: SessionOptions{IPVersion: "v4"}, family: "4"},
		{name: "ip_version ipv4 大小写", opts: SessionOptions{IPVersion: " IPv4 "}, family: "4"},
		{name: "ip_version v6 别名", opts: SessionOptions{IPVersion: "V6"}, family: "6"},
		{name: "ip_version any 视为不限", opts: SessionOptions{IPVersion: "any"}, family: ""},
		{name: "ip_version 未知", opts: SessionOptions{IPVersion: "5"}, wantErr: "ip_version"},
		{
			name:   "local_address 去括号",
			opts:   SessionOptions{LocalAddress: "[::1]"},
			family: "", local: "::1",
		},
		{name: "local_address 是网卡名", opts: SessionOptions{LocalAddress: "eth0"}, wantErr: "local_address"},
		{name: "local_address 是域名", opts: SessionOptions{LocalAddress: "a.example"}, wantErr: "local_address"},
		{
			name:    "绑定与族偏好冲突",
			opts:    SessionOptions{LocalAddress: "10.0.0.1", IPVersion: "6"},
			wantErr: "冲突",
		},
		{name: "resolve 值是域名", opts: SessionOptions{Resolve: map[string]string{"a.example": "b.example"}}, wantErr: "不是 IP 字面量"},
		{name: "resolve 与族偏好冲突", opts: SessionOptions{Resolve: map[string]string{"a.example": "::1"}, IPVersion: "4"}, wantErr: "冲突"},
		{
			name: "host 与 host:port 两种键",
			opts: SessionOptions{Resolve: map[string]string{"A.Example": "192.0.2.1", "b.example:8443": "192.0.2.2"}},
			pins: map[string]string{"a.example:443": "192.0.2.1", "a.example": "192.0.2.1", "b.example:8443": "192.0.2.2"},
		},
		{name: "归一后重复的键", opts: SessionOptions{Resolve: map[string]string{"a.example": "192.0.2.1", "A.Example.": "192.0.2.2"}}, wantErr: "重复"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			nc, err := normalizeNetControl(&o)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want 含 %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeNetControl: %v", err)
			}
			if nc.family != tc.family {
				t.Errorf("family = %q, want %q", nc.family, tc.family)
			}
			if got := nc.localIP.String(); got != tc.local {
				if !(tc.local == "" && nc.localIP == nil) {
					t.Errorf("localIP = %q, want %q", got, tc.local)
				}
			}
			for k, want := range tc.pins {
				host, port := k, ""
				if h, p, err := net.SplitHostPort(k); err == nil {
					host, port = h, p
				}
				if got := nc.pinned(host, port); got != want {
					t.Errorf("pinned(%s,%s) = %q, want %q", host, port, got, want)
				}
			}
		})
	}
}

// host:port 键优先于 host 键（curl --resolve 同规则：同一 host 可以按端口分流）。
func TestPinnedPrecedence(t *testing.T) {
	nc, err := normalizeNetControl(&SessionOptions{
		Resolve: map[string]string{"a.example": "192.0.2.1", "a.example:8443": "192.0.2.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := nc.pinned("a.example", "8443"); got != "192.0.2.2" {
		t.Errorf("host:port 键应赢: %q", got)
	}
	if got := nc.pinned("a.example", "443"); got != "192.0.2.1" {
		t.Errorf("未列出的端口应回落 host 键: %q", got)
	}
	if got := nc.pinned("c.example", "443"); got != "" {
		t.Errorf("没钉的主机不该命中: %q", got)
	}
	// 钉 a.example 不连带钉子域（刻意不做通配，见 target.go）
	if got := nc.pinned("cdn.a.example", "443"); got != "" {
		t.Errorf("resolve 不该做后缀匹配: %q", got)
	}
	var nilNC *netControl
	if nilNC.pinned("a.example", "443") != "" {
		t.Error("nil netControl 应返回未钉")
	}
}

func TestNetworkNarrowing(t *testing.T) {
	cases := []struct {
		name    string
		opts    SessionOptions
		host    string
		want    string
		wantErr string
	}{
		{"默认不限", SessionOptions{}, "a.example", "tcp", ""},
		{"v4 偏好", SessionOptions{IPVersion: "4"}, "a.example", "tcp4", ""},
		{"v6 偏好", SessionOptions{IPVersion: "6"}, "a.example", "tcp6", ""},
		{"v6 字面量", SessionOptions{}, "::1", "tcp6", ""},
		{"v4 字面量", SessionOptions{}, "127.0.0.1", "tcp4", ""},
		{"字面量与偏好冲突", SessionOptions{IPVersion: "6"}, "127.0.0.1", "", "不是同族"},
		{"v6 绑定隐含族", SessionOptions{LocalAddress: "::1"}, "a.example", "tcp6", ""},
		{"v6 绑定打 v4 目标", SessionOptions{LocalAddress: "::1"}, "127.0.0.1", "", "IPv6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := proxySession(t, tc.opts)
			got, err := s.network(tc.host)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want 含 %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("network(%s): %v", tc.host, err)
			}
			if got != tc.want {
				t.Errorf("network(%s) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

// 名字交给代理解析的档位不吃 resolve / ip_version（否则等于偷偷把远端 DNS
// 换成 local DNS，那正是这几档要区分的东西）。
func TestUsesRemoteDNS(t *testing.T) {
	for spec, want := range map[string]bool{
		"":                 false,
		"socks5://p:1080":  false,
		"socks4://p:1080":  false,
		"http://p:3128":    true,
		"https://p:3128":   true,
		"socks5h://p:1080": true,
		"socks4a://p:1080": true,
		"ftp://p:21":       false, // 非法 scheme 由拨号去报错
	} {
		if got := usesRemoteDNS(spec); got != want {
			t.Errorf("usesRemoteDNS(%q) = %v, want %v", spec, got, want)
		}
	}
}

// echoPort 取回环服务的端口。
func echoPort(t *testing.T, echoURL string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(echoURL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// 钉位命中时连的是 IP，但 SNI / Host / 指纹字节都还是原域名。
// 域名本身不可解析 ⇒ 请求能成功就只能是因为钉位生效。
func TestResolvePinsDialButKeepsSNIAndHost(t *testing.T) {
	echo := startEchoServer(t)
	port := echoPort(t, echo.URL)
	const name = "pinned.example"
	url := "https://" + name + ":" + port + "/echo"
	localhostEcho := strings.Replace(echo.URL, "127.0.0.1", "localhost", 1) + "/echo"

	for _, key := range []string{name + ":" + port, name} {
		s := proxySession(t, SessionOptions{Resolve: map[string]string{key: "127.0.0.1"}})
		resp, err := s.Do(&Request{Method: "GET", URL: url})
		if err != nil {
			t.Fatalf("resolve[%s] 钉位后应能连上回环服务: %v", key, err)
		}
		body := readBody(t, resp)
		if resp.Status != 200 || !strings.Contains(body, `"host":"`+name+`:`+port+`"`) {
			t.Fatalf("Host 应保持原域名: status=%d body=%s", resp.Status, body)
		}
		if resp.UsedProtocol != "h2" {
			t.Errorf("UsedProtocol = %q, want h2", resp.UsedProtocol)
		}
		// SNI 不能因为"实际连的是 IP"而被剔除——剔除会改变 JA4 的 d/i 标志。
		if !resp.SelfCheck.SNISent {
			t.Errorf("resolve[%s]: 钉位不该让 SNI 掉线（目标 IP 只用于连接，不用于指纹）", key)
		}

		// 同一 profile 的普通域名请求指纹必须一致：钉位不改变线上字节。
		// 参照必须是"域名形态"的目标（IP 字面量目标线上省略 SNI，JA4 的
		// d/i 标志本就不同，那不是钉位造成的差异）。
		base := proxySession(t, SessionOptions{})
		ref, err := base.Do(&Request{Method: "GET", URL: localhostEcho})
		if err != nil {
			t.Fatal(err)
		}
		readBody(t, ref)
		if resp.SelfCheck.JA4 != ref.SelfCheck.JA4 {
			t.Errorf("JA4 因钉位而变: %q vs %q", resp.SelfCheck.JA4, ref.SelfCheck.JA4)
		}
	}
}

// socks5 / socks4（本地解析档）：代理侧看到的是钉位 IP，不是域名。
// socks5h / socks4a / CONNECT（远端解析档）：域名原样交给代理，钉位不外泄。
func TestResolveAcrossProxyModes(t *testing.T) {
	echo := startEchoServer(t)
	port := echoPort(t, echo.URL)
	const name = "pinned.example"
	base := "https://" + name + ":" + port
	url := base + "/echo"
	resolve := map[string]string{name: "127.0.0.1"}

	localDNS := []struct{ scheme, at string }{
		{"socks5", "127.0.0.1"},
		{"socks4", "127.0.0.1"},
	}
	for _, tc := range localDNS {
		px := startSOCKSProxy(t)
		defer px.logNotes(t)
		s := proxySession(t, SessionOptions{Proxy: tc.scheme + "://" + px.addr, Resolve: resolve})
		getAndCheck(t, s, base) // 钉位生效才连得上（这个名字 DNS 解不出）
		h := px.lastHello(t)
		if h.ip != tc.at || h.host != "" {
			t.Errorf("%s + resolve: 代理应只见钉位 IP, got %+v", tc.scheme, h)
		}
	}

	for _, scheme := range []string{"socks5h", "socks4a"} {
		px := startSOCKSProxy(t)
		defer px.logNotes(t)
		s := proxySession(t, SessionOptions{Proxy: scheme + "://" + px.addr, Resolve: resolve})
		s.Do(&Request{Method: "GET", URL: url}) // 代理解不出这个名字，成功与否不重要
		h := px.lastHello(t)
		if h.host != name {
			t.Errorf("%s 应把域名交给代理: %+v", scheme, h)
		}
	}

	cpx := startConnectProxy(t)
	s := proxySession(t, SessionOptions{Proxy: "http://" + cpx.addr, Resolve: resolve})
	s.Do(&Request{Method: "GET", URL: url})
	hosts, _ := cpx.recorded()
	if len(hosts) == 0 || hosts[0] != name+":"+port {
		t.Errorf("CONNECT 应把域名交给代理, got %v", hosts)
	}
}

// local_address 绑的是出网 socket 的源地址（代理场景就是到代理那一条）。
func TestLocalAddressBinding(t *testing.T) {
	echo := startEchoServer(t)

	// 回环绑回环：可用
	s := proxySession(t, SessionOptions{LocalAddress: "127.0.0.1"})
	getAndCheck(t, s, echo.URL)

	// 绑一个本机没有的地址：必须失败，不能"绑不上就当没绑"
	strict := proxySession(t, SessionOptions{LocalAddress: "192.0.2.9"})
	if _, err := strict.Do(&Request{Method: "GET", URL: echo.URL + "/echo", TimeoutMs: 3000}); err == nil {
		t.Error("绑定不存在的源地址时请求应失败（说明 LocalAddr 真的落到了 socket 上）")
	}
}

// ip_version 与钉位/绑定的冲突在建会话时就拒（留到拨号只会得到难懂的错）。
func TestNewSessionRejectsBadNetControl(t *testing.T) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []SessionOptions{
		{IPVersion: "7"},
		{LocalAddress: "eth0"},
		{LocalAddress: "10.0.0.1", IPVersion: "6"},
		{Resolve: map[string]string{"a.example": "1.2.3"}},
	} {
		if _, err := NewSession(p, opts); err == nil {
			t.Errorf("会话创建时应拒绝 %+v", opts)
		}
	}
}

// 地址控制没有接进 QUIC 拨号：force_http3 要报错，而不是发一条没按
// 用户要求走的连接（与 A8 的代理口径一致）。非强制时静默让位 H2 —— H3 本来
// 只是"优先尝试"档，让位不改变用户要的东西。
func TestH3RefusedByAddressControl(t *testing.T) {
	echo := startEchoServer(t)
	cases := []struct {
		name  string
		opts  SessionOptions
		field string
	}{
		{"resolve", SessionOptions{Resolve: map[string]string{"a.example": "127.0.0.1"}}, "resolve"},
		{"local_address", SessionOptions{LocalAddress: "127.0.0.1"}, "local_address"},
		{"ip_version", SessionOptions{IPVersion: "4"}, "ip_version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := proxySession(t, tc.opts)
			_, err := s.Do(&Request{Method: "GET", URL: echo.URL + "/echo", ForceHTTP3: true})
			if err == nil || !strings.Contains(err.Error(), "force_http3 与 "+tc.field) {
				t.Fatalf("force_http3 + %s 应明确报错，实际: %v", tc.name, err)
			}
			if strings.Contains(err.Error(), "h3 request") {
				t.Fatalf("不该真的尝试 H3: %v", err)
			}
		})
	}
}
