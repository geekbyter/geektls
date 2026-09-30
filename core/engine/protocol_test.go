package engine

// G8：协议选择（默认 h1.1 + h2，H3 显式开启）。
//
// 判据分三层：
//  1. 行为层：UsedProtocol（h2 / http/1.1 / h3）；
//  2. 服务端视角：/whoami 回的 r.Proto（HTTP/2.0 vs HTTP/1.1）；
//  3. 线上 ALPN：`Negotiated.ALPN` 是**服务端从我方 offer 里挑的**——服务端
//     偏好 h2（NextProtos 顺序 ["h2","http/1.1"]），所以它协商出 http/1.1 就
//     证明我方根本没 offer h2（收窄真的发生在线上，而不只是本地偏好）；
//     扩展内容的收窄另有 narrowALPN 的纯函数单测直接钉住。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekbyter/geektls/core/profiles"
)

// protoSession 建会话：默认用 chrome_133（有 h2/hpack；**自带 http3 节**，
// 需要"预设无 H3 能力"的场景要在 mutate 里显式置 nil），mutate 可给 profile
// 挂 H3 能力 / 去 ECH。
func protoSession(t *testing.T, opts SessionOptions, mutate func(*profiles.Profile)) *Session {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(p)
	}
	opts.InsecureSkipVerify = true
	s, err := NewSession(p, opts)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// withH3 给 profile 挂上"预设声明了 H3"的能力（是否真的走由 protocols 决定）。
func withH3(raceMs int) func(*profiles.Profile) {
	return func(p *profiles.Profile) {
		p.HTTP3 = &profiles.HTTP3Profile{
			Enabled: true, H2RaceMs: raceMs,
			TransportParams: map[string]uint64{"max_idle_timeout": 30000},
		}
	}
}

func getBody(t *testing.T, resp *Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func boolPtr(v bool) *bool { return &v }

// 默认（不给 protocols）：即使预设声明了 http3 + 竞速参数，也只走 TCP。
// 对照：h3_test.go 的 TestEngineH3Race 用了同一份 profile 但显式开 h3，H3 会赢。
func TestProtocolDefaultIsTCPOnly(t *testing.T) {
	pki := newTestPKI(t)
	base := startPKIServer(t, pki, false, []string{"h2", "http/1.1"})

	s := protoSession(t, SessionOptions{}, withH3(50))
	resp, err := s.Do(&Request{URL: base + "/whoami"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.UsedProtocol != "h2" {
		t.Errorf("UsedProtocol = %q, want h2（H3 默认关，不该被竞速抢走）", resp.UsedProtocol)
	}
	if body := getBody(t, resp); !strings.Contains(body, "proto=HTTP/2.0") {
		t.Errorf("服务端看到 %q, want 含 proto=HTTP/2.0", body)
	}
	if got := resp.SelfCheck.Negotiated.ALPN; got != "h2" {
		t.Errorf("协商 ALPN = %q, want h2", got)
	}
}

// protocols=["h1.1"]：不 offer h2（服务端偏好 h2 却只能给 http/1.1 ⇒ 线上确实收窄了）。
func TestProtocolH1Only(t *testing.T) {
	pki := newTestPKI(t)
	base := startPKIServer(t, pki, false, []string{"h2", "http/1.1"})

	s := protoSession(t, SessionOptions{Protocols: []string{"h1.1"}}, nil)
	resp, err := s.Do(&Request{URL: base + "/whoami"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.UsedProtocol != "http/1.1" {
		t.Errorf("UsedProtocol = %q, want http/1.1", resp.UsedProtocol)
	}
	if body := getBody(t, resp); !strings.Contains(body, "proto=HTTP/1.1") {
		t.Errorf("服务端看到 %q, want 含 proto=HTTP/1.1", body)
	}
	if got := resp.SelfCheck.Negotiated.ALPN; got != "http/1.1" {
		t.Errorf("协商 ALPN = %q, want http/1.1（说明 offer 里没有 h2）", got)
	}
}

// protocols=["h2"]：只允许 h2；对端不支持时**失败**，不静默回落 H1。
func TestProtocolH2Only(t *testing.T) {
	pki := newTestPKI(t)

	h2srv := startPKIServer(t, pki, false, []string{"h2", "http/1.1"})
	s := protoSession(t, SessionOptions{Protocols: []string{"h2"}}, nil)
	resp, err := s.Do(&Request{URL: h2srv + "/whoami"})
	if err != nil {
		t.Fatalf("h2 服务端 + protocols=[h2] 不该失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.UsedProtocol != "h2" {
		t.Errorf("UsedProtocol = %q, want h2", resp.UsedProtocol)
	}

	h1srv := startPKIServer(t, pki, false, []string{"http/1.1"})
	s2 := protoSession(t, SessionOptions{Protocols: []string{"h2"}}, nil)
	if _, err := s2.Do(&Request{URL: h1srv + "/whoami"}); err == nil {
		t.Error("对端不支持 h2 时应当失败（不静默回落 H1）")
	}
}

// narrowALPN 纯函数：收窄只发生在"允许集合不完全覆盖"时，且默认路径原样返回。
func TestNarrowALPNUnit(t *testing.T) {
	detail := func(alpn []string) *profiles.Detail {
		return &profiles.Detail{Extensions: []profiles.Extension{{Type: 16, ALPN: alpn}, {Type: 0}}}
	}
	defaultSet := protocolSet{h1: true, h2: true}

	// 默认集合：原样（连指针都不换 ⇒ 默认路径不可能改字节）
	d := detail([]string{"h2", "http/1.1"})
	got, list, changed := narrowALPN(d, defaultSet, false)
	if changed || got != d || strings.Join(list, ",") != "h2,http/1.1" {
		t.Errorf("默认集合应当原样返回：changed=%v same=%v list=%v", changed, got == d, list)
	}

	// h1.1 only：扩展内容被收窄
	nd, list, changed := narrowALPN(d, protocolSet{h1: true}, true)
	if !changed || strings.Join(list, ",") != "http/1.1" {
		t.Fatalf("h1.1 only 收窄失败：changed=%v list=%v", changed, list)
	}
	if got := alpnOf(nd); strings.Join(got, ",") != "http/1.1" {
		t.Errorf("收窄后的扩展 = %v, want [http/1.1]", got)
	}
	if got := alpnOf(d); strings.Join(got, ",") != "h2,http/1.1" {
		t.Errorf("原 detail 不该被改动：%v", got)
	}

	// h2 only：profile 只声明 http/1.1 ⇒ 补位成 [h2]（空 ALPN 是反常形态）
	nd2, list2, _ := narrowALPN(detail([]string{"http/1.1"}), protocolSet{h2: true}, true)
	if strings.Join(list2, ",") != "h2" || strings.Join(alpnOf(nd2), ",") != "h2" {
		t.Errorf("h2 only 补位失败：list=%v ext=%v", list2, alpnOf(nd2))
	}

	// profile 本就不发 ALPN：不凭空插扩展，只把列表交给 cfg.NextProtos
	nd3, list3, changed3 := narrowALPN(&profiles.Detail{Extensions: []profiles.Extension{{Type: 0}}},
		protocolSet{h1: true}, true)
	if !changed3 || strings.Join(list3, ",") != "http/1.1" || len(nd3.Extensions) != 1 || nd3.Extensions[0].Type != 0 {
		t.Errorf("无 ALPN 扩展时不该插扩展：list=%v exts=%v", list3, nd3.Extensions)
	}
}

func alpnOf(d *profiles.Detail) []string {
	if d == nil {
		return nil
	}
	return alpnProtocols(d)
}

// 非法配置：建会话时就报错，不留到"连不上"那种模糊失败。
func TestProtocolValidation(t *testing.T) {
	cases := []struct {
		name string
		opts SessionOptions
		want string
	}{
		{"未知取值", SessionOptions{Protocols: []string{"spdy"}}, "未知"},
		{"与 h3 同时给", SessionOptions{Protocols: []string{"h2"}, H3: boolPtr(true)}, "不能同时"},
		{"h3 打开但预设没有 http3 节", SessionOptions{H3: boolPtr(true)}, "没有 http3 声明"},
		{"只给 h3 但预设没有 http3 节", SessionOptions{Protocols: []string{"h3"}}, "http3 声明"},
		{"空集合", SessionOptions{Protocols: []string{}}, ""}, // 空切片 = 默认（不算错）
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profiles.Get("chrome_133")
			if err != nil {
				t.Fatal(err)
			}
			// chrome_133 自带 http3 节（enabled=true）；"预设没有 http3 节"
			// 的用例必须显式剥掉，否则校验根本走不到。
			p.HTTP3 = nil
			tc.opts.InsecureSkipVerify = true
			_, err = NewSession(p, tc.opts)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("空 protocols 应当是默认行为，不该报错：%v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want 含 %q", err, tc.want)
			}
		})
	}
}

// 明文 http:// 与协议集合的冲突：只有 h1.1 能承载（无 h2c / QUIC）。
func TestProtocolPlaintextNeedsH1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	s := protoSession(t, SessionOptions{Protocols: []string{"h2"}}, nil)
	if _, err := s.Do(&Request{URL: srv.URL + "/echo"}); err == nil ||
		!strings.Contains(err.Error(), "h1.1") {
		t.Fatalf("err = %v, want 提示 http:// 只能走 h1.1", err)
	}

	s2 := protoSession(t, SessionOptions{}, nil)
	resp, err := s2.Do(&Request{URL: srv.URL + "/echo"})
	if err != nil {
		t.Fatalf("Do plain: %v", err)
	}
	defer resp.Body.Close()
	if resp.UsedProtocol != "http/1.1" {
		t.Errorf("明文 UsedProtocol = %q", resp.UsedProtocol)
	}
}

// force_http3 的兼容性：默认会话下照旧可用（老行为不变）；显式限定了 protocols
// 且不含 h3 时才冲突报错。
func TestProtocolForceHTTP3Compatibility(t *testing.T) {
	// 默认会话（protocols 未设）：force 走到 QUIC 拨号，报错必须来自拨号而不是协议策略
	s := protoSession(t, SessionOptions{}, withH3(0))
	_, err := s.Do(&Request{URL: "https://127.0.0.1:1/echo", ForceHTTP3: true})
	if err == nil || strings.Contains(err.Error(), "protocols") {
		t.Fatalf("err = %v, want QUIC 拨号失败（不是协议策略拦截）", err)
	}

	// 显式 protocols=[h1.1,h2] + force_http3 ⇒ 冲突，报错
	s2 := protoSession(t, SessionOptions{Protocols: []string{"h1.1", "h2"}}, withH3(0))
	_, err = s2.Do(&Request{URL: "https://127.0.0.1:1/echo", ForceHTTP3: true})
	if err == nil || !strings.Contains(err.Error(), "protocols") {
		t.Fatalf("err = %v, want 提示与 protocols 冲突", err)
	}
}
