package engine

// selfcheck 的 SNI 语义：IP 字面量目标（含 IPv6）线上省略 SNI 扩展
// （uTLS 与真 Chrome 一致，RFC 6066 §3），selfcheck 自算必须反映这一实情；
// 域名目标 SNI 上链，JA4_a 的 SNI 标志位为 d。

import (
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// ja4SNIFlag 取 JA4_a 段的 SNI 标志位：a 段 = 协议(t/q) + 2 位版本 + d/i +
// 2 位 cipher 数 + 2 位扩展数 + 2 位 ALPN，d/i 在 index 3。
func ja4SNIFlag(t *testing.T, ja4 string) byte {
	t.Helper()
	a := strings.Split(ja4, "_")[0]
	if len(a) != 10 {
		t.Fatalf("ja4_a %q length = %d, want 10 (ja4=%s)", a, len(a), ja4)
	}
	return a[3]
}

// ja3HasExt 判断 JA3 扩展段是否含给定扩展 id 字符串。
func ja3HasExt(ja3, id string) bool {
	for _, e := range strings.Split(strings.Split(ja3, ",")[2], "-") {
		if e == id {
			return true
		}
	}
	return false
}

// TestSelfCheckIPLiteralOmitsSNI：127.0.0.1（IP 字面量）目标线上无 SNI，
// selfcheck JA4 标志位为 i，JA3 扩展段不含 0。
func TestSelfCheckIPLiteralOmitsSNI(t *testing.T) {
	echo := startEchoServer(t) // URL host 是 127.0.0.1（IP 字面量）
	s := testSession(t, "chrome_133")

	resp, err := s.Do(&Request{URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if f := ja4SNIFlag(t, resp.SelfCheck.JA4); f != 'i' {
		t.Errorf("ja4 SNI flag = %c, want i (IP 字面量省略 SNI); ja4=%s", f, resp.SelfCheck.JA4)
	}
	if ja3HasExt(resp.SelfCheck.JA3, "0") {
		t.Errorf("ja3 扩展段不应含 SNI(0): %s", resp.SelfCheck.JA3)
	}
}

// TestSelfCheckHostnameKeepsSNI：域名目标（localhost）SNI 上链，
// selfcheck JA4 标志位为 d，JA3 扩展段含 0。
func TestSelfCheckHostnameKeepsSNI(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_133")

	u := strings.Replace(echo.URL, "127.0.0.1", "localhost", 1)
	resp, err := s.Do(&Request{URL: u + "/echo"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if f := ja4SNIFlag(t, resp.SelfCheck.JA4); f != 'd' {
		t.Errorf("ja4 SNI flag = %c, want d (域名目标 SNI 上链); ja4=%s", f, resp.SelfCheck.JA4)
	}
	if !ja3HasExt(resp.SelfCheck.JA3, "0") {
		t.Errorf("ja3 扩展段应含 SNI(0): %s", resp.SelfCheck.JA3)
	}
}

// TestSelfCheckIPv6LiteralOmitsSNI：IPv6 字面量同样省略 SNI（net.ParseIP 判定），
// 纯单测不走网络；并断言剔除发生在副本上、原 spec 的 SNI 占位仍在（单次使用
// 契约不被破坏）。
func TestSelfCheckIPv6LiteralOmitsSNI(t *testing.T) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}

	sc := selfCheck(p, spec, "2001:db8::1", nil)
	if f := ja4SNIFlag(t, sc.JA4); f != 'i' {
		t.Errorf("IPv6: ja4 SNI flag = %c, want i; ja4=%s", f, sc.JA4)
	}
	if ja3HasExt(sc.JA3, "0") {
		t.Errorf("IPv6: ja3 扩展段不应含 SNI(0): %s", sc.JA3)
	}
	// 原 spec 未被改写
	if !specHasSNI(spec) {
		t.Error("selfCheck 改写了原 spec（SNI 占位丢失），剔除必须发生在副本上")
	}

	// 对照组：同一 detail 重新编译，域名目标标志位为 d
	spec2, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}
	sc2 := selfCheck(p, spec2, "example.com", nil)
	if f := ja4SNIFlag(t, sc2.JA4); f != 'd' {
		t.Errorf("域名: ja4 SNI flag = %c, want d; ja4=%s", f, sc2.JA4)
	}
}

func specHasSNI(spec *utls.ClientHelloSpec) bool {
	for _, e := range spec.Extensions {
		if _, ok := e.(*utls.SNIExtension); ok {
			return true
		}
	}
	return false
}
