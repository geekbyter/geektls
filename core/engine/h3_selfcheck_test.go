package engine

// T2.1：H3 请求的 selfcheck——QUIC 内层 ClientHello 的 JA3/JA4（q 变体）。
// 断言三件事：
//  1. 形态：JA4 首段 q13i（IP 字面量省略 SNI）/ q13d（域名目标带 SNI）；
//     cipher 段恒为 55b375c5d22e（clamp 后只有 3 个 TLS1.3 套件）；
//  2. 一致性：与 h3core.QUICConfigFromProfile + SpecForJA4 的独立自算逐字符
//     相同（引擎缓存路径 vs 现取重算——同一份 clamp 产物，防缓存接错线）；
//  3. 复用语义：共享 transport 下二次请求报告稳定。
//
// 域名侧为纯函数断言（selfCheckQUIC 直接传域名 host）：端到端不做 localhost
// 目标——本机 localhost 可能优先解析 ::1 而测试服务端绑 127.0.0.1，属环境
// 噪声，不该混进指纹断言。

import (
	"strings"
	"testing"

	h3core "github.com/geekbyter/geektls/core/h3"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

func TestH3SelfCheck(t *testing.T) {
	addr := startH3EchoServer(t)
	s := h3Session(t, 0)
	defer s.Close()

	// ---- IP 字面量目标（127.0.0.1）→ SNI 不上链（i 位）----
	resp, err := s.Do(&Request{URL: "https://" + addr + "/echo", ForceHTTP3: true})
	if err != nil {
		t.Fatalf("Do force_http3: %v", err)
	}
	defer resp.Body.Close()
	sc := resp.SelfCheck
	if sc.JA4 == "" || sc.JA3 == "" || sc.JA3Hash == "" {
		t.Fatalf("H3 selfcheck 为空: %+v", sc)
	}
	if !strings.HasPrefix(sc.JA4, "q13i") {
		t.Errorf("ja4 = %q, want q13i 开头（IP 字面量省略 SNI）", sc.JA4)
	}
	if sc.SNISent {
		t.Error("SNISent = true, want false（IP 字面量）")
	}
	parts := strings.Split(sc.JA4, "_")
	if len(parts) != 3 || parts[1] != "55b375c5d22e" {
		t.Errorf("ja4 = %q, cipher 段 want 55b375c5d22e（clamp 后 3 个 TLS1.3 套件）", sc.JA4)
	}
	if sc.Negotiated != nil {
		t.Errorf("H3 Negotiated 应为 nil（QUIC 握手状态无导出面），got %+v", sc.Negotiated)
	}
	if sc.JA3Match != nil || sc.JA4Match != nil {
		t.Errorf("H3 不比对 match（内层经 clamp 裁剪，与 TCP 期望值不可比），got %v/%v", sc.JA3Match, sc.JA4Match)
	}

	// ---- 独立路径：同一份 clamp 产物现取自算，逐字符一致 ----
	qcfg, err := h3core.QUICConfigFromProfile(s.profile)
	if err != nil {
		t.Fatalf("QUICConfigFromProfile: %v", err)
	}
	wantSpec := h3core.SpecForJA4(qcfg.ClientHelloSpec)
	if wantSpec == nil {
		t.Fatal("SpecForJA4 = nil")
	}
	wantIP := tlscore.ComputeJA4QUIC(tlscore.SpecWithoutSNI(wantSpec)) // IP 目标语义
	if wantIP != sc.JA4 {
		t.Errorf("selfcheck ja4 = %q, 独立自算 = %q", sc.JA4, wantIP)
	}

	// ---- 复用：同目标二次请求，报告稳定 ----
	resp2, err := s.Do(&Request{URL: "https://" + addr + "/echo", ForceHTTP3: true})
	if err != nil {
		t.Fatalf("Do 2nd: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.SelfCheck.JA4 != sc.JA4 {
		t.Errorf("复用后 ja4 = %q, want %q", resp2.SelfCheck.JA4, sc.JA4)
	}

	// ---- 域名目标语义（单元级）：SNI 上链 → d 位 ----
	scD := selfCheckQUIC(s.profile, wantSpec, "example.com")
	if !scD.SNISent || !strings.HasPrefix(scD.JA4, "q13d") {
		t.Errorf("域名: SNISent=%v ja4=%q, want true / q13d 开头", scD.SNISent, scD.JA4)
	}
	wantD := tlscore.ComputeJA4QUIC(wantSpec)
	if wantD != scD.JA4 {
		t.Errorf("域名 ja4 = %q, 独立自算 = %q", scD.JA4, wantD)
	}
	t.Logf("H3 selfcheck: ip=%s domain=%s", sc.JA4, scD.JA4)
}
