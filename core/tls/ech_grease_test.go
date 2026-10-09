package tlscore

// T5.1：GREASE ECH（65037）形状分族。2026-10-08 Firefox 157 四样本裁定：
//   - Chrome  = 单候选 kdf=1/aead=1（AES_128_GCM），线上长度 {144,176,208,240}；
//   - Firefox = 两候选 kdf=1/aead∈{1,3}（每连接随机挑，样本 2:2），线上长度
//     {240,400} 随机（2:2，与 aead 独立），候选填 {224,384}（安装 +16 惯例）。
// 旧 G13 结论"固定 aead=3、非随机"被推翻（两次一致是巧合）。
// 此处钉编译产物的字段；线上字节级证据由 e2e 嗅探链路覆盖。

import (
	"testing"

	utls "github.com/refraction-networking/utls"
	utlsdicttls "github.com/refraction-networking/utls/dicttls"

	"github.com/geekbyter/geektls/core/profiles"
)

func compileECHGrease(t *testing.T, shape string) *utls.GREASEEncryptedClientHelloExtension {
	t.Helper()
	spec, err := CompileDetail(&profiles.Detail{
		Ciphers: []string{"0x1301", "0x1302", "0x1303"},
		Extensions: []profiles.Extension{{
			Type: 65037,
			ECH:  &profiles.ECHConfig{Mode: "grease", GreaseShape: shape},
		}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, e := range spec.Extensions {
		if g, ok := e.(*utls.GREASEEncryptedClientHelloExtension); ok {
			return g
		}
	}
	t.Fatal("65037 未编译出 GREASE ECH 扩展")
	return nil
}

func TestECHGreaseShapeChromeDefault(t *testing.T) {
	for _, shape := range []string{"", "chrome"} {
		g := compileECHGrease(t, shape)
		cs := g.CandidateCipherSuites
		if len(cs) != 1 || cs[0].KdfId != utlsdicttls.HKDF_SHA256 ||
			cs[0].AeadId != utlsdicttls.AEAD_AES_128_GCM {
			t.Errorf("shape=%q: want 单候选 kdf=1/aead=1（BoringSSL），got %+v", shape, cs)
		}
		if len(g.CandidatePayloadLens) != 4 || g.CandidatePayloadLens[0] != 128 {
			t.Errorf("shape=%q: 线长候选应同 BoringSSL（128..224），got %v",
				shape, g.CandidatePayloadLens)
		}
	}
}

func TestECHGreaseShapeFirefox(t *testing.T) {
	g := compileECHGrease(t, "firefox")
	cs := g.CandidateCipherSuites
	// Firefox 157 裁定：两候选 {aead=1}/{aead=3}，utls 每连接随机挑一个。
	if len(cs) != 2 ||
		cs[0].KdfId != utlsdicttls.HKDF_SHA256 || cs[0].AeadId != utlsdicttls.AEAD_AES_128_GCM ||
		cs[1].KdfId != utlsdicttls.HKDF_SHA256 || cs[1].AeadId != utlsdicttls.AEAD_CHACHA20_POLY1305 {
		t.Errorf("want 两候选 {kdf=1,aead=1} 与 {kdf=1,aead=3}，got %+v", cs)
	}
	// 线上长度 {240,400} ⇒ 候选 {224,384}（安装 +16 惯例）。
	if len(g.CandidatePayloadLens) != 2 ||
		g.CandidatePayloadLens[0] != 224 || g.CandidatePayloadLens[1] != 384 {
		t.Errorf("want 线长候选 {224,384}（+16 → 线上 {240,400}），got %v", g.CandidatePayloadLens)
	}
}

func TestECHGreaseShapeUnknownRejected(t *testing.T) {
	_, err := CompileDetail(&profiles.Detail{
		Ciphers: []string{"0x1301"},
		Extensions: []profiles.Extension{{
			Type: 65037,
			ECH:  &profiles.ECHConfig{Mode: "grease", GreaseShape: "typo"},
		}},
	})
	if err == nil {
		t.Fatal("未知 grease_shape 应报错（不静默退回 Chrome 形状）")
	}
}
