package h3

import (
	"testing"

	utlsb "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"
	utlsbDicttls "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn/dicttls"
	utls "github.com/refraction-networking/utls"
	utlsdicttls "github.com/refraction-networking/utls/dicttls"
)

// TestECHGreasePayloadShape 钉住 ECH GREASE 合成负载的结构（真实抓包实证）：
//
//	outer(0x00) | kdf | aead | config_id(1B) | enc_len(0x0020) |
//	enc(32B) | payload_len | payload
//
// Chrome 149 实测 payload_len=176、总长 218（=42+176）；
// Firefox 157 实测 payload_len ∈ {240,400}（2026-10-08 四样本 2:2）。
func TestECHGreasePayloadShape(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kdf, aead uint16
		lens      []int
	}{
		{"chrome", 0x0001, 0x0001, []int{144, 176, 208, 240}},
		{"firefox", 0x0001, 0x0003, []int{240, 400}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[int]bool{}
			for i := 0; i < 64; i++ {
				p := echGreasePayload(tc.kdf, tc.aead, tc.lens)

				if p[0] != 0x00 {
					t.Fatalf("outer type = %#x, want 0x00", p[0])
				}
				if got := uint16(p[1])<<8 | uint16(p[2]); got != tc.kdf {
					t.Fatalf("kdf = %#x, want %#x", got, tc.kdf)
				}
				if got := uint16(p[3])<<8 | uint16(p[4]); got != tc.aead {
					t.Fatalf("aead = %#x, want %#x", got, tc.aead)
				}
				encLen := int(p[6])<<8 | int(p[7])
				if encLen != 32 {
					t.Fatalf("enc_len = %d, want 32（缺 enc 段会被检测侧区分）", encLen)
				}
				payloadLen := int(p[40])<<8 | int(p[41])
				ok := false
				for _, l := range tc.lens {
					if payloadLen == l {
						ok = true
					}
				}
				if !ok {
					t.Fatalf("payload_len = %d, want one of %v", payloadLen, tc.lens)
				}
				if len(p) != 42+payloadLen {
					t.Fatalf("total = %d, want %d（42+payload_len）", len(p), 42+payloadLen)
				}
				seen[payloadLen] = true
			}
			if len(seen) < 2 {
				t.Errorf("payload_len 未见随机化（候选集只用到了 %v）", seen)
			}
		})
	}
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPickEchGreaseShape 钉住形状挑取的分族行为（T5.1）——候选套件每连接随机
// 挑；线长候选 = CandidatePayloadLens + 16（线上长度）。Chrome 单候选 ⇒ 恒定；
// Firefox 两候选 aead∈{1,3} 应都出现（2026-10-08 四样本 2:2）。
func TestPickEchGreaseShape(t *testing.T) {
	chrome := &utlsb.GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: []utlsb.HPKESymmetricCipherSuite{
			{KdfId: utlsbDicttls.HKDF_SHA256, AeadId: utlsbDicttls.AEAD_AES_128_GCM},
		},
		CandidatePayloadLens: []uint16{128, 160, 192, 224},
	}
	kdf, aead, lens := pickEchGreaseShape(chrome)
	if kdf != 0x0001 || aead != 0x0001 || !sameInts(lens, []int{144, 176, 208, 240}) {
		t.Errorf("chrome 形状应恒定（kdf=1/aead=1/{144,176,208,240}），got kdf=%d aead=%d lens=%v",
			kdf, aead, lens)
	}

	fx := &utlsb.GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: []utlsb.HPKESymmetricCipherSuite{
			{KdfId: utlsbDicttls.HKDF_SHA256, AeadId: utlsbDicttls.AEAD_AES_128_GCM},
			{KdfId: utlsbDicttls.HKDF_SHA256, AeadId: utlsbDicttls.AEAD_CHACHA20_POLY1305},
		},
		CandidatePayloadLens: []uint16{224, 384},
	}
	aeads := map[uint16]int{}
	for i := 0; i < 128; i++ {
		_, a, l := pickEchGreaseShape(fx)
		aeads[a]++
		if !sameInts(l, []int{240, 400}) {
			t.Fatalf("firefox 线长集应为 {240,400}，got %v", l)
		}
	}
	if aeads[0x0001] == 0 || aeads[0x0003] == 0 {
		t.Errorf("firefox aead 未见随机化（aead=1 ×%d，aead=3 ×%d）", aeads[0x0001], aeads[0x0003])
	}
}

// TestSpecToBogdanPreservesECHGreaseShape（T5.1）：SpecToBogdan 保形状转换——
// 两候选与线长集都不得被归一为 BoringGREASEECH（Chrome 形状）。
func TestSpecToBogdanPreservesECHGreaseShape(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		CipherSuites: []uint16{0x1301},
		Extensions: []utls.TLSExtension{
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{KdfId: utlsdicttls.HKDF_SHA256, AeadId: utlsdicttls.AEAD_AES_128_GCM},
					{KdfId: utlsdicttls.HKDF_SHA256, AeadId: utlsdicttls.AEAD_CHACHA20_POLY1305},
				},
				CandidatePayloadLens: []uint16{224, 384},
			},
		},
	}
	got, err := SpecToBogdan(spec)
	if err != nil {
		t.Fatalf("SpecToBogdan: %v", err)
	}
	for _, e := range got.Extensions {
		if g, ok := e.(*utlsb.GREASEEncryptedClientHelloExtension); ok {
			if len(g.CandidateCipherSuites) != 2 ||
				g.CandidateCipherSuites[0].AeadId != utlsbDicttls.AEAD_AES_128_GCM ||
				g.CandidateCipherSuites[1].AeadId != utlsbDicttls.AEAD_CHACHA20_POLY1305 {
				t.Errorf("候选套件未被保留（回归为 Chrome？）: %+v", g.CandidateCipherSuites)
			}
			if len(g.CandidatePayloadLens) != 2 ||
				g.CandidatePayloadLens[0] != 224 || g.CandidatePayloadLens[1] != 384 {
				t.Errorf("线长候选未被保留: %v", g.CandidatePayloadLens)
			}
			return
		}
	}
	t.Fatal("未找到转换后的 GREASE ECH 扩展")
}
