package h3

import "testing"

// TestECHGreasePayloadShape 钉住 ECH GREASE 合成负载的结构（真实抓包实证）：
//
//	outer(0x00) | kdf(0x0001) | aead(0x0001) | config_id(1B) |
//	enc_len(0x0020) | enc(32B) | payload_len | payload
//
// Chrome 149 实测 payload_len=176、总长 218（=42+176）。
func TestECHGreasePayloadShape(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 64; i++ {
		p := echGreasePayload()

		if p[0] != 0x00 {
			t.Fatalf("outer type = %#x, want 0x00", p[0])
		}
		if p[1] != 0x00 || p[2] != 0x01 {
			t.Fatalf("kdf = %#x%#x, want 0x0001 (HKDF-SHA256)", p[1], p[2])
		}
		if p[3] != 0x00 || p[4] != 0x01 {
			t.Fatalf("aead = %#x%#x, want 0x0001 (AES-128-GCM)", p[3], p[4])
		}
		encLen := int(p[6])<<8 | int(p[7])
		if encLen != 32 {
			t.Fatalf("enc_len = %d, want 32（缺 enc 段会被检测侧区分）", encLen)
		}
		payloadLen := int(p[40])<<8 | int(p[41])
		switch payloadLen {
		case 144, 176, 208, 240:
		default:
			t.Fatalf("payload_len = %d, want one of {144,176,208,240}", payloadLen)
		}
		if len(p) != 42+payloadLen {
			t.Fatalf("total = %d, want %d（42+payload_len）", len(p), 42+payloadLen)
		}
		seen[payloadLen] = true
	}
	if len(seen) < 2 {
		t.Errorf("payload_len 未见随机化（候选集只用到了 %v）", seen)
	}
}
