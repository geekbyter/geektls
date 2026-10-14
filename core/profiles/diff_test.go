package profiles

import (
	"encoding/hex"
	"strings"
	"testing"
)

// buildTestCH 拼一份最小 ClientHello record（hex）：GREASE cipher、两个 GREASE 扩展位、
// SNI、supported_versions、一个未知扩展（透传 data）——供 diff 测试用。
func buildTestCH(greaseCipher, greaseExt uint16, unknownData byte, extraExt bool) string {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random（diff 不比对）
	body = append(body, 0x00)                // session_id len = 0
	ciphers := []byte{0x13, 0x01, byte(greaseCipher >> 8), byte(greaseCipher)}
	body = append(body, byte(len(ciphers)>>8), byte(len(ciphers)))
	body = append(body, ciphers...)
	body = append(body, 0x01, 0x00) // compression: null
	var exts []byte
	addExt := func(t0 uint16, payload []byte) {
		exts = append(exts, byte(t0>>8), byte(t0), byte(len(payload)>>8), byte(len(payload)))
		exts = append(exts, payload...)
	}
	addExt(43, []byte{0x02, 0x03, 0x04}) // supported_versions
	addExt(0, []byte{0x00, 0x03, 0x00, 0x00, 0x01, 'x'})
	if extraExt {
		addExt(35, nil) // session_ticket
	}
	addExt(0x1234, []byte{unknownData}) // 未知扩展（透传 data）
	addExt(greaseExt, nil)              // GREASE（类型每次重取）
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return hex.EncodeToString(append(rec, hs...))
}

// TestDiffClientHellos：GREASE 值不同不算差异；未知扩展的载荷不同、扩展数量不同、
// 长度不同都要报出来。
func TestDiffClientHellos(t *testing.T) {
	a := buildTestCH(0x0a0a, 0x1a1a, 0x11, true)
	b := buildTestCH(0x2a2a, 0x3a3a, 0x11, true)

	// ① 只有 GREASE 值不同 → 归一化后一致。
	diffs, err := DiffClientHellos(a, b)
	if err != nil {
		t.Fatalf("DiffClientHellos: %v", err)
	}
	if len(diffs) != 0 {
		t.Errorf("GREASE 值差异不应报出: %v", diffs)
	}
	// ② 未知扩展载荷不同 → 报 data 差异。
	c := buildTestCH(0x0a0a, 0x1a1a, 0x22, true)
	diffs, err = DiffClientHellos(a, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) == 0 || !strings.Contains(strings.Join(diffs, "\n"), "data") {
		t.Errorf("未知扩展载荷差异未报出: %v", diffs)
	}
	// ③ 扩展数量不同 → 报数量差异。
	d := buildTestCH(0x0a0a, 0x1a1a, 0x11, false)
	diffs, err = DiffClientHellos(a, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) == 0 || !strings.Contains(strings.Join(diffs, "\n"), "扩展数量") {
		t.Errorf("扩展数量差异未报出: %v", diffs)
	}
	// ④ 自身对比 → 零差异。
	if diffs, err = DiffClientHellos(a, a); err != nil || len(diffs) != 0 {
		t.Errorf("自身对比应为空: %v %v", err, diffs)
	}
}
