package tlscore

import (
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geekbyter/geektls/core/profiles"
)

// 官方向量数据（FoxIO JA4 技术文档 Example 节）：一个典型 Chrome ClientHello。
var ja4VectorCiphers = []string{
	"0x1301", "0x1302", "0x1303", "0xc02b", "0xc02f", "0xc02c", "0xc030",
	"0xcca9", "0xcca8", "0xc013", "0xc014", "0x009c", "0x009d", "0x002f", "0x0035",
}

func ja4VectorDetail() *profiles.Detail {
	return &profiles.Detail{
		Ciphers: ja4VectorCiphers,
		Extensions: []profiles.Extension{
			{Type: 27, CertCompression: []string{"brotli"}},
			{Type: 0, SNI: "example.com"},
			{Type: 51, KeyShares: []string{"X25519"}}, // 小 key_share 才触发 padding（与规范示例一致）
			{Type: 16, ALPN: []string{"h2", "http/1.1"}},
			{Type: 17513, ALPN: []string{"h2"}},
			{Type: 23},
			{Type: 45, PSKModes: []uint8{1}},
			{Type: 13, SigAlgs: []string{
				"0x0403", "0x0804", "0x0401", "0x0503", "0x0805", "0x0501", "0x0806", "0x0601"}},
			{Type: 5},
			{Type: 35},
			{Type: 18},
			{Type: 43, Versions: []string{"0x0304", "0x0303"}},
			{Type: 65281, Data: "00"}, // renegotiation_info
			{Type: 11, PointFormats: []uint8{0}},
			{Type: 10, Groups: []string{"X25519MLKEM768", "X25519", "P-256", "P-384"}},
			{Type: 21, PaddingTo: 512},
		},
	}
}

// TestComputeJA4OfficialVector 用 FoxIO 规范文档的完整示例做端到端断言：
// t13d1516h2_8daaf6152771_e5627efa2ab1（b/c 段 hash 在规范中逐步给出）。
func TestComputeJA4OfficialVector(t *testing.T) {
	spec, err := CompileDetail(ja4VectorDetail())
	if err != nil {
		t.Fatalf("CompileDetail: %v", err)
	}
	ja4 := ComputeJA4(spec)
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if ja4 != want {
		t.Errorf("JA4 = %s, want %s (FoxIO spec example)", ja4, want)
	}
}

// TestComputeJA4NoSigAlgs 规范文档第二条向量：13 号扩展在但 sig_algs 列表为空时，
// c 段 hash 为 6d807ffa2a79（列表不带下划线直接哈希，000d 仍在扩展列表里）。
func TestComputeJA4NoSigAlgs(t *testing.T) {
	d := ja4VectorDetail()
	for i := range d.Extensions {
		if d.Extensions[i].Type == 13 {
			d.Extensions[i].SigAlgs = nil
		}
	}

	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatal(err)
	}
	const want = "t13d1516h2_8daaf6152771_6d807ffa2a79"
	if ja4 := ComputeJA4(spec); ja4 != want {
		t.Errorf("JA4 = %s, want %s", ja4, want)
	}
}

// TestComputeJA4GreaseStripped GREASE 必须全剔除：插入 GREASE 后 JA4 不变。
func TestComputeJA4GreaseStripped(t *testing.T) {
	spec1, err := CompileDetail(ja4VectorDetail())
	if err != nil {
		t.Fatal(err)
	}
	d := ja4VectorDetail()
	d.Ciphers = append([]string{"grease"}, d.Ciphers...)
	d.Extensions = append([]profiles.Extension{{Type: 0x1a1a}}, d.Extensions...) // GREASE 扩展
	spec2, err := CompileDetail(d)
	if err != nil {
		t.Fatal(err)
	}
	if ComputeJA4(spec1) != ComputeJA4(spec2) {
		t.Errorf("GREASE changed JA4: %s vs %s", ComputeJA4(spec1), ComputeJA4(spec2))
	}
}

// TestComputeJA3 结构断言 + GREASE 剔除 + hash 自洽（md5 的正确性由标准库保证）。
func TestComputeJA3(t *testing.T) {
	d := &profiles.Detail{
		Ciphers: []string{"grease", "0x1301", "0x1302"},
		Extensions: []profiles.Extension{
			{Type: 0x0a0a}, // GREASE 扩展
			{Type: 0, SNI: "example.com"},
			{Type: 16, ALPN: []string{"h2"}},
			{Type: 10, Groups: []string{"grease", "X25519"}},
			{Type: 11, PointFormats: []uint8{0}},
		},
	}
	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatal(err)
	}
	ja3 := ComputeJA3(spec)
	const want = "771,4865-4866,0-16-10-11,29,0"
	if ja3 != want {
		t.Errorf("JA3 = %q, want %q", ja3, want)
	}
	// hash 输入必须是 full string 本身
	if h := JA3Hash(ja3); len(h) != 32 {
		t.Errorf("JA3Hash len = %d", len(h))
	}
	if JA3Hash("a") == JA3Hash("b") {
		t.Error("JA3Hash collision on trivial inputs")
	}
}

// TestJA4ALPNCode 覆盖规范的非字母数字回退规则。
func TestJA4ALPNCode(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "00"},
		{[]string{""}, "00"},
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"h3"}, "h3"},
		{[]string{"\xab"}, "ab"},
		{[]string{"\xab\xcd"}, "ad"},
		{[]string{"\x20\x61"}, "21"},
		{[]string{"\x30\xab"}, "3b"},
		// 注：FoxIO 文档中 "0x30 0xAB 0xCD 0x31 → 3d" 与其自身规则及其它
		// 示例不一致（按规则应为 "01" 或全 hex 的 "31"），判定为文档笔误，不跟随。
	}
	for _, tc := range cases {
		if got := ja4ALPNCode(tc.in); got != tc.want {
			t.Errorf("ja4ALPNCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestExtensionTypeIDUnknown 未知扩展类型必须被识别为 unknown 而不是误判。
func TestExtensionTypeIDUnknown(t *testing.T) {
	type fakeExt struct{ utls.TLSExtension }
	if _, ok := extensionTypeID(&fakeExt{}); ok {
		t.Error("unknown extension type reported as known")
	}
	g := &utls.GenericExtension{Id: 65280}
	if id, ok := extensionTypeID(g); !ok || id != 65280 {
		t.Errorf("GenericExtension id = %d, %v", id, ok)
	}
	if !isGreaseUint16(0xfafa) || isGreaseUint16(0x1301) {
		t.Error("isGreaseUint16 wrong")
	}
}
