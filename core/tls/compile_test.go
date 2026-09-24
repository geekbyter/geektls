package tlscore

import (
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"reflect"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

// extTypeID 通过扩展自身的 Read 序列化取线上 type（前两字节），是最贴近 wire 的断言。
// 注意：uTLS 的 fake 扩展以 (n, io.EOF) 为成功返回；空 ServerName 的 SNI
// Len()==0（线上省略），用类型断言兜底。
func extTypeID(t *testing.T, ext utls.TLSExtension) uint16 {
	t.Helper()
	n := ext.Len()
	if n == 0 {
		switch ext.(type) {
		case *utls.SNIExtension:
			return 0
		case *utls.UtlsPaddingExtension:
			// WillPad 在握手时才按总长决定，spec 阶段 Len==0 属正常。
			return 21
		}
		t.Fatalf("extension %T has zero Len", ext)
	}
	buf := make([]byte, n)
	if _, err := ext.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("read extension %T: %v", ext, err)
	}
	return binary.BigEndian.Uint16(buf[:2])
}

func extTypeOrder(t *testing.T, spec *utls.ClientHelloSpec) []uint16 {
	t.Helper()
	out := make([]uint16, 0, len(spec.Extensions))
	for _, e := range spec.Extensions {
		out = append(out, extTypeID(t, e))
	}
	return out
}

// TestCompileDetailBasic 覆盖任务要求的扩展类型映射与严格保序。
func TestCompileDetailBasic(t *testing.T) {
	d := &profiles.Detail{
		Ciphers: []string{"grease", "0x1301", "0x1302", "0x1303", "0xc02b"},
		Extensions: []profiles.Extension{
			{Type: 0, SNI: "auto"},
			{Type: 23}, // extended_master_secret
			{Type: 35}, // session_ticket
			{Type: 5},  // status_request
			{Type: 10, Groups: []string{"grease", "X25519MLKEM768", "X25519", "P-256"}},
			{Type: 11, PointFormats: []uint8{0}},
			{Type: 13, SigAlgs: []string{"0x0403", "0x0804", "0x0401"}},
			{Type: 50, SigAlgs: []string{"0x0403", "0x0804"}},
			{Type: 16, ALPN: []string{"h2", "http/1.1"}},
			{Type: 18}, // SCT
			{Type: 45, PSKModes: []uint8{1}},
			{Type: 43, Versions: []string{"grease", "0x0304", "0x0303"}},
			{Type: 51, KeyShares: []string{"grease", "X25519MLKEM768", "X25519"}},
			{Type: 27, CertCompression: []string{"brotli"}},
			{Type: 28, Data: "4001"},                // record_size_limit = 0x4001
			{Type: 34, SigAlgs: []string{"0x0403"}}, // delegated_credentials
			{Type: 17513, ALPN: []string{"h2"}},     // ALPS
			{Type: 65037, ECH: &profiles.ECHConfig{Mode: "grease"}},
			{Type: 65280, Data: "deadbeef"}, // 未知类型 → GenericExtension
			{Type: 21, PaddingTo: 512},
		},
	}

	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatalf("CompileDetail: %v", err)
	}

	wantCiphers := []uint16{utls.GREASE_PLACEHOLDER, 0x1301, 0x1302, 0x1303, 0xc02b}
	if !reflect.DeepEqual(spec.CipherSuites, wantCiphers) {
		t.Errorf("ciphers = %x, want %x", spec.CipherSuites, wantCiphers)
	}

	wantOrder := []uint16{0, 23, 35, 5, 10, 11, 13, 50, 16, 18, 45, 43, 51, 27, 28, 34, 17513, 65037, 65280, 21}
	got := extTypeOrder(t, spec)
	if !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("extension wire order = %v, want %v", got, wantOrder)
	}

	// supported_groups：grease 占位 + 组名映射。
	groups := spec.Extensions[4].(*utls.SupportedCurvesExtension)
	wantGroups := []utls.CurveID{utls.GREASE_PLACEHOLDER, utls.X25519MLKEM768, utls.X25519, utls.CurveP256}
	if !reflect.DeepEqual(groups.Curves, wantGroups) {
		t.Errorf("groups = %v, want %v", groups.Curves, wantGroups)
	}

	// key_share：GREASE 位按 uTLS 约定给单字节 0 负载。
	ks := spec.Extensions[12].(*utls.KeyShareExtension)
	if len(ks.KeyShares) != 3 || ks.KeyShares[0].Group != utls.GREASE_PLACEHOLDER ||
		ks.KeyShares[1].Group != utls.X25519MLKEM768 || ks.KeyShares[2].Group != utls.X25519 {
		t.Errorf("key_shares = %+v", ks.KeyShares)
	}

	// padding 策略：构造使总长落在 (255,512) 的输入应给出对齐 512 的长度。
	pad := spec.Extensions[19].(*utls.UtlsPaddingExtension)
	if n, ok := pad.GetPaddingLen(300); !ok || 300+4+n != 512 {
		t.Errorf("padding_to=512: GetPaddingLen(300) = %d,%v; want total 512", n, ok)
	}
}

// TestGreaseAllRFC8701Values 覆盖 RFC 8701 全部 16 个 GREASE 值在
// ciphers / groups / extensions 三处的传递（P1-T3）。
func TestGreaseAllRFC8701Values(t *testing.T) {
	for hi := 0; hi < 16; hi++ {
		v := uint16(hi)<<12 | 0x0a0a | uint16(hi)<<4 // 0x?a?a
		t.Run(fmt.Sprintf("0x%04x", v), func(t *testing.T) {
			d := &profiles.Detail{
				Ciphers: []string{"0x1301", fmt.Sprintf("0x%04x", v)},
				Extensions: []profiles.Extension{
					{Type: 10, Groups: []string{"X25519", fmt.Sprintf("0x%04x", v)}},
					{Type: v}, // GREASE 扩展占位
				},
			}
			spec, err := CompileDetail(d)
			if err != nil {
				t.Fatalf("CompileDetail: %v", err)
			}
			if spec.CipherSuites[1] != v {
				t.Errorf("cipher grease = %#04x, want %#04x", spec.CipherSuites[1], v)
			}
			groups := spec.Extensions[0].(*utls.SupportedCurvesExtension)
			if groups.Curves[1] != utls.CurveID(v) {
				t.Errorf("group grease = %#04x, want %#04x", groups.Curves[1], v)
			}
			ge := spec.Extensions[1].(*utls.UtlsGREASEExtension)
			if id := extTypeID(t, ge); id != v {
				t.Errorf("grease extension wire id = %#04x, want %#04x", id, v)
			}
		})
	}
}

// TestGreaseTokenPositions 验证 "grease" 字面量在三处映射为 uTLS 占位 0x0a0a。
func TestGreaseTokenPositions(t *testing.T) {
	d := &profiles.Detail{
		Ciphers: []string{"grease", "0x1301"},
		Extensions: []profiles.Extension{
			{Type: 10, Groups: []string{"grease", "X25519"}},
			{Type: 43, Versions: []string{"grease", "0x0304"}},
			{Type: 51, KeyShares: []string{"grease", "X25519"}},
		},
	}
	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatalf("CompileDetail: %v", err)
	}
	if spec.CipherSuites[0] != utls.GREASE_PLACEHOLDER {
		t.Errorf("cipher[0] = %#04x", spec.CipherSuites[0])
	}
	if spec.Extensions[0].(*utls.SupportedCurvesExtension).Curves[0] != utls.GREASE_PLACEHOLDER {
		t.Error("group grease placeholder missing")
	}
	if spec.Extensions[1].(*utls.SupportedVersionsExtension).Versions[0] != utls.GREASE_PLACEHOLDER {
		t.Error("version grease placeholder missing")
	}
	ks := spec.Extensions[2].(*utls.KeyShareExtension)
	if ks.KeyShares[0].Group != utls.GREASE_PLACEHOLDER || len(ks.KeyShares[0].Data) != 1 {
		t.Errorf("key_share grease = %+v", ks.KeyShares[0])
	}
}

// TestExtensionPermutationDeterministic 同种子两次洗牌结果一致；
// GREASE（首位）与 padding（末位）位置不变。
func TestExtensionPermutationDeterministic(t *testing.T) {
	mk := func() *profiles.Detail {
		return &profiles.Detail{
			Ciphers: []string{"0x1301"},
			Grease:  &profiles.GreaseControl{Extensions: true},
			Extensions: []profiles.Extension{
				{Type: 0, SNI: "auto"},
				{Type: 5},
				{Type: 10, Groups: []string{"X25519"}},
				{Type: 13, SigAlgs: []string{"0x0403"}},
				{Type: 16, ALPN: []string{"h2"}},
				{Type: 18},
				{Type: 35},
				{Type: 43, Versions: []string{"0x0304"}},
				{Type: 51, KeyShares: []string{"X25519"}},
				{Type: 21, PaddingTo: 512},
			},
			ExtensionPermutation: true,
		}
	}

	spec1, err := CompileDetailSeeded(mk(), mrand.New(mrand.NewSource(42)))
	if err != nil {
		t.Fatal(err)
	}
	spec2, err := CompileDetailSeeded(mk(), mrand.New(mrand.NewSource(42)))
	if err != nil {
		t.Fatal(err)
	}
	order1 := extTypeOrder(t, spec1)
	order2 := extTypeOrder(t, spec2)
	if !reflect.DeepEqual(order1, order2) {
		t.Fatalf("same seed produced different orders: %v vs %v", order1, order2)
	}
	if _, ok := spec1.Extensions[0].(*utls.UtlsGREASEExtension); !ok {
		t.Errorf("first extension after shuffle = %T, want GREASE (position invariant)", spec1.Extensions[0])
	}
	if _, ok := spec1.Extensions[len(spec1.Extensions)-1].(*utls.UtlsPaddingExtension); !ok {
		t.Errorf("last extension after shuffle = %T, want padding (position invariant)",
			spec1.Extensions[len(spec1.Extensions)-1])
	}

	// 不同种子应产生不同顺序（交换次数够多，碰撞概率可忽略；若真撞上说明洗牌没生效）。
	spec3, err := CompileDetailSeeded(mk(), mrand.New(mrand.NewSource(7)))
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(order1, extTypeOrder(t, spec3)) {
		t.Error("different seeds produced identical order; shuffle likely not applied")
	}
}

// TestCompileDetailConvenienceFields detail 级便捷字段在数组缺省时追加。
func TestCompileDetailConvenienceFields(t *testing.T) {
	limit := uint16(16385)
	d := &profiles.Detail{
		Ciphers:         []string{"0x1301"},
		Extensions:      []profiles.Extension{{Type: 0, SNI: "auto"}},
		CertCompression: []string{"brotli"},
		ALPS:            true,
		RecordSizeLimit: &limit,
		DelegatedCreds:  []string{"0x0403"},
	}
	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{0, 27, 17513, 28, 34}
	if got := extTypeOrder(t, spec); !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}

	// 数组里已有同类型时便捷字段不重复追加。
	d.Extensions = append(d.Extensions, profiles.Extension{Type: 27, CertCompression: []string{"zlib"}})
	spec, err = CompileDetail(d)
	if err != nil {
		t.Fatal(err)
	}
	want = []uint16{0, 27, 17513, 28, 34}
	if got := extTypeOrder(t, spec); !reflect.DeepEqual(got, want) {
		t.Errorf("with explicit ext 27, order = %v, want %v", got, want)
	}
}

// TestCompileDetailErrors 非法输入必须结构化报错，不 panic。
func TestCompileDetailErrors(t *testing.T) {
	cases := []struct {
		name string
		d    *profiles.Detail
	}{
		{"nil detail", nil},
		{"bad cipher hex", &profiles.Detail{Ciphers: []string{"not-hex"}}},
		{"unknown group", &profiles.Detail{Extensions: []profiles.Extension{
			{Type: 10, Groups: []string{"X25519-fake"}}}}},
		{"bad sig alg", &profiles.Detail{Extensions: []profiles.Extension{
			{Type: 13, SigAlgs: []string{"zz"}}}}},
		{"bad rsl data", &profiles.Detail{Extensions: []profiles.Extension{
			{Type: 28, Data: "010203"}}}},
		{"ech bad mode", &profiles.Detail{Extensions: []profiles.Extension{
			{Type: 65037, ECH: &profiles.ECHConfig{Mode: "weird"}}}}},
		{"ech missing config", &profiles.Detail{Extensions: []profiles.Extension{
			{Type: 65037}}}},
		{"bad generic data", &profiles.Detail{Extensions: []profiles.Extension{
			{Type: 65280, Data: "xyz"}}}},
		{"bad convenience cert comp", &profiles.Detail{CertCompression: []string{"lz4"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileDetail(tc.d); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
