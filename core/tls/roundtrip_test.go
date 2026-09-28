package tlscore

// hex 入口的线上 round-trip 测试：detail → 编译 spec → 经 net.Pipe 对内存
// 服务端真实握手，抓客户端写出的 ClientHello 字节 → FromClientHelloHex 解析
// → 重新编译 → 比较 cipher 列表与扩展顺序（GREASE 值归一化）。
// 这同时验证了 T2 编译器输出在真实线上字节层的正确性和 T5 hex 解析器。

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

// recordingConn 记录客户端写出的全部字节。
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.buf.Write(p)
	return c.Conn.Write(p)
}

// normalizeGrease 把任何 GREASE 值归一化为占位 0x0a0a（线上值是随机的）。
func normalizeGrease(v uint16) uint16 {
	if isGreaseUint16(v) {
		return utls.GREASE_PLACEHOLDER
	}
	return v
}

func TestClientHelloHexRoundTrip(t *testing.T) {
	detail := &profiles.Detail{
		Ciphers: []string{"grease", "0x1301", "0x1302", "0x1303", "0xc02b", "0xc02f"},
		Extensions: []profiles.Extension{
			{Type: 0x2a2a}, // GREASE 扩展（首位，Chrome 风格）
			{Type: 0, SNI: "example.com"},
			{Type: 23},
			{Type: 35},
			{Type: 5},
			{Type: 10, Groups: []string{"grease", "X25519", "P-256", "P-384"}},
			{Type: 11, PointFormats: []uint8{0}},
			{Type: 13, SigAlgs: []string{"0x0403", "0x0804", "0x0401", "0x0503", "0x0805", "0x0501", "0x0806", "0x0601"}},
			{Type: 16, ALPN: []string{"h2", "http/1.1"}},
			{Type: 18},
			{Type: 45, PSKModes: []uint8{1}},
			{Type: 43, Versions: []string{"grease", "0x0304", "0x0303"}},
			{Type: 51, KeyShares: []string{"grease", "X25519", "P-256"}},
			{Type: 27, CertCompression: []string{"brotli"}},
		},
	}
	spec1, err := CompileDetail(detail)
	if err != nil {
		t.Fatalf("CompileDetail: %v", err)
	}

	serverCfg := newTestServerConfig(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// 服务端只负责读走字节并完成握手；结果不重要（握手失败也照样抓到了 ClientHello）。
		srv := tls.Server(serverConn, serverCfg)
		_ = srv.Handshake()
		srv.Close()
	}()

	rec := &recordingConn{Conn: clientConn}
	uconn, err := Handshake(rec, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}, spec1)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	uconn.Close()

	captured := rec.buf.Bytes()
	if len(captured) < 64 {
		t.Fatalf("captured only %d bytes", len(captured))
	}

	p, warnings, err := profiles.FromClientHelloHex(hex.EncodeToString(captured))
	if err != nil {
		t.Fatalf("FromClientHelloHex: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %+v", warnings)
	}
	spec2, err := CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatalf("recompile: %v", err)
	}

	// ciphers：GREASE 归一化后逐一相等
	if len(spec1.CipherSuites) != len(spec2.CipherSuites) {
		t.Fatalf("cipher count %d vs %d", len(spec1.CipherSuites), len(spec2.CipherSuites))
	}
	for i := range spec1.CipherSuites {
		if normalizeGrease(spec1.CipherSuites[i]) != normalizeGrease(spec2.CipherSuites[i]) {
			t.Errorf("cipher[%d] = %#04x vs wire %#04x", i, spec1.CipherSuites[i], spec2.CipherSuites[i])
		}
	}

	// 扩展线上顺序：GREASE 归一化后逐一相等（GREASE 扩展 type 每次编译重取随机值，
	// 见 grease_rerandomize_test.go；归一化后位置与数量必须逐项保真）。
	ids1 := normalizeGreaseIDs(specExtIDs(t, spec1))
	ids2 := normalizeGreaseIDs(specExtIDs(t, spec2))
	if len(ids1) != len(ids2) {
		t.Fatalf("extension count %d vs %d: %v vs %v", len(ids1), len(ids2), ids1, ids2)
	}
	for i := range ids1 {
		if ids1[i] != ids2[i] {
			t.Errorf("extension order mismatch at %d: %v vs %v", i, ids1, ids2)
			break
		}
	}

	// 自算指纹一致性（同字节必然同指纹）
	if ComputeJA3(spec1) != ComputeJA3(spec2) {
		t.Errorf("JA3 mismatch after round-trip:\n%s\n%s", ComputeJA3(spec1), ComputeJA3(spec2))
	}
	if ComputeJA4(spec1) != ComputeJA4(spec2) {
		t.Errorf("JA4 mismatch after round-trip:\n%s\n%s", ComputeJA4(spec1), ComputeJA4(spec2))
	}
	t.Logf("round-trip JA4: %s", ComputeJA4(spec2))
}

func specExtIDs(t *testing.T, spec *utls.ClientHelloSpec) []uint16 {
	t.Helper()
	out := make([]uint16, 0, len(spec.Extensions))
	for _, e := range spec.Extensions {
		id, ok := extensionTypeID(e)
		if !ok {
			t.Fatalf("unknown extension type %T", e)
		}
		out = append(out, id)
	}
	return out
}

// normalizeGreaseIDs 把扩展 id 列表里的 GREASE 值统一为占位常量。
func normalizeGreaseIDs(ids []uint16) []uint16 {
	out := make([]uint16, len(ids))
	for i, v := range ids {
		out[i] = normalizeGrease(v)
	}
	return out
}
