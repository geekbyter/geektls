package tlscore

// GREASE 重随机化回归：GREASE 值必须**逐连接重新取值**（真浏览器行为）。
// 若某个位置的 GREASE 值在多连接间恒定，等于给检测方留了一个稳定的强特征。
//
// 采样位置：ciphers[0] / sig_algs[0] / supported_versions[0] / supported_groups[0] /
// key_shares[0] / GREASE 扩展 type。
// 判定：6 次握手中同一位置至少出现 2 种取值（GREASE 有 16 个候选值，
// 6 次全同的概率约 16^-5 ≈ 1e-6，不构成 flaky；采样数取 6 而非更多是为控制
// net.Pipe 逐次握手带来的测试耗时）。
//
// 背景（2026-09-24 实测）：uTLS 只在部分字段的握手期替换 GREASE_PLACEHOLDER
// （ciphers / curves / versions / key_share），对 **sig_algs 与扩展 type 原样写出**；
// 后两者由 compile 在编译期（每次拨号一次）自行取值，见 compile.go 的 randomGrease。

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

// greaseSlots 取出 detail 里各 GREASE 采样位置的**线上原值**（不做归一化）。
func greaseSlots(d *profiles.Detail) map[string]string {
	out := map[string]string{}
	if len(d.Ciphers) > 0 {
		out["ciphers[0]"] = d.Ciphers[0]
	}
	for _, e := range d.Extensions {
		if isGreaseUint16(e.Type) {
			out["grease_ext_type"] = fmt.Sprintf("%#04x", e.Type)
		}
		switch e.Type {
		case 13:
			if len(e.SigAlgs) > 0 {
				out["sig_algs[0]"] = e.SigAlgs[0]
			}
		case 43:
			if len(e.Versions) > 0 {
				out["versions[0]"] = e.Versions[0]
			}
		case 10:
			if len(e.Groups) > 0 {
				out["groups[0]"] = e.Groups[0]
			}
		case 51:
			if len(e.KeyShares) > 0 {
				out["key_shares[0]"] = e.KeyShares[0]
			}
		}
	}
	return out
}

// captureClientHello 真实握手一次并抓取客户端写出的 ClientHello，解析回 detail。
// （与 roundtrip_test.go 同一链路：compile → net.Pipe 握手 → 抓字节 → FromClientHelloHex）
// serverCfg 由调用方复用：证书生成开销大，逐次新建会让测试慢一个数量级。
func captureClientHello(t *testing.T, d *profiles.Detail, serverCfg *tls.Config) *profiles.Detail {
	t.Helper()
	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatalf("CompileDetail: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		srv := tls.Server(serverConn, serverCfg)
		_ = srv.Handshake()
		srv.Close()
	}()

	rec := &recordingConn{Conn: clientConn}
	uconn, err := Handshake(rec, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}, spec)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	uconn.Close()

	p, _, err := profiles.FromClientHelloHex(hex.EncodeToString(rec.buf.Bytes()))
	if err != nil {
		t.Fatalf("FromClientHelloHex: %v", err)
	}
	if p.TLS == nil || p.TLS.Detail == nil {
		t.Fatal("no detail parsed")
	}
	return p.TLS.Detail
}

func TestGreaseRerandomization(t *testing.T) {
	detail := &profiles.Detail{
		Ciphers: []string{"grease", "0x1301", "0x1302", "0xc02b", "0xc02f"},
		Extensions: []profiles.Extension{
			{Type: 0x2a2a}, // GREASE 扩展（Chrome 首位）
			{Type: 0, SNI: "example.com"},
			{Type: 13, SigAlgs: []string{"grease", "0x0403", "0x0804"}},
			{Type: 11, PointFormats: []uint8{0}},
			{Type: 10, Groups: []string{"grease", "X25519", "P-256"}},
			{Type: 16, ALPN: []string{"h2", "http/1.1"}},
			{Type: 43, Versions: []string{"grease", "0x0304", "0x0303"}},
			{Type: 51, KeyShares: []string{"grease", "X25519"}},
			{Type: 45, PSKModes: []uint8{1}},
			{Type: 23},
			{Type: 35},
		},
	}

	const n = 6
	serverCfg := newTestServerConfig(t)
	seen := map[string]map[string]bool{}
	for i := 0; i < n; i++ {
		for k, v := range greaseSlots(captureClientHello(t, detail, serverCfg)) {
			if seen[k] == nil {
				seen[k] = map[string]bool{}
			}
			seen[k][v] = true
		}
	}

	for _, k := range []string{"ciphers[0]", "sig_algs[0]", "versions[0]", "groups[0]", "key_shares[0]", "grease_ext_type"} {
		vals := seen[k]
		if len(vals) == 0 {
			t.Errorf("采样位置 %s 未出现在结果里（编译或解析链路有问题）", k)
			continue
		}
		if len(vals) < 2 {
			t.Errorf("GREASE 位置 %s 在 %d 次握手中恒定不变（取值 %v）——未逐连接重随机化", k, n, vals)
			continue
		}
		t.Logf("%s：%d 次握手出现 %d 种取值 %v", k, n, len(vals), vals)
	}
}
