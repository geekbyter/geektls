package tlscore

import (
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

// captureCHHex 真实握手一次并返回客户端写出的 ClientHello record hex
// （与 grease_rerandomize_test.go 同一链路：compile → net.Pipe 握手 → 抓字节）。
func captureCHHex(t *testing.T, d *profiles.Detail) string {
	t.Helper()
	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatalf("CompileDetail: %v", err)
	}
	serverCfg := newTestServerConfig(t)
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
	defer uconn.Close()
	if rec.buf.Len() == 0 {
		t.Fatal("没有抓到客户端写出的字节")
	}
	return hex.EncodeToString(rec.buf.Bytes())
}

// 裸 hex（pcap / 抓包工具 / 采集端直接给出的 ClientHello record 字节）必须能直接进
// CheckProfile——这是"抓包 -> 装载"链路的入口。此前只认 {"clienthello_hex":...} 包装
// JSON，README 却宣称支持 hex，口径与实现脱节（2026-09-29 补齐）。
func TestCheckProfileAcceptsBareClientHelloHex(t *testing.T) {
	preset, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatalf("preset chrome_133: %v", err)
	}
	if preset.TLS == nil || preset.TLS.Detail == nil {
		t.Fatal("preset 没有 tls.detail")
	}
	hexStr := captureCHHex(t, preset.TLS.Detail)

	resBare, err := CheckProfile(hexStr)
	if err != nil {
		t.Fatalf("裸 hex 被拒: %v", err)
	}
	resWrapped, err := CheckProfile(`{"clienthello_hex":"` + hexStr + `"}`)
	if err != nil {
		t.Fatalf("包装 JSON 被拒: %v", err)
	}
	if resBare.JA4 != resWrapped.JA4 || resBare.JA3Hash != resWrapped.JA3Hash {
		t.Errorf("两种形态结果不一致: bare ja4=%s ja3h=%s / wrapped ja4=%s ja3h=%s",
			resBare.JA4, resBare.JA3Hash, resWrapped.JA4, resWrapped.JA3Hash)
	}
	if len(resBare.JA4) < 10 {
		t.Errorf("JA4 异常: %q", resBare.JA4)
	}
}

// 形状判定的正负例：避免把 JA3/JA4/任意文本误判成 CH hex。
func TestIsClientHelloHexShape(t *testing.T) {
	yes := "160301060c010006080303" + strings.Repeat("ab", 40)
	if !isClientHelloHexShape(yes) {
		t.Errorf("真实形状的 CH hex 应被判 true")
	}
	no := []string{
		"t13d1516h2_8daaf6152771_e2d80978ab2e",  // JA4 短哈希
		"771,4865-4866-4867,0-41-51,29,0",       // JA3
		"t13d1516h2_002f,0035,009c,009d_0904",   // JA4R 形状
		"xyz",                                    // 非 hex
		"1603",                                   // 太短
		"1703010020" + strings.Repeat("ab", 16),  // record type 0x17（app-data）
		strings.Repeat("ab", 64),                 // 无 TLS 头
	}
	for _, s := range no {
		if isClientHelloHexShape(s) {
			t.Errorf("不应判定为 CH hex: %q", s)
		}
	}
}
