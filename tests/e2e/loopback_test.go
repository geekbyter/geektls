// Package e2e 是 L1 回环验证 harness：对每个内置预设，编译 → 真实握手
// 抓字节 → hex 解析回读 → 三方断言（JA3/JA4、扩展序、cipher 序一致）。
// 无外部网络依赖，离线可跑。
package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
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

func loopbackServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "geektls-e2e"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

func isGrease(v uint16) bool { return v>>8 == v&0xff && v&0xf == 0xa }

func normalizeGrease(v uint16) uint16 {
	if isGrease(v) {
		return 0x0a0a
	}
	return v
}

// TestPresetsLoopback 全预设 L1 回环矩阵。
func TestPresetsLoopback(t *testing.T) {
	serverCfg := loopbackServerConfig(t)

	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			spec1, err := tlscore.CompileDetail(p.TLS.Detail)
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
			if _, err := tlscore.Handshake(rec, &utls.Config{
				ServerName:         "example.com", // 解析 sni:"auto" 占位
				InsecureSkipVerify: true,
			}, spec1); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			// 不调用 UConn.Close：close_notify 在 net.Pipe 上会等对端读，拖慢测试。

			parsed, warnings, err := profiles.FromClientHelloHex(hex.EncodeToString(rec.buf.Bytes()))
			if err != nil {
				t.Fatalf("FromClientHelloHex: %v", err)
			}
			for _, w := range warnings {
				t.Logf("parse warning: %s: %s", w.Code, w.Message)
			}
			spec2, err := tlscore.CompileDetail(parsed.TLS.Detail)
			if err != nil {
				t.Fatalf("recompile: %v", err)
			}

			// 三方一致：JA3 / JA4
			if ja3a, ja3b := tlscore.ComputeJA3(spec1), tlscore.ComputeJA3(spec2); ja3a != ja3b {
				t.Errorf("JA3 mismatch:\n  spec: %s\n  wire: %s", ja3a, ja3b)
			}
			if ja4a, ja4b := tlscore.ComputeJA4(spec1), tlscore.ComputeJA4(spec2); ja4a != ja4b {
				t.Errorf("JA4 mismatch:\n  spec: %s\n  wire: %s", ja4a, ja4b)
			}

			// cipher 序（GREASE 归一化）
			if len(spec1.CipherSuites) != len(spec2.CipherSuites) {
				t.Fatalf("cipher count %d vs wire %d", len(spec1.CipherSuites), len(spec2.CipherSuites))
			}
			for i := range spec1.CipherSuites {
				if normalizeGrease(spec1.CipherSuites[i]) != normalizeGrease(spec2.CipherSuites[i]) {
					t.Errorf("cipher[%d]: spec %#04x vs wire %#04x", i, spec1.CipherSuites[i], spec2.CipherSuites[i])
				}
			}

			t.Logf("%s wire=%dB ja4=%s", name, rec.buf.Len(), tlscore.ComputeJA4(spec2))
		})
	}
}
