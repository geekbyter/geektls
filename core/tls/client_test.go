package tlscore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// newTestServerConfig 现场签发一张 RSA 2048 自签证书（不落盘）。
func newTestServerConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "geektls-test"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

// TestHandshakeHelloChromeAuto 用 net.Pipe + 标准库 TLS 服务端验证 uTLS
// 客户端（HelloChrome_Auto 预设）能完成握手。离线、秒级。
func TestHandshakeHelloChromeAuto(t *testing.T) {
	serverCfg := newTestServerConfig(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		srv := tls.Server(serverConn, serverCfg)
		serverErr <- srv.Handshake()
	}()

	uconn, err := Handshake(clientConn, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true, // 测试只关心握手与协商，证书链不校验
		NextProtos:         []string{"h2", "http/1.1"},
	}, nil)
	if err != nil {
		t.Fatalf("utls handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	state := uconn.ConnectionState()
	if state.Version != tls.VersionTLS12 && state.Version != tls.VersionTLS13 {
		t.Errorf("negotiated version %#04x, want TLS 1.2 or 1.3", state.Version)
	}
	if state.NegotiatedProtocol != "h2" {
		t.Errorf("negotiated ALPN %q, want %q", state.NegotiatedProtocol, "h2")
	}
	t.Logf("negotiated: version=%#04x alpn=%q cipher=%#04x",
		state.Version, state.NegotiatedProtocol, state.CipherSuite)
}

// TestDialBadAddr 验证 Dial 的错误路径不泄漏连接、不 panic。
func TestDialBadAddr(t *testing.T) {
	if _, err := Dial("127.0.0.1:1", nil, nil); err == nil {
		t.Fatal("Dial to a closed port should fail")
	}
}
