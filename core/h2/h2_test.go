package h2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

func testServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "geektls-h2-test"},
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
		NextProtos:   []string{"h2"},
	}
}

// serveH2 在 net.Pipe 一端起 x/net/http2 服务端。
// 注意：必须先显式握手再 ServeConn——新版 x/net 委托 net/http 的 h2 server
// 会先读 ConnectionState，未握手拿到零值会被当作 TLS<1.2 拒连。
func serveH2(t *testing.T, conn net.Conn, handler http.Handler) {
	t.Helper()
	go func() {
		tlsConn := tls.Server(conn, testServerConfig(t))
		if err := tlsConn.Handshake(); err != nil {
			t.Logf("server handshake: %v", err)
			conn.Close()
			return
		}
		srv := &http2.Server{}
		srv.ServeConn(tlsConn, &http2.ServeConnOpts{
			BaseConfig: &http.Server{Handler: handler},
			Handler:    handler,
		})
	}()
}

func pipePair(t *testing.T, handler http.Handler) net.Conn {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	serveH2(t, serverConn, handler)

	// 客户端侧也要过 TLS（uTLS），不能只把裸 pipe 交给 H2。
	uconn, err := tlscore.Handshake(clientConn, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}, nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return uconn
}

func chromeH2() *profiles.HTTP2Profile {
	return &profiles.HTTP2Profile{
		Settings:          [][]uint32{{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144}},
		WindowUpdate:      15663105,
		PseudoHeaderOrder: []string{"m", "a", "s", "p"},
	}
}

func TestH2RoundTrip(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Len", fmt.Sprintf("%d", len(body)))
		fmt.Fprint(w, "hello h2")
	})
	conn := pipePair(t, handler)

	cc, err := NewClientConn(conn, chromeH2())
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	resp, err := Do(cc, "POST", "https://example.com/echo",
		[][2]string{{"user-agent", "geektls-test"}}, io.NopCloser(
			io.LimitReader(zeroReader{}, 1024)).(io.Reader))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Echo-Len"); got != "1024" {
		t.Errorf("server saw body len %s, want 1024", got)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello h2" {
		t.Errorf("body = %q", b)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestH2Streaming 流式上下行 100MB，RSS 增长必须远小于载荷（不一次性加载）。
func TestH2Streaming(t *testing.T) {
	const total = 100 << 20 // 100MB

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 上行：流式读丢
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("X-Up", fmt.Sprintf("%d", n))
		// 下行：流式写零
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		left := int64(total)
		chunk := make([]byte, 1<<20)
		for left > 0 {
			m := int64(len(chunk))
			if m > left {
				m = left
			}
			if _, err := w.Write(chunk[:m]); err != nil {
				return
			}
			left -= m
		}
	})
	conn := pipePair(t, handler)

	cc, err := NewClientConn(conn, chromeH2())
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	pr, pw := io.Pipe()
	go func() {
		left := int64(total)
		chunk := make([]byte, 1<<20)
		for left > 0 {
			m := int64(len(chunk))
			if m > left {
				m = left
			}
			if _, err := pw.Write(chunk[:m]); err != nil {
				return
			}
			left -= m
		}
		pw.Close()
	}()

	resp, err := Do(cc, "POST", "https://example.com/stream", nil, pr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	down, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if down != total {
		t.Errorf("downloaded %d, want %d", down, total)
	}
	if got := resp.Header.Get("X-Up"); got != fmt.Sprintf("%d", total) {
		t.Errorf("server saw upload %s, want %d", got, total)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	const tolerance = 64 << 20 // 64MB
	if growth > tolerance {
		t.Errorf("heap grew %d bytes on 100MB streaming (tolerance %d)", growth, tolerance)
	}
	t.Logf("streamed 2x100MB, heap growth = %d KB", growth/1024)
}
