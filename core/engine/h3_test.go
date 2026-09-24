package engine

// engine 层 H3 集成测试：force_http3 与 racing 路径。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/quic-go-utls/http3"
	utlsb "github.com/bogdanfinn/utls"

	"github.com/geektls/core/profiles"
)

func startH3EchoServer(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "h3-echo"},
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

	mux := fhttp.NewServeMux()
	mux.HandleFunc("/echo", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		io.Copy(io.Discard, r.Body)
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "path": r.URL.Path, "proto": r.Proto,
		})
	})

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		Handler: mux,
		TLSConfig: http3.ConfigureTLSConfig(&utlsb.Config{
			Certificates: []utlsb.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{"h3"},
		}),
	}
	go srv.Serve(udp)
	t.Cleanup(func() { srv.Close(); udp.Close() })
	return fmt.Sprintf("127.0.0.1:%d", udp.LocalAddr().(*net.UDPAddr).Port)
}

func h3Session(t *testing.T, raceMs int) *Session {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	// bogdanfinn H3 服务端不接受 ECH（见 core/h3 同注释）；剥掉测互操作。
	var noECH []profiles.Extension
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type != 65037 {
			noECH = append(noECH, e)
		}
	}
	p.TLS.Detail.Extensions = noECH
	p.HTTP3 = &profiles.HTTP3Profile{
		Enabled:           true,
		Settings:          [][]uint32{{7, 268435456}},
		PseudoHeaderOrder: []string{"m", "a", "s", "p"},
		GreaseFrames:      true,
		H2RaceMs:          raceMs,
		TransportParams: map[string]uint64{
			"max_idle_timeout": 30000,
			"initial_max_data": 10485760,
		},
	}
	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEngineH3Forced(t *testing.T) {
	addr := startH3EchoServer(t)
	s := h3Session(t, 0)

	resp, err := s.Do(&Request{URL: "https://" + addr + "/echo", ForceHTTP3: true})
	if err != nil {
		t.Fatalf("Do force_http3: %v", err)
	}
	defer resp.Body.Close()
	if resp.UsedProtocol != "h3" {
		t.Errorf("protocol = %q, want h3", resp.UsedProtocol)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	var got map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["proto"] != "HTTP/3.0" {
		t.Errorf("echo proto = %v", got["proto"])
	}
	t.Logf("engine h3 forced OK: %s", body)
}

func TestEngineH3Race(t *testing.T) {
	addr := startH3EchoServer(t)
	s := h3Session(t, 50)

	// race 模式：H3 应赢（本地回环远快于 50ms）
	resp, err := s.Do(&Request{URL: "https://" + addr + "/echo"})
	if err != nil {
		t.Fatalf("Do race: %v", err)
	}
	defer resp.Body.Close()
	if resp.UsedProtocol != "h3" {
		t.Errorf("race winner = %q, want h3 (loopback 应远快于 race_ms)", resp.UsedProtocol)
	}
}

func TestEngineH3Fallback(t *testing.T) {
	// H3 指向一个没有 QUIC 服务端的端口：force_http3 必须报错（不静默回落）。
	s := h3Session(t, 0)
	_, err := s.Do(&Request{URL: "https://127.0.0.1:1/echo", ForceHTTP3: true, TimeoutMs: 2000})
	if err == nil {
		t.Fatal("force_http3 to dead port should fail")
	}
}
