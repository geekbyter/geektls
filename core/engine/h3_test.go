package engine

// engine 层 H3 集成测试：force_http3 与 racing 路径。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
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

func h3TestCert(t *testing.T) ([]byte, *rsa.PrivateKey) {
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
	return der, key
}

func h3TestServer(t *testing.T, mux *fhttp.ServeMux) string {
	t.Helper()
	der, key := h3TestCert(t)
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

func startH3EchoServer(t *testing.T) string {
	t.Helper()
	mux := fhttp.NewServeMux()
	mux.HandleFunc("/echo", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		io.Copy(io.Discard, r.Body)
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "path": r.URL.Path, "proto": r.Proto,
		})
	})
	return h3TestServer(t, mux)
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

// TestReadTimeoutH3：A6 的 QUIC 侧——body 挂死必须按 read_timeout_ms 断开，
// 且取消要真的传到线上（服务端 handler 的 r.Context() 被取消）。
func TestReadTimeoutH3(t *testing.T) {
	handlerDone := make(chan struct{}, 1)
	mux := fhttp.NewServeMux()
	mux.HandleFunc("/stall", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		defer func() { handlerDone <- struct{}{} }()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "x")
		if fl, ok := w.(fhttp.Flusher); ok {
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	})
	addr := h3TestServer(t, mux)

	s := h3Session(t, 0)
	resp, err := s.Do(&Request{
		URL: "https://" + addr + "/stall", ForceHTTP3: true, ReadTimeoutMs: 300,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.UsedProtocol != "h3" {
		t.Fatalf("protocol = %q, want h3", resp.UsedProtocol)
	}
	buf := make([]byte, 16)
	if n, err := resp.Body.Read(buf); err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("首字节 = (%d, %v), want 1 'x'", n, err)
	}
	start := time.Now()
	if _, err := resp.Body.Read(buf); !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("超时读 err = %v, want ErrReadTimeout", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("超时耗时 %v：取消被底层 Close 挂住", d)
	}
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Error("服务端 handler 未被放掉：H3 超时没有把取消传到线上")
	}
}
