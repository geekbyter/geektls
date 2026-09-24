package h3

import (
	"bytes"
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

func testH3Server(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "h3-test"},
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
	tlsCfg := &utlsb.Config{
		Certificates: []utlsb.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h3"},
	}

	mux := fhttp.NewServeMux()
	mux.HandleFunc("/echo", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "path": r.URL.Path, "body": string(body),
			"proto": r.Proto, "ua": r.Header.Get("User-Agent"),
		})
	})

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		Handler:   mux,
		TLSConfig: http3.ConfigureTLSConfig(tlsCfg),
	}
	go srv.Serve(udp)
	t.Cleanup(func() { srv.Close(); udp.Close() })
	return fmt.Sprintf("127.0.0.1:%d", udp.LocalAddr().(*net.UDPAddr).Port)
}

func TestH3RoundTrip(t *testing.T) {
	addr := testH3Server(t)

	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	// bogdanfinn H3 服务端不接受 ECH（其 QUIC server 的兼容面限制）；
	// 本用例测互操作，剥掉 ECH。ECH 线上形态由 sniff 测试另行断言。
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
		TransportParams: map[string]uint64{
			"max_idle_timeout": 30000,
			"initial_max_data": 10485760,
		},
	}

	tr, err := NewTransport(p, true)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	req, err := fhttp.NewRequest("POST", "https://"+addr+"/echo", bytes.NewReader([]byte("h3-ping")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("user-agent", "geektls-h3")

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("h3 roundtrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("bad echo json: %v (%s)", err, body)
	}
	if got["method"] != "POST" || got["body"] != "h3-ping" || got["proto"] != "HTTP/3.0" {
		t.Errorf("echo = %v", got)
	}
	t.Logf("h3 roundtrip OK: %s", body)
}
