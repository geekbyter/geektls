package geektls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/geektls/core/engine"
)

func startEcho(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "echo"},
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
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "proto": r.Proto, "body": string(body),
		})
	})
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	}))
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return "https://" + ln.Addr().String()
}

func TestRoundTripper(t *testing.T) {
	base := startEcho(t)
	rt, err := NewRoundTripper("chrome_133", &Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(base + "/echo")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("proto = %s, want HTTP/2", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["method"] != "GET" || got["proto"] != "HTTP/2.0" {
		t.Errorf("echo = %v", got)
	}
	t.Logf("roundtripper echo OK: %s", body)
}

func TestSessionSelfCheck(t *testing.T) {
	base := startEcho(t)
	s, err := NewSession("firefox_120", &Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Do(&engine.Request{Method: "GET", URL: base + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if len(resp.SelfCheck.JA3Hash) != 32 || resp.SelfCheck.JA4 == "" {
		t.Errorf("selfcheck = %+v", resp.SelfCheck)
	}
	t.Logf("go binding ja4=%s", resp.SelfCheck.JA4)
}
