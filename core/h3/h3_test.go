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

	fhttp "github.com/geekbyter/geektls/core/third_party/fhttp"
	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/http3"
	utlsb "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"

	"github.com/geekbyter/geektls/core/profiles"
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
	return serveH3(t, &utlsb.Config{
		Certificates: []utlsb.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h3"},
	})
}

// serveH3 用给定服务端 TLS 配置起一个回环 H3 服务，返回 127.0.0.1:port。
func serveH3(t *testing.T, tlsCfg *utlsb.Config) string {
	t.Helper()

	mux := fhttp.NewServeMux()
	mux.HandleFunc("/echo", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		clientCN := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "path": r.URL.Path, "body": string(body),
			"proto": r.Proto, "ua": r.Header.Get("User-Agent"), "client_cn": clientCN,
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

	p := chrome133NoECH(t)
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

	tr, err := NewTransport(p, TLSSettings{InsecureSkipVerify: true})
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

// chrome133NoECH：bogdanfinn H3 服务端不接受 ECH（其 QUIC server 兼容面限制），
// 回环互操作用例统一剥掉扩展 65037；ECH 线上形态由 sniff 测试另行断言。
func chrome133NoECH(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	var noECH []profiles.Extension
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type != 65037 {
			noECH = append(noECH, e)
		}
	}
	p.TLS.Detail.Extensions = noECH
	return p
}

// h3PKI：一把 CA + 它签发的服务端（SAN 127.0.0.1）与客户端证书 + 只信该 CA 的池。
type h3PKI struct {
	Server utlsb.Certificate
	Client utlsb.Certificate
	Pool   *x509.CertPool
}

func newH3PKI(t *testing.T) h3PKI {
	t.Helper()
	mkKey := func() *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	base := func(cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
		}
	}
	sign := func(tmpl, parent *x509.Certificate, pub *rsa.PublicKey, parentKey *rsa.PrivateKey) ([]byte, *x509.Certificate) {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return der, leaf
	}

	caKey := mkKey()
	caTmpl := base("geektls h3 test CA")
	caTmpl.IsCA, caTmpl.KeyUsage = true, x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature
	caDER, caLeaf := sign(caTmpl, caTmpl, &caKey.PublicKey, caKey)

	leaf := func(cn string, ext x509.ExtKeyUsage) utlsb.Certificate {
		key := mkKey()
		tmpl := base(cn)
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{ext}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
		der, _ := sign(tmpl, caLeaf, &key.PublicKey, caKey)
		return utlsb.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}

	pool := x509.NewCertPool()
	pool.AddCert(caLeaf)
	return h3PKI{
		Server: leaf("127.0.0.1", x509.ExtKeyUsageServerAuth),
		Client: leaf("client.geektls.test", x509.ExtKeyUsageClientAuth),
		Pool:   pool,
	}
}

// TestH3TLSSettings：证明 TLSSettings 的 RootCAs / Certificates 真的接到了 QUIC 内层
// 握手。QUIC 侧用的是 bogdanfinn/utls 的类型（与 TCP 侧 refraction/utls 不同源），
// 光"能编译"说明不了接线正确，必须跑一次带 ClientAuth 的回环握手。
func TestH3TLSSettings(t *testing.T) {
	pki := newH3PKI(t)
	addr := serveH3(t, &utlsb.Config{
		Certificates: []utlsb.Certificate{pki.Server},
		ClientCAs:    pki.Pool,
		ClientAuth:   utlsb.RequireAndVerifyClientCert,
		NextProtos:   []string{"h3"},
	})

	post := func(settings TLSSettings) (map[string]any, error) {
		tr, err := NewTransport(chrome133NoECH(t), settings)
		if err != nil {
			return nil, err
		}
		defer tr.Close()
		req, err := fhttp.NewRequest("POST", "https://"+addr+"/echo", bytes.NewReader([]byte("h3-mtls")))
		if err != nil {
			return nil, err
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var got map[string]any
		return got, json.Unmarshal(mustReadAll(t, resp.Body), &got)
	}

	// 1) 无 CA：服务端证书由测试 CA 签发，系统信任库不认识 ⇒ 必须失败。
	if _, err := post(TLSSettings{}); err == nil {
		t.Fatal("没有 RootCAs 却握手成功：RootCAs 未接线")
	} else {
		t.Logf("no-ca rejected: %v", err)
	}
	// 2) 只给 CA 不给客户端证书：服务端索要证书 ⇒ 仍然失败。
	if _, err := post(TLSSettings{RootCAs: pki.Pool}); err == nil {
		t.Fatal("没有客户端证书却通过：Certificates 未接线")
	}
	// 3) CA + 客户端证书 ⇒ 通过，且服务端看到的就是我们给的证书 CN。
	got, err := post(TLSSettings{RootCAs: pki.Pool, Certificates: []utlsb.Certificate{pki.Client}})
	if err != nil {
		t.Fatalf("mTLS h3: %v", err)
	}
	if got["client_cn"] != "client.geektls.test" || got["body"] != "h3-mtls" {
		t.Errorf("echo = %v", got)
	}
	// 4) InsecureSkipVerify 放行证书链，但服务端仍然索要客户端证书 ⇒ 必须连证书一起给。
	if _, err := post(TLSSettings{InsecureSkipVerify: true}); err == nil {
		t.Error("服务端 RequireAndVerifyClientCert，无客户端证书却通过")
	}
	if _, err := post(TLSSettings{InsecureSkipVerify: true,
		Certificates: []utlsb.Certificate{pki.Client}}); err != nil {
		t.Errorf("insecure_skip_verify + 客户端证书应放行: %v", err)
	}
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
