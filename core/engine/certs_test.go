package engine

// 自持信任库（CA bundle）与 mTLS 客户端证书的离线闭环测试：自建一套 PKI +
// 需要客户端证书的服务端，逐项断言 verify=<path>/cert=<path> 真的生效
// （A5 的动机正是"传了 CA 路径被静默丢弃"）。全部走 127.0.0.1，不碰外网。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/geekbyter/geektls/core/profiles"
)

type testPKI struct {
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caPEM     string
	server    tls.Certificate
	serverPEM string
	serverKey string
	client    tls.Certificate
	clientPEM string
	clientKey string
}

func encodeCertDER(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func encodeKey(key *ecdsa.PrivateKey) string {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// newTestPKI 造一套最小可用 PKI：自签 CA + 由 CA 签的服务器证书（SAN 覆盖
// 127.0.0.1/localhost）+ 由 CA 签的客户端证书。
func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	caKey := newKey()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "geektls-test-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leaf := func(cn string, server bool) (tls.Certificate, string, string) {
		key := newKey()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			tmpl.DNSNames = []string{"localhost"}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(t, der)},
			encodeCertDER(der), encodeKey(key)
	}

	srv, srvPEM, srvKey := leaf("echo.geektls.test", true)
	cli, cliPEM, cliKey := leaf("client.geektls.test", false)

	return &testPKI{
		caKey: caKey, caCert: caCert, caPEM: encodeCertDER(caDER),
		server: srv, serverPEM: srvPEM, serverKey: srvKey,
		client: cli, clientPEM: cliPEM, clientKey: cliKey,
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// startPKIServer 起一个由 testPKI 背书的 HTTPS 服务；requireClientCert 为真时
// 双向认证（并校验客户端证书由本 CA 签出）。/whoami 回报看到的客户端证书 CN。
func startPKIServer(t *testing.T, pki *testPKI, requireClientCert bool, alpn []string) string {
	t.Helper()
	caPool := x509.NewCertPool()
	caPool.AddCert(pki.caCert)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		NextProtos:   alpn,
		ClientAuth:   tls.NoClientCert,
	}
	if requireClientCert {
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		cn := "-"
		if len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		fmt.Fprintf(w, "proto=%s client_cn=%s", r.Proto, cn)
	})

	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(tls.NewListener(ln, tlsCfg))
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return "https://" + ln.Addr().String()
}

func sessionWith(t *testing.T, opts SessionOptions) *Session {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func getP(t *testing.T, s *Session, url string) string {
	t.Helper()
	resp, err := s.Do(&Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return readBody(t, resp)
}

// TestCaBundleEnablesVerification：系统不信任我们的自签 CA ⇒ 默认必须失败；
// 给出 CA bundle 后必须成功，且 inline PEM / 文件 / 目录三种给法等价。
func TestCaBundleEnablesVerification(t *testing.T) {
	pki := newTestPKI(t)
	url := startPKIServer(t, pki, false, []string{"h2", "http/1.1"}) + "/whoami"

	if _, err := sessionWith(t, SessionOptions{}).Do(&Request{URL: url}); err == nil {
		t.Fatal("无 CA bundle 时应当校验失败，却成功了")
	} else if !strings.Contains(strings.ToLower(err.Error()), "x509") &&
		!strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Errorf("失败原因应是证书校验，实得：%v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geektls-ca.pem"), []byte(pki.caPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, bundle string }{
		{"inline PEM", pki.caPEM},
		{"file path", filepath.Join(dir, "geektls-ca.pem")},
		{"dir path", dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := getP(t, sessionWith(t, SessionOptions{CaBundle: tc.bundle}), url)
			if !strings.Contains(got, "proto=HTTP/2.0") {
				t.Errorf("期望 h2 协商成功，实得 %q", got)
			}
		})
	}

	// InsecureSkipVerify 优先级：即便 CA 不对也应放行（既有行为不变）。
	if got := getP(t, sessionWith(t, SessionOptions{InsecureSkipVerify: true}), url); !strings.Contains(got, "proto=") {
		t.Errorf("skip verify 路径异常：%q", got)
	}
}

// TestMutualTLS：服务端索要客户端证书。缺证书必须握手失败；分开给 / 同文件给
// 两种形态都要成功，且服务端能看到证书 CN。
func TestMutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	url := startPKIServer(t, pki, true, []string{"h2", "http/1.1"}) + "/whoami"

	if _, err := sessionWith(t, SessionOptions{InsecureSkipVerify: true}).Do(&Request{URL: url}); err == nil {
		t.Fatal("服务端索要客户端证书，未提供时应当失败")
	}

	// 同文件形态（requests 允许 cert=<内含证书+私钥的文件>）。
	combined := pki.clientPEM + pki.clientKey

	for _, tc := range []struct {
		name string
		opts SessionOptions
	}{
		{"split cert/key", SessionOptions{InsecureSkipVerify: true, ClientCert: pki.clientPEM, ClientKey: pki.clientKey}},
		{"combined file", SessionOptions{InsecureSkipVerify: true, ClientCert: combined}},
		{"with ca bundle", SessionOptions{CaBundle: pki.caPEM, ClientCert: pki.clientPEM, ClientKey: pki.clientKey}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := getP(t, sessionWith(t, tc.opts), url)
			if !strings.Contains(got, "client_cn=client.geektls.test") {
				t.Errorf("服务端未看到客户端证书：%q", got)
			}
		})
	}
}

// TestH1PathUsesSameCertMaterial：证书材料对 http/1.1 与 h2 两条路径同样生效。
func TestH1PathUsesSameCertMaterial(t *testing.T) {
	pki := newTestPKI(t)
	url := startPKIServer(t, pki, false, []string{"http/1.1"}) + "/whoami"

	got := getP(t, sessionWith(t, SessionOptions{CaBundle: pki.caPEM}), url)
	if !strings.Contains(got, "proto=HTTP/1.1") {
		t.Errorf("期望 h1 路径，实得 %q", got)
	}
}

// TestCertConfigErrorsAtSessionNew：坏配置必须在建会话时结构化报错，
// 不能拖到握手期，更不能静默忽略。
func TestCertConfigErrorsAtSessionNew(t *testing.T) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		opts SessionOptions
		want string
	}{
		{"CA 是坏 PEM", SessionOptions{CaBundle: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}, "没有解析成功的 PEM"},
		{"CA 像路径但读不到", SessionOptions{CaBundle: "not a pem at all"}, "读不到文件"},
		{"空目录当 CA", func() SessionOptions {
			return SessionOptions{CaBundle: t.TempDir()}
		}(), "没有 .pem/.crt/.cer"},
		{"只给私钥", SessionOptions{ClientKey: "x"}, "client_key 需要与 client_cert"},
		{"证书无私钥", SessionOptions{ClientCert: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}, "未找到私钥段"},
		{"证书与私钥不匹配", SessionOptions{ClientCert: newTestPKI(t).clientPEM, ClientKey: newTestPKI(t).clientKey}, "配对失败"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSession(p, tc.opts)
			if err == nil {
				t.Fatal("期望报错，实际成功")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("报错应含 %q，实得 %v", tc.want, err)
			}
		})
	}
}
