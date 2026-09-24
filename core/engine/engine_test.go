package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// echoServer：同时支持 h2 与 http/1.1 的回环服务。
type echoServer struct {
	URL string
	ln  net.Listener
	srv *http.Server
}

func startEchoServer(t *testing.T) *echoServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "echo"},
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
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"host":   r.Host,
			"body":   string(body),
			"proto":  r.Proto,
			"ua":     r.Header.Get("User-Agent"),
		})
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/echo", 302)
	})
	mux.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"})
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		chunk := make([]byte, 16384)
		for i := 0; i < 64; i++ { // 1MB 分 64 块
			w.Write(chunk)
			if fl != nil {
				fl.Flush()
			}
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	go srv.Serve(tls.NewListener(ln, tlsCfg))
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return &echoServer{URL: "https://" + ln.Addr().String(), ln: ln, srv: srv}
}

func testSession(t *testing.T, presetName string) *Session {
	t.Helper()
	p, err := profiles.Get(presetName)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func readBody(t *testing.T, r *Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEngineH2Echo(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_133")

	resp, err := s.Do(&Request{Method: "GET", URL: echo.URL + "/echo",
		Headers: [][2]string{{"user-agent", "geektls-test"}}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.UsedProtocol != "h2" {
		t.Errorf("protocol = %q, want h2", resp.UsedProtocol)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	body := readBody(t, resp)
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got["ua"] != "geektls-test" || got["method"] != "GET" {
		t.Errorf("echo = %v", got)
	}
	// selfcheck：JA3/JA4 结构合法
	if len(resp.SelfCheck.JA3Hash) != 32 || resp.SelfCheck.JA4 == "" {
		t.Errorf("selfcheck = %+v", resp.SelfCheck)
	}
	t.Logf("h2 echo OK, ja4=%s", resp.SelfCheck.JA4)
}

func TestEngineH1(t *testing.T) {
	echo := startEchoServer(t)

	// 无 ALPN 扩展的 profile → 走 h1
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	var noALPN []profiles.Extension
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type != 16 {
			noALPN = append(noALPN, e)
		}
	}
	p.TLS.Detail.Extensions = noALPN

	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Do(&Request{Method: "POST", URL: echo.URL + "/echo",
		Headers: [][2]string{{"user-agent", "geektls-h1"}}, Body: []byte("ping")})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.UsedProtocol != "http/1.1" {
		t.Errorf("protocol = %q, want http/1.1", resp.UsedProtocol)
	}
	body := readBody(t, resp)
	var got map[string]any
	json.Unmarshal([]byte(body), &got)
	if got["body"] != "ping" || got["proto"] != "HTTP/1.1" {
		t.Errorf("echo = %v", got)
	}
}

func TestEngineRedirectAndCookies(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "firefox_120")

	// 302 → GET 跟随
	resp, err := s.Do(&Request{URL: echo.URL + "/redirect"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Errorf("redirect final status = %d", resp.Status)
	}
	readBody(t, resp)

	// set-cookie → 下次请求带 Cookie
	resp, err = s.Do(&Request{URL: echo.URL + "/set-cookie"})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)

	resp, err = s.Do(&Request{URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	// echo 端看不到 cookie（handler 未回显），改为直接查 jar
	u, _ := url.Parse(echo.URL + "/echo")
	cookies := s.jar.Cookies(u)
	if len(cookies) != 1 || cookies[0].Name != "sid" || cookies[0].Value != "abc123" {
		t.Errorf("jar cookies = %v", cookies)
	}
	readBody(t, resp)
}

func TestEngineStreaming(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_131")

	resp, err := s.Do(&Request{URL: echo.URL + "/stream"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if n != 64*16384 {
		t.Errorf("streamed %d bytes, want %d", n, 64*16384)
	}
}

// TestEngineSelfCheckJA3Entry：JA3 入口 profile 的 selfcheck 应与期望值一致。
func TestEngineSelfCheckJA3Entry(t *testing.T) {
	echo := startEchoServer(t)

	// 先取 chrome_133 的固定序 spec 算 JA3 作为"期望"
	p0, _ := profiles.Get("chrome_133")
	p0.TLS.Detail.ExtensionPermutation = false
	spec0, err := tlscore.CompileDetail(p0.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}
	ja3 := tlscore.ComputeJA3(spec0)

	p, _, err := profiles.FromJA3(ja3)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Do(&Request{URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.SelfCheck.JA3Match == nil || !*resp.SelfCheck.JA3Match {
		t.Errorf("ja3_match = %v, want true (selfcheck %+v)", resp.SelfCheck.JA3Match, resp.SelfCheck)
	}
}
