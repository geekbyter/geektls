package engine

// 连接池（二期阶段 5）验证：握手计数（复用连接不发新 ClientHello）、
// keep-alive 复用、并发安全（配合 go test -race）、Close 排池。

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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/geektls/core/profiles"
)

// countingServer：统计 TLS 握手次数的回环服务（h2 + h1）。
type countingServer struct {
	URL        string
	handshakes atomic.Int32
	ln         net.Listener
	srv        *http.Server
}

func startCountingServer(t *testing.T) *countingServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "counting"},
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
	cs := &countingServer{}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
		// 每收到一个 ClientHello 计一次握手（复用连接不会再触发）
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cs.handshakes.Add(1)
			return nil, nil
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(map[string]any{"body": string(body), "proto": r.Proto})
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cs.ln = ln
	cs.srv = &http.Server{Handler: mux}
	if err := http2.ConfigureServer(cs.srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	go cs.srv.Serve(tls.NewListener(ln, tlsCfg))
	cs.URL = "https://" + ln.Addr().String()
	t.Cleanup(func() { cs.srv.Close(); ln.Close() })
	return cs
}

// poolSession：可开关连接池的测试会话。
func poolSession(t *testing.T, preset string, poolOn bool) *Session {
	t.Helper()
	p, err := profiles.Get(preset)
	if err != nil {
		t.Fatal(err)
	}
	if !poolOn {
		off := false
		p.Behavior = &profiles.BehaviorProfile{ConnectionPool: &off}
	}
	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// TestPoolH2SingleHandshake：默认开池——同 origin N 个请求只握手一次
// （H2 多路复用，复用连接不发新 ClientHello）。
func TestPoolH2SingleHandshake(t *testing.T) {
	cs := startCountingServer(t)
	s := poolSession(t, "chrome_133", true)

	const n = 20
	for i := 0; i < n; i++ {
		resp, err := s.Do(&Request{URL: cs.URL + "/echo"})
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		readBody(t, resp)
	}
	if got := cs.handshakes.Load(); got != 1 {
		t.Errorf("handshakes = %d, want 1（h2 单连接多路复用）", got)
	}
}

// TestPoolDisabledNewConnPerRequest：behavior.connection_pool=false 回到
// 旧默认——每请求一条新连接（一次握手）。
func TestPoolDisabledNewConnPerRequest(t *testing.T) {
	cs := startCountingServer(t)
	s := poolSession(t, "chrome_133", false)

	const n = 10
	for i := 0; i < n; i++ {
		resp, err := s.Do(&Request{URL: cs.URL + "/echo"})
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		readBody(t, resp)
	}
	if got := cs.handshakes.Load(); got != n {
		t.Errorf("handshakes = %d, want %d（关池=每请求新连接）", got, n)
	}
}

// h1Profile：剥 ALPN 强制走 h1。
func h1Profile(t *testing.T, preset string) *profiles.Profile {
	t.Helper()
	p, err := profiles.Get(preset)
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
	return p
}

// TestPoolH1KeepAlive：H1 keep-alive——串行 N 请求读干净后只握手一次。
func TestPoolH1KeepAlive(t *testing.T) {
	cs := startCountingServer(t)
	p := h1Profile(t, "chrome_133")
	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	const n = 10
	for i := 0; i < n; i++ {
		resp, err := s.Do(&Request{Method: "POST", URL: cs.URL + "/echo", Body: []byte("ping")})
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		body := readBody(t, resp)
		if resp.UsedProtocol != "http/1.1" {
			t.Fatalf("protocol = %q, want http/1.1", resp.UsedProtocol)
		}
		_ = body
	}
	if got := cs.handshakes.Load(); got != 1 {
		t.Errorf("handshakes = %d, want 1（h1 keep-alive 复用）", got)
	}
}

// TestPoolConcurrent：100 goroutine × 100 请求共用一个 Session（-race 下跑）。
// 连接复用 + 并发建连撞车 + cookie/Alt-Svc 并发读写都在这条路径上。
func TestPoolConcurrent(t *testing.T) {
	cs := startCountingServer(t)
	s := poolSession(t, "chrome_133", true)

	const workers, perWorker = 100, 100
	var wg sync.WaitGroup
	var errs atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				resp, err := s.Do(&Request{URL: cs.URL + "/echo"})
				if err != nil {
					errs.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}(w)
	}
	wg.Wait()
	if errs.Load() != 0 {
		t.Errorf("errors = %d, want 0", errs.Load())
	}
	// 并发撞车可能产生少量孤儿连接，但绝不应接近 10000 条
	if got := cs.handshakes.Load(); got > int32(workers) {
		t.Errorf("handshakes = %d, want ≤ %d（池化下最多每 worker 一条）", got, workers)
	}
	t.Logf("100x100 并发完成，握手 %d 次", cs.handshakes.Load())
}

// TestPoolCloseDrain：Close 排池后再请求报错；池内连接被关闭。
func TestPoolCloseDrain(t *testing.T) {
	cs := startCountingServer(t)
	s := poolSession(t, "chrome_133", true)

	resp, err := s.Do(&Request{URL: cs.URL + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	s.Close()
	if _, err := s.Do(&Request{URL: cs.URL + "/echo"}); err == nil {
		t.Error("Close 后 Do 应报错")
	}
}

// TestH1HeaderCase：http1.header_case 三档（preserve/lower/title）。
func TestH1HeaderCase(t *testing.T) {
	mk := func(mode string) *profiles.Profile {
		p, _ := profiles.Get("chrome_133")
		p.HTTP1 = &profiles.HTTP1Profile{HeaderCase: mode}
		return p
	}
	u, _ := url.Parse("https://example.com/x")
	in := [][2]string{{"User-Agent", "ua"}, {"x-cuSTom-hdr", "v"}, {"accept", "*/*"}}

	preserve := orderH1Headers(mk(""), in, u)
	if preserve[0][0] != "host" || preserve[1][0] != "User-Agent" || preserve[2][0] != "x-cuSTom-hdr" {
		t.Errorf("preserve = %v", preserve)
	}
	lower := orderH1Headers(mk("lower"), in, u)
	for i, kv := range lower {
		if kv[0] != strings.ToLower(kv[0]) {
			t.Errorf("lower[%d] = %q, 应全小写", i, kv[0])
		}
	}
	if lower[2][0] != "x-custom-hdr" {
		t.Errorf("lower = %v", lower)
	}
	title := orderH1Headers(mk("title"), in, u)
	if title[0][0] != "Host" || title[1][0] != "User-Agent" || title[2][0] != "X-Custom-Hdr" || title[3][0] != "Accept" {
		t.Errorf("title = %v", title)
	}
	// 值不变换
	if title[1][1] != "ua" {
		t.Errorf("title 不应改动头值: %v", title[1])
	}
}
