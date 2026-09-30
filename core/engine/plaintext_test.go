package engine

// 明文（G5）测试：http:// 与 ws:// 走 TCP-only 路径。
//
// 断言面（这些就是"明文支持"的全部承诺，别的都不承诺）：
//   - 能拿到响应，UsedProtocol 恒为 http/1.1（h2c 不在承诺面内）；
//   - SelfCheck 恒为零值：TLS 层不存在，就不报任何"看起来像 TLS"的东西；
//   - 身份注入（profile.identity）、cookie jar、H1 连接复用照常工作；
//   - 流式上传与重定向在明文档下同样可用；force_http3 要 https；
//   - HTTP_PROXY 只对明文目标生效、HTTPS_PROXY 只对 TLS 目标生效（不跨 scheme）。

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPlaintextH1Basic(t *testing.T) {
	var mu sync.Mutex
	seenCookie := map[string]string{}
	var gotUA, gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenCookie[r.URL.Path] = r.Header.Get("Cookie")
		if gotUA == "" {
			gotUA, gotHost = r.Header.Get("User-Agent"), r.Host
		}
		mu.Unlock()
		if r.URL.Path == "/p" {
			w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		}
		_, _ = io.WriteString(w, "plain-ok")
	}))
	defer srv.Close()

	s := testSession(t, "chrome_133")
	resp, err := s.Do(&Request{Method: "GET", URL: srv.URL + "/p"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 || resp.UsedProtocol != "http/1.1" {
		t.Fatalf("status=%d proto=%q, want 200/http/1.1", resp.Status, resp.UsedProtocol)
	}
	if body := readBody(t, resp); body != "plain-ok" {
		t.Errorf("body = %q", body)
	}
	// 明文无 TLS 层：selfcheck 必须零值（绑定层按空串报"无指纹"）
	sc := resp.SelfCheck
	if sc.JA3 != "" || sc.JA3Hash != "" || sc.JA4 != "" || sc.SNISent ||
		sc.Negotiated != nil || len(sc.Extensions) != 0 || len(sc.Grease) != 0 {
		t.Errorf("明文档 selfcheck 应为零值: %+v", sc)
	}
	wantHost := strings.TrimPrefix(srv.URL, "http://")
	if gotHost != wantHost {
		t.Errorf("Host = %q, want %q", gotHost, wantHost)
	}
	if gotUA == "" || gotUA == "Go-http-client/1.1" {
		t.Errorf("User-Agent = %q（identity 未注入？）", gotUA)
	}

	// cookie jar：明文响应的 Set-Cookie 进 jar，第二跳带上
	resp2, err := s.Do(&Request{Method: "GET", URL: srv.URL + "/q"})
	if err != nil {
		t.Fatalf("Do2: %v", err)
	}
	_ = readBody(t, resp2)
	mu.Lock()
	got := seenCookie["/q"]
	mu.Unlock()
	if got != "sid=abc" {
		t.Errorf("第二跳 Cookie = %q, want sid=abc", got)
	}
}

// TestPlaintextH1Reuse 断言明文 H1 连接复用真的发生（池键含 scheme）。
func TestPlaintextH1Reuse(t *testing.T) {
	var conns int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	s := testSession(t, "chrome_133")
	for i := 0; i < 3; i++ {
		resp, err := s.Do(&Request{Method: "GET", URL: srv.URL + "/reuse"})
		if err != nil {
			t.Fatalf("Do#%d: %v", i, err)
		}
		if body := readBody(t, resp); body != "ok" {
			t.Fatalf("Do#%d body = %q", i, body)
		}
	}
	if got := atomic.LoadInt32(&conns); got != 1 {
		t.Errorf("新建 TCP 连接数 = %d, want 1（复用失效）", got)
	}
}

// TestPlaintextRedirectAndForceH3：明文档下重定向照常跟随；force_http3 报错。
func TestPlaintextRedirectAndForceH3(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/from", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/to", http.StatusFound)
	})
	mux.HandleFunc("/to", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "final")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := testSession(t, "chrome_133")
	resp, err := s.Do(&Request{Method: "GET", URL: srv.URL + "/from"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d, want 200（重定向未跟随）", resp.Status)
	}
	if body := readBody(t, resp); body != "final" {
		t.Errorf("body = %q", body)
	}

	if _, err := s.Do(&Request{Method: "GET", URL: srv.URL + "/to", ForceHTTP3: true}); err == nil {
		t.Error("force_http3 + http:// 应当报错，却成功了")
	} else if !strings.Contains(err.Error(), "force_http3") {
		t.Errorf("错误信息未指向 force_http3: %v", err)
	}
}

// TestPlaintextStreamingUpload：流式上传（gtls_request_begin 路径）在明文档可用。
func TestPlaintextStreamingUpload(t *testing.T) {
	var mu sync.Mutex
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		// Go 的 server 会把 Transfer-Encoding 从 r.Header 摘到 r.TransferEncoding，
		// 所以这里读后者（引擎发的是 chunked，见 upload.go 的 H1 分支）。
		got = strings.Join(r.TransferEncoding, ",") + "|" + string(b)
		mu.Unlock()
		_, _ = io.WriteString(w, "up-ok")
	}))
	defer srv.Close()

	s := testSession(t, "chrome_133")
	up, err := s.BeginUpload(&Request{Method: "POST", URL: srv.URL + "/up"})
	if err != nil {
		t.Fatalf("BeginUpload: %v", err)
	}
	if _, err := up.Write([]byte("hello-")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := up.Write([]byte("plain")); err != nil {
		t.Fatalf("Write2: %v", err)
	}
	resp, err := up.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	_ = readBody(t, resp)
	mu.Lock()
	gotVal := got
	mu.Unlock()
	if gotVal != "chunked|hello-plain" {
		t.Errorf("服务端收到 %q, want chunked|hello-plain", gotVal)
	}
}

// TestPlaintextWS：ws:// 明文 WebSocket（帧层与 wss 共用，握手不走 TLS）。
func TestPlaintextWS(t *testing.T) {
	ws := startWSServerMode(t, true)
	s := testSession(t, "chrome_133")
	c, err := s.DialWS(&WSRequest{URL: ws.URL, TimeoutMs: 5000})
	if err != nil {
		t.Fatalf("DialWS(ws://): %v", err)
	}
	defer func() { _ = c.Close(1000) }()

	if err := c.Send(WSOpText, []byte("ping-plain")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	op, payload, err := c.Recv(3000)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if op != WSOpText || string(payload) != "ping-plain" {
		t.Errorf("echo = op%d %q", op, payload)
	}
	if !ws.clientMasked {
		t.Error("客户端帧未 mask（RFC 6455 要求）")
	}
	if len(ws.gotHeaderOrder) == 0 || ws.gotHeaderOrder[0] != "host" {
		t.Errorf("握手头序异常: %v", ws.gotHeaderOrder)
	}
	if ws.gotUA == "" || ws.gotUA == "Go-http-client/1.1" {
		t.Errorf("握手 UA = %q（identity 未注入？）", ws.gotUA)
	}
}

// TestProxyEnvPerScheme：HTTP_PROXY 只服务明文目标，HTTPS_PROXY 只服务 TLS 目标，
// 两者都不跨 scheme 取（curl/requests 同语义）；ALL_PROXY 是共同兜底。
func TestProxyEnvPerScheme(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	t.Setenv("HTTP_PROXY", "http://plain-proxy:8080")
	t.Setenv("HTTPS_PROXY", "http://tls-proxy:8080")

	if got := proxyFromEnv("http", "a.example", "80"); got != "http://plain-proxy:8080" {
		t.Errorf("http 目标应取 HTTP_PROXY: %q", got)
	}
	if got := proxyFromEnv("ws", "a.example", "80"); got != "http://plain-proxy:8080" {
		t.Errorf("ws 目标应取 HTTP_PROXY: %q", got)
	}
	if got := proxyFromEnv("https", "a.example", "443"); got != "http://tls-proxy:8080" {
		t.Errorf("https 目标应取 HTTPS_PROXY: %q", got)
	}
	// 反向：只有 HTTP_PROXY 时 https 不该用它（curl/requests 都拒绝的误配面）
	t.Setenv("HTTPS_PROXY", "")
	if got := proxyFromEnv("https", "a.example", "443"); got != "" {
		t.Errorf("https 目标不该退到 HTTP_PROXY: %q", got)
	}
	// ALL_PROXY 兜底
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("ALL_PROXY", "socks5h://all:1080")
	if got := proxyFromEnv("http", "a.example", "80"); got != "socks5h://all:1080" {
		t.Errorf("明文目标的 ALL_PROXY 兜底失效: %q", got)
	}
}
