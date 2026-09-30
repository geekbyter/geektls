package engine

// A6 读超时测试：慢速/挂死的 body 必须按 read_timeout_ms 断开，且断开要能把
// 服务端 handler 一并放掉（证明"关闭底层"真的是取消入口，而不是只让调用方返回）。

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/geektls/core/profiles"
)

// startStallServer 起一个带 /stall（发一字节后就挂住）与 /trickle（分块慢发）的
// TLS 回环服务。返回 URL、release（放掉挂住的 handler）、handlerDone。
func startStallServer(t *testing.T, alpn []string, stallFor time.Duration) (string, func(), chan struct{}) {
	t.Helper()
	pki := newTestPKI(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		NextProtos:   alpn,
	}

	releaseCh := make(chan struct{})
	releaseOnce := new(sync.Once)
	release := func() { releaseOnce.Do(func() { close(releaseCh) }) }
	done := make(chan struct{}, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/stall", func(w http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "x")
		w.(http.Flusher).Flush()
		// r.Context() 在对端复位流 / 断开连接时被 server 取消：它是最硬的
		// "取消是否真的到了线上"的证据。
		select {
		case <-releaseCh:
		case <-r.Context().Done():
		case <-time.After(stallFor):
		}
		// 对端已断开时这一笔写会返回错误；无论成败 handler 都要退出。
		fmt.Fprint(w, "y")
		w.(http.Flusher).Flush()
	})
	mux.HandleFunc("/trickle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		for i := 0; i < 6; i++ {
			fmt.Fprintf(w, "%d", i)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			time.Sleep(30 * time.Millisecond)
		}
		done <- struct{}{}
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
	t.Cleanup(func() { release(); srv.Close(); ln.Close() })
	return "https://" + ln.Addr().String(), release, done
}

func stallSession(t *testing.T, readTimeoutMs int) *Session {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(p, SessionOptions{
		InsecureSkipVerify: true,
		ReadTimeoutMs:      readTimeoutMs,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// waitHandlerDone 等服务端 handler 退出（超时=没被真正取消）。
func waitHandlerDone(t *testing.T, done chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("服务端 handler 没被放掉：超时后连接并未真正取消")
	}
}

func TestReadTimeoutH2(t *testing.T) {
	url, _, done := startStallServer(t, []string{"h2", "http/1.1"}, 30*time.Second)
	s := stallSession(t, 300)

	resp, err := s.Do(&Request{Method: "GET", URL: url + "/stall"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// 第一字节应当拿得到（超时是"每次 Read"的空闲上限，不是总时长）。
	buf := make([]byte, 16)
	n, err := resp.Body.Read(buf)
	if err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("首字节读取 = (%d, %v)，want 1 'x'", n, err)
	}

	start := time.Now()
	_, err = resp.Body.Read(buf)
	if !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("第二次 Read err = %v，want ErrReadTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("超时耗时 %v，不在 [250ms, 3s] 区间", elapsed)
	}
	// 超时后连接作废：后续读仍然是同一个错误，不会卡住。
	if _, err = resp.Body.Read(buf); !errors.Is(err, ErrReadTimeout) {
		t.Errorf("超时后再读 err = %v", err)
	}
	waitHandlerDone(t, done, 5*time.Second)
}

func TestReadTimeoutH1(t *testing.T) {
	url, _, done := startStallServer(t, []string{"http/1.1"}, 30*time.Second)
	s := stallSession(t, 300)

	resp, err := s.Do(&Request{Method: "GET", URL: url + "/stall"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.UsedProtocol != "http/1.1" {
		t.Fatalf("proto = %s", resp.UsedProtocol)
	}
	start := time.Now()
	if _, err := resp.Bytes(); !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("Bytes() err = %v，want ErrReadTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("超时耗时 %v", elapsed)
	}
	waitHandlerDone(t, done, 5*time.Second)
}

// TestReadTimeoutRequestOverride：会话不设超时、请求级给 300ms ⇒ 请求级生效；
// 同一请求不给超时 ⇒ 慢 body 照常读完整（默认行为零改变）。
func TestReadTimeoutRequestOverride(t *testing.T) {
	url, release, done := startStallServer(t, []string{"h2", "http/1.1"}, 3*time.Second)
	s := stallSession(t, 0)

	resp, err := s.Do(&Request{Method: "GET", URL: url + "/stall", ReadTimeoutMs: 300})
	if err != nil {
		t.Fatal(err)
	}
	_, err = resp.Bytes()
	resp.Body.Close()
	if !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("请求级超时未生效: %v", err)
	}

	// 会话与请求都不给超时：3s 后服务端自己放掉，body 完整读到。
	release()
	waitHandlerDone(t, done, 5*time.Second)
	resp2, err := s.Do(&Request{Method: "GET", URL: url + "/trickle"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	b, err := resp2.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "012345" {
		t.Errorf("body = %q，want 012345", b)
	}
}

// TestReadTimeoutNotFalsePositive：阈值远大于分块间隔时不得误报。
func TestReadTimeoutNotFalsePositive(t *testing.T) {
	url, _, done := startStallServer(t, []string{"h2", "http/1.1"}, time.Second)
	s := stallSession(t, 5000)
	resp, err := s.Do(&Request{Method: "GET", URL: url + "/trickle"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "012345" {
		t.Errorf("body = %q", b)
	}
	waitHandlerDone(t, done, 5*time.Second)
}
