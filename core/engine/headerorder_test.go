package engine

// G9：请求头顺序策略（preserve/input/random）与身份自洽（UA ↔ 客户端提示）。
//
// 判据取"线上真实字节"：起一个原始 TCP 明文服务端，把请求头**按收到的顺序**记下来
// （`http.Header` 是 map，会丢顺序，所以不能用 httptest）。

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geektls/core/profiles"
)

// captureServer 是一个"把请求头按原样记下来"的极简 HTTP/1.1 服务端（明文）。
type captureServer struct {
	addr string
	mu   sync.Mutex
	reqs []string // 每次请求的 head（含请求行）
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cs := &captureServer{addr: "http://" + ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var sb strings.Builder
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					sb.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				cs.mu.Lock()
				cs.reqs = append(cs.reqs, sb.String())
				cs.mu.Unlock()
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return cs
}

// headerNames 返回第 i 次请求的头名顺序（不含请求行，去掉 Host）。
func (cs *captureServer) headerNames(t *testing.T, i int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		cs.mu.Lock()
		n := len(cs.reqs)
		var head string
		if n > i {
			head = cs.reqs[i]
		}
		cs.mu.Unlock()
		if head != "" {
			var out []string
			for j, line := range strings.Split(head, "\r\n") {
				if j == 0 || line == "" {
					continue
				}
				name, _, _ := strings.Cut(line, ":")
				if strings.EqualFold(name, "host") {
					continue
				}
				out = append(out, strings.ToLower(name))
			}
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("第 %d 次请求没到达（收到 %d 次）", i, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (cs *captureServer) headerValue(t *testing.T, i int, name string) string {
	t.Helper()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if i >= len(cs.reqs) {
		t.Fatalf("第 %d 次请求没到达", i)
	}
	for _, line := range strings.Split(cs.reqs[i], "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func orderSession(t *testing.T, opts SessionOptions, mutate func(*profiles.Profile)) *Session {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(p)
	}
	opts.InsecureSkipVerify = true
	s, err := NewSession(p, opts)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// preserve（默认）按 profile.http1.header_order 归位；input 保留调用方/注入后的原序。
func TestHeaderOrderPreserveVsInput(t *testing.T) {
	cs := newCaptureServer(t)
	// 给 profile 一个显式 header_order：accept / user-agent 提到最前
	mutate := func(p *profiles.Profile) {
		p.HTTP1 = &profiles.HTTP1Profile{HeaderOrder: []string{"accept", "user-agent"}}
	}

	s := orderSession(t, SessionOptions{}, mutate)
	if _, err := s.Do(&Request{URL: cs.addr + "/x"}); err != nil {
		t.Fatalf("Do(preserve): %v", err)
	}
	preserve := cs.headerNames(t, 0)
	if len(preserve) < 2 || preserve[0] != "accept" || preserve[1] != "user-agent" {
		t.Fatalf("preserve 序 = %v, want 以 accept, user-agent 开头（profile.header_order）", preserve)
	}

	s2 := orderSession(t, SessionOptions{HeaderOrder: "input"}, mutate)
	if _, err := s2.Do(&Request{URL: cs.addr + "/x"}); err != nil {
		t.Fatalf("Do(input): %v", err)
	}
	input := cs.headerNames(t, 1)
	if len(input) < 1 || input[0] != "sec-ch-ua" {
		t.Fatalf("input 序 = %v, want 保留注入后的原序（首个为 sec-ch-ua）", input)
	}
	if strings.Join(input, ",") == strings.Join(preserve, ",") {
		t.Error("input 与 preserve 结果相同 ⇒ 策略没生效")
	}
}

// random：与 preserve 同一集合（不多不少不重）+ Host 仍在最前 + 多次请求顺序确有变化。
func TestHeaderOrderRandom(t *testing.T) {
	cs := newCaptureServer(t)
	s := orderSession(t, SessionOptions{HeaderOrder: "random"}, nil)
	for i := 0; i < 12; i++ {
		if _, err := s.Do(&Request{URL: cs.addr + "/x"}); err != nil {
			t.Fatalf("Do #%d: %v", i, err)
		}
	}
	base := orderSession(t, SessionOptions{}, nil)
	if _, err := base.Do(&Request{URL: cs.addr + "/x"}); err != nil {
		t.Fatal(err)
	}
	want := cs.headerNames(t, 12) // preserve 的那次（最后一次）

	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		got := cs.headerNames(t, i)
		if strings.Join(got, ",") == strings.Join(want, ",") {
			seen["same"] = true
		} else {
			seen["diff"] = true
		}
		if len(got) != len(want) {
			t.Fatalf("random 头数 %d != preserve %d", len(got), len(want))
		}
		a, b := append([]string(nil), got...), append([]string(nil), want...)
		sortStrings(a)
		sortStrings(b)
		if strings.Join(a, ",") != strings.Join(b, ",") {
			t.Fatalf("random 头集合变了：\n got %v\nwant %v", a, b)
		}
	}
	if !seen["diff"] {
		t.Error("12 次请求顺序全都相同 ⇒ random 没生效")
	}
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// 身份自洽：调用方 UA（Windows/Chrome 161）与预设（chrome_154_macos）冲突时，
// 客户端提示被校正 + 如实告警；identity_sync="off" 时保持旧行为。
func TestIdentitySyncClientHints(t *testing.T) {
	cs := newCaptureServer(t)
	winUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Chrome/161.0.0.0 Safari/537.36"

	build := func(t *testing.T, sync string) *Session {
		t.Helper()
		p, err := profiles.Get("chrome_154_macos")
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true, IdentitySync: sync})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}

	// auto（默认）：校到 Windows / 161，并给一条 identity_sync 告警
	s := build(t, "")
	resp, err := s.Do(&Request{URL: cs.addr + "/x", Headers: [][2]string{{"user-agent", winUA}}})
	if err != nil {
		t.Fatalf("Do(auto): %v", err)
	}
	defer resp.Body.Close()
	if got := cs.headerValue(t, 0, "sec-ch-ua-platform"); got != `"Windows"` {
		t.Errorf("sec-ch-ua-platform = %s, want \"Windows\"（应随调用方 UA 校正）", got)
	}
	if got := cs.headerValue(t, 0, "sec-ch-ua"); !strings.Contains(got, `v="161"`) {
		t.Errorf("sec-ch-ua = %s, want 版本号换成 161", got)
	}
	if got := cs.headerValue(t, 0, "user-agent"); got != winUA {
		t.Errorf("user-agent = %s, want 调用方原值（不被覆盖）", got)
	}
	var warned bool
	for _, w := range resp.Warnings {
		if strings.Contains(w, "identity_sync") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("缺少 identity_sync 告警：%v", resp.Warnings)
	}

	// off：保持预设身份（macOS / 154），且不告警
	s2 := build(t, "off")
	resp2, err := s2.Do(&Request{URL: cs.addr + "/x", Headers: [][2]string{{"user-agent", winUA}}})
	if err != nil {
		t.Fatalf("Do(off): %v", err)
	}
	defer resp2.Body.Close()
	if got := cs.headerValue(t, 1, "sec-ch-ua-platform"); got != `"macOS"` {
		t.Errorf("identity_sync=off 时 sec-ch-ua-platform = %s, want \"macOS\"（旧行为）", got)
	}
	if len(resp2.Warnings) != 0 {
		t.Errorf("identity_sync=off 不该产生告警：%v", resp2.Warnings)
	}
}

func TestHeaderOrderAndIdentitySyncValidation(t *testing.T) {
	for _, tc := range []struct {
		opts SessionOptions
		want string
	}{
		{SessionOptions{HeaderOrder: "sorted"}, "header_order"},
		{SessionOptions{IdentitySync: "strict"}, "identity_sync"},
	} {
		p, err := profiles.Get("chrome_133")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewSession(p, tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("opts=%+v err=%v, want 含 %q", tc.opts, err, tc.want)
		}
	}
}
