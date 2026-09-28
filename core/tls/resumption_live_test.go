//go:build external

package tlscore

// 会话复用上游互操作「实测探针」（遵循项目 V-3 约定：build tag external，只打印不断言）。
//
// 为什么需要它：resumption_test.go 记录的是"uTLS + **Go std** 服务端 PSK 复用 binder
// 失败"，而文中"真实 CDN（BoringSSL 系）按上游实践可用"当时只是**假设**。是否该在
// engine 层开会话复用取决于这个假设，本探针把它变成可复现实测。
//
// 两个已踩到的坑（探针自身修正后才有意义）：
//
//	1. spec 不可跨连接复用（uTLS ApplyPreset 会回写 SNI/key_share）——每次拨号重新编译，
//	   详见 spec_reuse_test.go。否则第二次握手直接 local error: tls: internal error，
//	   会把"A 的失败"误读成"复用不可用"。
//	2. TLS 1.3 的 NewSessionTicket 是**握手之后**才发的：握手完立刻关连接，票据从没被
//	   读取路径处理 ⇒ 缓存恒空、resumed 恒 false。必须在握手后读一点数据。
//
// 三段分离测量：
//
//	A 无缓存基线：全新握手本身能否成功
//	B 每 host 独立缓存：连两次 + 读票据 → 第二次是否真的 resumed
//	C 跨 host 共享缓存：观察缓存键是否按 SNI 隔离（engine 若用单一全局缓存即此形态）
//
// 运行：
//
//	cd core/tls && set GEEKTLS_LIVE=1 && go test -tags external -run TestLiveResumptionProbe -v -timeout 300s
//
// 无 GEEKTLS_LIVE=1 时跳过，避免无意中打外网。

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

// countingCache 包一层记录 Get/Put——用于区分"没拿到票据"与"拿到票据但服务端不接受 PSK"，
// 并顺带暴露缓存键（判断是否按 SNI 隔离）。
type countingCache struct {
	t     *testing.T
	inner utls.ClientSessionCache
}

func (c *countingCache) Get(key string) (*utls.ClientSessionState, bool) {
	s, ok := c.inner.Get(key)
	c.t.Logf("      [cache] Get(%q) → hit=%v", key, ok)
	return s, ok
}

func (c *countingCache) Put(key string, cs *utls.ClientSessionState) {
	c.t.Logf("      [cache] Put(%q) ticket=%v", key, cs != nil)
	c.inner.Put(key, cs)
}

// probeDial 每次拨号都**重新 CompileDetail**（spec 不可复用，见文件头坑 1）。
func probeDial(t *testing.T, tag, hostport, host string, cache utls.ClientSessionCache, d *profiles.Detail) {
	t.Helper()
	spec, err := CompileDetail(d)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	conn, err := net.DialTimeout("tcp", hostport, 10*time.Second)
	if err != nil {
		t.Logf("  %-22s dial 失败: %v", tag, err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	uconn, err := Handshake(conn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, spec)
	if err != nil {
		t.Logf("  %-22s **握手失败**: %v", tag, err)
		return
	}
	cs := uconn.ConnectionState()
	t.Logf("  %-22s 成功: resumed=%v version=%#x alpn=%q", tag, cs.DidResume, cs.Version, cs.NegotiatedProtocol)

	// 读一点数据，让握手后的 NewSessionTicket 被处理进缓存（坑 2）。
	_ = uconn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, rerr := uconn.Read(make([]byte, 4096))
	if rerr != nil && n == 0 {
		t.Logf("  %-22s   读票据：%v（票据通常已在超时前处理完）", tag, rerr)
	} else {
		t.Logf("  %-22s   读到 %d 字节（票据已处理）", tag, n)
	}
}

func TestLiveResumptionProbe(t *testing.T) {
	if os.Getenv("GEEKTLS_LIVE") == "" {
		t.Skip("设置 GEEKTLS_LIVE=1 才打外网")
	}
	hosts := []string{"tls.peet.ws:443", "www.cloudflare.com:443", "www.google.com:443"}

	for _, name := range []string{"chrome_149_windows", "firefox_156_windows"} {
		p, err := profiles.Get(name)
		if err != nil {
			t.Logf("== [%s] 预设不可用: %v", name, err)
			continue
		}
		d := p.TLS.Detail
		if _, err := CompileDetail(d); err != nil {
			t.Fatalf("[%s] compile: %v", name, err)
		}
		t.Logf("== 预设 %s ==", name)

		// ---- A / B：逐 host ----
		for _, hostport := range hosts {
			host, _, _ := strings.Cut(hostport, ":")
			t.Logf("- %s", hostport)

			probeDial(t, "A 无缓存 #1", hostport, host, nil, d)
			probeDial(t, "A 无缓存 #2", hostport, host, nil, d)

			cache := &countingCache{t: t, inner: utls.NewLRUClientSessionCache(4)}
			probeDial(t, "B cache #1", hostport, host, cache, d)
			probeDial(t, "B cache #2（应复用）", hostport, host, cache, d)
		}

		// ---- C：跨 host 共享缓存 ----
		t.Logf("- C 跨 host 共享缓存")
		shared := &countingCache{t: t, inner: utls.NewLRUClientSessionCache(8)}
		for i, hostport := range hosts {
			host, _, _ := strings.Cut(hostport, ":")
			probeDial(t, "C shared #"+string(rune('1'+i)), hostport, host, shared, d)
		}
	}
}

var _ = io.Discard
