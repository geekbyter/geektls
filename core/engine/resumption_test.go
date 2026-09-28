package engine

// 会话复用的**引擎级**行为（P7-T2 收口）。
//
// 背景与实测修正（见 core/tls/spec_reuse_test.go 与 core/tls/resumption_live_test.go）：
//
//	1. uTLS 的会话复用**可用**：真机对 tls.peet.ws 实测 `resumed=true`；
//	2. 旧记录"Go std 服务端不接受 uTLS binder（bad record MAC）"**是误诊**——当时那份
//	   测试两次握手复用了同一个 ClientHelloSpec，失败其实来自 spec 回写（SNI/key_share），
//	   与 PSK 互操作无关。本测试的对照组在真缓存 + 本地 std 服务端上实测该结论；
//	3. uTLS 在"缓存命中票据、而 spec 无 pre_shared_key(41) 占位"时**直接 panic**
//	   （u_session_controller.go:128）。按 E1 首访抓包生成的 9 个预设曾缺占位，而引擎
//	   默认开会话复用 ⇒ 那曾是一条真实的**进程崩溃**路径，现由生成器的
//	   normalizePskPlaceholder 保证预设恒带占位。
//
// 引擎侧还必须能扛住"复用失败"（对端拒绝/票据失效/过期）：dial.go 的策略是
// **丢票回退全新握手**（与浏览器一致）。本测试用注入"命中但不可用"的票据把它钉住。

import (
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// stdProbeHandshake 直连做一次握手（每次重新编译 spec），握手后读一点数据让服务端
// 发的 NewSessionTicket 进入缓存（TLS1.3 票据是握手后发的，不读就不进缓存）。
func stdProbeHandshake(t *testing.T, hostport, host string, d *profiles.Detail, cache utls.ClientSessionCache) (bool, error) {
	t.Helper()
	spec, err := tlscore.CompileDetail(d)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	conn, err := net.DialTimeout("tcp", hostport, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	uconn, err := tlscore.Handshake(conn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, spec)
	if err != nil {
		return false, err
	}
	_ = uconn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _ = uconn.Read(make([]byte, 1024))
	return uconn.ConnectionState().DidResume, nil
}

// bogusCache 注入"命中但内容不可用"的票据：让复用手握**必然失败**，
// 从而确定性地验证丢票回退（不依赖某个服务端恰好不吃复用）。
// Put(key, nil) 按 uTLS 语义删除条目——引擎丢票回退正是靠它生效。
type bogusCache struct {
	key string
	bad bool
}

func (b *bogusCache) Get(key string) (*utls.ClientSessionState, bool) {
	if key == b.key && b.bad {
		return &utls.ClientSessionState{}, true
	}
	return nil, false
}

func (b *bogusCache) Put(key string, cs *utls.ClientSessionState) {
	if key == b.key && cs == nil {
		b.bad = false
	}
}

// TestSessionResumptionStdServerFacts：对照组——本地 Go std 服务端会发票据，
// 且第二次握手能否复用（记录实测，用于纠正旧文档的"std 不接受 binder"结论）。
func TestSessionResumptionStdServerFacts(t *testing.T) {
	echo := startEchoServer(t)
	hostport := strings.TrimPrefix(echo.URL, "https://")
	host, _, _ := strings.Cut(hostport, ":")

	p, err := profiles.Get("chrome_149_windows")
	if err != nil {
		t.Fatal(err)
	}
	cache := utls.NewLRUClientSessionCache(4)
	if resumed, err := stdProbeHandshake(t, hostport, host, p.TLS.Detail, cache); err != nil {
		t.Fatalf("第 1 次握手本应成功: %v", err)
	} else if resumed {
		t.Errorf("第 1 次握手不应复用（缓存为空），却 resumed=true")
	}
	if _, ok := cache.Get(host); !ok {
		t.Fatalf("服务端未发票据（缓存未命中 %q）", host)
	}
	resumed, err := stdProbeHandshake(t, hostport, host, p.TLS.Detail, cache)
	switch {
	case err != nil:
		t.Logf("实测：std 服务端第 2 次（带票据）握手失败：%v", err)
	case resumed:
		t.Log("实测：std 服务端**接受**了 uTLS 的复用（resumed=true）⇒" +
			" 旧文档“std 不接受 uTLS binder”是误诊，根因是 spec 跨连接复用")
	default:
		t.Log("实测：std 服务端未复用但仍完成全新握手（resumed=false）⇒ 无硬失败")
	}
}

// TestSessionResumptionFallback：注入坏票据 ⇒ 第一次尝试失败 ⇒ 丢票回退 ⇒ 请求仍成功。
func TestSessionResumptionFallback(t *testing.T) {
	echo := startEchoServer(t)
	host := strings.TrimPrefix(echo.URL, "https://")
	host, _, _ = strings.Cut(host, ":")

	s := testSession(t, "chrome_149_windows")
	s.sessionCache = &bogusCache{key: host, bad: true} // 同包内直接注入（不依赖服务端行为）

	resp, err := s.Do(&Request{URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatalf("坏票据下请求失败——丢票回退未生效: %v", err)
	}
	_ = readBody(t, resp)
	resp2, err := s.Do(&Request{URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatalf("第二次请求失败: %v", err)
	}
	_ = readBody(t, resp2)
	t.Log("坏票据（Get 命中但不可用）下连续两次请求均成功 ⇒ 丢票回退生效")
}
