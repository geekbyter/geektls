package tlscore

// P7-T2 会话复用测试（诚实口径；2026-09-24 修订）。
//
// 结论（本地实测）：共享 ClientSessionCache 时，第二次握手的 ClientHello 携带
// pre_shared_key(41)（含票据 identity），且服务端**确实复用**（DidResume=true）。
// 真机同样可用：core/tls/resumption_live_test.go 对 tls.peet.ws 与本地 Go std
// 服务端都实测到 resumed=true。
//
// **修订说明（重要）**：本文件原先记着"refraction uTLS 与 Go std 服务端做 PSK 复用时
// binder 校验失败（服务端 bad record MAC），属上游互操作问题，真实 CDN 按上游实践可用
// （未验证）"。那是**误诊**——当时两次握手复用了同一个 ClientHelloSpec，而 uTLS 的
// ApplyPreset 会把 SNI / key_share **回写进 spec**（实测见 spec_reuse_test.go），
// 第二次握手失败的真实原因就在此，与 PSK/binder 无关。修正后本测试直接断言 DidResume。
//
// 另有两个**真实存在**的 uTLS 陷阱，均已在库侧处理：
//  1. spec 里没有 pre_shared_key 占位、而缓存命中票据 → uTLS **panic**
//     （u_session_controller.go:128 initPskExt）→ 生成器 normalizePskPlaceholder
//     保证预设恒带占位；tlscore.Handshake 另把该 panic 兜成错误。
//  2. 缓存里的会话状态异常/不完整 → uTLS 空指针 panic（handshake_client.go:441）
//     → 同样由 Handshake 兜成错误。

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geekbyter/geektls/core/profiles"
)

func TestSessionResumptionPSKSent(t *testing.T) {
	serverCfg := newTestServerConfig(t)
	cache := utls.NewLRUClientSessionCache(8)

	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.TLS.Detail.ExtensionPermutation = false

	// dial 每次重新编译 spec（spec 不可跨连接复用）。
	dial := func(n int) (*recordingConn, *utls.UConn) {
		spec, err := CompileDetail(p.TLS.Detail)
		if err != nil {
			t.Fatalf("compile #%d: %v", n, err)
		}
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
		deadline := time.Now().Add(5 * time.Second)
		_ = clientConn.SetDeadline(deadline)
		_ = serverConn.SetDeadline(deadline)
		go func() {
			srv := tls.Server(serverConn, serverCfg)
			_ = srv.Handshake()
			_, _ = io.Copy(io.Discard, srv)
		}()
		rec := &recordingConn{Conn: clientConn}
		uconn, err := Handshake(rec, &utls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
			OmitEmptyPsk:       true,
		}, spec)
		if err != nil {
			t.Fatalf("handshake #%d: %v", n, err)
		}
		return rec, uconn
	}

	// 第一次：全新握手，并把握手后服务端发的票据读进缓存
	// （TLS1.3 的 NewSessionTicket 在握手之后才发，不读就不会入缓存）。
	rec1, u1 := dial(1)
	if u1.ConnectionState().DidResume {
		t.Error("第一次握手不应复用（缓存为空）")
	}
	_ = u1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		if _, err := u1.Read(make([]byte, 2048)); err != nil {
			break
		}
	}

	// 第二次：命中票据
	rec2, u2 := dial(2)

	// 第一次 hello：无 pre_shared_key（fresh，OmitEmptyPsk 线上省略）
	p1, _, err := profiles.FromClientHelloHex(hex.EncodeToString(rec1.buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p1.TLS.Detail.Extensions {
		if e.Type == 41 {
			t.Error("fresh hello should not carry pre_shared_key on wire")
		}
	}

	// 第二次 hello：必须有 pre_shared_key(41)（含票据 identity）
	p2, _, err := profiles.FromClientHelloHex(hex.EncodeToString(rec2.buf.Bytes()))
	if err != nil {
		t.Fatalf("parse resumed hello: %v", err)
	}
	var pskExt *profiles.Extension
	for i := range p2.TLS.Detail.Extensions {
		if p2.TLS.Detail.Extensions[i].Type == 41 {
			pskExt = &p2.TLS.Detail.Extensions[i]
		}
	}
	if pskExt == nil {
		t.Fatal("resumed hello missing pre_shared_key(41)")
	}
	if pskExt.Data == "" {
		t.Error("resumed psk extension has empty payload (ticket not loaded?)")
	}
	// 关键升级：不再只查"线上带了 PSK"，而是断言服务端**确实复用了**。
	if !u2.ConnectionState().DidResume {
		t.Error("第二次握手未复用（DidResume=false）——复用链路回归")
	}
	t.Logf("resumed hello carries pre_shared_key (%d bytes payload), DidResume=%v",
		len(pskExt.Data)/2, u2.ConnectionState().DidResume)
}
