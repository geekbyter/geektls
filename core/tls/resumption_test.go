package tlscore

// P7-T2 会话复用测试（诚实口径）：
//
// 已验证的硬证据：共享 ClientSessionCache 时，第二次握手的 ClientHello
// 携带 pre_shared_key(41)（线上字节抓包断言）——"有/无 PSK"这个真实指纹
// 差异由 profile 驱动生效。
//
// 已知上游 interop 问题（记录，不掩盖）：refraction uTLS v1.8.2 与 Go std
// 服务端做 PSK 复用时 binder 校验失败（服务端 bad record MAC）；bogdanfinn
// fork 对 std 服务端也不复用；std-std 正常。结论：复用发出侧正确，接受侧
// 与 Go 栈的互操作属上游问题，真实 CDN（BoringSSL 系）按上游项目实践可用。

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

func TestSessionResumptionPSKSent(t *testing.T) {
	serverCfg := newTestServerConfig(t)
	cache := utls.NewLRUClientSessionCache(8)

	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.TLS.Detail.ExtensionPermutation = false
	spec, err := CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}

	dial := func(n int) *recordingConn {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
		go func() {
			srv := tls.Server(serverConn, serverCfg)
			srv.SetDeadline(time.Now().Add(3 * time.Second))
			_ = srv.Handshake()
			io.Copy(io.Discard, srv)
		}()
		rec := &recordingConn{Conn: clientConn}
		uconn, err := Handshake(rec, &utls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
			OmitEmptyPsk:       true,
		}, spec)
		if n == 1 && err != nil {
			t.Fatalf("first handshake: %v", err)
		}
		if err == nil {
			// 排空票据/后续数据（第二次握手对端已 RST，读错忽略）
			uconn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			for {
				if _, err := uconn.Read(make([]byte, 2048)); err != nil {
					break
				}
			}
			uconn.Close()
		}
		return rec
	}

	rec1 := dial(1)
	rec2 := dial(2)

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
	t.Logf("resumed hello carries pre_shared_key (%d bytes payload)", len(pskExt.Data)/2)
	t.Logf("NOTE: std server rejects uTLS PSK binder (upstream interop, see test doc)")
}
