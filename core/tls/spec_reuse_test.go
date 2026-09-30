package tlscore

// ClientHelloSpec 复用安全性 —— 上游契约的回归钉。
//
// 起因（真机实测，见 resumption_live_test.go 探针）：对真实服务端**连续拨号**时，
// 只有全局第一次握手成功，之后连"无 session cache 的全新握手"都失败
// （`local error: tls: internal error`）。根因不在会话复用，而在**编译产物被复用**。
//
// uTLS 自己在 ApplyPreset 上写明了这条契约（u_parrots.go:2764）：
//
//	"Fields of TLSExtensions that are slices/pointers are shared across different
//	 connections with same ClientHelloSpec. It is advised to use different specs
//	 and avoid any shared state."
//
// 而"共享状态"具体是什么，本地实测可精确到扩展（见下方 (b) 的快照断言）：
//
//	SNI(0)        0:0      → 0:<len(host)+5>   把解析出的主机名写回 spec
//	key_share(51) 19       → 1267              把真实密钥数据写回（下次公私钥不匹配 → 崩）
//	GREASE 扩展值 51914..  → 64250..           uTLS 每次 ApplyPreset 重新取（这条是好的）
//
// 影响面：**engine 安全**（core/engine/dial.go:68 每次拨号重新 CompileDetail）。
// 但库 API 是陷阱：调用方若"编译一次、多处复用"，第二次握手会以 `tls: internal error`
// 失败，且 SNI 会被上一台主机名污染（跨主机身份泄漏）。故 Handshake 侧加了显式守卫
// （见 client.go CheckSpecFresh）。

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geekbyter/geektls/core/profiles"
)

// handshakeOnce 用给定 spec 对本地服务端握手一次。
// 返回从线上字节解析出的 CH（握手失败时可能为 nil，例如 CH 未写完就报错）与错误。
func handshakeOnce(t *testing.T, serverCfg *tls.Config, spec *utls.ClientHelloSpec) (*profiles.Detail, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	// net.Pipe 同步且无缓冲：两侧都必须设 deadline，否则一端提前退出时
	// 另一端会永久阻塞在读写上（实测踩到过，表现为测试整体挂死）。
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	go func() {
		srv := tls.Server(serverConn, serverCfg)
		_ = srv.Handshake()
		_, _ = io.Copy(io.Discard, srv)
	}()

	rec := &recordingConn{Conn: clientConn}
	_, err := Handshake(rec, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, spec)
	if rec.buf.Len() == 0 {
		return nil, err
	}
	p, _, perr := profiles.FromClientHelloHex(hex.EncodeToString(rec.buf.Bytes()))
	if perr != nil {
		return nil, err // 半截 CH：解析不了，只回错误
	}
	return p.TLS.Detail, err
}

// specSnapshot 把 spec 的扩展列表压成 "type:len" 序列，用于对比"用过的 spec"
// 与新编译的 spec——差异即 uTLS 在握手期回写进 spec 的共享状态。
func specSnapshot(s *utls.ClientHelloSpec) []string {
	out := make([]string, 0, len(s.Extensions))
	for _, e := range s.Extensions {
		id, _ := extensionTypeID(e)
		out = append(out, fmt.Sprintf("%d:%d", id, e.Len()))
	}
	return out
}

func firstExt[T utls.TLSExtension](s *utls.ClientHelloSpec) T {
	var zero T
	for _, e := range s.Extensions {
		if v, ok := e.(T); ok {
			return v
		}
	}
	return zero
}

// greaseExtTypes 取 CH 里的 GREASE 扩展 type（观测跨连接是否重随机）。
func greaseExtTypes(d *profiles.Detail) []uint16 {
	var out []uint16
	if d == nil {
		return nil
	}
	for _, e := range d.Extensions {
		if isGreaseUint16(e.Type) {
			out = append(out, e.Type)
		}
	}
	return out
}

func TestSpecReuseIsUnsafe(t *testing.T) {
	serverCfg := newTestServerConfig(t)

	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.TLS.Detail.ExtensionPermutation = false

	// ---- (a) 复用同一 spec：第 1 次成功，第 2 次必须失败 ----
	specA, err := CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}
	ch1, err1 := handshakeOnce(t, serverCfg, specA)
	if err1 != nil {
		t.Fatalf("(a) 第一次握手本应成功: %v", err1)
	}
	ch2, err2 := handshakeOnce(t, serverCfg, specA)
	if err2 == nil {
		t.Error("(a) 复用同一 spec 的第二次握手居然成功了：上游可能已修复 spec 复用，" +
			"请重新评估本测试与 client.go 的 CheckSpecFresh 守卫")
	} else {
		t.Logf("(a) 复用同一 spec 第二次: %v（预期失败）", err2)
	}

	// (a') 观测：复用（未重新编译）时线上 GREASE 扩展值是否仍逐连接随机。
	// 这决定"G12：GREASE 跨连接恒定"是否成立——扩展 type 部分由 uTLS 的
	// greaseSeed 在每次 ApplyPreset 时重取，所以**不是**缺口。
	if g1, g2 := greaseExtTypes(ch1), greaseExtTypes(ch2); len(g1) > 0 && len(g2) > 0 {
		if fmt.Sprint(g1) == fmt.Sprint(g2) {
			t.Logf("(a') 复用 spec 时 GREASE 扩展 type 相同 %v ⇒ 需由编译期取值保证随机", g1)
		} else {
			t.Logf("(a') 复用 spec 时 GREASE 扩展 type 仍逐连接变化 %v → %v ⇒ uTLS 每连接重取（G12 此面无缺口）", g1, g2)
		}
	}

	// ---- (b) 去掉 pre_shared_key(41) 占位后复用，仍然失败 ⇒ 根因不止 PSK ----
	d2 := *p.TLS.Detail
	d2.Extensions = nil
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type != 41 {
			d2.Extensions = append(d2.Extensions, e)
		}
	}
	specB, err := CompileDetail(&d2)
	if err != nil {
		t.Fatal(err)
	}
	sniBefore := len(firstExt[*utls.SNIExtension](specB).ServerName)
	ksBefore := firstExt[*utls.KeyShareExtension](specB).Len()
	if _, err := handshakeOnce(t, serverCfg, specB); err != nil {
		t.Fatalf("(b) 第一次握手本应成功: %v", err)
	}
	if _, err := handshakeOnce(t, serverCfg, specB); err == nil {
		t.Log("(b) 无 PSK 占位时复用两次均成功 ⇒ 复用不安全只与 PSK 有关（与 (a) 结论合并）")
	} else {
		t.Logf("(b) 无 PSK 占位复用仍失败（%v）⇒ 根因是整个 spec 被握手回写，不止 PSK", err)
	}

	// 断言"回写"这一机制本身：SNI 被写入主机名、key_share 被写入真实密钥数据。
	// 若上游某天不再回写（从而允许复用），这两条会先失败，提示我们重审守卫。
	sniAfter := len(firstExt[*utls.SNIExtension](specB).ServerName)
	ksAfter := firstExt[*utls.KeyShareExtension](specB).Len()
	if sniAfter == sniBefore {
		t.Errorf("(b) SNI 未被回写（%d→%d）：与实测不符，请复核 uTLS 版本行为", sniBefore, sniAfter)
	} else {
		t.Logf("(b) SNI 被回写：ServerName %d→%d 字节（= 本次握手用掉的主机名）", sniBefore, sniAfter)
	}
	if ksAfter <= ksBefore {
		t.Errorf("(b) key_share 未被回写（%d→%d）：与实测不符，请复核 uTLS 版本行为", ksBefore, ksAfter)
	} else {
		t.Logf("(b) key_share 被回写：扩展长度 %d→%d 字节（真实密钥数据）", ksBefore, ksAfter)
	}
	fresh, err := CompileDetail(&d2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("(b) 快照对比：新编译 %v", specSnapshot(fresh))

	// ---- (c) 每连接重新 CompileDetail：两次都成功（正确用法；engine 亦如此）----
	for i := 1; i <= 2; i++ {
		spec, err := CompileDetail(p.TLS.Detail)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := handshakeOnce(t, serverCfg, spec); err != nil {
			t.Errorf("(c) 每连接重新编译：第 %d 次失败: %v", i, err)
		}
	}
	t.Log("(c) 每次重新 CompileDetail：连续两次握手均成功")
}
