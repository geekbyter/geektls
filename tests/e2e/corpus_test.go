// ClientHello 语料库对拍（T1-5 / V 系验证）。
//
// 语料来源：gospider007/ja3 内置的真实浏览器 ClientHello 标本（社区采集，
// 覆盖到 Chrome 152 / Firefox 144 / Safari 26——比我们内置预设更新）。
//
// 链路：标本 hex → profiles.FromClientHelloHex（解析）→ engine 编译重放
//
//	→ fp（独立解析器）抓 wire 逐字段对比。
//
// 断言语义：GREASE 值归一化后精确相等——Chrome 每次连接会重随机化 GREASE 值，
// 但 GREASE 的位置/数量/其余字段必须逐字节保真（对应 01 文档维度 #18 hex 回放
// 与 #4 GREASE 位置）。
package e2e

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	gbt "github.com/geekbyter/geektls/bindings/golang"
	"github.com/geekbyter/geektls/core/profiles"
	"github.com/geekbyter/geektls/tests/e2e/specimens"
	"github.com/gospider007/ja3"
)

// chSpecimen 语料条目：本地冻结的真实浏览器抓包（tests/e2e/specimens），
// 原始字节由 ja3 解析器独立解析作为对照侧。
type chSpecimen struct {
	name string
	orig *ja3.TlsSpec
}

func loadCorpus(t *testing.T) []chSpecimen {
	t.Helper()
	var out []chSpecimen
	for _, it := range specimens.All() {
		raw, err := hex.DecodeString(it.Hex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", it.Name, err)
		}
		orig, err := ja3.ParseTlsSpec(raw)
		if err != nil {
			t.Fatalf("%s: independent parse: %v", it.Name, err)
		}
		out = append(out, chSpecimen{name: it.Name, orig: orig})
	}
	return out
}

// dropPSK 剔除 pre_shared_key(41)：标本可能带真实票据，hex 回放在无有效票据时
// 按 OmitEmptyPsk 省略该扩展（fresh 连接语义；不可复用他人票据），两侧对齐后再比。
func dropPSK(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if v != 41 {
			out = append(out, v)
		}
	}
	return out
}

// normalizeGreaseList 把所有 GREASE 值（0x?a?a）归一化为占位常量，便于逐位置比对。
// （标量版 normalizeGrease 见 loopback_test.go。）
func normalizeGreaseList(vs []uint16) []uint16 {
	out := make([]uint16, len(vs))
	for i, v := range vs {
		if isGrease16(v) {
			out[i] = 0x0a0a
		} else {
			out[i] = v
		}
	}
	return out
}

func extTypes16(exts []ja3.Extension) []uint16 {
	out := make([]uint16, 0, len(exts))
	for _, e := range exts {
		out = append(out, e.Type)
	}
	return out
}

func TestClientHelloCorpusReplay(t *testing.T) {
	results := make(chan fpCaptured, 64)
	addr := startFPOracle(t, results)
	url := fmt.Sprintf("https://localhost:%d/", addr.(*net.TCPAddr).Port)

	for _, item := range loadCorpus(t) {
		name, orig := item.name, item.orig
		t.Run(name, func(t *testing.T) {
			p, warnings, err := profiles.FromClientHelloHex(orig.Hex())
			if err != nil {
				t.Fatalf("FromClientHelloHex: %v", err)
			}
			for _, w := range warnings {
				t.Logf("parse warning（透传/有损记录）: %+v", w)
			}

			sess, err := gbt.NewSessionFromProfile(p, &gbt.Options{InsecureSkipVerify: true, TimeoutMs: 15000})
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			resp, err := sess.Get(url)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			var cap fpCaptured
			select {
			case cap = <-results:
			case <-time.After(10 * time.Second):
				t.Fatal("fp did not capture request")
			}
			ts := cap.tls
			if ts == nil {
				t.Fatal("fp returned nil TlsSpec")
			}

			// GREASE 归一化后逐位置精确对比（位置/数量保真，值允许重随机化）。
			assertEq(t, "cipher 列表（GREASE 归一）", normalizeGreaseList(orig.CipherSuites), normalizeGreaseList(ts.CipherSuites))
			assertEq(t, "扩展类型顺序（GREASE 归一，剔 PSK）", dropPSK(normalizeGreaseList(extTypes16(orig.Extensions))), dropPSK(normalizeGreaseList(extTypes16(ts.Extensions))))
			assertEq(t, "curves（GREASE 归一）", normalizeGreaseList(orig.Curves()), normalizeGreaseList(ts.Curves()))
			assertEq(t, "ec_point_formats", u8sTo16(orig.Points()), u8sTo16(ts.Points()))
			assertEq(t, "supported_versions（GREASE 归一）", normalizeGreaseList(orig.Versions()), normalizeGreaseList(ts.Versions()))
			// sig_algs 也按本文件声明的语义归一化 GREASE：真标本里可能带 GREASE 位
			// （如 chrome_152_macos 标本首位 0xEAEA），而我们现在在编译期重取该值。
			assertEq(t, "signature_algorithms（GREASE 归一）", normalizeGreaseList(orig.Algorithms()), normalizeGreaseList(ts.Algorithms()))
			assertEq(t, "ALPN", orig.Protocols(), ts.Protocols())
			assertEq(t, "handshake legacy_version", orig.HandshakeVersion, ts.HandshakeVersion)
			assertEq(t, "SNI（重放应保留原值）", sniFromSpec(orig), sniFromSpec(ts))
		})
	}
}

var _ = net.IPv4zero // 保留 net 引用（url 构造用 *net.TCPAddr）
