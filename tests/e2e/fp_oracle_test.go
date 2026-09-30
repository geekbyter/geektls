// 第二 oracle（V-5 / T1-4）：gospider007/fp 作为独立指纹解析器，
// 对 geektls 发出的 ClientHello 与 HTTP/2 帧做逐字段交叉硬断言。
//
// 与 external_oracle_test.go（L3，回读服务，build tag external）不同：
// 本测试完全本地、默认必跑、失败即断言——fp 是与我们自算无关的第三套实现
// （gospider007/ja3 + gaukas/clienthellod），用于打破"同源自证"。
//
// 对比面：
//
//	TLS：cipher 列表 / 扩展顺序 / curves / points / supported_versions /
//	      signature_algorithms / ALPN / SNI（观察项）
//	H2 ：SETTINGS id:value 有序 / 连接级 WINDOW_UPDATE / 伪头顺序
//
// 运行：go test ./... -run TestFPSecondOracle -v
package e2e

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	fp "github.com/gospider007/fp"
	"github.com/gospider007/gtls"
	"github.com/gospider007/ja3"

	gbt "github.com/geekbyter/geektls/bindings/golang"
	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

// fpCaptured 是一次请求在 fp 侧解析出的全部指纹。
type fpCaptured struct {
	tls  *ja3.TlsSpec
	h2   *ja3.H2Spec
	h1   *ja3.H1Spec
	sni  string
	addr string
}

func isGrease16(v uint16) bool {
	return v&0x0f0f == 0x0a0a && (v>>8) == (v&0xff)
}

// sniFromSpec 从 fp 捕获的原始扩展字节里自行解析 SNI。
// 不能用 fp 的 TlsSpec.ServerName()：其内置 utls 被 gaukas 打过补丁
// （"don't copy SNI from ClientHello to ClientHelloSpec!"），恒返回空。
// 自行解析原始字节可保持"独立 oracle"性质。
func sniFromSpec(ts *ja3.TlsSpec) string {
	if ts == nil {
		return ""
	}
	for _, e := range ts.Extensions {
		if e.Type != 0 {
			continue
		}
		data := []byte(e.Data)
		// server_name_list: u16 listLen, entries: u8 nameType, u16 nameLen, name
		if len(data) < 2 {
			return ""
		}
		listLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if listLen > len(data) {
			listLen = len(data)
		}
		data = data[:listLen]
		for len(data) >= 3 {
			nameLen := int(data[1])<<8 | int(data[2])
			data = data[3:]
			if nameLen > len(data) {
				return ""
			}
			name := string(data[:nameLen])
			data = data[nameLen:]
			if name != "" {
				return name
			}
		}
	}
	return ""
}

func stripGrease16(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !isGrease16(v) {
			out = append(out, v)
		}
	}
	return out
}

func dashUint16(s string) []uint16 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "-")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		var v uint32
		if _, err := fmt.Sscanf(p, "%d", &v); err != nil {
			return nil
		}
		out = append(out, uint16(v))
	}
	return out
}

func u8sTo16(vs []uint8) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		out = append(out, uint16(v))
	}
	return out
}

// startFPOracle 起一个 fp 采集端（独立解析器），返回地址与结果通道。
// 用 NewListen 而非 fp.Server 以便拿到可关闭的 Listener。
func startFPOracle(t *testing.T, results chan<- fpCaptured) net.Addr {
	t.Helper()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := fp.GetRawConn(r.Context())
		ts := raw.TLSSpec()
		results <- fpCaptured{
			tls:  ts,
			h2:   raw.H2Spec(),
			h1:   raw.H1Spec(),
			sni:  sniFromSpec(ts),
			addr: r.RemoteAddr,
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})

	tlsConfig := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return gtls.GetCertificate(chi, nil, nil)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}

	ln, err := fp.NewListen("localhost:0", handler, tlsConfig)
	if err != nil {
		t.Fatalf("fp listen: %v", err)
	}
	srv := &http.Server{ConnContext: fp.ConnContext, Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr()
}

func TestFPSecondOracle(t *testing.T) {
	results := make(chan fpCaptured, 64)
	addr := startFPOracle(t, results)
	// 以 localhost 访问（而非 addr.String() 的 IP）：保证 SNI 出现在 wire 上，
	// 与真实浏览器访问域名的形态一致。
	url := fmt.Sprintf("https://localhost:%d/", addr.(*net.TCPAddr).Port)

	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			if p.Grade != "" {
				// **非自测预设**（E3 第三方导入 / E2i、E2i-u 谱系内插）不参与 E1 级断言：
				// 它们没有该版本的真机实测背书，拿来"验证"真机形态等于自证。
				// 它们的覆盖由 TestPresetsAreValid（能编译 + JA3/JA4 自洽）与
				// cmd/gen-profiles 的谱系一致性测试负责。
				return
			}
			spec, err := tlscore.CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatal(err)
			}

			sess, err := gbt.NewSession(name, &gbt.Options{InsecureSkipVerify: true, TimeoutMs: 15000})
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

			// ---- TLS 层：JA3 语义对齐（双侧剔除 GREASE）----
			ja3parts := strings.Split(tlscore.ComputeJA3(spec), ",")
			if len(ja3parts) != 5 {
				t.Fatalf("unexpected JA3 parts: %q", tlscore.ComputeJA3(spec))
			}
			wantCiphers := dashUint16(ja3parts[1])
			wantExts := dashUint16(ja3parts[2])
			wantGroups := dashUint16(ja3parts[3])
			wantPoints := dashUint16(ja3parts[4])

			gotCiphers := stripGrease16(ts.CipherSuites)
			var gotExts []uint16
			for _, e := range ts.Extensions {
				gotExts = append(gotExts, e.Type)
			}
			gotExts = stripGrease16(gotExts)
			gotGroups := stripGrease16(ts.Curves())
			gotPoints := u8sTo16(ts.Points())

			assertEq(t, "cipher 列表与顺序", wantCiphers, gotCiphers)
			if p.TLS.Detail.ExtensionPermutation {
				// Chrome 式 per-connection 洗牌：CompileDetail 与 engine 各自独立洗牌，
				// 两次随机序本就不同——此处断言"集合一致"而非"顺序一致"。
				assertSetEq(t, "扩展集合（洗牌 profile，比集合）", wantExts, gotExts)
			} else {
				assertEq(t, "扩展集合与线上顺序", wantExts, gotExts)
			}
			assertEq(t, "supported_groups/curves", wantGroups, gotGroups)
			assertEq(t, "ec_point_formats", wantPoints, gotPoints)

			// ---- TLS 层补充维度：versions / sig_algs / ALPN ----
			var wantVersions, wantSigAlgs []uint16
			var wantALPN []string
			for _, e := range spec.Extensions {
				switch ext := e.(type) {
				case *utls.SupportedVersionsExtension:
					wantVersions = stripGrease16(ext.Versions)
				case *utls.SignatureAlgorithmsExtension:
					for _, s := range ext.SupportedSignatureAlgorithms {
						if !isGrease16(uint16(s)) {
							wantSigAlgs = append(wantSigAlgs, uint16(s))
						}
					}
				case *utls.ALPNExtension:
					wantALPN = ext.AlpnProtocols
				}
			}
			assertEq(t, "supported_versions", wantVersions, stripGrease16(ts.Versions()))
			assertEq(t, "signature_algorithms", wantSigAlgs, stripGrease16(ts.Algorithms()))
			assertEq(t, "ALPN", wantALPN, ts.Protocols())
			assertEq(t, "SNI（localhost 场景应发送）", "localhost", cap.sni)

			// ---- HTTP/2 层（Akamai 四段：settings/window/pseudo 三段可断）----
			if resp.UsedProtocol != "h2" {
				t.Fatalf("expected h2, got %q", resp.UsedProtocol)
			}
			if cap.h2 == nil {
				t.Fatal("fp returned nil H2Spec")
			}
			if p.HTTP2 == nil {
				t.Fatal("profile has no http2 section")
			}

			var gotSettings [][2]uint32
			for _, s := range cap.h2.Settings {
				if isGrease16(uint16(s.ID)) {
					continue
				}
				gotSettings = append(gotSettings, [2]uint32{uint32(s.ID), s.Val})
			}
			var wantSettings [][2]uint32
			for _, kv := range p.HTTP2.Settings {
				if len(kv) != 2 {
					t.Fatalf("bad http2.settings entry: %v", kv)
				}
				wantSettings = append(wantSettings, [2]uint32{kv[0], kv[1]})
			}
			assertEq(t, "H2 SETTINGS id:value 有序", wantSettings, gotSettings)
			assertEq(t, "H2 WINDOW_UPDATE 增量", flowOnWire(p.HTTP2.WindowUpdate), cap.h2.ConnFlow)

			// ---- G11：HEADERS 帧**内嵌** priority（线上 flags 0x20）----
			// 实测（2026-09-24，tls.peet.ws；peet 报的 weight = 线上值 +1）：
			//   Chrome/Edge：exclusive=true, stream_dep=0, weight 线上 255（peet 报 256）
			//   Firefox 156（普通 + 无痕各一次）：exclusive=false, weight 线上 41（报 42）
			// Safari 未实测 ⇒ 不钉值（缺口记 docs/07 G11）。
			switch {
			case strings.HasSuffix(name, "_ios"):
				// **名字前缀 ≠ TLS 栈**：iOS 上第三方浏览器必须用 WebKit，故 chrome_/edge_ 的
				// iOS 预设也是 WebKit 形态（实测见 docs/07 §5.5）。priority 取 Safari 值。
				assertEq(t, "HEADERS 内嵌 priority（iOS/WebKit 实测）",
					ja3.Http2PriorityParam{StreamDep: 0, Exclusive: false, Weight: 254}, cap.h2.Priority)
			case strings.HasPrefix(name, "chrome_"), strings.HasPrefix(name, "edge_"):
				assertEq(t, "HEADERS 内嵌 priority（Chrome/Edge 实测）",
					ja3.Http2PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255}, cap.h2.Priority)
			case strings.HasPrefix(name, "firefox_"):
				assertEq(t, "HEADERS 内嵌 priority（Firefox 实测）",
					ja3.Http2PriorityParam{StreamDep: 0, Exclusive: false, Weight: 41}, cap.h2.Priority)
			case strings.HasPrefix(name, "safari_"):
				// 真 Safari 实测（2026-09-28，17.3.1 与 18.6 两份）：**exclusive=false**
				// ——这是与 Chrome（exclusive=true）的硬区别；weight 线上值随版本
				// （17.3.1 → 254，18.6 → 255）。
				switch name {
				case "safari_17_3_macos":
					assertEq(t, "HEADERS 内嵌 priority（Safari 17.3.1 实测）",
						ja3.Http2PriorityParam{StreamDep: 0, Exclusive: false, Weight: 254}, cap.h2.Priority)
				case "safari_18_6_macos":
					assertEq(t, "HEADERS 内嵌 priority（Safari 18.6 实测）",
						ja3.Http2PriorityParam{StreamDep: 0, Exclusive: false, Weight: 255}, cap.h2.Priority)
				default:
					// 其余 Safari 预设未单独实测：exclusive=false 是两版实测一致的族特征，
					// weight 借自 18.6（如实测到差异再改）。
					if cap.h2.Priority.Exclusive {
						t.Errorf("%s: Safari 族实测 exclusive=false，实际 %+v", name, cap.h2.Priority)
					} else {
						t.Logf("%s: priority = %+v（weight 借自实测 18.6）", name, cap.h2.Priority)
					}
				}
			default:
				t.Logf("HEADERS 内嵌 priority（未实测族，不钉值）: %+v", cap.h2.Priority)
			}

			// ---- 身份一致性（T2-1）：常规头应全等 profile.identity 缺省头 ----
			// fp 的 H2Spec.OrderHeaders 来自 MetaHeadersFrame.RegularFields()，
			// 只含常规头（不含伪头）；伪头顺序不在 fp 解析面内，该维度由
			// nginx 采集端 $http2_fingerprint_pseudo_headers 覆盖（T1-1）。
			if p.Identity == nil || len(p.Identity.Headers) == 0 {
				t.Fatal("profile missing identity section (T2-1)")
			}
			gotHeaders := cap.h2.OrderHeaders
			assertEq(t, "identity 常规头（有序全等）", p.Identity.Headers, gotHeaders)
			for _, kv := range gotHeaders {
				if strings.Contains(kv[1], "Go-http-client") {
					t.Errorf("头部暴露 Go 栈身份: %s: %s", kv[0], kv[1])
				}
			}
		})
	}
}

// flowOnWire 把预设的三态 window_update 归一成线上实际写出的连接级
// WINDOW_UPDATE 增量：nil 由引擎补 Chrome 默认 15663105，显式 0 表示不发。
func flowOnWire(v *uint32) uint32 {
	if v == nil {
		return 15663105
	}
	return *v
}

func assertEq[T any](t *testing.T, what string, want, got T) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Errorf("%s 不一致\n  want: %v\n  got:  %v", what, want, got)
	}
}

// assertSetEq 比对集合（忽略顺序），用于 Chrome 式 per-connection 洗牌的扩展列表。
func assertSetEq(t *testing.T, what string, want, got []uint16) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("%s 集合大小不一致\n  want: %v\n  got:  %v", what, want, got)
		return
	}
	count := map[uint16]int{}
	for _, v := range want {
		count[v]++
	}
	for _, v := range got {
		count[v]--
	}
	for v, n := range count {
		if n != 0 {
			t.Errorf("%s 集合不一致，元素 %d 差 %d 个\n  want: %v\n  got:  %v", what, v, n, want, got)
			return
		}
	}
}
