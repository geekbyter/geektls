// tls12_fallback_test.go — G1 判定（TLS 1.2 回退指纹）
//
// 要回答两个问题（07-capability-gaps.md 里 G1 的"影响"列是否成立）：
//  1. 功能面：服务端只支持 TLS1.2 时，我们能不能完成握手？
//  2. 指纹面：此时发出的 ClientHello，是否与 TLS1.3 场景逐字段一致？
//
// 设计依据：ClientHello 是在得知服务端版本偏好之前就发出去的字节，
// 因此"服务端降级"在原理上不应改变 CH。本测试把同一 profile 分别打到
// 两个本地 fp 采集端（一个默认含 1.3、一个 MinVersion=MaxVersion=TLS1.2），
// 用独立解析器 double-check 两侧结果，并与 profile 声明值对齐。
//
// 注意：本测试判定的是"服务端强制降级"（风控主动只提供 1.2）这一场景。
// "客户端自身上限=1.2"（企业策略 SSLVersionMax / 老浏览器）会产生被裁剪的
// CH（无 supported_versions/key_share 等），属另一种形态，不在本测试范围。
//
// 运行：go test ./... -run TestTLS12Fallback -v
package e2e

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	fp "github.com/gospider007/fp"
	"github.com/gospider007/gtls"
	"github.com/gospider007/ja3"

	gbt "github.com/geekbyter/geektls/bindings/golang"
	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

// fpVerCaptured = fp 独立解析结果 + 客户端在 CH 里声明的 supported_versions。
type fpVerCaptured struct {
	fpCaptured
	offered []uint16
}

// startFPOracleVersioned 起本地 fp 采集端。
// minVer/maxVer 非 0 时钉死 TLS 版本区间：maxVer=TLS1.2 即"服务端只支持 1.2"。
func startFPOracleVersioned(t *testing.T, minVer, maxVer uint16, results chan<- fpVerCaptured) net.Addr {
	t.Helper()
	offeredCh := make(chan []uint16, 64)

	tlsConfig := &tls.Config{
		MinVersion: minVer,
		MaxVersion: maxVer,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return gtls.GetCertificate(chi, nil, nil)
		},
		// 在握手前拿到 CH 里的 supported_versions（证明客户端确实提供了 1.2）。
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case offeredCh <- append([]uint16(nil), chi.SupportedVersions...):
			default:
			}
			return nil, nil // nil = 沿用原配置
		},
		NextProtos: []string{"h2", "http/1.1"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := fp.GetRawConn(r.Context())
		ts := raw.TLSSpec()
		c := fpVerCaptured{
			fpCaptured: fpCaptured{
				tls: ts, h2: raw.H2Spec(), h1: raw.H1Spec(),
				sni: sniFromSpec(ts), addr: r.RemoteAddr,
			},
		}
		select {
		case c.offered = <-offeredCh:
		case <-time.After(2 * time.Second):
		}
		results <- c
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})

	ln, err := fp.NewListen("localhost:0", handler, tlsConfig)
	if err != nil {
		t.Fatalf("fp listen: %v", err)
	}
	srv := &http.Server{ConnContext: fp.ConnContext, Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr()
}

// tlsParts 是"跨连接可比"的 ClientHello 归一化面（已剔 GREASE）。
type tlsParts struct {
	ciphers  []uint16
	exts     []uint16
	groups   []uint16
	points   []uint16
	versions []uint16
	sigalgs  []uint16
	alpn     []string
}

func partsOfTS(ts *ja3.TlsSpec) tlsParts {
	var p tlsParts
	p.ciphers = stripGrease16(ts.CipherSuites)
	for _, e := range ts.Extensions {
		p.exts = append(p.exts, e.Type)
	}
	p.exts = stripGrease16(p.exts)
	p.groups = stripGrease16(ts.Curves())
	p.points = u8sTo16(ts.Points())
	p.versions = stripGrease16(ts.Versions())
	p.sigalgs = stripGrease16(ts.Algorithms())
	p.alpn = ts.Protocols()
	return p
}

// hexStrsToU16 解析 profile 里的 "0x0304" 形式列表（跳过 "grease"）。
func hexStrsToU16(vals []string) []uint16 {
	var out []uint16
	for _, v := range vals {
		if strings.EqualFold(v, profiles.GreaseToken) {
			continue
		}
		var x uint32
		if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(v, "0x")), "%x", &x); err != nil {
			continue
		}
		out = append(out, uint16(x))
	}
	return out
}

// wantTLS 从 profile 的 detail 取 supported_versions / sig_algs / ALPN 期望值。
func wantTLS(p *profiles.Profile) (versions, sigalgs []uint16, alpn []string) {
	for _, e := range p.TLS.Detail.Extensions {
		switch e.Type {
		case 43:
			versions = hexStrsToU16(e.Versions)
		case 13:
			sigalgs = hexStrsToU16(e.SigAlgs)
		case 16:
			alpn = e.ALPN
		}
	}
	return
}

func containsU16(vs []uint16, want uint16) bool {
	for _, v := range vs {
		if v == want {
			return true
		}
	}
	return false
}

func h2Settings(spec *ja3.H2Spec) [][2]uint32 {
	var out [][2]uint32
	for _, s := range spec.Settings {
		if isGrease16(uint16(s.ID)) {
			continue
		}
		out = append(out, [2]uint32{uint32(s.ID), s.Val})
	}
	return out
}

// runProfile 用一个 profile 打一次采集端，返回 ALPN 结果与 fp 解析快照。
func runProfile(t *testing.T, name, url string, ch <-chan fpVerCaptured) (string, fpVerCaptured) {
	t.Helper()
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
	select {
	case c := <-ch:
		return resp.UsedProtocol, c
	case <-time.After(10 * time.Second):
		t.Fatal("fp did not capture request")
	}
	return "", fpVerCaptured{}
}

func TestTLS12Fallback(t *testing.T) {
	results13 := make(chan fpVerCaptured, 64)
	results12 := make(chan fpVerCaptured, 64)
	addr13 := startFPOracleVersioned(t, 0, 0, results13).(*net.TCPAddr)
	addr12 := startFPOracleVersioned(t, tls.VersionTLS12, tls.VersionTLS12, results12).(*net.TCPAddr)
	u13 := fmt.Sprintf("https://localhost:%d/", addr13.Port)
	u12 := fmt.Sprintf("https://localhost:%d/", addr12.Port)

	for _, name := range profiles.List() {
		if p, err := profiles.Get(name); err == nil && p.Grade != "" {
			continue // 非自测（E3 第三方 / E2i 内插）：G1 是"我们自测预设"的性质
		}
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := tlscore.CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatal(err)
			}

			proto13, c13 := runProfile(t, name, u13, results13)
			if proto13 != "h2" {
				t.Fatalf("1.3 场景期望 h2，得 %q", proto13)
			}
			// 功能面：服务端只提供 TLS1.2 时必须仍能握手成功。
			proto12, c12 := runProfile(t, name, u12, results12)
			if proto12 != "h2" {
				t.Errorf("1.2 场景 ALPN 期望 h2，得 %q", proto12)
			}
			if c13.tls == nil || c12.tls == nil {
				t.Fatal("nil TlsSpec")
			}
			if c13.h2 == nil || c12.h2 == nil {
				t.Fatal("nil H2Spec")
			}

			// 客户端必须在 CH 里声明支持 TLS1.2（真 Chrome 的 supported_versions 含 1.2）。
			if !containsU16(c12.offered, tls.VersionTLS12) {
				t.Errorf("CH 未声明支持 TLS1.2，offered=%#x", c12.offered)
			}

			a13, a12 := partsOfTS(c13.tls), partsOfTS(c12.tls)

			// ---- 与 profile 声明值对齐（1.2 场景，防"两侧同错"）----
			ja3parts := strings.Split(tlscore.ComputeJA3(spec), ",")
			if len(ja3parts) != 5 {
				t.Fatalf("unexpected JA3: %q", tlscore.ComputeJA3(spec))
			}
			assertEq(t, "1.2 场景 cipher 列表与顺序", dashUint16(ja3parts[1]), a12.ciphers)
			if p.TLS.Detail.ExtensionPermutation {
				assertSetEq(t, "1.2 场景扩展集合（洗牌 profile）", dashUint16(ja3parts[2]), a12.exts)
			} else {
				assertEq(t, "1.2 场景扩展顺序", dashUint16(ja3parts[2]), a12.exts)
			}
			assertEq(t, "1.2 场景 supported_groups", dashUint16(ja3parts[3]), a12.groups)
			assertEq(t, "1.2 场景 ec_point_formats", dashUint16(ja3parts[4]), a12.points)

			// 期望值按 JA3/JA4 语义剔除 GREASE 后再比（profile 里 GREASE 可能写成
			// "grease" 占位，也可能被抓包转录成字面量如 "0xeaea"——两者都要剔）。
			wv, ws, wa := wantTLS(p)
			assertEq(t, "1.2 场景 supported_versions", stripGrease16(wv), a12.versions)
			assertEq(t, "1.2 场景 signature_algorithms", stripGrease16(ws), a12.sigalgs)
			assertEq(t, "1.2 场景 ALPN", wa, a12.alpn)

			// ---- 核心判定：CH 不因服务端降级而改变 ----
			assertEq(t, "cipher 列表（1.3 vs 1.2）", a13.ciphers, a12.ciphers)
			assertSetEq(t, "扩展集合（1.3 vs 1.2）", a13.exts, a12.exts)
			assertEq(t, "supported_groups（1.3 vs 1.2）", a13.groups, a12.groups)
			assertEq(t, "ec_point_formats（1.3 vs 1.2）", a13.points, a12.points)
			assertEq(t, "supported_versions（1.3 vs 1.2）", a13.versions, a12.versions)
			assertEq(t, "signature_algorithms（1.3 vs 1.2）", a13.sigalgs, a12.sigalgs)
			assertEq(t, "ALPN（1.3 vs 1.2）", a13.alpn, a12.alpn)

			// ---- H2 帧层：降级不应影响 SETTINGS / WINDOW_UPDATE ----
			assertEq(t, "H2 SETTINGS（1.3 vs 1.2）", h2Settings(c13.h2), h2Settings(c12.h2))
			assertEq(t, "H2 WINDOW_UPDATE（1.3 vs 1.2）", c13.h2.ConnFlow, c12.h2.ConnFlow)

			var wantSettings [][2]uint32
			for _, kv := range p.HTTP2.Settings {
				if len(kv) == 2 {
					wantSettings = append(wantSettings, [2]uint32{kv[0], kv[1]})
				}
			}
			assertEq(t, "1.2 场景 H2 SETTINGS 与 profile", wantSettings, h2Settings(c12.h2))

			t.Logf("OK %s：1.2 回退握手成功，CH/H2 与 1.3 场景一致（exts=%d）", name, len(a12.exts))
		})
	}
}
