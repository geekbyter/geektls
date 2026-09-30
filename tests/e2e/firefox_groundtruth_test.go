package e2e

// Firefox ground truth 回归（2026-09-24）。
//
// 来源：**真 Firefox 156 / Windows** 对 tls.peet.ws 的字段级实测（真机 + 外部 oracle
// 逐字段记录，无原始 ClientHello 字节——故新预设 `firefox_156_windows` 是字段级转录，
// 证据等级记为 E1r/E2，与 Chrome/Edge 的原始字节级 E1 区分）。
//
// 断言策略：
//   - 对 **所有** firefox_* 预设：钉版本无关的不变量（导航头顺序、伪头序 m,p,a,s、
//     连接级 WINDOW_UPDATE），这些是"一眼假"的高风险项；
//   - 对 `firefox_156_windows`：按实测**严格全等**（cipher 顺序、扩展集合、groups、
//     sig_algs、delegated_credentials、record_size_limit、证书压缩算法、H2 SETTINGS）。

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/geekbyter/geektls/core/profiles"
)

var (
	// Firefox 156 / Windows 实测（tls.peet.ws，2026-09-24）。
	ffGT156Ciphers = []uint16{
		0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
		0xc02c, 0xc030, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}
	ffGT156Exts = []uint16{0, 5, 10, 11, 13, 16, 18, 23, 27, 28, 34, 35, 43, 45, 51, 65037, 65281}
	// groups 含 **P-521(25)**——这是 Firefox 与 Chromium 的稳定差异（Chrome 只到 P-384）。
	ffGT156Groups    = []uint16{4588, 29, 23, 24, 25}
	ffGT156SigAlgs   = []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201}
	ffGT156DCSigAlgs = []uint16{0x0403, 0x0503, 0x0603, 0x0203}

	// Firefox 导航头顺序（实测）：**无 UA-CH**，收尾是 `te: trailers`（Chromium 没有）。
	ffGTIdentityOrder = []string{
		"user-agent", "accept", "accept-language", "accept-encoding",
		"upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
		"sec-fetch-site", "sec-fetch-user", "priority", "te",
	}
)

func ffHexU16(vals []string) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		var x uint32
		if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(v, "0x")), "%x", &x); err == nil {
			out = append(out, uint16(x))
		}
	}
	return out
}

// ffGTAndroidIdentityOrder 是 Firefox/Android 的导航头顺序（真机实测，2026-09-28）：
// 与桌面版的差别是**没有** `sec-fetch-user`（10 头 vs 11 头）。
var ffGTAndroidIdentityOrder = []string{
	"user-agent", "accept", "accept-language", "accept-encoding", "upgrade-insecure-requests",
	"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "priority", "te",
}

func ffExt(p *profiles.Profile, t uint16) *profiles.Extension {
	for i := range p.TLS.Detail.Extensions {
		if p.TLS.Detail.Extensions[i].Type == t {
			return &p.TLS.Detail.Extensions[i]
		}
	}
	return nil
}

func TestFirefoxGroundTruth(t *testing.T) {
	checked := 0
	for _, name := range profiles.List() {
		if !strings.HasPrefix(name, "firefox_") {
			continue
		}
		p, err := profiles.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if p.Grade != "" {
			continue // 非自测（E3 第三方 / E2i 内插）：不参与 E1 级断言
		}
		checked++
		t.Run(name, func(t *testing.T) {
			// --- 版本无关不变量 ---
			var gotOrder []string
			for _, kv := range p.Identity.Headers {
				gotOrder = append(gotOrder, strings.ToLower(kv[0]))
			}
			// 导航头顺序按平台分：桌面（Windows/macOS）与 Android 实测不同
			// （Android 版**没有** `sec-fetch-user`，共 10 头）。
			wantOrder := ffGTIdentityOrder
			if strings.HasSuffix(name, "_android") {
				wantOrder = ffGTAndroidIdentityOrder
			}
			assertEq(t, "Firefox 导航头顺序（实测）", wantOrder, gotOrder)

			// 首访形态（三次 Firefox 实测综合）：session_ticket(35) 与
			// psk_key_exchange_modes(45) 必须存在——只有**无痕窗口**才同时缺这两个
			// （无痕关闭会话恢复）。41 是恢复占位，无票据时线上省略，故不要求。
			for _, need := range []uint16{35, 45} {
				if ffExt(p, need) == nil {
					t.Errorf("缺扩展 %d：普通窗口首访形态应有它（仅无痕窗口才没有）", need)
				}
			}

			// G11：Firefox 的 HEADERS 内嵌 priority 必须显式给实测值
			// （fhttp 默认值是 Chrome 形状 excl=true/w=255，不覆盖就露出 Chrome 形态）。
			if p.HTTP2.HeadersPriority == nil {
				t.Error("缺 http2.headers_priority（会退化为 Chrome 形状 excl=true/weight=255）")
			} else {
				assertEq(t, "HEADERS 内嵌 priority",
					profiles.H2HeadersPriority{Exclusive: false, StreamDep: 0, Weight: 41},
					*p.HTTP2.HeadersPriority)
			}
			assertEq(t, "伪头顺序", []string{"m", "p", "a", "s"}, p.HTTP2.PseudoHeaderOrder)
			if p.HTTP2.WindowUpdate == nil {
				t.Error("H2 WINDOW_UPDATE 缺失，want 12517377（Firefox 实测）")
			} else {
				assertEq(t, "H2 WINDOW_UPDATE", uint32(12517377), *p.HTTP2.WindowUpdate)
			}

			// --- 156 预设：严格全等实测 ---
			if name != "firefox_156_windows" {
				return
			}
			assertEq(t, "cipher 列表与顺序", ffGT156Ciphers, ffHexU16(p.TLS.Detail.Ciphers))

			var exts []uint16
			for _, e := range p.TLS.Detail.Extensions {
				exts = append(exts, e.Type)
			}
			// 41 是会话复用占位（无票据时线上省略），与实测集合一并比较。
			want := append(append([]uint16(nil), ffGT156Exts...), 41)
			got := append([]uint16(nil), exts...)
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
			assertEq(t, "扩展集合（含 41 空占位，属会话复用项）", want, got)

			if e := ffExt(p, 10); e == nil {
				t.Fatal("缺 supported_groups")
			} else {
				assertEq(t, "supported_groups", ffGT156Groups, ffHexU16(e.Groups))
			}
			if e := ffExt(p, 13); e == nil {
				t.Fatal("缺 signature_algorithms")
			} else {
				assertEq(t, "signature_algorithms", ffGT156SigAlgs, ffHexU16(e.SigAlgs))
			}
			if e := ffExt(p, 34); e == nil {
				t.Fatal("缺 delegated_credentials")
			} else {
				assertEq(t, "delegated_credentials sig_algs", ffGT156DCSigAlgs, ffHexU16(e.SigAlgs))
			}
			if e := ffExt(p, 28); e == nil {
				t.Fatal("缺 record_size_limit")
			} else if e.Data != "4001" {
				t.Errorf("record_size_limit data = %q, want 4001（实测 16385）", e.Data)
			}
			if e := ffExt(p, 27); e == nil {
				t.Fatal("缺 compress_certificate")
			} else {
				assertEq(t, "cert_compression", []string{"zlib", "brotli", "zstd"}, e.CertCompression)
			}
			var gotSettings [][2]uint32
			for _, kv := range p.HTTP2.Settings {
				if len(kv) != 2 {
					t.Fatalf("bad http2.settings entry: %v", kv)
				}
				gotSettings = append(gotSettings, [2]uint32{kv[0], kv[1]})
			}
			assertEq(t, "H2 SETTINGS（有序）",
				[][2]uint32{{1, 65536}, {2, 0}, {4, 131072}, {5, 16384}}, gotSettings)

			// 身份头取值抽查（实测原文）
			if v, ok := headerValue(p.Identity.Headers, "accept"); !ok ||
				v != "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" {
				t.Errorf("accept = %q（与实测不符）", v)
			}
			if v, ok := headerValue(p.Identity.Headers, "te"); !ok || v != "trailers" {
				t.Errorf("te = %q, want trailers", v)
			}
			if _, ok := headerValue(p.Identity.Headers, "sec-ch-ua"); ok {
				t.Error("Firefox 不应有 sec-ch-ua（UA-CH 是 Chromium 专有）")
			}
		})
	}
	if checked == 0 {
		t.Fatal("没有扫到任何 firefox_* 预设——本测试可能已失效")
	}
	t.Logf("覆盖 %d 个 Firefox 预设；156 严格全等实测值", checked)
}
