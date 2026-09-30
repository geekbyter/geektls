// 真实抓包 ground truth 回归（2026-09-24）。
//
// 来源：Chrome 149 / Edge 149 (Windows) 与某同类库同样对 tls.peet.ws 的实测，
// 完整记录与逐项 diff 见 docs/07-capability-gaps.md。
//
// 作用：把实测值钉进回归——身份头格式（UA-CH 品牌顺序 / GREASE 品牌）与
// HTTP/2 段（akamai 四段）一旦漂移立即报错。
package e2e

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/geektls/core/profiles"
)

// 抓包实测的 Chromium 导航头顺序（Chrome 149 / Edge 149）。
var gtChromiumHeaderOrder = []string{
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
	"user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
	"sec-fetch-dest", "accept-encoding", "accept-language", "priority",
}

// gtChromiumAndroidHeaderOrder 是 **Android** Chrome/Edge 的导航头顺序（真机实测，2026-09-28）：
// 与桌面版的关键差别是 **UA-CH 三件套在 `accept` 之后**（桌面上它们排在最前）。
var gtChromiumAndroidHeaderOrder = []string{
	"upgrade-insecure-requests", "user-agent", "accept", "sec-ch-ua", "sec-ch-ua-mobile",
	"sec-ch-ua-platform", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
	"sec-fetch-dest", "accept-encoding", "accept-language", "priority",
}

// 实测 sec-ch-ua 的**结构**：自家品牌 + Chromium + 一个 GREASE 品牌（三项齐备）。
//
// 注意（E1 实测，2026-09-24 与 09-28 两次修正）：**品牌顺序、GREASE 品牌名称与版本
// 都不是常量**——此前把 "Not)A;Brand";v="24" 当固定格式、并把"自家品牌在首位"当规则，
// 都属过度固化。三个实测样本给出三种顺序：
//
//	Chrome 149 (Windows) → "Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"
//	Edge  153 (Windows) → "Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"
//	Chrome 154 (macOS)   → "Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"
//
// 三个样本三种顺序，无法区分"每版本固定"与"每会话随机"（未定论）⇒ 只钉三项齐全 +
// 版本自洽（UA 主版本 == UA-CH 自家品牌版本），**不钉位置**。预设各自保留其抓包实测的
// 那一份顺序（数据驱动）。
var (
	gtOwnBrand    = regexp.MustCompile(`"(Google Chrome|Microsoft Edge)";v="(\d+)"`)
	gtGreaseBrand = regexp.MustCompile(`"Not[^"]*Brand";v="\d+"`)
	gtUAMajor     = regexp.MustCompile(`(?:Chrome|Edg)/(\d+)`)
)

// TLS 扩展集合（剔除 GREASE 与 pre_shared_key）：Chrome 149 实测。
// ALPS 码点单独判定：Chrome ≤131 用旧码点 17513，132+ 用 17613。
var gtTLSExtensions = []uint16{
	0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 65037, 65281,
}

func headerValue(headers [][2]string, name string) (string, bool) {
	for _, kv := range headers {
		if strings.EqualFold(kv[0], name) {
			return kv[1], true
		}
	}
	return "", false
}

func TestChromiumGroundTruth(t *testing.T) {
	for _, name := range profiles.List() {
		p, err := profiles.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if p.Identity == nil || p.TLS == nil || p.TLS.Detail == nil {
			continue
		}
		if p.Grade != "" {
			continue // 非自测（E3 第三方 / E2i 内插）：无该版本真机实测背书，不参与 E1 级断言
		}
		ua, _ := headerValue(p.Identity.Headers, "user-agent")
		if !strings.Contains(ua, "Chrome/") {
			continue // 只覆盖 Chromium 系（Firefox/Safari 导航头无抓包依据）
		}
		t.Run(name, func(t *testing.T) {
			// --- 身份头：顺序与 UA-CH 格式 ---
			var gotOrder []string
			for _, kv := range p.Identity.Headers {
				gotOrder = append(gotOrder, strings.ToLower(kv[0]))
			}
			wantOrder := gtChromiumHeaderOrder
			if strings.HasSuffix(name, "_android") {
				wantOrder = gtChromiumAndroidHeaderOrder
			}
			if fmt.Sprint(gotOrder) != fmt.Sprint(wantOrder) {
				t.Errorf("导航头顺序不符实测:\n  want %v\n  got  %v", wantOrder, gotOrder)
			}
			chUA, ok := headerValue(p.Identity.Headers, "sec-ch-ua")
			if !ok {
				t.Fatal("missing sec-ch-ua")
			}
			own := gtOwnBrand.FindStringSubmatch(chUA)
			if own == nil {
				t.Errorf("sec-ch-ua 缺自家品牌（Google Chrome / Microsoft Edge）: %q", chUA)
			} else if m := gtUAMajor.FindStringSubmatch(ua); m != nil && own[2] != m[1] {
				t.Errorf("sec-ch-ua 自家品牌版本 %s 与 UA 主版本 %s 不一致: %q", own[2], m[1], chUA)
			}
			if !strings.Contains(chUA, `"Chromium";v=`) {
				t.Errorf("sec-ch-ua 缺 Chromium 品牌: %q", chUA)
			}
			if !gtGreaseBrand.MatchString(chUA) {
				t.Errorf("sec-ch-ua 缺 GREASE 品牌（形如 Not…Brand;v=N）: %q", chUA)
			}
			if v, _ := headerValue(p.Identity.Headers, "priority"); v != "u=0, i" {
				t.Errorf("priority = %q, want %q", v, "u=0, i")
			}
			// 平台串按实测：桌面 Windows/macOS、Android（2026-09-28 真机实测 "Android"）。
			// 注意 Chrome 在 Android 10+ 的 UA 是**缩减形态**（`Android 10; K`），与平台串无关。
			if v, _ := headerValue(p.Identity.Headers, "sec-ch-ua-platform"); v != `"Windows"` && v != `"macOS"` && v != `"Android"` {
				t.Errorf("sec-ch-ua-platform = %q", v)
			}
			if strings.HasSuffix(name, "_android") {
				if v, _ := headerValue(p.Identity.Headers, "sec-ch-ua-mobile"); v != "?1" {
					t.Errorf("Android 预设的 sec-ch-ua-mobile = %q, want ?1", v)
				}
			}
			if v, _ := headerValue(p.Identity.Headers, "accept-encoding"); !strings.Contains(v, "zstd") {
				t.Errorf("accept-encoding = %q, 缺 zstd", v)
			}

			// --- TLS：扩展集合须覆盖实测集合（剔除 GREASE 与 41）---
			have := map[uint16]bool{}
			for _, e := range p.TLS.Detail.Extensions {
				if e.Type == 41 {
					continue // PSK 属会话复用场景，非首访固定项
				}
				if e.Type>>8 == e.Type&0xff && e.Type&0xf == 0xa {
					continue // GREASE
				}
				have[e.Type] = true
			}
			for _, want := range gtTLSExtensions {
				if !have[want] {
					t.Errorf("TLS 扩展集合缺 %d（实测 Chrome 149 有）", want)
				}
			}
			if !have[17513] && !have[17613] {
				t.Error("TLS 扩展集合缺 ALPS（17513 旧码点 / 17613 新码点），实测 Chrome 必有")
			}

			// --- HTTP/2：akamai 四段中的 SETTINGS / WINDOW_UPDATE / 伪头 ---
			if p.HTTP2 == nil {
				t.Fatal("missing http2 section")
			}
			wantSettings := [][2]uint32{{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144}}
			if len(p.HTTP2.Settings) != len(wantSettings) {
				t.Fatalf("h2 settings = %v, want %v", p.HTTP2.Settings, wantSettings)
			}
			for i, kv := range p.HTTP2.Settings {
				if len(kv) != 2 || kv[0] != wantSettings[i][0] || kv[1] != wantSettings[i][1] {
					t.Errorf("h2 settings[%d] = %v, want %v", i, kv, wantSettings[i])
				}
			}
			if f := p.HTTP2.WindowUpdate; f == nil || *f != 15663105 {
				t.Errorf("h2 window_update = %v, want 15663105", f)
			}
			if fmt.Sprint(p.HTTP2.PseudoHeaderOrder) != "[m a s p]" {
				t.Errorf("h2 pseudo order = %v, want [m a s p]", p.HTTP2.PseudoHeaderOrder)
			}
		})
	}
}
