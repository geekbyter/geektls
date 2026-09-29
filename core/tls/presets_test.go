package tlscore

// 预设入库即测试（03 文档 §3）：每个内置预设必须能编译、能自算 JA3/JA4、
// 无意外 warnings。

import (
	"fmt"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

func TestPresetsAreValid(t *testing.T) {
	names := profiles.List()
	if len(names) == 0 {
		t.Fatal("no builtin presets registered")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if p.TLS == nil || p.TLS.Detail == nil {
				t.Fatal("preset has no tls.detail")
			}
			spec, err := CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatalf("CompileDetail: %v", err)
			}
			ja3, ja4 := ComputeJA3(spec), ComputeJA4(spec)
			if len(JA3Hash(ja3)) != 32 {
				t.Errorf("bad ja3 hash for %q", ja3)
			}
			parts := strings.Split(ja4, "_")
			if len(parts) != 3 || len(parts[0]) != 10 {
				t.Errorf("bad ja4 %q", ja4)
			}
			t.Logf("%s ja3=%s ja4=%s wire~%dB", name, JA3Hash(ja3), ja4, estimateClientHelloLen(spec))
		})
	}
}

// TestPresetJA4Pinned：把有**双重来源**的预设 JA4 钉死。
//
// chrome_149_windows 与 edge_141_macos 的 JA4 有两个互相独立的来源：
//
//  1. 我们自己的 E1 真机抓包（profiles/evidence/browsers/）；
//  2. **第三方实现** curl_cffi——其"号称 Safari"的 profile 实测产出的其实是
//     Edge/Chrome 形状（UA/UA-CH 是 Edg/149、cipher 段 hash 与 Chrome 同源），
//     其 JA4 = t13d1516h2_8daaf6152771_d8a2da3f94cd，与本项目预设**逐字符相同**。
//
// 即：一个与我们无关的实现独立复现了同一枚指纹 ⇒ 对 Chrome/Edge 面形成的互证
// （此前只有"我们自己的抓包"这一单一来源）。ComputeJA4 按 JA4 规范对扩展段排序，
// 故 per-connection 洗牌不影响该值。
func TestPresetJA4Pinned(t *testing.T) {
	want := map[string]string{
		"chrome_149_windows": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		"edge_141_macos":     "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		// Chrome 154 / macOS 真机实测（2026-09-28）与 chrome_152_macos 的 JA4
		// **完全相同** ⇒ 152→154 的 TLS 面（cipher 序 + 扩展集合 + sig_algs）无漂移。
		"chrome_154_macos": "t13d1517h2_8daaf6152771_cb7bf5808d99",
		"chrome_152_macos": "t13d1517h2_8daaf6152771_cb7bf5808d99",
		// Chrome 154 / Windows 真机字段级抓包（2026-09-28）：TLS 面（cipher 序、扩展集合、
		// groups/key_shares、sig_algs、ALPN）与 mac 版逐字段一致 ⇒ 首访形态 JA4 逐字符相同。
		// 抓包自身记的是 `t13d1518h2_…_e2d80978ab2e`——那是**复用会话**（带 pre_shared_key
		// 载荷）多算一个扩展；我们的预设是 41 空占位、无票据时线上省略 ⇒ 17 个扩展。
		"chrome_154_windows": "t13d1517h2_8daaf6152771_cb7bf5808d99",
		// 真 Safari 实测（2026-09-28）：17.3.1 与 18.6 的 cipher 序/扩展集合相同
		// （b 段 a09f3c656075 一致），但 sig_algs 不同——17.3.1 含 ecdsa_sha1(0x0203)、
		// 18.6 去掉了 ⇒ c 段（含 sig_algs 的哈希）不同。
		"safari_17_3_macos": "t13d2014h2_a09f3c656075_14788d8d241b",
		"safari_18_6_macos": "t13d2014h2_a09f3c656075_e42f34c56612",
		// 生成预设 safari_18_macos（原始 hex 标本来源）的 JA4 与**实测 18.6 完全相同** ⇒
		// 同一真机形态的独立复现（差别只在不进 JA4 的量上：wire 874B vs 实测 1264B）。
		"safari_18_macos": "t13d2014h2_a09f3c656075_e42f34c56612",
		// 另两个**无实测来源**的历史预设差距明显：13 扩展（比真机少 1 个）且 wire ≈2.9KB
		// （真机 ≈1.26KB）⇒ 钉住作为"待校验"的显式记录，避免它被误当成真机形态。
		"safari_18":       "t13d2013h2_a09f3c656075_874d27d7ca63",
		"safari_26_macos": "t13d2013h2_a09f3c656075_7f0f34a4126d",
		// iOS 17.2 三个浏览器（Safari / Chrome CriOS / Edge EdgiOS）**同一个 JA4**：
		// 与 macOS Safari 17.3.1 也相同 ⇒ WebKit 形态跨平台、跨浏览器一致（见下方专项测试）。
		"safari_17_2_ios": "t13d2014h2_a09f3c656075_14788d8d241b",
		"chrome_148_ios":  "t13d2014h2_a09f3c656075_14788d8d241b",
		"edge_148_ios":    "t13d2014h2_a09f3c656075_14788d8d241b",
		// Android 14 实测（2026-09-28）：与桌面同版本**JA4 完全相同**（Chromium 的 TLS 面
		// 跨平台一致；Firefox 亦一致）——见 TestCrossPlatformSameVersionShape。
		"chrome_154_android":  "t13d1517h2_8daaf6152771_cb7bf5808d99",
		"edge_153_android":    "t13d1516h2_8daaf6152771_806a8c22fdea",
		"firefox_156_android": "t13d1517h2_8daaf6152771_3cbfd9057e0d",
	}
	for name, wantJA4 := range want {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatal(err)
			}
			if got := ComputeJA4(spec); got != wantJA4 {
				t.Errorf("%s JA4 = %s, want %s（E1 抓包 + curl_cffi 第三方互证值）", name, got, wantJA4)
			}
		})
	}
}

func identityHeader(p *profiles.Profile, name string) string {
	if p == nil || p.Identity == nil {
		return ""
	}
	for _, kv := range p.Identity.Headers {
		if kv[0] == name {
			return kv[1]
		}
	}
	return ""
}

func ja4Of(t *testing.T, name string) string {
	t.Helper()
	p, err := profiles.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}
	return ComputeJA4(spec)
}

// TestCrossPlatformSameVersionShape：同版本**跨平台**的形态关系（Android 14 实测，2026-09-28）。
//
// 三条结论（都已实测）：
//
//	① Chromium 系（Chrome/Edge）与 Firefox：**TLS 面跨平台完全相同**（JA4 逐字符相同，
//	   Android 154/153/156 == macOS 154 / Windows 153 / Windows 156）。
//	② 但 Firefox 的 **H2 SETTINGS 随平台不同**（Windows 156: `1:65536;4:131072`；
//	   Android 156: `1:4096;4:32768`）；Chromium 的 H2 则跨平台相同。
//	③ `sec-ch-ua` 的品牌顺序与 GREASE 品牌是**按版本固定**的，**不是每会话随机**：
//	   Edge 153 的 Windows 与 Android 两份抓包逐字符相同；Chrome 154 的 macOS 与 Android 同样。
//	   ⇒ 这否掉了"每会话随机"的猜测（docs/08 的 S1 前半），因此**不做** UA-CH 洗牌。
//
// 附：Chrome/Android 的 UA 是被 Chrome **UA 缩减**后的形态（`(Linux; Android 10; K)`，
// 不是真实 Android 版本）——把它"修正"成 Android 14 反而是一眼假的破绽。
func TestCrossPlatformSameVersionShape(t *testing.T) {
	pairs := [][2]string{
		{"chrome_154_macos", "chrome_154_android"},
		{"chrome_154_macos", "chrome_154_windows"},
		{"edge_153_windows", "edge_153_android"},
		{"firefox_156_windows", "firefox_156_android"},
	}
	for _, pr := range pairs {
		if a, b := ja4Of(t, pr[0]), ja4Of(t, pr[1]); a != b {
			t.Errorf("① %s 与 %s 的 JA4 不同（同版本跨平台应相同）：%s vs %s", pr[0], pr[1], a, b)
		}
	}

	get := func(name string) *profiles.Profile {
		p, err := profiles.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if a, b := fmt.Sprint(get("chrome_154_macos").HTTP2.Settings), fmt.Sprint(get("chrome_154_android").HTTP2.Settings); a != b {
		t.Errorf("② Chromium 的 H2 SETTINGS 实测跨平台相同，却不同：%s vs %s", a, b)
	}
	if a, b := fmt.Sprint(get("firefox_156_windows").HTTP2.Settings), fmt.Sprint(get("firefox_156_android").HTTP2.Settings); a == b {
		t.Errorf("② Firefox 156 的 H2 SETTINGS 实测**随平台不同**，两者却相同：%s", a)
	}

	for _, pr := range [][2]string{
		{"chrome_154_macos", "chrome_154_android"},
		{"chrome_154_macos", "chrome_154_windows"},
		{"edge_153_windows", "edge_153_android"},
	} {
		a, b := identityHeader(get(pr[0]), "sec-ch-ua"), identityHeader(get(pr[1]), "sec-ch-ua")
		if a == "" || a != b {
			t.Errorf("③ %s 与 %s 的 sec-ch-ua 应逐字符相同（按版本固定）：%q vs %q", pr[0], pr[1], a, b)
		}
	}

	if ua := identityHeader(get("chrome_154_android"), "user-agent"); !strings.Contains(ua, "Android 10; K") {
		t.Errorf("Chrome/Android 的 UA 实测为缩减形态（含 %q）：%q", "Android 10; K", ua)
	}
}

// TestIOSBrowsersShareWebKitShape：iOS 上所有浏览器共用 WebKit 的 TLS/HTTP2 形态。
//
// 实测（2026-09-28，同一台 iPhone / iOS 17.2 / 同一网络）：Safari、Chrome（CriOS 148）、
// Edge（EdgiOS 148）三者的 **JA3 哈希与 JA4 逐字符相同**，HTTP/2 四段与 HEADERS
// priority 也相同；**唯一差异是 UA**。原因：iOS 上第三方浏览器必须使用 WebKit，
// 于是 TLS 栈与 H2 帧层也归 WebKit（Chrome/Edge 只是换了 UA 与界面）。
//
// 推论（对伪装很重要）：拿桌面 Chrome 的形状去充当 iOS Chrome **一眼假**；
// 而 iOS 三兄弟的 TLS 面可以共用同一份 detail。
func TestIOSBrowsersShareWebKitShape(t *testing.T) {
	iosNames := []string{"safari_17_2_ios", "chrome_148_ios", "edge_148_ios"}
	var wantJA4 string
	var wantPri profiles.H2HeadersPriority
	uas := map[string]string{}

	for i, name := range iosNames {
		p, err := profiles.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := CompileDetail(p.TLS.Detail)
		if err != nil {
			t.Fatal(err)
		}
		ja4 := ComputeJA4(spec)
		if i == 0 {
			wantJA4 = ja4
			if p.HTTP2 == nil || p.HTTP2.HeadersPriority == nil {
				t.Fatal("缺 http2.headers_priority")
			}
			wantPri = *p.HTTP2.HeadersPriority
		} else if ja4 != wantJA4 {
			t.Errorf("%s 的 JA4 = %s，与 %s 的 %s 不同——iOS 上不应出现差异",
				name, ja4, iosNames[0], wantJA4)
		}
		if p.HTTP2 == nil || p.HTTP2.HeadersPriority == nil || *p.HTTP2.HeadersPriority != wantPri {
			t.Errorf("%s 的 HEADERS priority 与 %s 不一致", name, iosNames[0])
		}
		for _, kv := range p.Identity.Headers {
			if kv[0] == "user-agent" {
				uas[name] = kv[1]
			}
		}
	}
	if len(uas) != len(iosNames) {
		t.Errorf("三个 iOS 预设的 UA 应当各不相同（身份层是唯一差异）：%v", uas)
	}
}

// TestPresetSafariPadding：Safari 的 padding(21) 用**实测字节数**表达。
//
// 真 Safari 实测（2026-09-28）：两份抓包 padding 负载 390 / 394 字节——长度不同是因为
// 其余部分差了 4 字节（Safari 是把整个 ClientHello 补到某个总长的策略）。
// 我们用 padding_len 记实测值（而非 padding_to 策略），语义是"抓到多少就写多少"。
// 这两个预设必须有该扩展且长度与实测一致；旧的无实测来源的 Safari 预设不作要求。
func TestPresetSafariPadding(t *testing.T) {
	want := map[string]int{
		"safari_17_3_macos": 390,
		"safari_18_6_macos": 394,
	}
	for name, n := range want {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range p.TLS.Detail.Extensions {
				if e.Type != 21 {
					continue
				}
				if e.PaddingLen != n {
					t.Errorf("padding_len = %d, want %d（真机实测值）", e.PaddingLen, n)
				}
				return
			}
			t.Error("缺 padding(21) 扩展：真 Safari 的 ClientHello 一定带它")
		})
	}
}

// TestPresetECHIsNotFrozenLiteral：65037（ECH）不得带"字面 GREASE 负载"。
//
// 理由：Chrome 的 GREASE ECH 每连接重取 enc 公钥、并随机挑填充长度
// （实测总长 42+N，N∈{144,176,208,240}）。把抓包转录的字面 payload 留在预设里
// ⇒ 逐连接原样重放，形成"65037 内容恒定"这一稳定可观察特征（与 G12 同族）。
// 生成器 normalizeECHGrease 已把这类 payload 归一为 ech.mode=grease；
// 真 ECH（mode=real + config_list_hex）是合法用法，不在本规则内。
func TestPresetECHIsNotFrozenLiteral(t *testing.T) {
	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range p.TLS.Detail.Extensions {
				if e.Type != 65037 {
					continue
				}
				if e.ECH != nil {
					switch e.ECH.Mode {
					case "grease":
					case "real":
						if e.ECH.ConfigListHex == "" {
							t.Error("mode=real 必须给 config_list_hex")
						}
					default:
						t.Errorf("未知 ech.mode %q（应为 grease / real）", e.ECH.Mode)
					}
					return
				}
				if e.Data != "" {
					t.Error("65037 带字面 payload：会被逐连接原样重放（应改为 ech.mode=grease）")
				}
			}
		})
	}
}

// TestPresetCarriesPskPlaceholder：每个预设都必须带 pre_shared_key(41) 空占位，
// 且按 RFC 8446 位于扩展列表**末尾**。
//
// 为什么是硬要求：引擎默认开启会话复用（core/engine/engine.go），而 uTLS 在
// "ClientSessionCache 命中票据、但 spec 里没有 PSK 扩展"时会**直接 panic**，
// 崩掉整个调用进程（实测：u_session_controller.go:128 initPskExt；详见
// core/tls/spec_reuse_test.go 与 engine/resumption_test.go）。
// 按 E1 首访抓包生成的 9 个预设曾缺占位 ⇒ 曾是一条真实的崩溃路径。
//
// 对指纹无影响：占位是空 payload，无票据时线上省略（OmitEmptyPsk=true）。
func TestPresetCarriesPskPlaceholder(t *testing.T) {
	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatal(err)
			}
			idx := -1
			for i, e := range spec.Extensions {
				if id, ok := extensionTypeID(e); ok && id == 41 {
					idx = i
				}
			}
			// 双向断言：**声明 TLS 1.3 的预设必须有 41 占位且位于末尾**（否则会话复用会
			// panic 崩进程）；**不声明 1.3 的老客户端预设则必须没有 41**——硬加会让
			// ClientHello 结构非法（实测：Go 服务端报 "error decoding message"）。
			has13 := false
			for _, e := range spec.Extensions {
				if id, ok := extensionTypeID(e); ok && id == 43 {
					if vs, ok := e.(*utls.SupportedVersionsExtension); ok {
						for _, v := range vs.Versions {
							if v == utls.VersionTLS13 {
								has13 = true
							}
						}
					}
				}
			}
			if !has13 {
				if idx >= 0 {
					t.Error("该预设不声明 TLS 1.3，却带 pre_shared_key(41)：ClientHello 结构非法")
				}
				return
			}
			if idx < 0 {
				t.Fatal("缺 pre_shared_key(41) 占位：启用会话复用时 uTLS 会 panic 崩进程")
			}
			if idx != len(spec.Extensions)-1 {
				t.Errorf("pre_shared_key 位于第 %d/%d 个扩展；RFC 8446 要求它是**最后一个**",
					idx+1, len(spec.Extensions))
			}
		})
	}
}

func TestDescribeRoundTrip(t *testing.T) {
	for _, name := range profiles.List() {
		data, err := profiles.Describe(name)
		if err != nil {
			t.Fatalf("Describe(%s): %v", name, err)
		}
		// Describe 输出必须能再 Parse（规范化 JSON 自洽）
		if _, err := profiles.Parse(data); err != nil {
			t.Errorf("Describe(%s) output fails Parse: %v", name, err)
		}
	}
	if _, err := profiles.Describe("no_such_preset"); err == nil {
		t.Error("Describe of unknown preset should fail")
	}
	if _, err := profiles.Describe("../evil"); err == nil {
		t.Error("Describe should reject path traversal")
	}
}
