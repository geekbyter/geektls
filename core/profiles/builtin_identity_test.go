package profiles

// 身份层守门（2026-09-28）：预设的 identity 是"我们主动发出去的东西"，
// 一旦不自洽就是一眼假。起因：E1 采集链路用 `--headless=new`，UA 里的
// `HeadlessChrome/…` 令牌被生成器原样写进了 chrome_149_windows / edge_153_windows
// 两条预设（真机抓包逐字段复核证明 TLS/H2 面完全一致，只有这枚令牌露馅）。
//
// 三条规则（已对全部内置预普查过，0 违反，故可直接作为门禁）：
//  1. 不得出现 headless 令牌；
//  2. UA 声明的平台与 `sec-ch-ua-platform` 一致；
//  3. UA 的 Chrome/Edge 主版本与 `sec-ch-ua` 里的 Chromium 主版本一致。
//
// 注：无 UA-CH 的老客户端（curl/IE/OKHttp 等）不参与 2、3 两条。

import (
	"regexp"
	"strings"
	"testing"
)

func identityMap(p *Profile) map[string]string {
	m := map[string]string{}
	if p == nil || p.Identity == nil {
		return m
	}
	for _, kv := range p.Identity.Headers {
		m[strings.ToLower(kv[0])] = kv[1]
	}
	return m
}

// TestBuiltinIdentityNoHeadlessToken：无头令牌绝不允许进预设。
//
// 无头与有头浏览器的 ClientHello/H2 逐字段相同（真机复核见
// profiles/evidence/browsers/chrome_149_windows_peetws.json），所以只要抹掉 UA 令牌
// 就与真机一致；反过来留着它就是"一眼假"。源头已修（cmd/e1-browser 的
// sanitizeHeaders），本测试防止任何路径（生成器、第三方导入、手写）再漏进来。
func TestBuiltinIdentityNoHeadlessToken(t *testing.T) {
	for _, name := range List() {
		t.Run(name, func(t *testing.T) {
			p, err := Get(name)
			if err != nil {
				t.Fatal(err)
			}
			if p.Identity == nil {
				return
			}
			for _, kv := range p.Identity.Headers {
				if strings.Contains(strings.ToLower(kv[1]), "headless") {
					t.Errorf("identity 头 %q 含 headless 令牌：%q（真机不会这么发；采集端应归一为有头形态）", kv[0], kv[1])
				}
			}
		})
	}
}

// TestBuiltinIdentityPlatformConsistency：UA 与 UA-CH 的平台串必须一致。
func TestBuiltinIdentityPlatformConsistency(t *testing.T) {
	cases := []struct {
		uaToken  string
		platform string
	}{
		{"Windows NT", `"Windows"`},
		{"Macintosh", `"macOS"`},
		{"Linux; Android", `"Android"`},
	}
	for _, name := range List() {
		t.Run(name, func(t *testing.T) {
			p, err := Get(name)
			if err != nil {
				t.Fatal(err)
			}
			h := identityMap(p)
			ua, plat := h["user-agent"], h["sec-ch-ua-platform"]
			if ua == "" || plat == "" {
				return // 无 UA-CH 的老客户端不参与
			}
			for _, c := range cases {
				if strings.Contains(ua, c.uaToken) && plat != c.platform {
					t.Errorf("UA 含 %q 但 sec-ch-ua-platform=%s（应为 %s）：%q", c.uaToken, plat, c.platform, ua)
				}
			}
		})
	}
}

// TestBuiltinIdentityVersionConsistency：UA 主版本与 UA-CH 的 Chromium 主版本必须一致。
func TestBuiltinIdentityVersionConsistency(t *testing.T) {
	uaVer := regexp.MustCompile(`(?:Chrome|Edg)/(\d+)`)
	chVer := regexp.MustCompile(`"Chromium";v="(\d+)"`)
	for _, name := range List() {
		t.Run(name, func(t *testing.T) {
			p, err := Get(name)
			if err != nil {
				t.Fatal(err)
			}
			h := identityMap(p)
			a, b := uaVer.FindStringSubmatch(h["user-agent"]), chVer.FindStringSubmatch(h["sec-ch-ua"])
			if a == nil || b == nil {
				return
			}
			if a[1] != b[1] {
				t.Errorf("UA 主版本 %s 与 sec-ch-ua 的 Chromium %s 不一致：%q / %q",
					a[1], b[1], h["user-agent"], h["sec-ch-ua"])
			}
		})
	}
}
