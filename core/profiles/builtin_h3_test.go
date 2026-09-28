package profiles

import (
	"strings"
	"testing"
)

// TestBuiltinChromiumH3Coverage 钉住 Chromium 家族的 H3 覆盖。
//
// 为什么必须有 http3 节：core/h3 在 `p.HTTP3 == nil` 时直接用 quic-go 的默认
// transport params——那等于在 H3 上暴露"通用 Go 客户端"形态，比"未验证"更糟。
//
// 边界：Firefox / Safari 的 H3 transport params 与 Chromium 不同，不能靠家族继承
// 生成，必须来自真实浏览器 H3 抓包（见 profiles/evidence/README.md 的待补证据）。
// 因此本测试只约束 Chromium 家族，并为其余预设显式记录这条缺口。
func TestBuiltinChromiumH3Coverage(t *testing.T) {
	names := List()
	chromium, missing := 0, []string{}
	others := []string{}

	for _, name := range names {
		isChromium := strings.HasPrefix(name, "chrome_") || strings.HasPrefix(name, "edge_")
		p, err := Get(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		hasH3 := p.HTTP3 != nil && p.HTTP3.Enabled

		if !isChromium {
			if !hasH3 {
				others = append(others, name)
			}
			continue
		}
		if !hasH3 {
			missing = append(missing, name)
			continue
		}
		// QUIC 内层 CH 形态（实测驱动，见 docs/07-capability-gaps.md §6.1）：
		// Chromium 家族必须带实测形态，否则 H3 上的 ClientHello 不是浏览器形状
		// （漏剔/GREASE 残留都会让 JA4(QUIC) 偏离真机）。
		if !p.HTTP3.InnerHelloDropGrease {
			t.Errorf("%s: http3 缺 inner_hello_drop_grease（实测真机 QUIC 无 TLS 层 GREASE）", name)
		}
		if len(p.HTTP3.InnerHelloDropExtensions) == 0 {
			t.Errorf("%s: http3 缺 inner_hello_drop_extensions（实测剔 5/18）", name)
		}
		if len(p.HTTP3.InnerHelloExtraSigAlgs) == 0 {
			t.Errorf("%s: http3 缺 inner_hello_extra_sig_algs（实测补 0x0201）", name)
		}
		chromium++
	}

	if len(missing) > 0 {
		t.Errorf("Chromium 家族预设缺 http3 节（H3 会退回 quic-go 默认参数）: %v", missing)
	}
	if chromium == 0 {
		t.Error("没有扫描到任何带 H3 的 Chromium 预设——本测试可能已失效")
	}
	t.Logf("Chromium 家族 %d 个预设均带 H3；非 Chromium 家族缺 H3（待真实抓包）: %v", chromium, others)
}
