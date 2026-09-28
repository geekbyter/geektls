package profiles

import "testing"

// TestBuiltinGreaseExtensionsRandomized 钉住 G12：内置预设里凡是 type 为 GREASE 值
// （0x?a?a）的扩展，都必须标记 grease_random。
//
// 原因：uTLS 的 UtlsGREASEExtension 把 Value 原样写出（不做握手期替换），
// 若不标记，线上该扩展 id 会跨连接恒定，而真浏览器每连接都重取 GREASE 值——
// 这会成为"这个客户端不是真浏览器"的可观察特征（详见 docs/07 G12）。
//
// 注意：字面 GREASE 值原样透传是**刻意保留**的能力（P1-T3，见 core/tls 的
// TestGreaseAllRFC8701Values）；本测试只约束本仓库内置预设的数据质量。
func TestBuiltinGreaseExtensionsRandomized(t *testing.T) {
	names := List()
	if len(names) == 0 {
		t.Fatal("List() 返回空——内置预设没被 embed 进来？")
	}

	greaseExts := 0
	for _, name := range names {
		p, err := Get(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.TLS == nil || p.TLS.Detail == nil {
			continue
		}
		for i, e := range p.TLS.Detail.Extensions {
			if !IsGrease(e.Type) {
				continue
			}
			greaseExts++
			if !e.GreaseRandom {
				t.Errorf("%s: extensions[%d] type=%#04x 是 GREASE 扩展但未标记 grease_random（线上 id 会跨连接恒定）",
					name, i, e.Type)
			}
		}
	}

	if greaseExts == 0 {
		t.Error("没有扫描到任何 GREASE 扩展——本测试可能已失效（预设数据或 IsGrease 变了）")
	}
	t.Logf("扫描 %d 个预设，%d 处 GREASE 扩展全部带 grease_random", len(names), greaseExts)
}
