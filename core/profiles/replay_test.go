package profiles

import "testing"

// 重放自洽归一的规则测试（与内置预设的 PSK 占位守门同源）。
func TestNormalizeForReplayPskPlaceholder(t *testing.T) {
	t.Run("声明 43 但缺 41 ⇒ 末尾补占位", func(t *testing.T) {
		// JA3 里带 supported_versions(43) 即代表有 TLS 1.3 能力（有损入口没有 versions 列表）。
		p, _, err := FromJA3("771,4865-4866-4867,43-10-11-13-16-23-5-0-65281,4588-29-23-24,0")
		if err != nil {
			t.Fatal(err)
		}
		if hasExt(p, 41) {
			t.Fatal("JA3 入口不该凭空产生 41")
		}
		w := NormalizeForReplay(p)
		if !hasExt(p, 41) {
			t.Fatal("声明 TLS 1.3 却缺 41：应补空占位（否则会话复用会 panic）")
		}
		if got := lastExtType(p); got != 41 {
			t.Errorf("41 应在扩展末尾，实际末尾是 %d", got)
		}
		if !hasWarning(w, "psk_placeholder_added") {
			t.Errorf("应给出 psk_placeholder_added 告警，实际 %+v", w)
		}

		// 幂等：再跑一次不应再加第二个 41、也不应再告警。
		w2 := NormalizeForReplay(p)
		if n := countExt(p, 41); n != 1 {
			t.Errorf("41 出现 %d 次，应为 1", n)
		}
		if len(w2) != 0 {
			t.Errorf("第二次归一不该再有告警：%+v", w2)
		}
	})

	t.Run("不声明 43 却带 41 ⇒ 移除（结构非法）", func(t *testing.T) {
		p, err := Parse([]byte(`{"name":"x","tls":{"detail":{"legacy_version":"0x0303",
			"ciphers":["0x1301"],"extensions":[{"type":23},{"type":41}]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		w := NormalizeForReplay(p)
		if hasExt(p, 41) {
			t.Error("未声明 TLS 1.3 时应移除 41")
		}
		if !hasWarning(w, "psk_removed") {
			t.Errorf("应给出 psk_removed 告警：%+v", w)
		}
	})

	t.Run("41 不在末尾 ⇒ 移到末尾", func(t *testing.T) {
		p, err := Parse([]byte(`{"name":"x","tls":{"detail":{"legacy_version":"0x0303",
			"ciphers":["grease","0x1301"],"extensions":[{"type":43,"versions":["grease","0x0304","0x0303"]},
			{"type":41},{"type":16,"alpn":["h2"]}]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		w := NormalizeForReplay(p)
		if got := lastExtType(p); got != 41 {
			t.Errorf("41 应被移到最后，实际末尾 %d", got)
		}
		if !hasWarning(w, "psk_moved_to_end") {
			t.Errorf("应给出 psk_moved_to_end 告警：%+v", w)
		}
	})

	t.Run("无 tls.detail 时不动手", func(t *testing.T) {
		p := &Profile{Name: "empty"}
		if w := NormalizeForReplay(p); len(w) != 0 {
			t.Errorf("空 profile 不该产生告警：%+v", w)
		}
	})
}

func hasExt(p *Profile, typ uint16) bool { return countExt(p, typ) > 0 }

func countExt(p *Profile, typ uint16) int {
	n := 0
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func lastExtType(p *Profile) uint16 {
	exts := p.TLS.Detail.Extensions
	return exts[len(exts)-1].Type
}

func hasWarning(ws []Warning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}
