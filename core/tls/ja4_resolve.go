package tlscore

// JA4 短哈希反查（2026-09-28）。
//
// 背景：用户只想给一个 JA4（形如 `t13d1516h2_8daaf6152771_d8a2da3f94cd`）就用同一枚
// 指纹。但 JA4 的三段都是 SHA256 截断哈希，**不可逆**——从它拿不到 ciphers/扩展/sig_algs
// 列表，更拿不到任何扩展负载。所以"只给 JA4"时唯一诚实的做法：在内置预设里找**同一个
// JA4**（同一 TLS 面形状）并把它的参数拿来用；找不到就明确报错，而不是编一个近似指纹。
//
// 精确复刻应当给 JA4R（raw，含列表）或完整 profile —— 见 docs/03-profile-format.md。

import (
	"fmt"
	"sort"
	"strings"

	"github.com/geekbyter/geektls/core/profiles"
)

// JA4PresetHit 是一次 JA4 反查的结果。
type JA4PresetHit struct {
	// Name 是最终采用的预设（多个命中时取名字排序第一个）。
	Name string
	// Candidates 是全部命中（同族同版本跨平台、或第三方导入的重复指纹会 >1）。
	Candidates []string
}

// ResolveJA4Profile 处理"只给 JA4"的两种形态：
//
//	JA4R（含 cipher/扩展/签名算法列表，带逗号）⇒ 按 raw 编译（顺序不可还原，有 warning）；
//	JA4 短哈希（三段带哈希）⇒ 反查内置预设（哈希不可逆，编不出近似指纹）。
func ResolveJA4Profile(v string) (*profiles.Profile, []profiles.Warning, error) {
	if strings.Contains(v, ",") {
		return profiles.FromJA4R(v)
	}
	hit, err := ResolveJA4Preset(v)
	if err != nil {
		return nil, nil, err
	}
	p, err := profiles.Get(hit.Name)
	if err != nil {
		return nil, nil, err
	}
	w := []profiles.Warning{{
		Code: "ja4_resolved_to_preset",
		Message: fmt.Sprintf("JA4 %s 不可逆，已解析为内置预设 %s（同指纹候选：%s）——采用该预设的完整参数（含身份层）；"+
			"想精确复刻请给 JA4R 或完整 profile", v, hit.Name, strings.Join(hit.Candidates, ", ")),
	}}
	return p, w, nil
}

// ResolveJA4Preset 把 JA4 短哈希反查成内置预设。
func ResolveJA4Preset(ja4 string) (*JA4PresetHit, error) {
	want := strings.TrimSpace(ja4)
	if !isJA4HashShape(want) {
		return nil, fmt.Errorf("not a JA4 hash: %q（JA4 形如 t13d1516h2_<12位>_<12位>）", ja4)
	}
	var hits []string
	for _, name := range profiles.List() {
		p, err := profiles.Get(name)
		if err != nil || p.TLS == nil || p.TLS.Detail == nil {
			continue
		}
		spec, err := CompileDetail(p.TLS.Detail)
		if err != nil {
			continue
		}
		if ComputeJA4(spec) == want {
			hits = append(hits, name)
		}
	}
	if len(hits) == 0 {
		return nil, fmt.Errorf("no builtin preset has JA4 %s: JA4 是哈希、不可逆，"+
			"请改给 JA4R（含 cipher/扩展列表）或完整 profile", want)
	}
	sort.Strings(hits)
	return &JA4PresetHit{Name: hits[0], Candidates: hits}, nil
}

// isJA4HashShape：三段下划线分隔，a 段形如 t13d1516h2，b/c 段各 12 位小写 hex。
func isJA4HashShape(s string) bool {
	parts := strings.Split(s, "_")
	if len(parts) != 3 {
		return false
	}
	if len(parts[0]) != 10 || (parts[0][0] != 't' && parts[0][0] != 'q') {
		return false
	}
	for _, p := range parts[1:] {
		if len(p) != 12 {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
