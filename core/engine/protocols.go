package engine

// HTTP 协议选择（G8）。
//
// **默认 = `h1.1` + `h2`，H3 必须显式开启**，与 curl / curl_cffi / requests 生态
// 的心智模型一致：同一个 URL 走 H2 还是 H3 是**可观测差异**（协议入口不同、
// QUIC 侧 JA4 与 TCP 侧不同），不该由"预设里写了 http3 节"这一个事实替用户决定。
// 此前的行为是：只要 profile 带 `http3.enabled` + `h2_race_ms > 0` 就自动竞速 H3，
// 用户没有开关——那不是"更强"，是"不可控"。
//
// 语义（都是"允许集合"，顺序无关；线上 ALPN 顺序仍由 profile 决定，见 narrowALPN）：
//
//	protocols=["h1.1","h2"]          默认：只走 TCP，ALPN 里不含 h3 之外的东西
//	protocols=["h1.1"]               只走 H1.1（ALPN 收窄到 http/1.1，不协商 h2）
//	protocols=["h2"]                 只走 H2（服务端不选 h2 即失败，**不静默回落 H1**）
//	protocols=["h3"]                 只走 H3（= 会话级 force，失败不回落）
//	protocols=["h2","h3"]            H3 参与竞速/Alt-Svc 优先，H2 兜底（旧默认行为）
//	h3=true                          = 在默认集合上加 "h3"（便捷写法）
//
// 与 `Request.ForceHTTP3` 的关系：force 是**请求级**的"必须 H3"，要求会话允许 h3
// （否则报错，不静默降级）；protocols 是会话级的允许集合。

import (
	"fmt"
	"strings"

	"github.com/geektls/core/profiles"
)

const (
	protoH1 = "h1.1"
	protoH2 = "h2"
	protoH3 = "h3"
)

// protocolSet 是归一化后的协议允许集合。
type protocolSet struct {
	h1 bool
	h2 bool
	h3 bool
}

// String 用于错误信息与自检输出（canonical 顺序）。
func (p protocolSet) String() string {
	out := make([]string, 0, 3)
	for _, v := range []struct {
		on bool
		s  string
	}{{p.h1, protoH1}, {p.h2, protoH2}, {p.h3, protoH3}} {
		if v.on {
			out = append(out, v.s)
		}
	}
	if len(out) == 0 {
		return "(空)"
	}
	return strings.Join(out, "+")
}

// h3Only 表示"只允许 H3"（等价会话级 force）。
func (p protocolSet) h3Only() bool { return p.h3 && !p.h1 && !p.h2 }

// protoOrder 是"profile 没声明 ALPN 或收窄后为空"时用的补位顺序（Chrome 常识序）。
// 注意：返回的是**线上 ALPN 协议名**（会进 cfg.NextProtos 与扩展内容），
// 所以 h1 的线上名是 "http/1.1"，不是集合里的短码 "h1.1"。
func (p protocolSet) protoOrder() []string {
	out := make([]string, 0, 2)
	if p.h2 {
		out = append(out, protoH2)
	}
	if p.h1 {
		out = append(out, "http/1.1")
	}
	return out
}

// allows 判断某个 ALPN 协议名是否被允许。
func (p protocolSet) allows(proto string) bool {
	switch strings.ToLower(proto) {
	case "h2":
		return p.h2
	case "h3":
		return p.h3
	default: // http/1.1 及其变体
		return p.h1
	}
}

// resolveProtocols 归一化 SessionOptions 里的 protocols / h3，并在**建会话时**就挡住
// 非法组合（与代理、地址控制同口径：配置错不要拖到第一次拨号才暴露）。
func resolveProtocols(opts SessionOptions, prof *profiles.Profile) (protocolSet, error) {
	// h3=true 是"在默认集合上加 h3"的便捷写法，与 protocols 同给属于两种意图打架 ⇒ 报错。
	// 但 h3=**false** 与 protocols 同给是常见写法（JS 调用方常显式转发 h3:false），
	// 它不表达任何额外意图（默认本就不开 h3），不该拦。
	explicitH3 := opts.H3 != nil && *opts.H3
	if explicitH3 && len(opts.Protocols) > 0 {
		return protocolSet{}, fmt.Errorf("engine: h3=true 与 protocols 不能同时给出（h3 是 protocols 的便捷写法）：用 protocols=%v，或只写 h3=true", opts.Protocols)
	}

	set := protocolSet{h1: true, h2: true} // 默认：主流两档
	switch {
	case len(opts.Protocols) > 0:
		set = protocolSet{}
		for _, raw := range opts.Protocols {
			v := strings.ToLower(strings.TrimSpace(raw))
			switch v {
			case "h1", "h1.1", "http/1.1":
				set.h1 = true
			case "h2", "http/2":
				set.h2 = true
			case "h3", "http/3", "quic":
				set.h3 = true
			default:
				return protocolSet{}, fmt.Errorf("engine: protocols 取值 %q 未知（want h1.1 / h2 / h3）", raw)
			}
		}
	case explicitH3:
		set.h3 = true // 默认集合 + h3
	}
	// h3=false 与 protocols 里的 "h3" 是真矛盾（一个说不开一个说开）⇒ 报错
	if opts.H3 != nil && !*opts.H3 && set.h3 {
		return protocolSet{}, fmt.Errorf("engine: h3=false 与 protocols 里的 \"h3\" 矛盾（二者只留一个）")
	}

	if !set.h1 && !set.h2 && !set.h3 {
		return protocolSet{}, fmt.Errorf("engine: protocols 不能为空")
	}
	// 只有 H3：等价会话级 force ⇒ 需要 profile 真的声明了 H3 能力，否则是"用默认
	// QUIC 参数假装浏览器"，不如直接报错（与 force_http3 的既有口径一致）。
	if set.h3Only() && (prof == nil || prof.HTTP3 == nil || !prof.HTTP3.Enabled) {
		return protocolSet{}, fmt.Errorf("engine: protocols 只给 h3 时要求预设带 http3 声明（当前预设没有）；换用带 H3 的预设，或把 h2/h1.1 一起允许")
	}
	// 开了 H3 但预设根本没有 http3 节 ⇒ 报错而不是"永远也走不到"（不静默）。
	// 请求级 force_http3 不受这条约束（它是老 API 的显式要求，走另一条路径）。
	if set.h3 && (prof == nil || prof.HTTP3 == nil || !prof.HTTP3.Enabled) {
		return protocolSet{}, fmt.Errorf("engine: 该预设没有 http3 声明（http3.enabled=false），开 h3 无从生效；换用带 H3 的预设（如 chrome_154_windows），或别开 h3")
	}
	return set, nil
}

// narrowALPN 按允许集合收窄 profile 的 ALPN 扩展（type 16）内容。
//
// 返回 (detail, 协议列表, 是否发生收窄)：
//   - 允许集合完全覆盖原列表 ⇒ 返回**原 detail 指针**与 changed=false，
//     调用方走原路 —— 默认配置（h1.1+h2）与改动前**线上逐字节相同**；
//   - 收窄后列表为空（例如 profile 只声明 h2、用户只要 h1.1）⇒ 用允许集合的
//     常识顺序补位（h2 → h1.1），并把 changed 置真 —— 空 ALPN 扩展是反常形态，
//     不能发出去。
//
// 为什么必须改扩展内容而不只是 cfg.NextProtos：uTLS 线上发的是扩展里的列表，
// 只改 NextProtos 会出现"发出去的 ALPN 里还有 h2，本地却不认 h2"的错位（WS 握手
// 早就踩过这个点，见 ws.go 的同类处理）。
func narrowALPN(d *profiles.Detail, set protocolSet, explicit bool) (*profiles.Detail, []string, bool) {
	if d == nil {
		return d, nil, false
	}
	orig := alpnProtocols(d)
	if len(orig) == 0 && !explicit {
		// profile 本就不发 ALPN 且用户没点名协议 ⇒ 保持"不发"（老行为）
		return d, nil, false
	}
	kept := make([]string, 0, 3)
	for _, proto := range orig {
		if set.allows(proto) {
			kept = append(kept, proto)
		}
	}
	if len(kept) == 0 {
		kept = set.protoOrder()
	}
	if len(orig) > 0 && sameList(orig, kept) {
		// 默认集合覆盖 profile 原列表 ⇒ 原样返回（默认路径线上逐字节不变）
		return d, kept, false
	}
	if len(orig) == 0 {
		// 没有 ALPN 扩展：**不凭空插一个**（会改指纹字节），只把列表交给
		// cfg.NextProtos；"profile 不发 ALPN"的既有点位由此保留。
		return d, kept, true
	}
	nd := *d
	exts := make([]profiles.Extension, len(d.Extensions))
	copy(exts, d.Extensions)
	for i, e := range exts {
		if e.Type == 16 {
			e.ALPN = kept
			exts[i] = e
		}
	}
	nd.Extensions = exts
	return &nd, kept, true
}

func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}
