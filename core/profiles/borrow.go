package profiles

import (
	"fmt"
	"strings"
)

// BorrowPayloads 用"最相似内置预设"把有损入口（ja3/ja4r）的扩展载荷替换/补全为
// 目标族的真实形态：
//
//   - ja3 只携带 ciphers/groups/points 与扩展类型序；扩展载荷是 FromJA3 填的
//     "通用默认"（supported_versions=[0304,0303]、ALPN=h2/http1.1、sig_algs=
//     Chrome 八项…）——能握手，但形态与目标客户端不符，用同族预设的具体值替换
//     才谈得上"伪装"；
//   - ja4r 额外携带推断出的 sig_algs/versions/ALPN，但没有 key_share/groups 等
//     载荷（编译期会生成缺载荷的扩展）。
//
// 语义（**入口直接携带的信息一律保留**）：
//   - 扩展集合与顺序保持 p 原样（ja3 的类型序 / ja4r 的排序序就是入口语义）；
//   - ja3 的 groups(10)/points(11)、ja4r 的 sig_algs(13) 保留不覆盖；
//   - 其余载荷字段按同 type 从预设整体替换（SNI/ALPN/padding/cert_compression/
//     versions/psk_modes/key_shares/ECH/透传 data）；
//   - ciphers 为空才借；legacy_version 与 GREASE 位置不动。
//
// 触发条件：profile 来自 ja3=/ja4r= 入口（TLS.JA3 / TLS.JA4R 非空）；hex 与
// 手写 detail 是保真路径，原样返回、零开销。相似度低于 MatchMinScore 时不借
// ——借错家族会制造"TLS 说 A、内容说 B"的分裂，比如实告警（保持现状）更糟。
// 返回的 warnings 说明借了什么、为什么没借、哪些类型没得借。
func BorrowPayloads(p *Profile) (*Profile, string, float64, []Warning) {
	if p == nil || p.TLS == nil || p.TLS.Detail == nil || len(p.TLS.Detail.Extensions) == 0 {
		return p, "", 0, nil
	}
	// 入口直接携带的信息（保留不覆盖）：ja3 有 groups/points，ja4r 有 sig_algs。
	keepGroups := p.TLS.JA3 != ""
	keepPoints := p.TLS.JA3 != ""
	keepSigAlgs := p.TLS.JA4R != ""
	if !keepGroups && !keepPoints && !keepSigAlgs {
		return p, "", 0, nil // 非有损入口（hex / 预设 / 手写 detail）：原样返回
	}
	name, score := MatchPreset(p)
	if name == "" || score < MatchMinScore {
		return p, name, score, []Warning{warnf("payload_borrow_unavailable",
			"ja3/ja4r 的扩展载荷是通用默认/推断值；未找到足够相似的内置预设（最高相似度 %.2f < %.2f），保持现状——要保真请改用 clienthello_hex 或完整 profile",
			score, MatchMinScore)}
	}
	preset, err := Get(name)
	if err != nil || preset.TLS == nil || preset.TLS.Detail == nil {
		return p, name, score, []Warning{warnf("payload_borrow_unavailable",
			"载荷借用失败：预设 %q 不可解析（%v）", name, err)}
	}

	src := make(map[uint16]Extension, len(preset.TLS.Detail.Extensions))
	for _, e := range preset.TLS.Detail.Extensions {
		if _, ok := src[e.Type]; !ok {
			src[e.Type] = e
		}
	}
	d := *p.TLS.Detail
	exts := make([]Extension, len(d.Extensions))
	copy(exts, d.Extensions)
	// pre_shared_key(41) 必须在扩展列表末尾（RFC 8446 与 uTLS 的共同要求）：ja4r 的
	// 排序序必然把它混在中间（装载会直接报 "PreSharedKeyExtension must be the last
	// extension"），ja3 手写也可能写错位置——统一归位到末尾（其余扩展相对顺序不变）。
	pskMoved := false
	{
		var ordered []Extension
		var psk *Extension
		for i := range exts {
			if exts[i].Type == 41 {
				e := exts[i]
				psk = &e
				continue
			}
			ordered = append(ordered, exts[i])
		}
		if psk != nil {
			ordered = append(ordered, *psk)
			pskMoved = true
		}
		exts = ordered
	}
	var noSrc []string
	// type 51 的借用需要知道"最终面向线上的 supported_groups"：RFC 8446 §4.2.8
	// 要求每个 KeyShareEntry 的组都必须出现在 supported_groups 里，否则服务端以
	// illegal parameter 拒握手。入口保留自带 groups（ja3 已剔 GREASE）时，预设的
	// key_shares 可能带 GREASE 占位等入口没有的组——服务端不会替客户端剥离，必须过滤。
	var finalGroups []string
	if keepGroups {
		for _, e := range exts {
			if e.Type == 10 {
				finalGroups = e.Groups
				break
			}
		}
	} else if e, ok := src[10]; ok {
		finalGroups = e.Groups
	}
	for i := range exts {
		e := &exts[i]
		if isGreaseVal(e.Type) {
			continue // GREASE 线上值每连接重取，字面借用没有意义
		}
		s, ok := src[e.Type]
		if !ok {
			noSrc = append(noSrc, fmt.Sprintf("0x%04x", e.Type))
			continue
		}
		borrowExtensionOverwrite(e, s, keepGroups, keepPoints, keepSigAlgs, finalGroups)
	}
	d.Extensions = exts
	if len(d.Ciphers) == 0 && len(preset.TLS.Detail.Ciphers) > 0 {
		d.Ciphers = append([]string(nil), preset.TLS.Detail.Ciphers...)
	}
	// 浅拷贝 + 新 TLS 副本：不污染调用方传入的 profile 对象。
	tlsCp := *p.TLS
	tlsCp.Detail = &d
	cp := *p
	cp.TLS = &tlsCp

	var warns []Warning
	if pskMoved {
		warns = append(warns, warnf("psk_placeholder",
			"入口含 pre_shared_key(41)：已归位到扩展列表末尾（协议要求它在最后）；冷启动握手不会发出它，JA3/JA4 对拍会少这一项"))
	}
	warns = append(warns, warnf("payload_borrowed",
		"ja3/ja4r 的扩展载荷已按最相似预设 %q 的真实形态替换/补全（相似度 %.2f）；要逐字节保真请改用 clienthello_hex 或完整 profile",
		name, score))
	if len(noSrc) > 0 {
		warns = append(warns, warnf("payload_borrow_partial",
			"扩展 %s 在内置预设 %q 里没有同类型可参照，载荷保持原样", strings.Join(noSrc, ", "), name))
	}
	return &cp, name, score, warns
}

// borrowExtensionOverwrite 用 src 替换 dst 的载荷（有损入口专用：dst 的载荷是
// 通用默认/推断值，替换为目标族预设的真实形态）。keep* 为真的字段是入口真实
// 携带的信息（ja3 的 groups/points、ja4r 的 sig_algs），保留不覆盖。
// borrowExtensionOverwrite 用 src 替换 dst 的载荷（有损入口专用：dst 的载荷是
// 通用默认/推断值，替换为目标族预设的真实形态）。keep* 为真的字段是入口真实
// 携带的信息（ja3 的 groups/points、ja4r 的 sig_algs），保留不覆盖。
// groups 是"最终面向线上的 supported_groups"（用于 key_share 的组一致性过滤）。
func borrowExtensionOverwrite(dst *Extension, src Extension, keepGroups, keepPoints, keepSigAlgs bool, groups []string) {
	if !keepGroups {
		dst.Groups = cloneStr(src.Groups)
	}
	if !keepPoints {
		dst.PointFormats = cloneU8(src.PointFormats)
	}
	if !keepSigAlgs {
		dst.SigAlgs = cloneStr(src.SigAlgs)
	}
	dst.SNI = src.SNI
	dst.ALPN = cloneStr(src.ALPN)
	dst.PaddingTo = src.PaddingTo
	dst.PaddingLen = src.PaddingLen
	dst.CertCompression = cloneStr(src.CertCompression)
	dst.Versions = cloneStr(src.Versions)
	dst.PSKModes = cloneU8(src.PSKModes)
	if dst.Type == 51 {
		dst.KeyShares = filterKeyShares(cloneStr(src.KeyShares), groups)
	} else {
		dst.KeyShares = cloneStr(src.KeyShares)
	}
	if src.ECH != nil {
		ech := *src.ECH
		dst.ECH = &ech
	} else {
		dst.ECH = nil
	}
	dst.Data = src.Data
}

// filterKeyShares 把借来的 key_share 组过滤为"出现在 groups（最终 supported_groups）
// 里的"——GREASE 组同样必须在列（服务端不做客户端侧的 GREASE 剥离；实测不带时会以
// illegal parameter 拒握手）。过滤后为空时退回 groups 的第一个非 GREASE 组，保证
// 至少有一个共享；groups 为空（入口没有该扩展）时原样保留。
func filterKeyShares(shares, groups []string) []string {
	if len(shares) == 0 {
		return nil
	}
	if len(groups) == 0 {
		return shares
	}
	in := make(map[string]bool, len(groups))
	for _, g := range groups {
		in[strings.ToLower(strings.TrimSpace(g))] = true
	}
	var out []string
	for _, s := range shares {
		if in[strings.ToLower(strings.TrimSpace(s))] {
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, g := range groups {
		if !isGreaseName(g) {
			return []string{g}
		}
	}
	return shares
}

// isGreaseName 报告组/版本名是否是 GREASE 占位（"grease" 字面量或 0x?a?a 值）。
func isGreaseName(s string) bool {
	if strings.EqualFold(strings.TrimSpace(s), "grease") {
		return true
	}
	if v, ok := parseSpecHex16(s); ok {
		return isGreaseVal(v)
	}
	return false
}

func cloneStr(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	return append([]string(nil), v...)
}

func cloneU8(v []uint8) []uint8 {
	if len(v) == 0 {
		return nil
	}
	return append([]uint8(nil), v...)
}
