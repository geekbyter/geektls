package profiles

// 重放自洽归一（2026-09-28）：用户自带的指纹输入（JA3 / JA4 / JA4R / ClientHello hex /
// 手写 detail）经此归一后，与内置预设遵循**同一套**"可重放且自洽"的规则，避免
// "指纹看着对、第二次请求却莫名其妙失败"这类跨层不一致。
//
// 目前唯一硬规则是 pre_shared_key(41) 的双向约束（与 core/tls/presets_test.go 的
// TestPresetCarriesPskPlaceholder 同源）：
//
//	声明 TLS 1.3 ⇒ 必须有 41 空占位，且位于扩展列表末尾（RFC 8446）；
//	不声明 TLS 1.3 ⇒ 必须没有 41（否则 ClientHello 结构非法）。
//
// 为什么必须做：引擎默认开启会话复用，而 uTLS 在"缓存命中票据、spec 里却没有 41"时
// 会 panic（u_session_controller.go:128 initPskExt；tlscore.Handshake 只把它兜成错误）。
// 占位是**空负载**：无票据时线上省略（OmitEmptyPsk），也不计入 JA3/JA4（引擎自算前剔除），
// 所以补上它不改变首次握手的指纹。
func NormalizeForReplay(p *Profile) []Warning {
	if p == nil || p.TLS == nil || p.TLS.Detail == nil {
		return nil
	}
	d := p.TLS.Detail
	idx := -1
	for i, e := range d.Extensions {
		if e.Type == 41 {
			idx = i
		}
	}

	var warnings []Warning
	switch {
	case declaresTLS13(d) && idx < 0:
		d.Extensions = append(d.Extensions, Extension{Type: 41})
		warnings = append(warnings, warnf("psk_placeholder_added",
			"declares TLS 1.3 but has no pre_shared_key(41): appended an empty placeholder at the end "+
				"(required when a cached ticket is reused; omitted on the wire without a ticket, so the first-flight fingerprint is unchanged)"))

	case declaresTLS13(d) && idx != len(d.Extensions)-1:
		e := d.Extensions[idx]
		d.Extensions = append(d.Extensions[:idx], d.Extensions[idx+1:]...)
		d.Extensions = append(d.Extensions, e)
		warnings = append(warnings, warnf("psk_moved_to_end",
			"pre_shared_key(41) was not the last extension: moved to the end (RFC 8446 requires it last)"))

	case !declaresTLS13(d) && idx >= 0:
		d.Extensions = append(d.Extensions[:idx], d.Extensions[idx+1:]...)
		warnings = append(warnings, warnf("psk_removed",
			"does not declare TLS 1.3 but carries pre_shared_key(41): removed (illegal ClientHello structure)"))
	}
	return warnings
}

// declaresTLS13 判断该 detail 是否声明 TLS 1.3。
//
// 两种表达：supported_versions(43) 存在即可（JA3/JA4 这类有损入口只有扩展 type，
// 没有 versions 列表）；若 versions 列表显式给了值，则以列表为准（必须含 0x0304）。
func declaresTLS13(d *Detail) bool {
	if d == nil {
		return false
	}
	for _, e := range d.Extensions {
		if e.Type != 43 {
			continue
		}
		if len(e.Versions) == 0 {
			return true // 有损入口：只有 type，按 TLS 1.3 能力处理
		}
		for _, v := range e.Versions {
			if v == "0x0304" {
				return true
			}
		}
		return false
	}
	return false
}
