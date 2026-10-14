package profiles

import (
	"strconv"
	"strings"
	"sync"
)

// MatchMinScore 是"最相似预设"可用的最低相似度（见 MatchPreset）。低于它的
// 匹配视为不可信——宁可如实告警，也不借一个错误家族的身份/载荷："TLS 说 A、
// 请求头说 B"的分裂比缺身份更容易被识破。0.75 ≈ 扩展与密码集合都高度重合、
// ALPN 一致；跨浏览器家族（扩展集合只部分重合）通常过不了线。
const MatchMinScore = 0.75

// MatchPreset 在全部内置预设里找 TLS 形态最接近 p 的一份，返回预设名与相似度
// （0..1）。用途：低层装载的无损补全——ja3/ja4r 的扩展载荷借用（borrow.go）与
// 无 identity 会话的 HTTP 身份兜底（engine 侧）。单看 TLS 无从得知"这是哪个
// 客户端"，而与 ClientHello 最像的内置预设就是最佳依据（TLS 与 HTTP 身份同源，
// 同族借用才不制造分裂）。
//
// 评分只看 TLS detail 的稳定特征（随机项与载荷字节不参与）：
//   - 扩展类型集合 Jaccard（权重 0.5）
//   - 密码套件集合 Jaccard（权重 0.3）
//   - ALPN 集合一致（权重 0.2）
//
// GREASE 值（RFC 8701 的 0x?a?a）在比较前剔除；空集合记 0 分（不虚高）。p 无
// detail 或无可比特征时返回 ("", 0)。
func MatchPreset(p *Profile) (string, float64) {
	if p == nil || p.TLS == nil || p.TLS.Detail == nil {
		return "", 0
	}
	target := featureOf("", p)
	if len(target.exts) == 0 && len(target.ciphers) == 0 {
		return "", 0
	}
	presetFeaturesOnce.Do(loadPresetFeatures)
	bestName, bestScore := "", 0.0
	for _, f := range presetFeatures {
		score := 0.5*jaccardU16(target.exts, f.exts) +
			0.3*jaccardU16(target.ciphers, f.ciphers) +
			0.2*alpnEqual(target.alpn, f.alpn)
		// 同分取"更主流家族"：Chromium 系内部（Chrome/Brave/Edge…）TLS 形态逐字节
		// 相同、抓包无从区分——默认落到 chrome_ 前缀（实际抓包绝大多数来自 Chrome，
		// 且族内借用的身份头互通）。
		if score > bestScore+1e-9 || (bestScore-score < 1e-9 && preferPreset(f.name, bestName)) {
			bestName, bestScore = f.name, score
		}
	}
	return bestName, bestScore
}

// preferPreset 报告同分候选里 a 是否比 b 更可取：家族优先级 chrome(桌面) >
// chrome(移动) > edge > firefox > safari > 其它；同级按版本号数值比较（大者优先，
// 同版本按名字典序倒序保证确定）。桌面优先是因为实际抓包绝大多数来自桌面浏览器；
// 版本大者优先是因为同族 TLS 形态逐字节相同、无从区分具体版本，取最新更不容易
// "过时"。
func preferPreset(a, b string) bool {
	if b == "" {
		return true
	}
	if ra, rb := presetRank(a), presetRank(b); ra != rb {
		return ra < rb
	}
	if ba, bb := presetBuild(a), presetBuild(b); ba != bb {
		return ba > bb
	}
	return a > b
}

// presetBuild 取预设名里的版本号（"chrome_154_windows" → 154；无数字返回 0）。
func presetBuild(name string) int {
	rest := name
	if i := strings.IndexByte(rest, '_'); i >= 0 {
		rest = rest[i+1:]
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	v, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return v
}

func presetRank(name string) int {
	isMobile := strings.Contains(name, "android") || strings.Contains(name, "ios")
	switch {
	case strings.HasPrefix(name, "chrome_") && !isMobile:
		return 0
	case strings.HasPrefix(name, "chrome_"):
		return 1
	case strings.HasPrefix(name, "edge_"):
		return 2
	case strings.HasPrefix(name, "firefox_"):
		return 3
	case strings.HasPrefix(name, "safari_"):
		return 4
	default:
		return 9
	}
}

// presetFeature 是内置预设的"可比较 TLS 特征"（MatchPreset 的缓存单元）。
type presetFeature struct {
	name    string
	exts    map[uint16]bool
	ciphers map[uint16]bool
	alpn    map[string]bool
}

var (
	presetFeaturesOnce sync.Once
	presetFeatures     []presetFeature
)

// loadPresetFeatures 一次性抽取全部内置预设的特征（解析失败/无 detail 的跳过）。
// 只收录"浏览器形态身份"的预设：兜底的目标就是"像浏览器"，自动化工具/无头
// 客户端一类预设不该成为身份与载荷的借用来源。
func loadPresetFeatures() {
	for _, name := range List() {
		p, err := Get(name)
		if err != nil || p.TLS == nil || p.TLS.Detail == nil || !browserIdentityPreset(p) {
			continue
		}
		presetFeatures = append(presetFeatures, featureOf(name, p))
	}
}

// browserIdentityPreset 报告预设的 identity 是否浏览器形态（user-agent 含
// "Mozilla/"）——MatchPreset 的候选过滤判据。
func browserIdentityPreset(p *Profile) bool {
	if p.Identity == nil {
		return false
	}
	for _, kv := range p.Identity.Headers {
		if strings.EqualFold(kv[0], "user-agent") && strings.Contains(kv[1], "Mozilla/") {
			return true
		}
	}
	return false
}

func featureOf(name string, p *Profile) presetFeature {
	f := presetFeature{
		name:    name,
		exts:    map[uint16]bool{},
		ciphers: map[uint16]bool{},
		alpn:    map[string]bool{},
	}
	d := p.TLS.Detail
	for _, c := range d.Ciphers {
		if v, ok := parseSpecHex16(c); ok && !isGreaseVal(v) {
			f.ciphers[v] = true
		}
	}
	for _, e := range d.Extensions {
		if !isGreaseVal(e.Type) {
			f.exts[e.Type] = true
		}
		if e.Type == 16 { // ALPN
			for _, a := range e.ALPN {
				f.alpn[a] = true
			}
		}
	}
	return f
}

// parseSpecHex16 解析 "0x1301"/"1301" 形态的 hex 16 位值；"grease"/空/非法返回 false。
func parseSpecHex16(s string) (uint16, bool) {
	t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if t == "" || t == "grease" {
		return 0, false
	}
	v, err := strconv.ParseUint(t, 16, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
}

// isGreaseVal 报告 v 是否为 RFC 8701 的 GREASE 保留值（两个字节相同且低 4 位为 a）。
func isGreaseVal(v uint16) bool {
	return v&0x0f0f == 0x0a0a && uint8(v>>8) == uint8(v)
}

// jaccardU16 是两集合的 Jaccard 相似度；任一侧为空记 0（不把"都没有"当相似）。
func jaccardU16(a, b map[uint16]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter, union := 0, len(a)
	for k := range b {
		if a[k] {
			inter++
		} else {
			union++
		}
	}
	return float64(inter) / float64(union)
}

// alpnEqual 报告两 ALPN 集合是否完全一致（1/0；任一侧为空记 0）。
func alpnEqual(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return 0
	}
	for k := range a {
		if !b[k] {
			return 0
		}
	}
	return 1
}
