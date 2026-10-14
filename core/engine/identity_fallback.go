package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/geekbyter/geektls/core/profiles"
)

// --- 低层装载的开箱即用兜底（T-I5 / T-I9，2026-10-14 创宇盾案例驱动） ---

// resolveIdentityAndPayloads 在克隆出的 profile 上做两件事（都不污染调用方对象）：
//
//  1. 载荷借用（T-I9）：ja3=/ja4r= 只有扩展类型，直接装载会生成被真实服务端
//     判为畸形的 ClientHello（error decoding message）。检测到关键载荷缺失时，
//     按"最相似内置预设"同类型借载荷（顺序/类型集合保持入口语义）。
//  2. HTTP 身份兜底（T-I5）：低层装载不带 identity 节，请求头会落到 Go 默认
//     UA（Go-http-client/…）——云 WAF 的"精准访问控制"据此一眼判非浏览器
//     （创宇盾案例 403）。默认自动借用最相似预设的 identity 节（TLS 与 HTTP
//     身份同源，同族借用才不制造分裂）。
//
// 显式控制（SessionOptions.Identity）：
//   - 不传      → 自动兜底（上面两条）
//   - "预设名"  → 借该预设的 identity 节
//   - {"headers": [["name","value"],…]} 或 {"User-Agent": "…"} → 直接用给定头表
//   - false     → 显式关闭自动身份（TLS 对拍场景：要什么发什么；载荷借用不受影响）
//
// 返回：替换后的 profile、告警（挂响应 Warnings）、是否显式关闭自动身份。
func resolveIdentityAndPayloads(p *profiles.Profile, raw json.RawMessage) (*profiles.Profile, []string, bool, error) {
	mode, presetName, headers, err := parseIdentityOption(raw)
	if err != nil {
		return nil, nil, false, err
	}
	cur := p
	var warns []string

	// 1) 有损入口的载荷借用（在 identity=false 下也照借——该开关只关 HTTP 身份）。
	// 无可借时 BorrowPayloads 原样返回入参（零开销），告警照带。
	bp, _, _, bw := profiles.BorrowPayloads(cur)
	cur = bp
	warns = append(warns, warningLines(bw)...)

	// 2) HTTP 身份。
	switch mode {
	case identDisabled:
		return withIdentity(cur, nil), warns, true, nil
	case identHeaders:
		return withIdentity(cur, &profiles.IdentityProfile{Headers: headers}), warns, false, nil
	case identPreset:
		pp, err := profiles.Get(presetName)
		if err != nil {
			return nil, nil, false, fmt.Errorf("engine: identity 指定的预设 %q 不可用：%v", presetName, err)
		}
		if pp.Identity == nil || len(pp.Identity.Headers) == 0 {
			return nil, nil, false, fmt.Errorf("engine: identity 预设 %q 没有 identity 节（换预设或直接给头表）", presetName)
		}
		return withIdentity(cur, pp.Identity), warns, false, nil
	}

	// identAuto：仅在会话确实没有身份时兜底（预设/profile 自带 identity 的不动）。
	if cur.Identity != nil && len(cur.Identity.Headers) > 0 {
		return cur, warns, false, nil
	}
	name, score := profiles.MatchPreset(cur)
	if name == "" || score < profiles.MatchMinScore {
		warns = append(warns, fmt.Sprintf(
			"identity_auto: 会话未携带 HTTP 身份，且未找到足够相似的内置预设（最高相似度 %.2f）：请求头将回落 Go 默认形态，浏览器伪装场景请用 identity= 指定",
			score))
		return cur, warns, false, nil
	}
	pp, err := profiles.Get(name)
	if err != nil || pp.Identity == nil || len(pp.Identity.Headers) == 0 {
		warns = append(warns, fmt.Sprintf(
			"identity_auto: 最相似预设 %q 没有 identity 节，请求头将回落 Go 默认形态；浏览器伪装场景请用 identity= 指定",
			name))
		return cur, warns, false, nil
	}
	warns = append(warns, fmt.Sprintf(
		"identity_auto: 会话未携带 HTTP 身份（低层装载），已自动借用最相似预设 %q 的 identity 节（相似度 %.2f）；不符可用 identity= 显式指定，identity=false 关闭",
		name, score))
	return withIdentity(cur, pp.Identity), warns, false, nil
}

// warningLines 把 profiles.Warning 渲染成响应 warnings 的行（code: message）。
func warningLines(ws []profiles.Warning) []string {
	if len(ws) == 0 {
		return nil
	}
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, fmt.Sprintf("%s: %s", w.Code, w.Message))
	}
	return out
}

type identMode int

const (
	identAuto identMode = iota
	identPreset
	identHeaders
	identDisabled
)

// parseIdentityOption 解析 SessionOptions.Identity 的三种形态（见
// resolveIdentityAndPayloads 的说明）。零值/空串/null 都归"自动"。
func parseIdentityOption(raw json.RawMessage) (identMode, string, [][2]string, error) {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == `""` {
		return identAuto, "", nil, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		if !b {
			return identDisabled, "", nil, nil
		}
		return identAuto, "", nil, fmt.Errorf(
			"engine: identity=true 没有额外含义（自动兜底已是默认）；请用预设名 / 头表 / false")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if strings.TrimSpace(s) == "" {
			return identAuto, "", nil, nil
		}
		return identPreset, strings.TrimSpace(s), nil, nil
	}
	var obj struct {
		Headers [][2]string `json:"headers"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj.Headers) > 0 {
		return identHeaders, "", obj.Headers, nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err == nil && len(m) > 0 {
		h := make([][2]string, 0, len(m))
		for k, v := range m {
			h = append(h, [2]string{k, v})
		}
		sort.Slice(h, func(i, j int) bool { return h[i][0] < h[j][0] }) // map 无序：定序保证可复现
		return identHeaders, "", h, nil
	}
	return identAuto, "", nil, fmt.Errorf(
		`engine: identity 只接受 预设名（字符串）/ 头表（{"headers": [["name","value"],…]} 或 {"User-Agent": "…"}）/ false`)
}

// withIdentity 返回浅拷贝的 profile（Identity 换成 id；nil 清空）——不改调用方对象。
func withIdentity(p *profiles.Profile, id *profiles.IdentityProfile) *profiles.Profile {
	cp := *p
	cp.Identity = id
	return &cp
}

// fillHTTPSelfCheck 填 SelfCheck 的 HTTP 层快照（T-I8），返回应挂到响应上的告警
// （未显式关闭自动身份、又没有 user-agent 时——该请求会以 Go 默认 UA 上线）。
// warnOnDefault=false 表示调用方已明确知道自己要什么（identity=false）。
func (s *Session) fillHTTPSelfCheck(sc *SelfCheck, headers [][2]string, warnOnDefault bool) string {
	sc.HeaderCount = len(headers)
	ua := ""
	for _, kv := range headers {
		if strings.EqualFold(kv[0], "user-agent") {
			ua = kv[1]
			break
		}
	}
	sc.UserAgent = ua
	sc.GoDefaultUA = ua == ""
	if !sc.GoDefaultUA || !warnOnDefault {
		return ""
	}
	return "http_identity: 请求不带 user-agent，线上会回落 Go 默认 UA（Go-http-client/…）——浏览器伪装场景请用 identity= 补齐身份头"
}
