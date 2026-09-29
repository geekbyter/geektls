// 谱系（lineage）生成：把"一个版本一份预设"升级为"用我们自己的实测锚点描述演化的规则"。
//
// 为什么这么做（与 curl_cffi / tls_client / curl-impersonate 等的差别）：
// 它们的预设是**人工维护的有限清单**，浏览器一发新版就得等库更新；我们是
// **锚点 + 逐字段演化规则**：
//
//  1. 每个字段先做**跨版本稳定性判定**：在实测锚点之间它变过没有、在哪个版本变的；
//  2. 锚点窗口内的中间版本按"最近下界锚点"取值生成，并**逐字段标注**该值是否可信
//     （稳定 ⇒ 可信；区间内变过但边界未知 ⇒ 明确标为"未定界"）；
//  3. 窗口外**一律不外推**（无实测依据），需要新版本时只需再采一个锚点，一条命令扩展。
//
// 诚实性：生成的预设一律标 `grade: "E2i"`（内插，未实测该版本），绝不混入自测等级；
// E1 级断言（fp oracle / GT / TLS1.2 回退）按 grade 非空一律跳过。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/geektls/core/profiles"
	"github.com/geektls/tests/e2e/specimens"
)

// lineageAnchor 是一个实测锚点及其编译结果。
type lineageAnchor struct {
	item specimens.Item
	prof *profiles.Profile
}

// lineageField 是参与演化分析的一个字段。
type lineageField struct {
	key   string                       // 字段名
	value func(*profiles.Profile) string // 取值（已做 GREASE/随机归一）
}

// lineageFields 是要分析的字段集合。覆盖 JA3/JA4 与 H2 可观测的骨架：
// 这些字段一变，指纹就变；identity 不在其列（它由版本规则重算，见 generateAt）。
var lineageFields = []lineageField{
	{"ciphers", func(p *profiles.Profile) string { return strings.Join(p.TLS.Detail.Ciphers, "-") }},
	{"ext_order", func(p *profiles.Profile) string { return extOrderOf(p) }},
	{"ext_set", func(p *profiles.Profile) string { return extSetOf(p) }},
	{"ext_13_sig_algs", func(p *profiles.Profile) string { return fieldData(p, 13, "sig_algs") }},
	{"ext_34_delegated", func(p *profiles.Profile) string { return fieldData(p, 34, "sig_algs") }},
	{"ext_43_versions", func(p *profiles.Profile) string { return fieldData(p, 43, "versions") }},
	{"ext_45_psk_modes", func(p *profiles.Profile) string { return fieldData(p, 45, "psk_modes") }},
	{"ext_10_groups", func(p *profiles.Profile) string { return fieldData(p, 10, "groups") }},
	{"ext_51_key_shares", func(p *profiles.Profile) string { return fieldData(p, 51, "key_shares") }},
	{"ext_27_cert_compression", func(p *profiles.Profile) string { return fieldData(p, 27, "cert_compression") }},
	{"ext_28_record_size_limit", func(p *profiles.Profile) string { return fieldData(p, 28, "data") }},
	{"ext_21_padding", func(p *profiles.Profile) string { return fieldData(p, 21, "padding") }},
	{"ext_65281_renegotiation", func(p *profiles.Profile) string { return fieldData(p, 65281, "data") }},
	{"ext_17513_alps", func(p *profiles.Profile) string { return fieldData(p, 17513, "alpn") }},
	{"ext_17613_alps", func(p *profiles.Profile) string { return fieldData(p, 17613, "alpn") }},
	{"ext_65037_ech", func(p *profiles.Profile) string { return fieldData(p, 65037, "ech") }},
	{"ext_51764_unknown_grease", func(p *profiles.Profile) string { return fieldData(p, 51764, "data") }},
	{"h2_settings", func(p *profiles.Profile) string { return h2SettingsOf(p) }},
	{"h2_window_update", func(p *profiles.Profile) string { return strconv.FormatUint(uint64(h2FlowOf(p)), 10) }},
	{"h2_headers_priority", func(p *profiles.Profile) string {
		if p.HTTP2 == nil || p.HTTP2.HeadersPriority == nil {
			return "(nil=Chrome 默认 excl:true,w:255)"
		}
		hp := p.HTTP2.HeadersPriority
		return fmt.Sprintf("excl:%v,dep:%d,w:%d", hp.Exclusive, hp.StreamDep, hp.Weight)
	}},
	{"identity_header_order", func(p *profiles.Profile) string {
		if p.Identity == nil {
			return ""
		}
		var out []string
		for _, kv := range p.Identity.Headers {
			out = append(out, kv[0])
		}
		return strings.Join(out, ",")
	}},
}

// fieldProvenance 是一个字段在某版本上的取值来源。
type fieldProvenance struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Source  string `json:"source"`  // "stable" / "anchor@143" / "unbounded@143-152"
	Trusted bool   `json:"trusted"` // false = 该区间内此字段变过但边界未知
}

// lineageReport 输出给人与机器看的谱系报告。
type lineageReport struct {
	Family    string                       `json:"family"`
	Platform  string                       `json:"platform"`
	Anchors   []string                     `json:"anchors"`   // 实测锚点版本
	Stability map[string][]string          `json:"stability"` // 字段 → ["stable"] 或 ["@143→152: 值A → 值B"]
	Generated map[string][]fieldProvenance `json:"generated"` // 版本 → 逐字段来源
	Refused   map[string]string            `json:"refused,omitempty"`
}

// lineageBuild 为每个族构建锚点序列（按版本升序）。
func lineageBuild() (map[string][]lineageAnchor, error) {
	byFam := map[string][]lineageAnchor{}
	for _, it := range specimens.All() {
		p, err := build(it)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", it.Name, err)
		}
		byFam[it.Family] = append(byFam[it.Family], lineageAnchor{it, p})
	}
	for fam := range byFam {
		list := byFam[fam]
		sort.Slice(list, func(i, j int) bool { return atoiSafe(list[i].item.Version) < atoiSafe(list[j].item.Version) })
		byFam[fam] = list
	}
	return byFam, nil
}

// classify 判定一个字段在锚点序列上的演化：全同 ⇒ stable；否则给出每个变化点。
//
// 例外：Chromium/Edge 的扩展顺序是**逐连接洗牌**的（预设里存的只是基准序），
// 拿它比"跨版本稳定性"是假信号 ⇒ 该族直接标记为 shuffled，不参与判定。
func classify(f lineageField, anchors []lineageAnchor) (stable bool, steps []string) {
	if f.key == "ext_order" && anchors[0].prof.TLS.Detail.ExtensionPermutation {
		return false, []string{"shuffled（该族逐连接洗牌，顺序不构成指纹）"}
	}
	stable = true
	for i := 1; i < len(anchors); i++ {
		prev, cur := f.value(anchors[i-1].prof), f.value(anchors[i].prof)
		if prev == cur {
			continue
		}
		stable = false
		steps = append(steps, fmt.Sprintf("@%s→%s: %s → %s",
			anchors[i-1].item.Version, anchors[i].item.Version, orDash(prev), orDash(cur)))
	}
	return stable, steps
}

// gapVersions 返回锚点窗口内、缺失的中间版本（不外推窗口外）。
func gapVersions(anchors []lineageAnchor) []string {
	var out []string
	for i := 1; i < len(anchors); i++ {
		lo, hi := atoiSafe(anchors[i-1].item.Version), atoiSafe(anchors[i].item.Version)
		for v := lo + 1; v < hi; v++ {
			out = append(out, strconv.Itoa(v))
		}
	}
	return out
}

// ErrRefused 表示"按设计拒绝内插"（不是程序错误）。调用方用 errors.Is 区分。
var ErrRefused = errors.New("refused")

// generateAt 以内插方式生成某版本的预设：
//
//	TLS 骨架：取"≤该版本的最高锚点"（step 语义）
//	identity：用版本规则**重算**（UA/UA-CH 必须带该版本号，否则会露馅）
//	标注：grade=E2i / E2i-u + source=lineage:…；逐字段来源写进报告
//
// 拒绝（返回 ErrRefused）的两种情形：**窗口外**（不外推）、**区间内密码套件变过**
//（骨架取值不知道落哪一侧，内插等于凭空造栈）。strict 为 true 时，任何字段在区间内
// 变化且边界未知也拒绝。
func generateAt(fam string, anchors []lineageAnchor, version string, strict bool) (*profiles.Profile, []fieldProvenance, error) {
	base, next := anchorBounding(anchors, version)
	if base == nil {
		return nil, nil, fmt.Errorf("%w：版本 %s 低于最低锚点 %s（不外推）", ErrRefused, version, anchors[0].item.Version)
	}
	if atoiSafe(version) > atoiSafe(anchors[len(anchors)-1].item.Version) {
		return nil, nil, fmt.Errorf("%w：版本 %s 高于最高锚点 %s（不外推；再采一个锚点即可扩展）",
			ErrRefused, version, anchors[len(anchors)-1].item.Version)
	}
	// 该区间内哪些字段变过（边界未知）⇒ 逐字段标注不可信
	unstable := map[string]string{}
	if next != nil {
		permuted := base.prof.TLS.Detail.ExtensionPermutation
		for _, f := range lineageFields {
			if f.key == "ext_order" && permuted {
				continue // 洗牌族的顺序不构成指纹，别当变化
			}
			if a, b := f.value(base.prof), f.value(next.prof); a != b {
				unstable[f.key] = fmt.Sprintf("unbounded@%s-%s", base.item.Version, next.item.Version)
			}
		}
	}
	// 硬拒绝：**cipher 套件在区间内变过**意味着整条 TLS 骨架的取值都不知道落在哪一侧
	//（例如 Safari 18→26 换了密码套件序），此时内插等于凭空造一套 TLS 栈 ⇒ 拒绝并要锚点。
	if _, bad := unstable["ciphers"]; bad {
		return nil, nil, fmt.Errorf("%w：密码套件在 %s→%s 之间变过（边界未知）⇒ 拒绝内插，需要区间内锚点",
			ErrRefused, base.item.Version, next.item.Version)
	}
	if strict && len(unstable) > 0 {
		keys := make([]string, 0, len(unstable))
		for k := range unstable {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return nil, nil, fmt.Errorf("%w：区间内 %d 个字段变化且边界未知（%s）⇒ strict 拒绝",
			ErrRefused, len(keys), strings.Join(keys, ","))
	}

	p, err := cloneProfile(base.prof)
	if err != nil {
		return nil, nil, err
	}
	p.Name = fmt.Sprintf("%s_%s_%s", fam, version, strings.ToLower(base.item.Platform))
	// 两级内插可信度：全部被比较字段在区间内稳定 ⇒ E2i；有字段变化且边界未知 ⇒ E2i-u。
	p.Grade = "E2i"
	if len(unstable) > 0 {
		p.Grade = "E2i-u"
	}
	p.Source = fmt.Sprintf("lineage:%s@%s", fam, anchorVersions(anchors))
	// identity 必须按目标版本重算（UA 与 UA-CH 里都带版本号）。
	p.Identity = &profiles.IdentityProfile{Headers: identityHeaders(specimens.Item{
		Name: p.Name, Family: fam, Version: version, Platform: base.item.Platform,
	})}

	var prov []fieldProvenance
	for _, f := range lineageFields {
		src, ok := unstable[f.key]
		trusted := true
		if !ok {
			src = "stable-in-window"
		} else {
			// 该字段在区间内有变化、边界未知 ⇒ 保留 unstable 里的说明，但不可信。
			trusted = false
		}
		prov = append(prov, fieldProvenance{Field: f.key, Value: f.value(p), Source: src, Trusted: trusted})
	}
	return p, prov, nil
}

// anchorBounding 返回 ≤v 的最高锚点与其下一个锚点。
func anchorBounding(anchors []lineageAnchor, version string) (base, next *lineageAnchor) {
	v := atoiSafe(version)
	for i := range anchors {
		if atoiSafe(anchors[i].item.Version) <= v {
			base = &anchors[i]
			if i+1 < len(anchors) {
				next = &anchors[i+1]
			}
		}
	}
	return base, next
}

func anchorVersions(anchors []lineageAnchor) string {
	out := make([]string, 0, len(anchors))
	for _, a := range anchors {
		out = append(out, a.item.Version)
	}
	return strings.Join(out, ",")
}

func cloneProfile(p *profiles.Profile) (*profiles.Profile, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out profiles.Profile
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------- 字段取值辅助 ----------

func extOf(p *profiles.Profile, t uint16) *profiles.Extension {
	for i := range p.TLS.Detail.Extensions {
		if p.TLS.Detail.Extensions[i].Type == t {
			return &p.TLS.Detail.Extensions[i]
		}
	}
	return nil
}

// fieldData 返回扩展的某个字段（按 key 取），用于演化比较。
func fieldData(p *profiles.Profile, t uint16, key string) string {
	e := extOf(p, t)
	if e == nil {
		return "(absent)"
	}
	switch key {
	case "sig_algs":
		return strings.Join(e.SigAlgs, ",")
	case "versions":
		return strings.Join(e.Versions, ",")
	case "psk_modes":
		return fmt.Sprintf("%v", e.PSKModes)
	case "groups":
		return strings.Join(e.Groups, ",")
	case "key_shares":
		return strings.Join(e.KeyShares, ",")
	case "cert_compression":
		return strings.Join(e.CertCompression, ",")
	case "alpn":
		return strings.Join(e.ALPN, ",")
	case "data":
		return e.Data
	case "padding":
		return fmt.Sprintf("len=%d,to=%d", e.PaddingLen, e.PaddingTo)
	case "ech":
		if e.ECH == nil {
			return "(nil)"
		}
		return fmt.Sprintf("mode=%s", e.ECH.Mode)
	}
	return "(unknown-key)"
}

// extOrderOf 返回扩展顺序（GREASE 与占位项不计，只比"实质顺序"）。
// Chromium 是逐连接洗牌的 ⇒ 对 Chromium 该字段天然会"变化"，报告里会如实显示。
func extOrderOf(p *profiles.Profile) string {
	var out []string
	for _, e := range p.TLS.Detail.Extensions {
		if e.GreaseRandom || e.Type == 0 || e.Type == 41 {
			continue
		}
		out = append(out, strconv.Itoa(int(e.Type)))
	}
	return strings.Join(out, "-")
}

func extSetOf(p *profiles.Profile) string {
	ids := map[int]bool{}
	for _, e := range p.TLS.Detail.Extensions {
		if e.GreaseRandom || e.Type == 0 || e.Type == 41 {
			continue
		}
		ids[int(e.Type)] = true
	}
	list := make([]int, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Ints(list)
	out := make([]string, 0, len(list))
	for _, id := range list {
		out = append(out, strconv.Itoa(id))
	}
	return strings.Join(out, ",")
}

func h2SettingsOf(p *profiles.Profile) string {
	if p.HTTP2 == nil {
		return "(no-h2)"
	}
	var out []string
	for _, kv := range p.HTTP2.Settings {
		out = append(out, fmt.Sprintf("%d:%d", kv[0], kv[1]))
	}
	return strings.Join(out, ",")
}

func h2FlowOf(p *profiles.Profile) uint32 {
	if p.HTTP2 == nil {
		return 0
	}
	return p.HTTP2.WindowUpdate
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func orDash(s string) string {
	if s == "" {
		return "(空)"
	}
	return s
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// ---------- 驱动 ----------

// runLineage 跑谱系流程：分析锚点 → 内插窗口内缺失版本 → 打印报告 + 落盘 JSON。
func runLineage(out, reportPath string, strict, dry bool) {
	byFam, err := lineageBuild()
	if err != nil {
		fatal(err)
	}
	fams := make([]string, 0, len(byFam))
	for f := range byFam {
		fams = append(fams, f)
	}
	sort.Strings(fams)

	var reports []lineageReport
	total := 0
	for _, fam := range fams {
		anchors := byFam[fam]
		rep := lineageReport{
			Family: fam, Platform: anchors[0].item.Platform,
			Anchors:   anchorVersionsSlice(anchors),
			Stability: map[string][]string{},
			Generated: map[string][]fieldProvenance{},
			Refused:   map[string]string{},
		}
		fmt.Printf("\n=== %s（锚点 %s，平台 %s）===\n", fam, strings.Join(rep.Anchors, ","), rep.Platform)
		var changed []string
		for _, f := range lineageFields {
			stable, steps := classify(f, anchors)
			if stable {
				rep.Stability[f.key] = []string{"stable"}
				continue
			}
			rep.Stability[f.key] = steps
			changed = append(changed, f.key)
		}
		fmt.Printf("  跨锚点稳定字段 %d / 会变字段 %d", len(lineageFields)-len(changed), len(changed))
		fmt.Println()
		for _, k := range changed {
			for _, s := range rep.Stability[k] {
				if strings.HasPrefix(s, "shuffled") {
					fmt.Printf("    · %s: %s\n", k, s)
					continue
				}
				fmt.Printf("    · %s %s\n", k, truncate(s, 150))
			}
		}

		gaps := gapVersions(anchors)
		if len(gaps) == 0 {
			fmt.Println("  锚点窗口内无缺失版本")
		}
		for _, v := range gaps {
			p, prov, err := generateAt(fam, anchors, v, strict)
			if err != nil {
				rep.Refused[v] = err.Error()
				if errors.Is(err, ErrRefused) {
					fmt.Printf("  - %s: 按设计拒绝（%v）\n", v, err)
				} else {
					fmt.Printf("  ! %s: 生成失败（%v）\n", v, err)
				}
				continue
			}
			if why, ok := existingBlocks(out, p.Name); ok {
				rep.Refused[v] = why
				fmt.Printf("  - %s: 跳过（%s）\n", v, why)
				continue
			}
			untrusted := 0
			for _, fp := range prov {
				if !fp.Trusted {
					untrusted++
				}
			}
			rep.Generated[v] = prov
			total++
			if dry || out == "" {
				fmt.Printf("  + %s（%d/%d 字段为区间内插、边界未知）\n", p.Name, untrusted, len(prov))
				continue
			}
			b, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				fatal(err)
			}
			b = renderByteSliceFields(b)
			b = append(b, '\n')
			if err := os.WriteFile(filepath.Join(out, p.Name+".json"), b, 0o644); err != nil {
				fatal(err)
			}
			fmt.Printf("  + %s（%d/%d 字段为区间内插、边界未知）→ 已落盘\n", p.Name, untrusted, len(prov))
		}
		reports = append(reports, rep)
	}

	fmt.Printf("\n谱系：内插 %d 个版本（grade=E2i，未实测）\n", total)
	if reportPath != "" {
		b, err := json.MarshalIndent(map[string]any{"reports": reports}, "", "  ")
		if err != nil {
			fatal(err)
		}
		b = append(b, '\n')
		if err := os.WriteFile(reportPath, b, 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("报告已写入 %s\n", reportPath)
	}
}

// existingBlocks 判断目标名是否已被"非内插"预设占用（自测/第三方一律优先，不覆盖）。
func existingBlocks(dir, name string) (string, bool) {
	if dir == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return "", false
	}
	var p profiles.Profile
	if json.Unmarshal(b, &p) != nil {
		return "同名文件无法解析", true
	}
	if p.Grade == "E2i" {
		return "", false // 内插产物可覆盖（管线可重复执行）
	}
	return "已被非内插预设占用（" + orDash(p.Grade) + "）", true
}

func anchorVersionsSlice(anchors []lineageAnchor) []string {
	out := make([]string, 0, len(anchors))
	for _, a := range anchors {
		out = append(out, a.item.Version)
	}
	return out
}
