package profiles

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ja3FromPresetForTest 从内置预设的 detail 生成"真实形态"的 JA3 串（ciphers
// 数值化、扩展类型剔除 GREASE、groups/points 十进制）——模拟有损入口的真实输入。
func ja3FromPresetForTest(t *testing.T, name string) string {
	t.Helper()
	p, err := Get(name)
	if err != nil {
		t.Fatal(err)
	}
	d := p.TLS.Detail
	var ciphers, exts, groups, points []string
	for _, c := range d.Ciphers {
		if v, ok := parseSpecHex16(c); ok && !isGreaseVal(v) {
			ciphers = append(ciphers, fmt.Sprintf("%d", v))
		}
	}
	for _, e := range d.Extensions {
		if isGreaseVal(e.Type) {
			continue
		}
		if e.Type == 41 {
			continue // pre_shared_key 只在 resumption 时发出；冷启动形态的期望值不含它
		}
		exts = append(exts, fmt.Sprintf("%d", e.Type))
		if e.Type == 10 {
			for _, g := range e.Groups {
				if gv, ok := parseSpecHex16(g); ok && !isGreaseVal(gv) {
					groups = append(groups, fmt.Sprintf("%d", gv))
				}
			}
		}
		if e.Type == 11 {
			for _, pf := range e.PointFormats {
				points = append(points, fmt.Sprintf("%d", pf))
			}
		}
	}
	return fmt.Sprintf("771,%s,%s,%s,%s",
		strings.Join(ciphers, "-"), strings.Join(exts, "-"),
		strings.Join(groups, "-"), strings.Join(points, "-"))
}

// ja4rFromPresetForTest 从内置预设的 detail 生成"真实形态"的 JA4R 串（a 段按
// JA4 规范：剔除 GREASE 与 SNI/ALPN、扩展排序、计数十六进制）——模拟 ja4r 入口。
func ja4rFromPresetForTest(t *testing.T, name string) string {
	t.Helper()
	p, err := Get(name)
	if err != nil {
		t.Fatal(err)
	}
	d := p.TLS.Detail
	var ciphers []string
	for _, c := range d.Ciphers {
		if v, ok := parseSpecHex16(c); ok && !isGreaseVal(v) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", v))
		}
	}
	hasSNI := false
	alpnCode := "00"
	var exts []uint16
	var sigs []string
	for _, e := range d.Extensions {
		if isGreaseVal(e.Type) {
			continue
		}
		if e.Type == 41 {
			continue // 同 ja3：冷启动形态的期望值不含 pre_shared_key
		}
		switch e.Type {
		case 0:
			hasSNI = true
			continue
		case 16:
			for _, a := range e.ALPN {
				if a == "h2" {
					alpnCode = "h2"
				}
			}
			continue
		case 13:
			for _, s := range e.SigAlgs {
				if v, ok := parseSpecHex16(s); ok && !isGreaseVal(v) {
					sigs = append(sigs, fmt.Sprintf("%04x", v))
				}
			}
		}
		exts = append(exts, e.Type)
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	sort.Strings(ciphers) // JA4R 的 ciphers 段是排序值；sig_algs 段保持原始序
	extHex := make([]string, 0, len(exts))
	for _, v := range exts {
		extHex = append(extHex, fmt.Sprintf("%04x", v))
	}
	sniFlag := "i"
	if hasSNI {
		sniFlag = "d"
	}
	// a 段计数是"含 SNI/ALPN"的总扩展数（JA4R 的 exts 段则不含——它们由 d/i
	// 标志与 ALPN 码承载）。
	extCount := len(exts)
	if hasSNI {
		extCount++
	}
	if alpnCode != "00" {
		extCount++
	}
	return fmt.Sprintf("t13%s%02d%02d%s_%s_%s_%s",
		sniFlag, len(ciphers), extCount, alpnCode,
		strings.Join(ciphers, ","), strings.Join(extHex, ","), strings.Join(sigs, ","))
}

func extByType(p *Profile, t0 uint16) (Extension, bool) {
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == t0 {
			return e, true
		}
	}
	return Extension{}, false
}

// TestMatchPresetSelfConsistent：每个"浏览器形态身份"的内置预设与自身比较应拿到
// 该特征组合的满分；分数上限按"有哪些可比特征"动态计算。
func TestMatchPresetSelfConsistent(t *testing.T) {
	names := List()
	if len(names) == 0 {
		t.Fatal("内置预设为空——embed 没生效？")
	}
	checked := 0
	for _, name := range names {
		p, err := Get(name)
		if err != nil || p.TLS == nil || p.TLS.Detail == nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !browserIdentityPreset(p) {
			continue // 非浏览器形态身份的预设不参与匹配（候选过滤）
		}
		checked++
		f := featureOf(name, p)
		want := 0.0
		if len(f.exts) > 0 {
			want += 0.5
		}
		if len(f.ciphers) > 0 {
			want += 0.3
		}
		if len(f.alpn) > 0 {
			want += 0.2
		}
		got, score := MatchPreset(p)
		if got == "" || score < want-1e-9 {
			t.Errorf("%s: MatchPreset = %q, %.3f（应 ≥ %.3f）", name, got, score, want)
		}
	}
	if checked == 0 {
		t.Fatal("没有浏览器形态身份的预设可测——候选过滤可能过宽")
	}
}

// TestMatchPresetRejectsEmpty：无 detail / 无可比特征的输入返回 ("", 0)。
func TestMatchPresetRejectsEmpty(t *testing.T) {
	if n, s := MatchPreset(&Profile{}); n != "" || s != 0 {
		t.Errorf("空 profile: %q %.2f", n, s)
	}
	if n, s := MatchPreset(&Profile{TLS: &TLSProfile{Detail: &Detail{}}}); n != "" || s != 0 {
		t.Errorf("空 detail: %q %.2f", n, s)
	}
}

// TestBorrowPayloadsFromJA3：真实形态 ja3（由 chrome_154_windows 生成）借用后：
// 扩展顺序/类型不变；43/51 等载荷等于匹配预设的真实值（≠ FromJA3 的通用默认）；
// ja3 自带的 groups/points 保留；ciphers 不变；原 profile 不被污染。
func TestBorrowPayloadsFromJA3(t *testing.T) {
	ja3 := ja3FromPresetForTest(t, "chrome_154_windows")
	p, _, err := FromJA3(ja3)
	if err != nil {
		t.Fatal(err)
	}
	defaultVersions := append([]string(nil), extByTypeForTest(t, p, 43).Versions...)
	defaultShares := append([]string(nil), extByTypeForTest(t, p, 51).KeyShares...)

	bp, name, score, warns := BorrowPayloads(p)
	if bp == p {
		t.Fatalf("应发生借用（name=%q score=%.2f warns=%+v）", name, score, warns)
	}
	if name == "" || score < MatchMinScore {
		t.Fatalf("匹配不可用: name=%q score=%.2f", name, score)
	}
	// 扩展顺序/类型集合不变。
	before := []uint16{}
	for _, e := range p.TLS.Detail.Extensions {
		before = append(before, e.Type)
	}
	after := []uint16{}
	for _, e := range bp.TLS.Detail.Extensions {
		after = append(after, e.Type)
	}
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("扩展顺序/类型被改动: %v -> %v", before, after)
	}
	// 载荷等于匹配预设的真实值（51 例外：借来的共享组按入口 groups 过滤，见下）。
	preset, err := Get(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, t0 := range []uint16{43, 16, 13} {
		want, ok := extByType(preset, t0)
		if !ok {
			continue
		}
		got, ok2 := extByType(bp, t0)
		if !ok2 {
			t.Fatalf("扩展 %d 丢失", t0)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("扩展 %d 载荷 != 预设 %q 的真实值:\n got  %+v\n want %+v", t0, name, got, want)
		}
	}
	// 51：借来的 key_share 组必须落在入口 groups 内（RFC 8446：KeyShareEntry 的组
	// 必须出现在 supported_groups 里，否则服务端 illegal parameter）。
	got51, ok := extByType(bp, 51)
	if !ok || len(got51.KeyShares) == 0 {
		t.Fatalf("51 载荷未借到: %+v", got51)
	}
	entry10, _ := extByType(p, 10)
	inGroups := map[string]bool{}
	for _, g := range entry10.Groups {
		inGroups[strings.ToLower(g)] = true
	}
	for _, s := range got51.KeyShares {
		if !inGroups[strings.ToLower(s)] {
			t.Errorf("借来的 key_share 组 %q 不在入口 groups 内: %v", s, entry10.Groups)
		}
	}
	// 入口自带的信息保留：groups/points（来自 ja3）。
	want10, _ := extByType(p, 10)
	got10, _ := extByType(bp, 10)
	if fmt.Sprint(got10.Groups) != fmt.Sprint(want10.Groups) {
		t.Errorf("ja3 自带 groups 被改动: %v -> %v", want10.Groups, got10.Groups)
	}
	want11, _ := extByType(p, 11)
	got11, _ := extByType(bp, 11)
	if fmt.Sprint(got11.PointFormats) != fmt.Sprint(want11.PointFormats) {
		t.Errorf("ja3 自带 points 被改动: %v -> %v", want11.PointFormats, got11.PointFormats)
	}
	// ciphers 不变。
	if strings.Join(p.TLS.Detail.Ciphers, ",") != strings.Join(bp.TLS.Detail.Ciphers, ",") {
		t.Error("ciphers 被改动")
	}
	// 原 profile 不被污染（43 仍是 FromJA3 的通用默认）。
	nowVersions := extByTypeForTest(t, p, 43).Versions
	if fmt.Sprint(nowVersions) != fmt.Sprint(defaultVersions) {
		t.Errorf("原 profile 被污染: 43.Versions %v -> %v", defaultVersions, nowVersions)
	}
	_ = defaultShares
	// 告警齐备。
	codes := map[string]bool{}
	for _, w := range warns {
		codes[w.Code] = true
	}
	if !codes["payload_borrowed"] {
		t.Errorf("缺 payload_borrowed 告警: %+v", warns)
	}
}

// TestBorrowPayloadsFromJA4R：ja4r 入口的 key_share 等缺失载荷被补齐，且
// sig_algs（入口自带）保留。
func TestBorrowPayloadsFromJA4R(t *testing.T) {
	p, _, err := FromJA4R(ja4rFromPresetForTest(t, "chrome_154_windows"))
	if err != nil {
		t.Fatal(err)
	}
	bp, name, score, warns := BorrowPayloads(p)
	if bp == p {
		t.Fatalf("应发生借用（name=%q score=%.2f warns=%+v）", name, score, warns)
	}
	if score < MatchMinScore {
		t.Fatalf("匹配不可用: name=%q score=%.2f", name, score)
	}
	// sig_algs 保留（入口自带）。
	want13, _ := extByType(p, 13)
	got13, _ := extByType(bp, 13)
	if fmt.Sprint(got13.SigAlgs) != fmt.Sprint(want13.SigAlgs) {
		t.Errorf("ja4r 自带 sig_algs 被改动: %v -> %v", want13.SigAlgs, got13.SigAlgs)
	}
	// 51（ja4r 无载荷）被补齐。
	got51, ok := extByType(bp, 51)
	if !ok || len(got51.KeyShares) == 0 {
		t.Errorf("key_share 载荷未借到: %+v", got51)
	}
	preset, err := Get(name)
	if err != nil {
		t.Fatal(err)
	}
	want51, _ := extByType(preset, 51)
	if fmt.Sprint(got51.KeyShares) != fmt.Sprint(want51.KeyShares) {
		t.Errorf("key_share 与预设 %q 不一致: %v vs %v", name, got51.KeyShares, want51.KeyShares)
	}
	// 顺序（排序序）+ ExtensionsSorted 语义保持。
	if !bp.TLS.Detail.ExtensionsSorted {
		t.Error("ExtensionsSorted 应保持为 true（ja4r 顺序不可还原）")
	}
}

// TestBorrowPayloadsNoop：非有损入口（预设 / 手写 detail）原样返回、零告警。
func TestBorrowPayloadsNoop(t *testing.T) {
	p, err := Get("chrome_154_windows")
	if err != nil {
		t.Fatal(err)
	}
	if bp, name, score, warns := BorrowPayloads(p); bp != p || name != "" || score != 0 || len(warns) != 0 {
		t.Errorf("预设不应触发借用: name=%q score=%.2f warns=%+v", name, score, warns)
	}
	// 手写 detail（有扩展、无 JA3/JA4R 标记）也不借——保真路径不替调用方做主。
	manual := &Profile{TLS: &TLSProfile{Detail: &Detail{
		LegacyVersion: "0x0303",
		Ciphers:       []string{"0x1301"},
		Extensions:    []Extension{{Type: 43}, {Type: 51}},
	}}}
	if bp, _, _, warns := BorrowPayloads(manual); bp != manual || len(warns) != 0 {
		t.Errorf("手写 detail 不应触发借用: warns=%+v", warns)
	}
}

// TestBorrowPayloadsUnavailable：与所有内置预设都差异过大时不借，并给出
// payload_borrow_unavailable 告警（宁可如实告警，不借错误家族）。
func TestBorrowPayloadsUnavailable(t *testing.T) {
	// 极简形态：1 个 cipher、1 个扩展（43）——与任何真实浏览器预设的相似度都低。
	p, _, err := FromJA3("771,4865,43,,")
	if err != nil {
		t.Fatal(err)
	}
	bp, name, score, warns := BorrowPayloads(p)
	if bp != p {
		t.Errorf("低相似度不应借用（借到了 %q score=%.2f）", name, score)
	}
	codes := map[string]bool{}
	for _, w := range warns {
		codes[w.Code] = true
	}
	if !codes["payload_borrow_unavailable"] {
		t.Errorf("缺 payload_borrow_unavailable 告警: %+v", warns)
	}
}

// extByTypeForTest 取指定类型的扩展（测试 helper；不存在时 Fatal）。
func extByTypeForTest(t *testing.T, p *Profile, t0 uint16) Extension {
	t.Helper()
	e, ok := extByType(p, t0)
	if !ok {
		t.Fatalf("扩展 %d 不存在", t0)
	}
	return e
}
