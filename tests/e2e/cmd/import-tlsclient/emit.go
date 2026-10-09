// emit.go：import-tlsclient 的导入生成半（T5.5）。
//
// 把提取到的"整族缺失"条目转成 geektls 预设（grade=E3），并落一份快照 JSON
// 供 provenance 守门（core/profiles/provenance_test.go::TestE3SourceTraceable）
// 追溯 _const——该守门要求 `source = "<数据集>/<常量名>"` 里的常量必须能在
// profiles/evidence/thirdparty/<数据集>.json 的快照里找到，所以快照与预设必须
// 同一次生成、同源。
//
// 证据纪律（与 import-tlsconfig 同口径）：
//   - 同名跳过（我们的自测优先）；PSK 变体按约定跳过；
//   - source 的"常量名"取自上游 profiles.go 的 MappedTLSClients **变量名**
//     （AST 解析，机器可验证，不是手抄）；
//   - 上游没给的信息不臆造（缺 HTTP/2 就不写 http2 节，不套用家族默认）；
//   - 生成前对每条预设走一遍 tlscore.CompileDetail（能编译才算过）。
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

const datasetName = "tls-client-master" // source 前缀：<数据集>/<常量名>

// upstreamConsts 解析快照的 profiles.go，取 MappedTLSClients 的
// key → 变量名映射（_const 的可追溯标识；重复 key 取首次出现）。
func upstreamConsts(srcDir string) (map[string]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(srcDir, "profiles.go"), nil, 0)
	if err != nil {
		return nil, fmt.Errorf("解析上游 profiles.go: %w", err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if name.Name != "MappedTLSClients" || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				keyLit, ok := kv.Key.(*ast.BasicLit)
				if !ok || keyLit.Kind != token.STRING {
					continue
				}
				ident, ok := kv.Value.(*ast.Ident)
				if !ok {
					continue // 表达式（如函数调用）：无法静态追溯，跳过
				}
				k := strings.Trim(keyLit.Value, `"`)
				if _, dup := out[k]; !dup {
					out[k] = ident.Name
				}
			}
		}
		return true
	})
	if len(out) == 0 {
		return nil, fmt.Errorf("在上游 profiles.go 里没解析到 MappedTLSClients 条目")
	}
	return out, nil
}

// emitPresets 生成"整族缺失"条目的 E3 预设 + 落快照。dry 只打印不落盘。
func emitPresets(items []outItem, srcDir, outDir, snapPath string, dry bool) {
	consts, err := upstreamConsts(srcDir)
	fatalIf(err)

	ours := map[string]bool{}
	for _, n := range profiles.List() {
		ours[n] = true
	}
	haveFam := map[string]bool{}
	for n := range ours {
		haveFam[fam(n)] = true
	}

	// 选材：整族缺失 + 非 PSK + 提取无错 + 有变量名可追溯。
	var picks []outItem
	skipped := map[string]string{}
	for _, it := range items {
		if isPSKVariant(it.Key) {
			skipped[it.Key] = "PSK 变体（按约定跳过）"
			continue
		}
		if ours[it.Key] {
			skipped[it.Key] = "同名已在 builtin（自测优先）"
			continue
		}
		if haveFam[fam(it.Key)] {
			skipped[it.Key] = "同族已覆盖（非整族缺失；命名差异见差集报告的 ≈ 提示）"
			continue
		}
		if it.Err != "" {
			skipped[it.Key] = "提取失败: " + it.Err
			continue
		}
		if _, ok := consts[it.Key]; !ok {
			skipped[it.Key] = "上游 profiles.go 里找不到变量名（无法追溯 source）"
			continue
		}
		picks = append(picks, it)
	}
	sort.Slice(picks, func(i, j int) bool { return picks[i].Key < picks[j].Key })

	fmt.Printf("== 导入生成：候选 %d 条（整族缺失且可追溯）；跳过 %d 条 ==\n\n",
		len(picks), len(skipped))

	type snapEntry struct {
		Const string `json:"_const"`
	}
	snapshot := map[string]snapEntry{}
	var generated, failed []string
	var warns []string

	for _, it := range picks {
		p, w := buildPreset(it, consts[it.Key])
		warns = append(warns, w...)
		if err := selfValidate(p); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", it.Key, err))
			continue
		}
		generated = append(generated, it.Key)
		snapshot[it.Key] = snapEntry{Const: consts[it.Key]}

		if dry {
			fmt.Printf("  [dry] %-28s → %s.json（const=%s，扩展 %d，cipher %d）\n",
				it.Key, it.Key, consts[it.Key], len(p.TLS.Detail.Extensions), len(p.TLS.Detail.Ciphers))
			continue
		}
		if err := writePreset(outDir, p); err != nil {
			fatalIf(err)
		}
	}

	if !dry {
		if len(snapshot) > 0 {
			b, err := json.MarshalIndent(snapshot, "", "  ")
			fatalIf(err)
			fatalIf(os.WriteFile(snapPath, append(b, '\n'), 0o644))
		}
	}

	fmt.Printf("\n生成 %d 条 E3 预设%s\n", len(generated), map[bool]string{true: "（dry）", false: ""}[dry])
	if !dry && len(generated) > 0 {
		fmt.Printf("预设目录：%s\n快照：%s（%d 条 _const，供 TestE3SourceTraceable 追溯）\n",
			outDir, snapPath, len(snapshot))
	}
	if len(failed) > 0 {
		fmt.Printf("\n!! 编译失败 %d 条：\n", len(failed))
		for _, f := range failed {
			fmt.Printf("  %s\n", f)
		}
	}
	if len(warns) > 0 {
		fmt.Printf("\n提示（%d）：\n", len(warns))
		for _, w := range warns {
			fmt.Printf("  %s\n", w)
		}
	}
	if len(skipped) > 0 {
		fmt.Printf("\n跳过明细：\n")
		keys := make([]string, 0, len(skipped))
		for k := range skipped {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-28s %s\n", k, skipped[k])
		}
	}
}

// buildPreset 把一条提取结果构造为 E3 预设；返回"补了什么/为何留空"的提示。
func buildPreset(it outItem, constant string) (*profiles.Profile, []string) {
	var w []string

	d := &profiles.Detail{
		LegacyVersion: "0x0303",
		Ciphers:       append([]string(nil), it.Ciphers...),
		Extensions:    append([]profiles.Extension(nil), it.Extensions...),
	}
	// 与 import-tlsconfig 同口径：声明 TLS1.3 的预设必须有 pre_shared_key(41)
	// 占位——否则启用会话复用、命中票据时 uTLS 会 panic（守门见 presets_test
	// 的 TestPresetCarriesPskPlaceholder）。
	if advertisesTLS13(d) && !hasExtType(d, 41) {
		d.Extensions = append(d.Extensions, profiles.Extension{Type: 41})
		w = append(w, it.Key+": 声明 TLS1.3 但上游无 41 ⇒ 补空占位（uTLS 复用安全）")
	}
	// 上游 Chromium 系运行时洗牌（RandomExtensionOrder）；我们把它表达为
	// extension_permutation——这是"上游的运行时行为"，不含额外猜测。
	// Firefox/App 系不洗牌，保持精确顺序。
	if strings.Contains(strings.ToLower(it.Client), "chrome") ||
		strings.Contains(strings.ToLower(it.Client), "brave") ||
		strings.Contains(strings.ToLower(it.Client), "opera") ||
		strings.Contains(strings.ToLower(it.Client), "edge") {
		d.ExtensionPermutation = true
	}

	p := &profiles.Profile{
		Name:   it.Key,
		Grade:  "E3",
		Source: datasetName + "/" + constant,
		TLS:    &profiles.TLSProfile{Detail: d},
	}

	if len(it.Settings) > 0 {
		p.HTTP2 = &profiles.HTTP2Profile{
			Settings:          append([][]uint32(nil), it.Settings...),
			PseudoHeaderOrder: pseudoOrder(it.Pseudo),
		}
		if it.ConnectionFlow != nil {
			flow := *it.ConnectionFlow
			p.HTTP2.WindowUpdate = &flow
		}
	} else {
		w = append(w, it.Key+": 上游未定义 HTTP/2 settings ⇒ 不写 http2 节（不套家族默认）")
	}
	// 上游 ConnectionFlow/pseudo 缺失时同样不臆造（上面分支已覆盖 settings 缺失的
	// 主要情况；有 settings 但 flow 缺失则窗口更新留 nil，由引擎补族默认）。
	return p, w
}

func selfValidate(p *profiles.Profile) error {
	spec, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		return err
	}
	if len(spec.Extensions) == 0 {
		return fmt.Errorf("编译出的 spec 为空")
	}
	return nil
}

func writePreset(dir string, p *profiles.Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, p.Name+".json"), append(b, '\n'), 0o644)
}

// advertisesTLS13：supported_versions(43) 里是否含 TLS1.3(0x0304)。
func advertisesTLS13(d *profiles.Detail) bool {
	for _, e := range d.Extensions {
		if e.Type != 43 {
			continue
		}
		for _, v := range e.Versions {
			if strings.EqualFold(v, "0x0304") {
				return true
			}
		}
	}
	return false
}

func hasExtType(d *profiles.Detail, t uint16) bool {
	for _, e := range d.Extensions {
		if e.Type == t {
			return true
		}
	}
	return false
}

// pseudoCode/pseudoOrder：既有预设的伪头惯例是缩写 m/a/s/p（与
// import-tlsconfig 同表）；上游给的是全名，照惯例转换（未识别的丢弃，
// 不臆造）。
var pseudoCode = map[string]string{":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}

func pseudoOrder(in []string) []string {
	out := make([]string, 0, 4)
	for _, p := range in {
		if c, ok := pseudoCode[p]; ok {
			out = append(out, c)
		}
	}
	return out
}
