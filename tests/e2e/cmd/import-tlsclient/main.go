// Command import-tlsclient 从上游 tls-client@master 的 profiles 源码快照做两件事
// （T5.5；开工前置已就位：完整 7 文件在
// profiles/evidence/thirdparty/tls-client-master-profiles/）：
//
//  1. 差集报告（默认）：提取上游全部 ClientProfile → 与 builtin 对比 → 三节报告；
//  2. 导入生成（-emit）：把"整族缺失"的条目转成 geektls 预设（E3）+ 落一份
//     快照 JSON（供 provenance 守门 TestE3SourceTraceable 追溯 _const）。
//
// 原理：**编译式提取**，不是 AST 解析——把快照源文件复制到临时目录、把两处
// import（bogdanfinn/utls、bogdanfinn/fhttp）改写为我们的 in-tree fork、搭一个
// 临时 module（replace 指向本仓库 core），然后 go run 一个桥程序**真实调用**
// GetClientHelloSpec() 并输出结构化 JSON（含我们的 profiles.Extension 序列）。
//
// 为什么不能 AST 解析：profile 定义里大量使用函数字面量（SpecFactory）与常量
// 引用（tls.TLS_AES_128_GCM_SHA256、http2.SettingHeaderTableSize…），静态求值
// 做不到；真编译是唯一可靠路径（兼容性探针已验证：7 文件对 in-tree fork 直接
// 编译通过，2026-10-08）。
//
// 证据纪律：
//   - 只读快照、快照源码保持原样（改写只发生在临时目录）；
//   - 生成的预设带 `grade: "E3"`（第三方，未经我们实测）与
//     `source: "tls-client-master/<上游变量名>"`（变量名由 AST 解出，保证
//     provenance 守门能回到快照）；
//   - 与 builtin 同名的条目一律跳过（我们的自测优先）；PSK 变体按约定跳过；
//   - 上游没给的信息不臆造（缺 HTTP/2 节就不写，不套家族默认）。
//
// 用法：
//
//	go run ./cmd/import-tlsclient                        # 差集报告
//	go run ./cmd/import-tlsclient -emit -dry             # 预演导入生成
//	go run ./cmd/import-tlsclient -emit                  # 落盘预设 + 快照
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/geekbyter/geektls/core/profiles"
)

const (
	defaultSrcDir  = "../../profiles/evidence/thirdparty/tls-client-master-profiles"
	defaultCoreDir = "../../core"
	defaultOutDir  = "../../core/profiles/builtin"
	// 快照名即 provenance 的"数据集"名（datasetName）；TestE3SourceTraceable 会在
	// profiles/evidence/thirdparty/<dataset>.json 里核对 _const——两者必须一致，
	// 否则守门报"数据集没有对应快照"。
	snapshotPath = "../../profiles/evidence/thirdparty/tls-client-master.json"
)

// bridgeSrc 是注入临时 module 的桥程序源码。它 import 我们的 core（临时 module
// 已 require）直接把上游 spec 转成 profiles.Extension 序列。
//
// 注意：这里是 Go 原始字符串，**不能出现反引号**（结构体标签），所以桥程序一律
// 用 map[string]any 构造输出，不带 JSON 标签。
const bridgeSrc = `package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"

	tls "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"

	"github.com/geekbyter/geektls/core/profiles"

	tcprofiles "tcprofiles/profiles"
)

func hex16(v uint16) string { return fmt.Sprintf("0x%04x", v) }

// extToOurs 把上游（=我们的 in-tree fork 同源）扩展对象转成 profiles.Extension。
// 未知类型返回错误：E3 导入宁可少一条，不可静默丢形状。
func extToOurs(e tls.TLSExtension) (profiles.Extension, error) {
	switch x := e.(type) {
	case *tls.SNIExtension:
		return profiles.Extension{Type: 0, SNI: "auto"}, nil
	case *tls.StatusRequestExtension:
		return profiles.Extension{Type: 5, Data: "0100000000"}, nil
	case *tls.SupportedCurvesExtension:
		var g []string
		for _, c := range x.Curves {
			g = append(g, hex16(uint16(c)))
		}
		return profiles.Extension{Type: 10, Groups: g}, nil
	case *tls.SupportedPointsExtension:
		return profiles.Extension{Type: 11, PointFormats: append([]uint8(nil), x.SupportedPoints...)}, nil
	case *tls.SignatureAlgorithmsExtension:
		var s []string
		for _, a := range x.SupportedSignatureAlgorithms {
			s = append(s, hex16(uint16(a)))
		}
		return profiles.Extension{Type: 13, SigAlgs: s}, nil
	case *tls.ALPNExtension:
		return profiles.Extension{Type: 16, ALPN: append([]string(nil), x.AlpnProtocols...)}, nil
	case *tls.SCTExtension:
		return profiles.Extension{Type: 18}, nil
	case *tls.ExtendedMasterSecretExtension:
		return profiles.Extension{Type: 23}, nil
	case *tls.UtlsCompressCertExtension:
		var names []string
		for _, a := range x.Algorithms {
			switch a {
			case tls.CertCompressionZlib:
				names = append(names, "zlib")
			case tls.CertCompressionBrotli:
				names = append(names, "brotli")
			case tls.CertCompressionZstd:
				names = append(names, "zstd")
			default:
				return profiles.Extension{}, fmt.Errorf("unknown cert compression %v", a)
			}
		}
		return profiles.Extension{Type: 27, CertCompression: names}, nil
	case *tls.FakeRecordSizeLimitExtension:
		return profiles.Extension{Type: 28, Data: hex.EncodeToString([]byte{byte(x.Limit >> 8), byte(x.Limit)})}, nil
	case *tls.SessionTicketExtension:
		return profiles.Extension{Type: 35}, nil
	case *tls.UtlsPreSharedKeyExtension:
		return profiles.Extension{Type: 41}, nil
	case *tls.SupportedVersionsExtension:
		var v []string
		for _, ver := range x.Versions {
			v = append(v, hex16(ver))
		}
		return profiles.Extension{Type: 43, Versions: v}, nil
	case *tls.PSKKeyExchangeModesExtension:
		return profiles.Extension{Type: 45, PSKModes: append([]uint8(nil), x.Modes...)}, nil
	case *tls.SignatureAlgorithmsCertExtension:
		var s []string
		for _, a := range x.SupportedSignatureAlgorithms {
			s = append(s, hex16(uint16(a)))
		}
		return profiles.Extension{Type: 50, SigAlgs: s}, nil
	case *tls.KeyShareExtension:
		var k []string
		for _, ks := range x.KeyShares {
			k = append(k, hex16(uint16(ks.Group)))
		}
		return profiles.Extension{Type: 51, KeyShares: k}, nil
	case *tls.UtlsGREASEExtension:
		// GREASE 占位：Value=0 是 uTLS 的"运行时再挑一个"零值——我们表达为
		// 0x0a0a（合法 0x?a?a 值）+ grease_random（线上每连接重取）。
		v := x.Value
		if v == 0 {
			v = 0x0a0a
		}
		return profiles.Extension{Type: v, GreaseRandom: true}, nil
	case *tls.GREASEEncryptedClientHelloExtension:
		return profiles.Extension{Type: 65037, ECH: &profiles.ECHConfig{Mode: "grease"}}, nil
	case *tls.ApplicationSettingsExtension:
		return profiles.Extension{Type: 17513, ALPN: append([]string(nil), x.SupportedProtocols...)}, nil
	case *tls.ApplicationSettingsExtensionNew:
		return profiles.Extension{Type: 17613, ALPN: append([]string(nil), x.SupportedProtocols...)}, nil
	case *tls.FakeDelegatedCredentialsExtension:
		var s []string
		for _, a := range x.SupportedSignatureAlgorithms {
			s = append(s, hex16(uint16(a)))
		}
		return profiles.Extension{Type: 34, SigAlgs: s}, nil
	case *tls.RenegotiationInfoExtension:
		// 65281（renegotiation_info）：负载 = u8 长度 + renegotiated_connection。
		// 首访形态为空（长度 0x00），与既有预设的 "data": "00" 一致。
		return profiles.Extension{Type: 65281, Data: "00"}, nil
	case *tls.UtlsPaddingExtension:
		// 21（padding）：上游 profiles 一律用 BoringPaddingStyle（对齐到 512）——
		// 用函数指针相等来**验证**，而不是"假设它是 Boring"。
		if x.GetPaddingLen != nil &&
			reflect.ValueOf(x.GetPaddingLen).Pointer() == reflect.ValueOf(tls.BoringPaddingStyle).Pointer() {
			return profiles.Extension{Type: 21, PaddingTo: 512}, nil
		}
		if x.PaddingLen > 0 {
			return profiles.Extension{Type: 21, PaddingLen: int(x.PaddingLen)}, nil
		}
		return profiles.Extension{}, fmt.Errorf("unsupported padding style (not BoringPaddingStyle)")
	case *tls.GenericExtension:
		return profiles.Extension{Type: x.Id, Data: hex.EncodeToString(x.Data)}, nil
	}
	return profiles.Extension{}, fmt.Errorf("unsupported extension %T", e)
}

func main() {
	keys := make([]string, 0, len(tcprofiles.MappedTLSClients))
	for k := range tcprofiles.MappedTLSClients {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		pr := tcprofiles.MappedTLSClients[k]
		id := pr.GetClientHelloId()
		it := map[string]any{"key": k, "client": id.Client, "version": id.Version}

		spec, err := pr.GetClientHelloSpec()
		if err != nil {
			it["err"] = err.Error()
			out = append(out, it)
			continue
		}
		ciphers := []string{}
		for _, c := range spec.CipherSuites {
			ciphers = append(ciphers, hex16(c))
		}
		it["ciphers"] = ciphers

		exts := []profiles.Extension{}
		goTypes := []string{}
		for _, e := range spec.Extensions {
			goTypes = append(goTypes, fmt.Sprintf("%T", e))
			ours, err := extToOurs(e)
			if err != nil {
				it["err"] = err.Error()
				break
			}
			exts = append(exts, ours)
		}
		it["ext_go_types"] = goTypes
		if _, bad := it["err"]; bad {
			out = append(out, it)
			continue
		}
		it["extensions"] = exts

		vals := pr.GetSettings()
		settings := [][]uint32{}
		for _, sid := range pr.GetSettingsOrder() {
			if v, ok := vals[sid]; ok {
				settings = append(settings, []uint32{uint32(sid), v})
			}
		}
		if len(settings) > 0 {
			it["settings"] = settings
		}
		if f := pr.GetConnectionFlow(); f != 0 {
			it["connection_flow"] = f
		}
		if sid := pr.GetStreamID(); sid != 0 {
			it["stream_id"] = sid
		}
		if ph := pr.GetPseudoHeaderOrder(); len(ph) > 0 {
			it["pseudo_header_order"] = ph
		}
		out = append(out, it)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`

// outItem 与桥程序的输出结构保持一致（桥程序用 map 构造，主工具用带标签的
// struct 解析——struct 在本文件里，标签不受原始字符串限制）。
type outItem struct {
	Key            string               `json:"key"`
	Client         string               `json:"client"`
	Version        string               `json:"version"`
	Ciphers        []string             `json:"ciphers"`
	Extensions     []profiles.Extension `json:"extensions"`
	ExtGoTypes     []string             `json:"ext_go_types,omitempty"`
	Settings       [][]uint32           `json:"settings,omitempty"`
	ConnectionFlow *uint32              `json:"connection_flow,omitempty"`
	StreamID       uint32               `json:"stream_id,omitempty"`
	Pseudo         []string             `json:"pseudo_header_order,omitempty"`
	Err            string               `json:"err,omitempty"`
}

func main() {
	srcDir := flag.String("src", defaultSrcDir, "上游 profiles 源码快照目录")
	coreDir := flag.String("core", defaultCoreDir, "in-tree core 模块目录")
	outDir := flag.String("out", defaultOutDir, "预设输出目录（-emit 时生效）")
	emit := flag.Bool("emit", false, "导入生成：把整族缺失条目转成 E3 预设 + 落快照")
	dry := flag.Bool("dry", false, "预演（不落盘）")
	jsonOut := flag.String("json", "", "附写提取明细到该文件（调试用）")
	flag.Parse()

	absSrc, err := filepath.Abs(*srcDir)
	fatalIf(err)
	absCore, err := filepath.Abs(*coreDir)
	fatalIf(err)
	absOut, err := filepath.Abs(*outDir)
	fatalIf(err)
	absSnap, err := filepath.Abs(snapshotPath)
	fatalIf(err)

	items, err := extract(absSrc, absCore)
	fatalIf(err)
	fmt.Printf("上游 profile 提取完成：%d 条\n\n", len(items))

	if *jsonOut != "" {
		b, err := json.MarshalIndent(items, "", " ")
		fatalIf(err)
		fatalIf(os.WriteFile(*jsonOut, b, 0o644))
		fmt.Printf("机器可读明细已写入 %s\n\n", *jsonOut)
	}

	if *emit {
		emitPresets(items, absSrc, absOut, absSnap, *dry)
		return
	}
	report(items)
}

// extract 搭临时 module（改写 import + replace 到本地 core）并运行桥程序，
// 返回上游每一条 profile 的结构化提取结果。
func extract(absSrc, absCore string) ([]outItem, error) {
	files, err := filepath.Glob(filepath.Join(absSrc, "*.go"))
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("快照目录没有 .go 文件: %s", absSrc)
	}

	work, err := os.MkdirTemp("", "tlsclient-prof-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	profDir := filepath.Join(work, "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		s := string(b)
		s = strings.ReplaceAll(s,
			"github.com/bogdanfinn/utls",
			"github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn")
		s = strings.ReplaceAll(s,
			"github.com/bogdanfinn/fhttp",
			"github.com/geekbyter/geektls/core/third_party/fhttp")
		if err := os.WriteFile(filepath.Join(profDir, filepath.Base(f)), []byte(s), 0o644); err != nil {
			return nil, err
		}
	}

	gomod := fmt.Sprintf(`module tcprofiles

go 1.27.0

require github.com/geekbyter/geektls/core v0.0.0

replace github.com/geekbyter/geektls/core => %s
`, absCore)
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte(gomod), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(work, "main.go"), []byte(bridgeSrc), 0o644); err != nil {
		return nil, err
	}

	if out, err := run(work, "go", "mod", "tidy"); err != nil {
		return nil, fmt.Errorf("go mod tidy: %v\n%s", err, out)
	}
	out, err := run(work, "go", "run", ".")
	if err != nil {
		return nil, fmt.Errorf("桥程序运行失败: %v\n%s", err, out)
	}

	var items []outItem
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil, fmt.Errorf("解析桥程序输出: %v\n输出前 500 字节:\n%.500s", err, out)
	}
	return items, nil
}

func run(dir string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var sb strings.Builder
	cmd.Stdout = &sb
	cmd.Stderr = &sb
	err := cmd.Run()
	return sb.String(), err
}

func fam(name string) string {
	if i := strings.Index(name, "_"); i > 0 {
		return name[:i]
	}
	return name
}

// isPSKVariant 判断 PSK 变体（按 docs/08 §E 约定永久跳过：我们的建模 =
// 空占位 + 无票据省略，不需要单独预设）。
func isPSKVariant(k string) bool {
	return strings.HasSuffix(k, "_PSK") || strings.Contains(k, "_PSK_")
}

// report 把上游条目与 builtin 做差集，输出三节：整族缺失 / 同族新增 / 已命中。
func report(upstream []outItem) {
	ours := map[string]bool{}
	for _, n := range profiles.List() {
		ours[n] = true
	}
	haveFam := map[string]bool{}
	for n := range ours {
		haveFam[fam(n)] = true
	}

	var wholeMissing, sameFamNew, hit []outItem
	for _, it := range upstream {
		if isPSKVariant(it.Key) {
			it.Err = "（PSK 变体，按约定跳过）"
			sameFamNew = append(sameFamNew, it)
			continue
		}
		switch {
		case ours[it.Key]:
			hit = append(hit, it)
		case !haveFam[fam(it.Key)]:
			wholeMissing = append(wholeMissing, it)
		default:
			sameFamNew = append(sameFamNew, it)
		}
	}

	// 模糊命中：builtin 里名为 "<key>_<后缀>"（平台/变体）的条目——上游 key 无
	// 平台后缀，直接名字对比会把"其实已有"的（如 chrome_117 vs
	// chrome_117_windows）误报为缺失（plan 里点过的坑）。
	approx := map[string][]string{}
	for n := range ours {
		for _, it := range upstream {
			if strings.HasPrefix(n, it.Key+"_") {
				approx[it.Key] = append(approx[it.Key], n)
			}
		}
	}
	for k := range approx {
		sort.Strings(approx[k])
	}

	fmt.Printf("builtin 预设：%d 条；上游注册：%d 条\n\n", len(ours), len(upstream))

	fmt.Printf("== A. 整族缺失（上游家族在 builtin 无任何条目）：%d 条 ==\n", len(wholeMissing))
	for _, it := range wholeMissing {
		fmt.Printf("  %-28s %s/%s  扩展 %d 项%s\n",
			it.Key, it.Client, it.Version, len(it.Extensions), errSuffix(it))
	}

	fmt.Printf("\n== B. 同族新增/变体（家族已覆盖，具体条目缺失）：%d 条 ==\n", len(sameFamNew))
	for _, it := range sameFamNew {
		hint := ""
		if a := approx[it.Key]; len(a) > 0 {
			hint = "  ≈ " + strings.Join(a, ", ")
		}
		fmt.Printf("  %-28s %s/%s  扩展 %d 项%s%s\n",
			it.Key, it.Client, it.Version, len(it.Extensions), errSuffix(it), hint)
	}

	fmt.Printf("\n== C. 已命中（builtin 同名）：%d 条 ==\n", len(hit))
	names := make([]string, 0, len(hit))
	for _, it := range hit {
		names = append(names, it.Key)
	}
	sort.Strings(names)
	for i, n := range names {
		if i%4 == 0 {
			fmt.Print("  ")
		}
		fmt.Printf("%-28s", n)
		if i%4 == 3 {
			fmt.Println()
		}
	}
	if len(names)%4 != 0 {
		fmt.Println()
	}

	var failed []outItem
	for _, it := range upstream {
		if it.Err != "" && !strings.Contains(it.Err, "PSK 变体") {
			failed = append(failed, it)
		}
	}
	if len(failed) > 0 {
		fmt.Printf("\n== D. spec 提取/转换失败：%d 条 ==\n", len(failed))
		for _, it := range failed {
			fmt.Printf("  %-28s %s\n", it.Key, it.Err)
		}
	}
}

func errSuffix(it outItem) string {
	if it.Err == "" {
		return ""
	}
	return "  [" + it.Err + "]"
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}
