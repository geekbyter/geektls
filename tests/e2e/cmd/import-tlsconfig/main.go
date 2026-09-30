// Command import-tlsconfig 把第三方指纹集（tls_config-0.0.2）导入为 geektls 预设。
//
// 设计原则（与本项目的证据纪律一致）：
//
//  1. **不覆盖**：与现有入库预设**同名**的条目一律跳过（我们的自测优先），但会做
//     **结构对拍**并写进报告——这才是第三方数据的最大价值（交叉校验）。
//  2. **可追溯**：导入的预设带 `grade: "E3"`（第三方配置集，非本机实测）与
//     `source: "<数据集>/<常量名>"`（默认数据集名见 `defaultSource`，`-source` 可换）；
//     所有 E1 级断言据此跳过 E3。**换来源必须同时换 -source**，否则这个字段说谎。
//  3. **不臆造**：第三方没给的信息（ECH 负载、padding 长度、UA-CH 取值…）要么用**我们
//     已实测**的族级取值补、要么留空并记进报告，逐条列出"补了什么/为什么"。
//  4. **可复现**：输入是 dump.py 产出的 JSON 快照（入库），本工具是纯转换。
//
// 用法：
//
//	go run ./cmd/import-tlsconfig -in ../../profiles/evidence/thirdparty/tls_config-0.0.2.json \
//	    -out ../../core/profiles/builtin -dry
//	# 另一批快照（如上游 master 的其余族）：-source tls_config-master —— 不带这个
//	# 参数就会把新来源写成 tls_config-0.0.2，provenance 守门（provenance_test.go）看不出来。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	http2 "github.com/bogdanfinn/fhttp/http2"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// ---------- 第三方数据模型（只取用得到的字段）----------

type cfg struct {
	Const             string   `json:"_const"`
	ID                string   `json:"id"`
	JA3               string   `json:"ja3"`
	RandomJA3         bool     `json:"random_ja3"`
	HeadersOrder      []string `json:"headers_order"`
	ForceHTTP1        bool     `json:"force_http1"`
	PseudoHeaderOrder []string `json:"pseudo_header_order"`
	UA                string   `json:"user_agent"`

	TLS struct {
		SigAlgs         []string `json:"supported_signature_algorithms"`
		CertCompression []string `json:"cert_compression_algo"`
		RecordSizeLimit *uint32  `json:"record_size_limit"`
		Delegated       []string `json:"supported_delegated_credentials_algorithms"`
		Versions        []string `json:"supported_versions"`
		PSKModes        []string `json:"psk_key_exchange_modes"`
		SigAlgsCert     []string `json:"signature_algorithms_cert"`
		KeyShareCurves  []string `json:"key_share_curves"`
		NotUsedGrease   bool     `json:"not_used_grease"`
		ClientHelloHex  string   `json:"client_hello_hex_stream"`
	} `json:"tls_extensions"`

	H2 struct {
		Settings map[string]uint32 `json:"settings"`
		Order    []string          `json:"settings_order"`
		// Flow 保留原始 JSON：键缺失 / null / 数字是三件事，A11 之后 schema 能表达
		// "明确不发"（0）与"未指定"（nil），所以不能再用 uint32 把 null 读成 0。
		Flow           json.RawMessage `json:"connection_flow"`
		HeadersID      *uint32         `json:"headers_id"`
		SettingsAck    bool            `json:"settings_ack"`
		HeaderPriority *struct {
			Weight    uint32 `json:"weight"`
			StreamDep uint32 `json:"streamDep"`
			Exclusive bool   `json:"exclusive"`
		} `json:"header_priority"`
		PriorityFrames []json.RawMessage `json:"priority_frames"`
	} `json:"http2_settings"`
}

// ---------- 映射表 ----------

var sigAlgHex = map[string]string{
	"ecdsa_secp256r1_sha256": "0x0403",
	"ecdsa_secp384r1_sha384": "0x0503",
	"ecdsa_secp521r1_sha512": "0x0603",
	"rsa_pss_rsae_sha256":    "0x0804",
	"rsa_pss_rsae_sha384":    "0x0805",
	"rsa_pss_rsae_sha512":    "0x0806",
	"rsa_pkcs1_sha256":       "0x0401",
	"rsa_pkcs1_sha384":       "0x0501",
	"rsa_pkcs1_sha512":       "0x0601",
	"ecdsa_sha1":             "0x0203",
	"rsa_pkcs1_sha1":         "0x0201",
	"rsa_pss_pss_sha256":     "0x0809",
	"rsa_pss_pss_sha384":     "0x080a",
	"rsa_pss_pss_sha512":     "0x080b",
	"ed25519":                "0x0807",
	"ed448":                  "0x0808",
	"dsa_sha1":               "0x0202",
	"dsa_sha256":             "0x0402",
	"dsa_sha384":             "0x0602",
}

var h2SettingID = map[string]uint16{
	"HEADER_TABLE_SIZE":       1,
	"ENABLE_PUSH":             2,
	"MAX_CONCURRENT_STREAMS":  3,
	"INITIAL_WINDOW_SIZE":     4,
	"MAX_FRAME_SIZE":          5,
	"MAX_HEADER_LIST_SIZE":    6,
	"ENABLE_CONNECT_PROTOCOL": 8,
	"NO_RFC7540_PRIORITIES":   9,
}

var versionHex = map[string]string{"1.3": "0x0304", "1.2": "0x0303", "1.1": "0x0302", "1.0": "0x0301"}

// chromiumLike：Chromium/BoringSSL 形态约定（GREASE 位置、UA-CH、洗牌）。
var chromiumLike = map[string]bool{
	"chrome": true, "edge": true, "opera": true, "opr": true,
	"wechat": true, "ucbrowser": true, "qqbrowser": true, "mqqbrowser": true,
	"quarkpc": true, "miuibrowser": true, "huaweibrowser": true, "vivobrowser": true,
	"heytapbrowser": true, "samsungbrowser": true, "yabrowser": true, "slbrowser": true,
	"goldbrowser": true, "bdhonorbrowser": true, "baiduboxapp": true, "mzbrowser": true,
}

// measuredIdentity：我们有 E1 实测身份模板的族（其余族只给 UA，不编头）。
var measuredIdentity = map[string]bool{"chrome": true, "edge": true, "firefox": true, "safari": true}

// ---------- 主流程 ----------

type report struct {
	imported, skipped, warns, sups []string
	cross                          []string
}

// defaultSource 是本快照的数据集名。provenance 的 source 字段格式是
// "<数据集>/<常量名>"（见文件头设计原则 2），E1 级断言据此识别 E3。
// 换数据来源必须同时改这里或用 -source 传，否则 source 会指向不存在的数据集
// ——那是整个证据分级体系的地基，不能让一个默认值替新来源撒谎。
const defaultSource = "tls_config-0.0.2"

func main() {
	in := flag.String("in", "", "tls_config 导出的 JSON 快照")
	out := flag.String("out", "", "输出目录（core/profiles/builtin）")
	src := flag.String("source", defaultSource, "provenance 的 source 前缀（<前缀>/<常量名>）")
	dry := flag.Bool("dry", false, "只打印，不落盘")
	flag.Parse()

	source := strings.TrimSuffix(*src, "/")
	if source == "" {
		must(fmt.Errorf("-source 不能为空：预设的 provenance.source 会变成 \"/<常量名>\"，无法追溯"))
	}

	raw, err := os.ReadFile(*in)
	must(err)
	var all map[string]cfg
	must(json.Unmarshal(raw, &all))

	existing := loadExistingGrades(*out)
	h3Block := loadChromiumH3Block(*out)

	// 去重：同一 id 的多个常量（别名）只保留一个。
	byID := map[string]cfg{}
	for _, c := range all {
		prev, ok := byID[c.ID]
		if !ok || betterName(c.Const, prev.Const) {
			byID[c.ID] = c
		}
	}
	list := make([]cfg, 0, len(byID))
	for _, c := range byID {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Const < list[j].Const })

	rep := &report{}
	for _, c := range list {
		cn := c.Const
		ni, err := parseName(c.Const)
		if err != nil {
			rep.warns = append(rep.warns, fmt.Sprintf("%s: 跳过（%v）", cn, err))
			continue
		}
		if ni.version == "" {
			rep.warns = append(rep.warns, fmt.Sprintf("%s: 跳过（常量名无版本号，无法推导 UA/UA-CH）", cn))
			continue
		}
		p, warns, sups, err := convert(c, ni, h3Block, source)
		if err != nil {
			rep.warns = append(rep.warns, fmt.Sprintf("%s → %s: 跳过（%v）", cn, ni.preset, err))
			continue
		}
		// 覆盖规则：**E3 可覆盖（管线可重复执行）**；非 E3（我们的自测/手写）一律保留并改做对拍。
		if g, dup := existing[p.Name]; dup && g != "E3" {
			rep.skipped = append(rep.skipped, p.Name)
			if line := crossCheck(*out, p.Name, p); line != "" {
				rep.cross = append(rep.cross, line)
			}
			continue
		}
		if pl := platformless(p.Name); pl != p.Name {
			if g, ok := existing[pl]; ok && g != "E3" {
				rep.skipped = append(rep.skipped, p.Name)
				if line := crossCheck(*out, pl, p); line != "" {
					rep.cross = append(rep.cross, line)
				}
				continue
			}
		}
		if err := selfValidate(p); err != nil {
			rep.warns = append(rep.warns, fmt.Sprintf("%s → %s: 自校验失败（%v）", cn, p.Name, err))
			continue
		}
		rep.warns = append(rep.warns, warns...)
		rep.sups = append(rep.sups, sups...)
		if !*dry {
			must(writePreset(*out, p))
		}
		rep.imported = append(rep.imported, p.Name)
	}

	// 清理：删除本次未产出的 E3 文件（管线可重复执行 ⇒ 不留陈旧预设）。
	if !*dry {
		pruned := pruneStaleE3(*out, rep.imported)
		if len(pruned) > 0 {
			rep.warns = append(rep.warns, fmt.Sprintf("清理陈旧 E3 预设 %d 个：%s", len(pruned), strings.Join(pruned, ", ")))
		}
	}

	fmt.Printf("导入 %d 个；同名跳过（保留入库）%d 个\n", len(rep.imported), len(rep.skipped))
	fmt.Println("\n=== 同名条目结构对拍（第三方 vs 入库）===")
	if len(rep.cross) == 0 {
		fmt.Println("（无同名条目）")
	}
	for _, l := range rep.cross {
		fmt.Println(l)
	}
	fmt.Println("\n=== 补值 / 告警（汇总去重）===")
	seen := map[string]bool{}
	var keys []string
	for _, w := range append(rep.sups, rep.warns...) {
		if !seen[w] {
			seen[w] = true
			keys = append(keys, w)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println(" -", k)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func betterName(a, b string) bool {
	rank := func(s string) int {
		r := 0
		if strings.HasSuffix(s, "_LATEST") {
			r += 10
		}
		if strings.ContainsAny(s, "0123456789") {
			r -= 5
		}
		return r
	}
	return rank(a) < rank(b)
}

// ---------- 常量名解析 ----------

type nameInfo struct {
	family   string // chrome / edge / firefox / safari / opera / wechat ...
	version  string // "131" / "17_3"
	dotted   string // "131" / "17.3"
	major    string // "131" / "17"
	platform string // windows / macos / ios / android / linux / ""
	preset   string // chrome_131 / safari_17_3_macos
}

var platformTokens = map[string]string{
	"WINDOWS": "windows", "WIN": "windows",
	"MACOS": "macos", "MAC_OS": "macos", "MACOSX": "macos", "MAC": "macos",
	"IOS": "ios", "IPHONE": "ios", "IPAD": "ios",
	"ANDROID": "android", "LINUX": "linux", "UBUNTU": "linux",
}

// defaultPlatform：第三方把"该族默认平台"的常量放在不带平台后缀的文件里
// （chrome/windows.py、safari/macos.py 等）。无平台 token 时按族给默认值。
var defaultPlatform = map[string]string{"safari": "macos", "ie": "windows"}

// hpackStrategy 返回该族/平台应当使用的 HPACK 编码策略（T-HPACK，2026-09-28）。
//
// 与 tests/e2e/cmd/gen-profiles/main.go 的同名函数**保持一致**（两个 cmd 各自独立，
// 刻意重复；改一处要同步另一处）。语义与证据分级见 docs/p2-h2-capability.md。
//
// 这里只认"栈归属明确"的族：Chromium 系（chrome/edge/opera/opr/yabrowser）、Firefox、
// Safari（含 iOS —— 那儿所有浏览器都跑 WebKit）。**刻意不跟随 chromiumLike**：微信/UC/
// QQ/夸克/小米/华为等内嵌浏览器的 Chromium fork 各自改过，没有证据就不编；curl/okhttp
// 等工具同理（留空 = 上游 x/net 默认行为）。
//
// 等级：族级继承（E4 推断），不是实测——想让某条升级仍需采样本。
func hpackStrategy(family, platform string) string {
	if platform == "ios" {
		return http2.HpackStrategySafari
	}
	switch family {
	case "chrome", "edge", "opera", "opr", "yabrowser":
		return http2.HpackStrategyChrome
	case "firefox":
		return http2.HpackStrategyFirefox
	case "safari":
		return http2.HpackStrategySafari
	}
	return ""
}

func parseName(constName string) (nameInfo, error) {
	toks := strings.Split(strings.TrimPrefix(constName, "TLS_"), "_")
	if len(toks) < 2 {
		return nameInfo{}, fmt.Errorf("常量名过短")
	}
	fam := strings.ToLower(toks[0])
	if fam == "opr" {
		fam = "opera"
	}
	rest := toks[1:]
	plat := ""
	for i, t := range rest {
		if p, ok := platformTokens[t]; ok {
			plat = p
			rest = rest[:i] // 平台 token 之后的是版本细节（10_15_7/NT_10_0…），丢弃
			break
		}
	}
	ver := strings.Join(rest, "_")
	ver = strings.Trim(strings.ToLower(ver), "_")
	if plat == "" {
		if p, ok := defaultPlatform[fam]; ok {
			plat = p
		} else if fam == "chrome" || fam == "edge" || fam == "firefox" || fam == "opera" {
			plat = "windows"
		}
	}
	if ver == "" {
		return nameInfo{family: fam, platform: plat}, nil
	}
	ni := nameInfo{family: fam, version: ver, dotted: strings.ReplaceAll(ver, "_", "."), major: strings.Split(ver, "_")[0], platform: plat}
	ni.preset = fam + "_" + ver
	if plat != "" {
		ni.preset += "_" + plat
	}
	return ni, nil
}

// ---------- 转换 ----------

func convert(c cfg, ni nameInfo, h3 *profiles.HTTP3Profile, source string) (*profiles.Profile, []string, []string, error) {
	var warns, sups []string
	name := ni.preset
	if c.ForceHTTP1 {
		warns = append(warns, name+": 第三方标记 force_http1（HTTP/1.1 专属），本预设仍按 h2 形态入库")
	}
	if len(c.TLS.SigAlgsCert) > 0 {
		warns = append(warns, name+": signature_algorithms_cert(50) 已按第三方导入")
	}
	if c.H2.SettingsAck {
		warns = append(warns, name+": 第三方标记 settings_ack（我们不发额外 SETTINGS ACK）")
	}
	if len(c.H2.PriorityFrames) > 0 {
		warns = append(warns, fmt.Sprintf("%s: 第三方给了 %d 个独立 PRIORITY 帧（本库 schema 支持但未导入）", name, len(c.H2.PriorityFrames)))
	}

	grease := !c.TLS.NotUsedGrease
	chromium := chromiumLike[ni.family]

	parts := strings.Split(c.JA3, ",")
	if len(parts) != 5 {
		return nil, nil, nil, fmt.Errorf("ja3 字段数 = %d", len(parts))
	}
	ciphers, err := decHexList(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ciphers: %w", err)
	}
	extOrder, err := uint16List(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extensions: %w", err)
	}
	groups, err := decHexList(parts[3])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("groups: %w", err)
	}
	if len(ciphers) == 0 || len(extOrder) == 0 {
		return nil, nil, nil, fmt.Errorf("空 cipher/扩展列表")
	}

	// GREASE：第三方的 ja3 已把 GREASE 归一化掉，这里按 GREASE 位置约定补回
	// （位置来自我们 E1 实测：Chromium/Safari 的 cipher[0]、groups[0]、首尾各一个扩展）。
	if grease {
		if !hasGrease(ciphers) {
			ciphers = append([]string{"grease"}, ciphers...)
		}
		if !hasGrease(groups) {
			groups = append([]string{"grease"}, groups...)
		}
	}

	exts := make([]profiles.Extension, 0, len(extOrder)+3)
	if grease {
		exts = append(exts, profiles.Extension{Type: 0x9a9a, GreaseRandom: true}) // 首位 GREASE（空负载）
	}
	for _, t := range extOrder {
		if t == 41 { // 占位统一放最后
			continue
		}
		e, warn := extFor(t, c, ni, groups, &sups, name)
		if warn != "" {
			warns = append(warns, warn)
		}
		if e != nil {
			exts = append(exts, *e)
		}
	}
	if grease {
		exts = append(exts, profiles.Extension{Type: 0x3a3a, GreaseRandom: true, Data: "00"})
	}
	// pre_shared_key(41) 占位**只在声明 TLS 1.3 时**追加：
	// ① RFC 8446 要求它是最后一个扩展；② 老客户端（如 Safari 9）本不发它，硬加会
	// 让 ClientHello 结构非法（实测：Go 服务端报 "error decoding message"）。
	// ③ 这些不出 41 的预设启用会话复用时，uTLS 会在缓存命中票据时 panic——由
	//    tlscore.Handshake 的 panic→error 兜底 + engine 的丢票回退接住（多一次重试）。
	if advertisesTLS13(c.TLS.Versions) {
		exts = append(exts, profiles.Extension{Type: 41})
	} else {
		sups = append(sups, name+": 不声明 TLS 1.3 ⇒ 不发 pre_shared_key(41) 占位（该预设启用与会话复用时靠 panic 兜底 + 丢票回退）")
	}

	d := &profiles.Detail{LegacyVersion: "0x0303", Ciphers: ciphers, Extensions: exts}
	// 洗牌按**我们实测**的族行为（Chromium 洗牌；Firefox/Safari 不洗牌），
	// 不采纳第三方的 random_ja3——那是它自己的运行时选择，不是浏览器行为。
	if chromium {
		d.ExtensionPermutation = true
	}

	p := &profiles.Profile{
		Name: name, TLS: &profiles.TLSProfile{Detail: d},
		Grade: "E3", Source: source + "/" + c.Const,
	}

	// HTTP/2
	if len(c.H2.Order) > 0 {
		// WindowUpdate 三态（A11）：数字照抄；显式 0 ⇒ 不发连接级 WINDOW_UPDATE；
		// null/缺失 ⇒ 预设留 nil，由引擎补该族默认的 15663105。第三方对老 Safari
		// 写的是 null（不是 0），我们没有该版本的 H2 实测说它"不发"，故按 nil 处理
		// 并逐条登记 —— 不把来源的空白读成一种线上行为。
		flow, flowGiven, ferr := parseFlow(c.H2.Flow)
		if ferr != nil {
			return nil, nil, nil, fmt.Errorf("connection_flow: %w", ferr)
		}
		h2 := &profiles.HTTP2Profile{WindowUpdate: flow, PseudoHeaderOrder: pseudoOrder(c.PseudoHeaderOrder)}
		if !flowGiven {
			warns = append(warns, name+": 第三方 connection_flow 为 null/缺失 ⇒ 预设不指定，线上按引擎默认 15663105 发（该族实测形态）")
		}
		// 首个请求的 stream_id：第三方给的奇数（>1）直接照做；偶数或 ≥2^31 不是
		// 合法客户端流号 ⇒ 忽略并登记（不静默改语义）。
		if id := c.H2.HeadersID; id != nil && *id > 1 {
			if *id%2 == 1 && *id < 1<<31 {
				h2.FirstStreamID = *id
				sups = append(sups, fmt.Sprintf("%s: 首个请求 stream_id=%d（取自第三方 headers_id）", name, *id))
			} else {
				warns = append(warns, fmt.Sprintf("%s: 第三方 headers_id=%d 不是合法客户端流号（须为奇数且 <2^31）⇒ 忽略", name, *id))
			}
		}
		for _, sn := range c.H2.Order {
			id, ok := h2SettingID[sn]
			if !ok {
				if n, ok2 := unknownSettingID(sn); ok2 {
					id = n
				} else {
					warns = append(warns, name+": 未知 H2 setting 名 "+sn+"（丢弃）")
					continue
				}
			}
			h2.Settings = append(h2.Settings, []uint32{uint32(id), c.H2.Settings[sn]})
		}
		if hp := c.H2.HeaderPriority; hp != nil {
			w := uint8(0)
			if hp.Weight >= 1 {
				w = uint8(hp.Weight - 1) // 第三方/peet 的报数 = 线上值 + 1
			}
			h2.HeadersPriority = &profiles.H2HeadersPriority{Exclusive: hp.Exclusive, StreamDep: hp.StreamDep, Weight: w}
		} else {
			warns = append(warns, name+": 第三方未给 HEADERS priority（null）⇒ 该预设不发内嵌 priority")
		}
		// T-HPACK：第三方只给 JA3 与 H2 设置，不给 HPACK 编码策略 ⇒ 按族/平台映射补；
		// 归不了族的族一律留空（= 上游默认行为），理由见下面的函数注释。
		h2.HpackStrategy = hpackStrategy(ni.family, ni.platform)
		p.HTTP2 = h2
	} else {
		warns = append(warns, name+": 第三方无 H2 settings ⇒ 不出 http2 节")
	}

	// 身份头
	id, iw, is := identity(c, ni, name)
	warns = append(warns, iw...)
	sups = append(sups, is...)
	p.Identity = id

	// H3：Chromium 系必须有 http3 节（缺节会让 H3 侧露通用 Go 客户端）；第三方集无 QUIC
	// 数据 ⇒ 借我们已入库的 Chromium 实测参数并标注。
	if chromium && h3 != nil {
		p.HTTP3 = h3
		sups = append(sups, name+": http3 节借自我们已入库的 Chromium 实测（第三方集不含 QUIC 数据）")
	}
	return p, warns, sups, nil
}

// parseFlow 解析第三方 connection_flow。第二个返回值区分"给了数"与
// "null/缺失"：后者不能读成 0（0 在线上意味着"不发连接级 WINDOW_UPDATE"）。
func parseFlow(raw json.RawMessage) (*uint32, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	var v uint32
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false, err
	}
	return &v, true, nil
}

func unknownSettingID(name string) (uint16, bool) {
	if strings.HasPrefix(name, "UNKNOWN_SETTING_") {
		n, err := strconv.Atoi(strings.TrimPrefix(name, "UNKNOWN_SETTING_"))
		if err == nil && n > 0 && n < 65536 {
			return uint16(n), true
		}
	}
	return 0, false
}

func extFor(t uint16, c cfg, ni nameInfo, groups []string, sups *[]string, name string) (*profiles.Extension, string) {
	switch t {
	case 0:
		return &profiles.Extension{Type: 0, SNI: "auto"}, ""
	case 5:
		return &profiles.Extension{Type: 5, Data: "0100000000"}, ""
	case 10:
		if len(groups) == 0 {
			return nil, name + ": 组列表为空 ⇒ 跳过 supported_groups(10)"
		}
		return &profiles.Extension{Type: 10, Groups: groups}, ""
	case 11:
		return &profiles.Extension{Type: 11, PointFormats: []uint8{0}}, ""
	case 13:
		algs, warn := sigAlgs(c.TLS.SigAlgs)
		if warn != "" {
			warn = name + ": " + warn
		}
		if len(algs) == 0 {
			// 空 signature_algorithms 是**非法**的（Go 服务端报 "error decoding message"），
			// 宁可丢掉该扩展也不要发出结构性错误的 ClientHello。
			return nil, name + ": 签名算法表为空 ⇒ 跳过 signature_algorithms(13)（否则线上报解码错误）"
		}
		if chromiumLike[ni.family] {
			// E1 实测：Chromium 的 sig_algs 首位是 GREASE；Safari/Firefox 没有。
			algs = append([]string{"grease"}, algs...)
		}
		return &profiles.Extension{Type: 13, SigAlgs: algs}, warn
	case 16:
		// force_http1：第三方明确标记该客户端只走 HTTP/1.1（如 Chrome 43 / curl 7.x）。
		// 若仍提供 h2，ALPN 会协商成 h2——与真实客户端不符，且引擎会走 H2 路径。
		if c.ForceHTTP1 {
			return &profiles.Extension{Type: 16, ALPN: []string{"http/1.1"}}, ""
		}
		return &profiles.Extension{Type: 16, ALPN: []string{"h2", "http/1.1"}}, ""
	case 18:
		return &profiles.Extension{Type: 18}, ""
	case 21:
		// 第三方只给"存在"，不给长度 ⇒ 用我们实测的族级取值补
		if ni.family == "safari" {
			*sups = append(*sups, name+": padding(21) 长度用我们实测的 Safari 值（390），第三方未给长度")
			return &profiles.Extension{Type: 21, PaddingLen: 390}, ""
		}
		*sups = append(*sups, name+": padding(21) 用我们的 Chromium 策略 padding_to=512，第三方未给长度")
		return &profiles.Extension{Type: 21, PaddingTo: 512}, ""
	case 23:
		return &profiles.Extension{Type: 23}, ""
	case 27:
		return &profiles.Extension{Type: 27, CertCompression: c.TLS.CertCompression}, ""
	case 28:
		if c.TLS.RecordSizeLimit == nil {
			return &profiles.Extension{Type: 28}, ""
		}
		// 第三方的值按"线上 hex 数字"存（4001 表示 0x4001），故字面转字符串。
		*sups = append(*sups, name+": record_size_limit 取第三方字面值（按其语义即线上 hex）")
		return &profiles.Extension{Type: 28, Data: strconv.FormatUint(uint64(*c.TLS.RecordSizeLimit), 10)}, ""
	case 34:
		algs, warn := sigAlgs(c.TLS.Delegated)
		if warn != "" {
			warn = name + ": " + warn
		}
		return &profiles.Extension{Type: 34, SigAlgs: algs}, warn
	case 35:
		return &profiles.Extension{Type: 35}, ""
	case 43:
		return &profiles.Extension{Type: 43, Versions: versions(c.TLS.Versions, ni.family)}, ""
	case 45:
		return &profiles.Extension{Type: 45, PSKModes: []uint8{1}}, ""
	case 51:
		return &profiles.Extension{Type: 51, KeyShares: decOrGrease(c.TLS.KeyShareCurves)}, ""
	case 17: // status_request_v2：只当存在，无负载
		return &profiles.Extension{Type: 17}, ""
	case 50: // signature_algorithms_cert
		if len(c.TLS.SigAlgsCert) == 0 {
			// 空 sig_algs_cert 同样非法（实测：会让 Go 服务端报 error decoding message）
			*sups = append(*sups, name+": signature_algorithms_cert(50) 第三方为空 ⇒ 跳过该扩展")
			return nil, ""
		}
		algs, warn := sigAlgs(c.TLS.SigAlgsCert)
		if len(algs) == 0 {
			return nil, name + ": sig_algs_cert 全部无法识别 ⇒ 跳过 signature_algorithms_cert(50)"
		}
		return &profiles.Extension{Type: 50, SigAlgs: algs}, warn
	case 17513, 17613:
		if c.ForceHTTP1 {
			return nil, "" // ALPS 只对 h2 有意义
		}
		return &profiles.Extension{Type: t, ALPN: []string{"h2"}}, ""
	case 65037:
		*sups = append(*sups, name+": ECH(65037) 用 ech.mode=grease（第三方未给负载）")
		return &profiles.Extension{Type: 65037, ECH: &profiles.ECHConfig{Mode: "grease"}}, ""
	case 65281:
		return &profiles.Extension{Type: 65281, Data: "00"}, ""
	default:
		return &profiles.Extension{Type: t}, fmt.Sprintf("%s: 未知扩展 %d（按空负载透传）", name, t)
	}
}

func versions(in []string, fam string) []string {
	out := make([]string, 0, len(in)+1)
	hasGrease := false
	for _, v := range in {
		if strings.EqualFold(v, "GREASE") {
			hasGrease = true
			out = append(out, "grease")
			continue
		}
		if h, ok := versionHex[v]; ok {
			out = append(out, h)
			continue
		}
		out = append(out, v)
	}
	if !hasGrease && fam != "firefox" {
		out = append([]string{"grease"}, out...)
	}
	return out
}

func sigAlgs(in []string) ([]string, string) {
	out := make([]string, 0, len(in)+1)
	var unknown []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if h, ok := sigAlgHex[strings.ToLower(s)]; ok {
			out = append(out, h)
			continue
		}
		// 第三方有些条目直接给 hex 字面量（如 "0x402"）⇒ 归一成 4 位。
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 16); err == nil && strings.HasPrefix(strings.ToLower(s), "0x") {
			out = append(out, fmt.Sprintf("0x%04x", n))
			continue
		}
		unknown = append(unknown, s)
	}
	if len(unknown) > 0 {
		return out, "未识别的签名算法 " + strings.Join(unknown, ",") + "（已丢弃）"
	}
	return out, ""
}

func decOrGrease(in []string) []string {
	out := make([]string, 0, len(in)+1)
	for _, s := range in {
		if strings.EqualFold(s, "GREASE") {
			out = append(out, "grease")
			continue
		}
		if h, ok := groupHex[strings.ToLower(s)]; ok { // 第三方这里混用了名字（X25519/P256…）
			out = append(out, h)
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			out = append(out, strings.ToLower(s))
			continue
		}
		out = append(out, fmt.Sprintf("0x%04x", n))
	}
	return out
}

// groupHex：named group 名 → hex（第三方 key_share_curves 里混着名字与数字）。
var groupHex = map[string]string{
	"x25519":         "0x001d",
	"x25519mlkem768": "0x11ec",
	"secp256r1":      "0x0017",
	"p256":           "0x0017",
	"p-256":          "0x0017",
	"secp384r1":      "0x0018",
	"p384":           "0x0018",
	"p-384":          "0x0018",
	"secp521r1":      "0x0019",
	"p521":           "0x0019",
	"p-521":          "0x0019",
	"ffdhe2048":      "0x0100",
	"ffdhe3072":      "0x0101",
	"ffdhe4096":      "0x0102",
	"ffdhe6144":      "0x0103",
	"ffdhe8192":      "0x0104",
}

func decHexList(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	out := make([]string, 0, 16)
	for _, tok := range strings.Split(s, "-") {
		n, err := strconv.Atoi(tok)
		if err != nil {
			return nil, fmt.Errorf("非数字 %q", tok)
		}
		out = append(out, fmt.Sprintf("0x%04x", n))
	}
	return out, nil
}

func uint16List(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	out := make([]uint16, 0, 16)
	for _, tok := range strings.Split(s, "-") {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("非法扩展号 %q", tok)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

// advertisesTLS13：第三方的 supported_versions 里是否含 1.3。
func advertisesTLS13(versions []string) bool {
	for _, v := range versions {
		if v == "1.3" {
			return true
		}
	}
	return false
}

func hasGrease(l []string) bool {
	for _, s := range l {
		if s == "grease" {
			return true
		}
	}
	return false
}

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

// ---------- 身份头 ----------

// identity 只有两种模式，避免臆造：
//
//	模式 A（chrome/edge/firefox/safari，有 E1 实测模板）：按族模板 + 第三方版本号合成
//	        完整导航头（含 UA-CH）；iOS 平台因 iOS 版本在第三方 UA 里，直接采用其 UA。
//	模式 B（其余族：App 浏览器 / curl / okhttp / IE / 代理工具）：**只给 user-agent**
//	        （采用第三方 UA），其余头一律不编——那些客户端发什么头我们没实测过。
func identity(c cfg, ni nameInfo, name string) (*profiles.IdentityProfile, []string, []string) {
	var warns, sups []string
	if len(c.HeadersOrder) == 0 {
		return nil, []string{name + ": 第三方未给导航头顺序 ⇒ 身份节留空"}, nil
	}
	if !measuredIdentity[ni.family] {
		warns = append(warns, name+": 非浏览器族（"+ni.family+"）⇒ 身份节只放 user-agent（其余头无实测依据，不编）")
		return &profiles.IdentityProfile{Headers: [][2]string{{"user-agent", c.UA}}}, warns, nil
	}
	if ni.platform == "ios" {
		warns = append(warns, name+": iOS 平台直接采用第三方 UA（其版本信息在 UA 里）；UA-CH 不发")
		hdrs := [][2]string{}
		for _, h := range c.HeadersOrder {
			if lh := strings.ToLower(h); lh == "user-agent" {
				hdrs = append(hdrs, [2]string{"user-agent", c.UA})
			}
		}
		if len(hdrs) == 0 {
			hdrs = append(hdrs, [2]string{"user-agent", c.UA})
		}
		return &profiles.IdentityProfile{Headers: hdrs}, warns, nil
	}

	ua, uaWarn := buildUA(ni)
	if uaWarn != "" {
		warns = append(warns, name+": "+uaWarn)
	}
	vals := headerValues(ni, ua, &sups, name)
	hdrs := make([][2]string, 0, len(c.HeadersOrder))
	for _, h := range c.HeadersOrder {
		lh := strings.ToLower(h)
		v, ok := vals[lh]
		if !ok {
			warns = append(warns, name+": 导航头 "+lh+" 无实测模板（不发送）")
			continue
		}
		hdrs = append(hdrs, [2]string{lh, v})
	}
	return &profiles.IdentityProfile{Headers: hdrs}, warns, sups
}

// buildUA 按族 + 版本 + 平台合成 UA（模板来自我们的 E1 实测）。
func buildUA(ni nameInfo) (string, string) {
	switch ni.platform {
	case "windows":
		switch ni.family {
		case "chrome":
			return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", ni.major), ""
		case "edge":
			return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36 Edg/%s.0.0.0", ni.major, ni.major), ""
		case "firefox":
			return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%s.0) Gecko/20100101 Firefox/%s.0", ni.major, ni.major), ""
		}
	case "macos":
		switch ni.family {
		case "chrome":
			return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", ni.major), ""
		case "edge":
			return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36 Edg/%s.0.0.0", ni.major, ni.major), ""
		case "firefox":
			return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:%s.0) Gecko/20100101 Firefox/%s.0", ni.major, ni.major), ""
		case "safari":
			return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15", ni.dotted), ""
		}
	case "android":
		switch ni.family {
		case "chrome":
			// Chrome/Android 自 Android 10 起 UA 冻结为 "Android 10; K"（我们实测）
			return fmt.Sprintf("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Mobile Safari/537.36", ni.major), ""
		case "edge":
			return fmt.Sprintf("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Mobile Safari/537.36 EdgA/%s.0.0.0", ni.major, ni.major), ""
		case "firefox":
			return fmt.Sprintf("Mozilla/5.0 (Android 14; Mobile; rv:%s.0) Gecko/%s.0 Firefox/%s.0", ni.major, ni.major, ni.major), ""
		}
	case "linux":
		switch ni.family {
		case "chrome":
			return fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", ni.major), ""
		case "firefox":
			return fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64; rv:%s.0) Gecko/20100101 Firefox/%s.0", ni.major, ni.major), ""
		}
	}
	return "", fmt.Sprintf("族/平台组合（%s/%s）无实测 UA 模板 ⇒ 该预设不带 user-agent", ni.family, ni.platform)
}

// headerValues 返回该族 + 平台的导航头取值（全部来自我们的 E1 实测）。
func headerValues(ni nameInfo, ua string, sups *[]string, name string) map[string]string {
	v := map[string]string{"user-agent": ua}
	switch ni.family {
	case "firefox":
		v["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		v["accept-language"] = "en-US,en;q=0.9"
		v["accept-encoding"] = "gzip, deflate, br, zstd"
		v["upgrade-insecure-requests"] = "1"
		v["sec-fetch-dest"] = "document"
		v["sec-fetch-mode"] = "navigate"
		v["sec-fetch-site"] = "none"
		v["sec-fetch-user"] = "?1"
		v["priority"] = "u=0, i"
		v["te"] = "trailers"
		if ni.platform == "android" {
			delete(v, "sec-fetch-user") // 实测：Android Firefox 没有 sec-fetch-user
		}
	case "safari":
		v["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		v["accept-encoding"] = "gzip, deflate, br"
		v["accept-language"] = "en-US,en;q=0.9"
		v["sec-fetch-dest"] = "document"
		v["sec-fetch-mode"] = "navigate"
		v["sec-fetch-site"] = "none"
		// Safari 18 起导航头才带 priority（实测：17.x 无）
		if majorAtLeast(ni.major, 18) {
			v["priority"] = "u=0, i"
		}
	default: // chrome / edge
		v["upgrade-insecure-requests"] = "1"
		v["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
		// sec-ch-ua：我们只有两个版本的实测形态（149 与 154 系），中间版本按版本号就近取值
		v["sec-ch-ua"] = secCHUA(ni, sups, name)
		v["sec-ch-ua-mobile"] = "?0"
		v["sec-ch-ua-platform"] = `"Windows"`
		switch ni.platform {
		case "macos":
			v["sec-ch-ua-platform"] = `"macOS"`
		case "android":
			v["sec-ch-ua-mobile"] = "?1"
			v["sec-ch-ua-platform"] = `"Android"`
		case "linux":
			v["sec-ch-ua-platform"] = `"Linux"`
		}
		v["sec-fetch-site"] = "none"
		v["sec-fetch-mode"] = "navigate"
		v["sec-fetch-user"] = "?1"
		v["sec-fetch-dest"] = "document"
		v["accept-encoding"] = "gzip, deflate, br, zstd"
		v["accept-language"] = "en-US,en;q=0.9"
		v["priority"] = "u=0, i"
	}
	return v
}

// secCHUA 合成 sec-ch-ua。我们实测过两个形态：
//
//	≤149：`"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`
//	≥150：`"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`
//
// 之间的版本无实测 ⇒ 按 150 为界二分，并**逐条登记**这是推断（E3 预设本就不参与 E1 断言）。
func secCHUA(ni nameInfo, sups *[]string, name string) string {
	if ni.family == "edge" {
		*sups = append(*sups, name+": sec-ch-ua 用我们实测的 Edge 153 形态（含 GREASE 品牌 Not_A Brand;v=8），版本号按第三方")
		return fmt.Sprintf(`"Microsoft Edge";v="%s", "Not_A Brand";v="8", "Chromium";v="%s"`, ni.major, ni.major)
	}
	if majorAtLeast(ni.major, 150) {
		*sups = append(*sups, name+": sec-ch-ua 按「≥150」实测形态（Chromium 在前 + Not A(Brand;v=99），版本号按第三方")
		return fmt.Sprintf(`"Chromium";v="%s", "Google Chrome";v="%s", "Not A(Brand";v="99"`, ni.major, ni.major)
	}
	*sups = append(*sups, name+": sec-ch-ua 按「≤149」实测形态（Google Chrome 在前 + Not)A;Brand;v=24），版本号按第三方")
	return fmt.Sprintf(`"Google Chrome";v="%s", "Chromium";v="%s", "Not)A;Brand";v="24"`, ni.major, ni.major)
}

func majorAtLeast(major string, n int) bool {
	v, err := strconv.Atoi(major)
	return err == nil && v >= n
}

// ---------- 校验 / 落盘 / 对拍 ----------

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
	b = append(b, '\n')
	return os.WriteFile(filepath.Join(dir, p.Name+".json"), b, 0o644)
}

// platformless：去掉默认平台后缀（chrome_131_windows → chrome_131）。第三方对"默认平台"
// 会补后缀，而我们入库的手写预设通常不带 ⇒ 视为同一对象，走对拍而不是重复导入。
func platformless(name string) string {
	for _, sfx := range []string{"_windows", "_macos"} {
		if strings.HasSuffix(name, sfx) {
			return strings.TrimSuffix(name, sfx)
		}
	}
	return name
}

// loadExistingGrades 返回 名称→证据等级（"" = 自测）。
func loadExistingGrades(dir string) map[string]string {
	ents, err := os.ReadDir(dir)
	must(err)
	out := make(map[string]string, len(ents))
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var p profiles.Profile
		if json.Unmarshal(b, &p) == nil {
			out[name] = p.Grade
		}
	}
	return out
}

// pruneStaleE3 删除"目录里是 E3、但本次没产出"的预设文件。
func pruneStaleE3(dir string, kept []string) []string {
	keep := map[string]bool{}
	for _, n := range kept {
		keep[n] = true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var removed []string
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		if keep[name] {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var p profiles.Profile
		if json.Unmarshal(b, &p) != nil || p.Grade != "E3" {
			continue // 非 E3 一律不动
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	return removed
}

// loadChromiumH3Block 读一个已入库 Chromium 预设的 http3 节，供导入的 Chromium 系复用。
func loadChromiumH3Block(dir string) *profiles.HTTP3Profile {
	b, err := os.ReadFile(filepath.Join(dir, "chrome_152_macos.json"))
	if err != nil {
		return nil
	}
	var p profiles.Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil
	}
	return p.HTTP3
}

// crossCheck 把第三方条目与入库同名预设做**结构对拍**：cipher 序、扩展集合、H2。
// Chromium 的扩展顺序是洗牌的 ⇒ 只比集合；这已足以发现"根本不是一个东西"。
func crossCheck(dir, against string, third *profiles.Profile) string {
	b, err := os.ReadFile(filepath.Join(dir, against+".json"))
	if err != nil {
		return ""
	}
	var ours profiles.Profile
	if err := json.Unmarshal(b, &ours); err != nil {
		return ""
	}
	if ours.Grade == "E3" {
		return ""
	}
	var diffs []string
	if a, b := cipherSeq(&ours), cipherSeq(third); a != b {
		diffs = append(diffs, fmt.Sprintf("cipher 序不同\n      入库: %s\n      第三: %s", a, b))
	}
	if a, b := extSet(&ours), extSet(third); a != b {
		diffs = append(diffs, fmt.Sprintf("扩展集合不同\n      入库: %s\n      第三: %s", a, b))
	}
	if a, b := h2Summary(&ours), h2Summary(third); a != b {
		diffs = append(diffs, fmt.Sprintf("H2 不同\n      入库: %s\n      第三: %s", a, b))
	}
	if len(diffs) == 0 {
		return fmt.Sprintf("%s: cipher 序 / 扩展集合 / H2 全部一致 ✓（第三方与我们的 E1 实测互证）", third.Name)
	}
	return fmt.Sprintf("%s: 有差异\n    - %s", third.Name, strings.Join(diffs, "\n    - "))
}

func cipherSeq(p *profiles.Profile) string { return strings.Join(p.TLS.Detail.Ciphers, "-") }

func extSet(p *profiles.Profile) string {
	seen := map[uint16]bool{}
	var ids []int
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == 41 || e.Type == 0 || e.GreaseRandom {
			continue
		}
		if !seen[e.Type] {
			seen[e.Type] = true
			ids = append(ids, int(e.Type))
		}
	}
	sort.Ints(ids)
	ss := make([]string, 0, len(ids))
	for _, i := range ids {
		ss = append(ss, strconv.Itoa(i))
	}
	return strings.Join(ss, ",")
}

// effectiveFlow 给预设在线上实际写出的连接级 WINDOW_UPDATE 增量：nil 由引擎补
// Chrome 默认 15663105，故对拍时归一，避免"nil vs 显式默认值"被误报为差异。
func effectiveFlow(v *uint32) uint32 {
	if v == nil {
		return 15663105
	}
	return *v
}

func h2Summary(p *profiles.Profile) string {
	if p.HTTP2 == nil {
		return "(无 h2)"
	}
	var sb strings.Builder
	for _, kv := range p.HTTP2.Settings {
		fmt.Fprintf(&sb, "%d:%d,", kv[0], kv[1])
	}
	fmt.Fprintf(&sb, "|flow=%d", effectiveFlow(p.HTTP2.WindowUpdate))
	if id := p.HTTP2.FirstStreamID; id != 0 {
		fmt.Fprintf(&sb, "|sid=%d", id)
	}
	// nil 在本库语义上等价于 fhttp 默认值（excl=true/weight=255 = Chrome 实测形状），
	// 故对拍时统一归一成该形状，避免"nil vs 显式 Chrome 默认值"被误报为差异。
	hp := p.HTTP2.HeadersPriority
	if hp == nil {
		fmt.Fprintf(&sb, "|prio=excl:true,w=%d(报%d)", 255, 256)
	} else {
		fmt.Fprintf(&sb, "|prio=excl:%v,w=%d(报%d)", hp.Exclusive, int(hp.Weight), int(hp.Weight)+1)
	}
	return sb.String()
}
