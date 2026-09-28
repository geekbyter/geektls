// profile 生成器：从真实浏览器 ClientHello/TCP 抓包标本直接产出 profile JSON，
// 替代手写转录（转录是既往预设保真度的最大瓶颈）。
//
// 产物语义：
//   - tls.detail   来自标本原始字节（逐字段真实，GREASE 归一为占位符以保留
//                  每次连接重随机化的浏览器行为）
//   - http2        来自同一抓包的 SETTINGS / WINDOW_UPDATE（真实值）；
//                  伪头顺序标本内不可得，取该浏览器族的固定顺序（标注见 README）
//   - identity     按族/版本/平台合成 UA 与 UA-CH（确定性字符串）
//   - tcp          标本无 TCP 层数据（需 pcap），生成的预设不含 tcp 节
//
// 用法（在 tests/e2e 目录下）：
//
//	go run ./cmd/gen-profiles -dry                 # 打印到 stdout
//	go run ./cmd/gen-profiles -out ../../core/profiles/builtin
//	go run ./cmd/gen-profiles -only chrome_152_macos -out /tmp
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/geektls/core/profiles"
	"github.com/geektls/tests/e2e/specimens"
)

func main() {
	out := flag.String("out", "", "输出目录（为空则只打印）")
	only := flag.String("only", "", "只生成指定标本名")
	dry := flag.Bool("dry", false, "打印到 stdout 不落盘")
	records := flag.String("record", "", "E1 真浏览器记录 JSON（逗号分隔，来自 cmd/e1-browser）")
	lineageMode := flag.Bool("lineage", false, "谱系模式：在实测锚点窗口内内插缺失版本（grade=E2i）")
	reportPath := flag.String("report", "", "谱系报告 JSON 输出路径")
	strict := flag.Bool("strict", false, "谱系模式：区间内字段有变化（边界未知）则拒绝生成")
	flag.Parse()

	if *lineageMode {
		runLineage(*out, *reportPath, *strict, *dry)
		return
	}

	if !*dry && *out != "" {
		if err := os.MkdirAll(*out, 0o755); err != nil {
			fatal(err)
		}
	}

	n := 0
	for _, it := range specimens.All() {
		if *only != "" && it.Name != *only {
			continue
		}
		p, err := build(it)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", it.Name, err))
		}
		b, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			fatal(err)
		}
		b = renderByteSliceFields(b)
		b = append(b, '\n')

		switch {
		case *dry || *out == "":
			fmt.Printf("===== %s.json =====\n%s", it.Name, b)
		default:
			path := filepath.Join(*out, it.Name+".json")
			if err := os.WriteFile(path, b, 0o644); err != nil {
				fatal(err)
			}
			fmt.Printf("wrote %s (%d bytes)\n", path, len(b))
		}
		n++
	}
	// E1 真浏览器记录：走同一条 build 链路，identity 用记录里的真实请求头。
	for _, path := range strings.Split(*records, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		it, err := loadRecord(path)
		if err != nil {
			fatal(err)
		}
		p, err := build(it)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", it.Name, err))
		}
		b, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			fatal(err)
		}
		b = renderByteSliceFields(b)
		b = append(b, '\n')
		switch {
		case *dry || *out == "":
			fmt.Printf("===== %s.json =====\n%s", it.Name, b)
		default:
			pth := filepath.Join(*out, it.Name+".json")
			if err := os.WriteFile(pth, b, 0o644); err != nil {
				fatal(err)
			}
			fmt.Printf("wrote %s (%d bytes)\n", pth, len(b))
		}
		n++
	}
	fmt.Fprintf(os.Stderr, "generated %d profile(s)\n", n)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// build 把一个标本编译为 profile。
func build(it specimens.Item) (*profiles.Profile, error) {
	p, warnings, err := profiles.FromClientHelloHex(it.Hex)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  [%s] parse warning: %+v\n", it.Name, w)
	}

	p.Name = it.Name
	p.TLS.ClientHelloHex = "" // 规范形式是 detail
	normalizeGrease(p.TLS.Detail)
	normalizeSNI(p.TLS.Detail)
	normalizeFirefoxResumption(it, p.TLS.Detail)
	normalizePskPlaceholder(p.TLS.Detail)
	normalizeECHGrease(p.TLS.Detail)

	// Chrome/Edge 逐连接洗牌扩展顺序；Firefox/Safari 不洗牌。
	p.TLS.Detail.ExtensionPermutation = it.Family == "chrome" || it.Family == "edge"

	if len(it.H2Settings) > 0 {
		settings := make([][]uint32, 0, len(it.H2Settings))
		for _, kv := range it.H2Settings {
			settings = append(settings, []uint32{kv[0], kv[1]})
		}
		p.HTTP2 = &profiles.HTTP2Profile{
			Settings:          settings,
			WindowUpdate:      it.H2ConnFlow,
			PseudoHeaderOrder: pseudoHeaderOrder(it.Family),
			HeadersPriority:   headersPriority(it.Family),
		}
	}

	if len(it.Headers) > 0 {
		// E1 记录路径：直接用真实抓包的常规头（真实 UA-CH 保真度高于合成）。
		p.Identity = &profiles.IdentityProfile{Headers: it.Headers}
	} else {
		p.Identity = &profiles.IdentityProfile{Headers: identityHeaders(it)}
	}
	if p.HTTP3 == nil {
		p.HTTP3 = familyH3(it.Family)
	}
	return p, nil
}

// normalizeGrease 把字面 GREASE 值（0x?a?a）归一为 "grease" 占位符：
// 编译后由 TLS 栈每次连接重新取值，与真实浏览器行为一致。
func normalizeGrease(d *profiles.Detail) {
	for i, c := range d.Ciphers {
		if hexIsGrease(c) {
			d.Ciphers[i] = profiles.GreaseToken
		}
	}
	for i := range d.Extensions {
		e := &d.Extensions[i]
		// 扩展自身的 type 是 GREASE 值 → 标记为"随机 GREASE 扩展"（G12）：
		// uTLS 不做扩展 type 的握手期替换（原样写出 Value），必须由 compile
		// 每连接重取，否则首个扩展的 GREASE id 会跨连接恒定——真浏览器不是这样。
		// Type 保留标本里的字面值作为可读记录，线上取值由 grease_random 覆盖。
		if profiles.IsGrease(e.Type) {
			e.GreaseRandom = true
		}
		for j, g := range e.Groups {
			if hexIsGrease(g) {
				e.Groups[j] = profiles.GreaseToken
			}
		}
		for j, v := range e.Versions {
			if hexIsGrease(v) {
				e.Versions[j] = profiles.GreaseToken
			}
		}
		for j, k := range e.KeyShares {
			if hexIsGrease(k) {
				e.KeyShares[j] = profiles.GreaseToken
			}
		}
	}
}

// normalizeSNI 把标本里的 SNI 改为运行时占位 "auto"：抓包现场的 host
// （往往是 localhost/测试域）不能固化进预设。
func normalizeSNI(d *profiles.Detail) {
	for i := range d.Extensions {
		if d.Extensions[i].Type == 0 {
			d.Extensions[i].SNI = "auto"
		}
	}
}

// byteSliceFields 是 detail 里 []uint8 形态的字段：encoding/json 默认按 base64
// 编码，这里改写为数值数组，便于人工阅读与手改（与既有预设写法一致）。
var byteSliceFields = regexp.MustCompile(`"(point_formats|psk_modes)": "([A-Za-z0-9+/=]+)"`)

func renderByteSliceFields(b []byte) []byte {
	return byteSliceFields.ReplaceAllFunc(b, func(m []byte) []byte {
		sub := byteSliceFields.FindSubmatch(m)
		raw, err := base64.StdEncoding.DecodeString(string(sub[2]))
		if err != nil {
			return m
		}
		parts := make([]string, 0, len(raw))
		for _, v := range raw {
			parts = append(parts, fmt.Sprintf("%d", v))
		}
		return []byte(fmt.Sprintf("%q: [%s]", string(sub[1]), strings.Join(parts, ", ")))
	})
}

func hexIsGrease(s string) bool {
	if s == profiles.GreaseToken {
		return true
	}
	v, err := profiles.ParseHex16(s)
	if err != nil {
		return false
	}
	return v>>8 == v&0xff && v&0xf == 0xa
}

// pseudoHeaderOrder 返回浏览器族的伪头顺序（标本不含伪头，取族内固定值）。
func pseudoHeaderOrder(family string) []string {
	switch family {
	case "firefox":
		return []string{"m", "p", "a", "s"}
	case "safari":
		return []string{"m", "s", "a", "p"}
	default: // chrome / edge
		return []string{"m", "a", "s", "p"}
	}
}

// normalizePskPlaceholder 保证预设带 pre_shared_key(41) 的**空占位**（族无关）。
//
// 为什么必须：uTLS 在"ClientSessionCache 命中票据、而 spec 里没有 PSK 扩展"时
// **直接 panic**（u_session_controller.go:128 `initPskExt failed: ... there is no
// pre-shared key extension in the ClientHelloSpec`），会崩掉调用进程而不是返回错误。
// 实测（core/tls/resumption_live_test.go 真机探针）：按 E1 首访抓包生成的预设
// （chrome_149_windows 等 9 个）都没有占位，一旦启用会话复用即命中该 panic。
//
// 为什么对指纹无损：占位是空 payload，无票据时线上**省略**（client.go 设
// OmitEmptyPsk），因此全新连接的 ClientHello 与之前逐字节一致（e2e 的 JA3/JA4
// 与 fp oracle 断言不受影响）；有票据时它才会被 uTLS 填成真实 PSK——这正是真
// 浏览器的行为。位置按 RFC 8446：pre_shared_key 必须是**最后一个**扩展。
//
// 顺带清掉标本里可能转录下来的**真实票据负载**：票据属于某次会话、不可复用，
// 留在预设里只会看起来"钉死了票据"。
func normalizePskPlaceholder(d *profiles.Detail) {
	for i := range d.Extensions {
		if d.Extensions[i].Type == 41 {
			d.Extensions[i].Data = ""
			return
		}
	}
	d.Extensions = append(d.Extensions, profiles.Extension{Type: 41})
}

// normalizeECHGrease 把"字面 GREASE ECH 负载"改成 ech.mode=grease（逐连接随机）。
//
// 为什么必须：Chrome 的 GREASE ECH 每次连接都重取 enc 公钥、并随机挑选填充长度
// （实测总长 42+N，N∈{144,176,208,240}）。抓包转录下来的字面 payload 会被**逐连接
// 原样重放**，也就是"65037 内容恒定"这一稳定可观察特征（与 G12 同族）。手写预设
// （chrome_131/133/150、firefox_*）早已用 ech.mode=grease，生成的 12 个却带着字面
// payload —— 本次归一化把这批补齐。
//
// 判据：GREASE ECH 的 outer 字节为 0x00（结构 outer|kdf|aead|config_id|enc_len|enc|payload），
// 而真实 ECHConfigList 以版本号 0xfe0d 开头。因此只动 0x00 开头者：mode=real 的
// 预设（真 ECH 测试用）不受影响。
func normalizeECHGrease(d *profiles.Detail) {
	for i := range d.Extensions {
		e := &d.Extensions[i]
		if e.Type != 65037 || e.ECH != nil || len(e.Data) < 2 {
			continue
		}
		if e.Data[0] == '0' && e.Data[1] == '0' { // outer = 0x00 ⇒ GREASE 形状
			e.Data = ""
			e.ECH = &profiles.ECHConfig{Mode: "grease"}
		}
	}
}

// headersPriority 返回该族 HEADERS 帧内嵌 priority（实测驱动，G11）。
//
// Chromium 返回 nil：fhttp 的默认值**就是** Chrome 实测形状
// （exclusive=true / weight=255 = peet 报的 256），显式写反而会掩盖
// "默认值即实测值"这一事实——该形状由 e2e 的 fp oracle 断言钉住。
// Firefox 必须显式给值：默认值是 Chrome 形状，与实测（exclusive=false /
// weight=41 = peet 报的 42）不符。
//
// Safari 实测（2026-09-28，真机 17.3.1 与 18.6 两份）：**exclusive=false**——这是与
// Chrome（exclusive=true）的硬区别；weight 线上值两版分别为 254 / 255，生成预设统一
// 取 255（18.6 的值）。
func headersPriority(family string) *profiles.H2HeadersPriority {
	switch family {
	case "firefox":
		return &profiles.H2HeadersPriority{Exclusive: false, StreamDep: 0, Weight: 41}
	case "safari":
		return &profiles.H2HeadersPriority{Exclusive: false, StreamDep: 0, Weight: 255}
	}
	return nil
}

// identityHeaders 按族/版本/平台合成缺省身份头。
//
// 顺序与取值以**真实抓包实测**为准：
//
//	Chromium（Chrome 149 / Edge 149，Windows，2026-09-24 对 tls.peet.ws）：
//	  sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests,
//	  user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user,
//	  sec-fetch-dest, accept-encoding, accept-language, priority
//	Firefox（156，Windows，2026-09-24 对 tls.peet.ws）：
//	  user-agent, accept, accept-language, accept-encoding, upgrade-insecure-requests,
//	  sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, priority, te
//	  —— 注意 Firefox **没有 UA-CH 头**，且收尾是 `te: trailers`（Chromium 没有）。
//	Safari（17.3.1 / 18.6，macOS，2026-09-28 真机对 tls.peet.ws，见 safariIdentity）。
func identityHeaders(it specimens.Item) [][2]string {
	os_ := "Macintosh; Intel Mac OS X 10_15_7"
	switch it.Family {
	case "chrome", "edge":
		ua := fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", os_, it.Version)
		brand := "Google Chrome"
		if it.Family == "edge" {
			ua = fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36 Edg/%s.0.0.0", os_, it.Version, it.Version)
			brand = "Microsoft Edge"
		}
		return chromiumIdentity(ua, it.Version, brand, "macOS")
	case "firefox":
		return firefoxIdentity(it)
	default: // safari
		return safariIdentity(it)
	}
}

// safariAccept 是 Safari 导航请求的 accept 实测值。
const safariAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// safariIdentity 是 Safari 的**导航**身份头（真机实测：Safari 17.3.1 与 18.6 / macOS）。
//
// 顺序与取值实测：
//
//	17.3.1：accept, sec-fetch-site, accept-encoding, sec-fetch-mode, user-agent,
//	        accept-language, sec-fetch-dest ——**无 priority、无 UA-CH**
//	18.6  ：sec-fetch-dest, user-agent, accept, sec-fetch-site, sec-fetch-mode,
//	        accept-language, priority, accept-encoding
//
// 两点说明：① 18 起多了 `priority: u=0, i`（按主版本判定）；② 实测的
// `accept-language` 含用户 locale，预设一律用中性值。
// 原先 Safari 走的是"精简集 + accept: */*"（非导航形态，来源不可考），本次以实测替换。
func safariIdentity(it specimens.Item) [][2]string {
	ver := 0
	_, _ = fmt.Sscanf(it.Version, "%d", &ver)
	ua := fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s.0 Safari/605.1.15", it.Version)
	if ver >= 18 {
		return [][2]string{
			{"sec-fetch-dest", "document"},
			{"user-agent", ua},
			{"accept", safariAccept},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
			{"accept-encoding", "gzip, deflate, br"},
		}
	}
	return [][2]string{
		{"accept", safariAccept},
		{"sec-fetch-site", "none"},
		{"accept-encoding", "gzip, deflate, br"},
		{"sec-fetch-mode", "navigate"},
		{"user-agent", ua},
		{"accept-language", "en-US,en;q=0.9"},
		{"sec-fetch-dest", "document"},
	}
}

// firefoxIdentity 是 Firefox 的导航身份头（顺序与取值见 identityHeaders 注释的实测）。
func firefoxIdentity(it specimens.Item) [][2]string {
	platform := "Macintosh; Intel Mac OS X 10.15"
	switch it.Platform {
	case "Windows":
		platform = "Windows NT 10.0; Win64; x64"
	case "Linux":
		platform = "X11; Linux x86_64"
	}
	ua := fmt.Sprintf("Mozilla/5.0 (%s; rv:%s.0) Gecko/20100101 Firefox/%s.0", platform, it.Version, it.Version)
	return [][2]string{
		{"user-agent", ua},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.5"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"upgrade-insecure-requests", "1"},
		{"sec-fetch-dest", "document"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-user", "?1"},
		{"priority", "u=0, i"},
		{"te", "trailers"},
	}
}

// normalizeFirefoxResumption 让 Firefox 预设表达**首访**形态。
//
// 实测（2026-09-24）：Firefox 156/Windows 首访带 session_ticket(35)、不带 pre_shared_key(41)；
// 而复访标本（firefox_144_macos 的来源抓包）用 41 顶替了 35。预设建模"首访"，
// 因此确保 35 存在（实测位置：紧跟 ec_point_formats(11) 之后）。
// 41 保留为空占位——compile 只把它当占位（无票据时线上省略），所以清掉标本里
// 那条真实票据负载，避免"看似钉死了票据"。
func normalizeFirefoxResumption(it specimens.Item, d *profiles.Detail) {
	if it.Family != "firefox" {
		return
	}
	for i := range d.Extensions {
		if d.Extensions[i].Type == 41 {
			d.Extensions[i].Data = ""
		}
	}
	for _, e := range d.Extensions {
		if e.Type == 35 {
			return
		}
	}
	ins := len(d.Extensions)
	for i, e := range d.Extensions {
		if e.Type == 11 {
			ins = i + 1
			break
		}
	}
	d.Extensions = append(d.Extensions[:ins],
		append([]profiles.Extension{{Type: 35}}, d.Extensions[ins:]...)...)
}

// chromiumIdentity Chromium 系（Chrome/Edge）的完整导航身份头。
//
// 注意 UA-CH 的两个易错点（抓包实证）：
//  1. 品牌顺序：当前版本 Chrome 把自家品牌放第一位（"Google Chrome"/"Microsoft Edge"），
//     Chromium 第二——不是老版本的 Chromium 在前；
//  2. GREASE 品牌：现行为 "Not)A;Brand";v="24"（不是 "Not/A)Brand";v="99"）。
func chromiumIdentity(ua, version, brand, platform string) [][2]string {
	chUA := fmt.Sprintf("%q;v=%q, \"Chromium\";v=%q, \"Not)A;Brand\";v=\"24\"", brand, version, version)
	return [][2]string{
		{"sec-ch-ua", chUA},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", fmt.Sprintf("%q", platform)},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", ua},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
	}
}
