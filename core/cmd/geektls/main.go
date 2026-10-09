// geektls 命令行入口（G6）：不写代码也能看预设、离线验指纹、真发一跳请求。
//
// 设计口径（保证"CLI 看到的"与"代码里跑的"是同一件事）：
//   - 指纹构造走与绑定同一批入口（profiles.Get / FromJA3 / FromJA4R /
//     FromClientHelloHex / ResolveJA4Profile），用户自带输入同样过一遍
//     NormalizeForReplay 自洽归一；
//   - selfcheck（本次握手实际发出的 JA3/JA4）打 **stderr**，stdout 只放正文，
//     这样 `geektls request ... > out.html` 和 `| jq` 都是干净可用的；
//   - 退出码：0 = 传输成功（含 4xx/5xx，curl 口径；加 --fail 让 4xx/5xx 返回 1），
//     1 = 配置或传输错误（原因在 stderr），2 = 用法错误。
//
// 为什么值得有：仓库此前没有任何命令行入口，试用门槛是"先写一段代码"；
// 同行里带 CLI 的（fetchr 等）在"快速看一个库到底发什么"这件事上明显占优。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/geekbyter/geektls/core/engine"
	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
	"github.com/geekbyter/geektls/core/version"
)

const usage = `geektls — TLS/HTTP 指纹工具（命令行）

用法：
  geektls version
  geektls presets [--json] [--grade E3|self] [--name 子串]
  geektls describe <预设名>
  geektls check-profile <预设名 | ja3:… | ja4:… | ja4r:… | {"ja3":…} | hex>  [--json]
  geektls request <url> [选项]
  geektls import-pcap --pcap <文件> [选项]   从 Wireshark/tcpdump 抓包提取指纹（E1p 记录）

request 选项：
  --profile <名>                        内置预设（默认 chrome_133）
  --ja3 / --ja4 / --ja4r <值>           自带指纹（与绑定同口径，含自洽归一）
  --clienthello-hex <hex>               直接给 ClientHello
  -X, --method <方法>                   默认 GET
  -H '<k>: <v>'                         可重复
  -d, --data <文本>                     请求体
  --json-body                           data 视为 JSON（自动补 content-type）
  --timeout <秒>                        到响应头为止（默认 30）
  --read-timeout <秒>                   body 读取空闲上限（默认 0 = 不限）
  --proxy <url>                         http/https(CONNECT)/socks5/socks5h/socks4/socks4a
  --protocols <表>                      允许的协议集合，逗号分隔（默认 h1.1,h2；例：h1.1 / h2 / h2,h3）
  --h3                                  允许 H3（= 默认集合加 h3；默认关闭，与 curl_cffi 一致）
  --http3                               **强制** H3（失败不回落；请求级 force）
  --header-order <档>                   请求头顺序：preserve（默认）/ input（按传入序）/ random（打乱）
  --identity-sync <档>                  自带 UA 与预设身份冲突时：auto（默认，校正 sec-ch-ua* + 告警）/ off
  --insecure                            跳过证书校验
  --resolve host[:port]=<IP>            钉位，可重复
  --local-address <IP>                  出网源地址
  --ipv4 / --ipv6                       协议族偏好
  --redirect-max <n>                    重定向上限（<0 = 不跟随；默认 10）
  -i, --show-headers                    先打印状态行与响应头
  --selfcheck                           把 selfcheck 打到 stderr（不污染 stdout）
  --fail                                4xx/5xx 时退出码 1

例：
  geektls presets --grade self | head
  geektls describe chrome_154_windows | jq '.tls.detail.extensions | length'
  geektls check-profile chrome_133
  geektls request https://example.com -i --selfcheck
  geektls request http://127.0.0.1:8000/ --ja4 t13d1516h2_8daaf6152771_02713d6af862
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "core %s（abi %d，utls %s）\n", version.Core, version.ABI, version.UTLSVersion())
		return 0
	case "presets":
		return cmdPresets(args[1:], stdout, stderr)
	case "describe":
		return cmdDescribe(args[1:], stdout, stderr)
	case "check-profile":
		return cmdCheckProfile(args[1:], stdout, stderr)
	case "request":
		return cmdRequest(args[1:], stdout, stderr)
	case "import-pcap":
		return cmdImportPcap(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n%s", args[0], usage)
		return 2
	}
}

func usageErr(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "geektls: "+format+"\n\n"+usage, args...)
	return 2
}

// --- presets ---

func cmdPresets(args []string, stdout, stderr io.Writer) int {
	asJSON, grade, nameFilter := false, "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--grade":
			if i+1 >= len(args) {
				return usageErr(stderr, "presets --grade 需要值（E3 或 self）")
			}
			i++
			grade = args[i]
		case "--name":
			if i+1 >= len(args) {
				return usageErr(stderr, "presets --name 需要子串")
			}
			i++
			nameFilter = args[i]
		default:
			return usageErr(stderr, "presets: 未知参数 %q", args[i])
		}
	}

	type row struct {
		Name   string `json:"name"`
		Grade  string `json:"grade"`
		Source string `json:"source,omitempty"`
	}
	rows := make([]row, 0, 380)
	for _, n := range profiles.List() {
		if nameFilter != "" && !strings.Contains(n, nameFilter) {
			continue
		}
		p, err := profiles.Get(n)
		if err != nil {
			continue // 内置集里解析不了的条目不该让整条命令失败
		}
		g := p.Grade
		if g == "" {
			g = "self" // 留空 = 本项目自测（见 profiles.Profile 的 Grade 注释）
		}
		if grade != "" && !strings.EqualFold(g, grade) {
			continue
		}
		rows = append(rows, row{Name: n, Grade: g, Source: p.Source})
	}

	if asJSON {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "geektls: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	for _, r := range rows {
		if r.Source != "" {
			fmt.Fprintf(stdout, "%-46s %-6s %s\n", r.Name, r.Grade, r.Source)
			continue
		}
		fmt.Fprintf(stdout, "%-46s %s\n", r.Name, r.Grade)
	}
	fmt.Fprintf(stderr, "共 %d 条（--json 结构化；--grade self 只看自测；--name 过滤）\n", len(rows))
	return 0
}

// --- describe ---

func cmdDescribe(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return usageErr(stderr, "describe 需要一个预设名")
	}
	b, err := profiles.Describe(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}

// --- check-profile ---

func cmdCheckProfile(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	rest := make([]string, 0, 1)
	for _, a := range args {
		if a == "--json" {
			asJSON = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) != 1 {
		return usageErr(stderr, "check-profile 需要一个入参（预设名 / ja3: / ja4: / ja4r: / hex）")
	}
	input := rest[0]
	// 预设名也是一种合法入参：CheckProfile 只吃 profile JSON / JA3 / JA4 / JA4R /
	// hex，所以名字先展开成规范 JSON（与 describe 同一份）——`check-profile chrome_133`
	// 与 `geektls describe chrome_133 | ...` 的语义由此一致。
	if _, err := profiles.Get(input); err == nil {
		if b, derr := profiles.Describe(input); derr == nil {
			input = string(b)
		}
	}
	res, err := tlscore.CheckProfile(input)
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	if asJSON {
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "geektls: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprintf(stdout, "ja3      %s\n", res.JA3)
	fmt.Fprintf(stdout, "ja3_hash %s\n", res.JA3Hash)
	fmt.Fprintf(stdout, "ja4      %s\n", res.JA4)
	fmt.Fprintf(stdout, "wire_len %d（估算的 ClientHello record 总长）\n", res.WireLen)
	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "warn %s: %s\n", w.Code, w.Message)
	}
	return 0
}

// --- request ---

type reqOpts struct {
	url          string
	profile      string
	ja3          string
	ja4          string
	ja4r         string
	clientHello  string
	method       string
	headers      [][2]string
	data         string
	jsonBody     bool
	timeout      int
	readTimeout  int
	proxy        string
	http3        bool
	h3           bool
	protocols    string
	headerOrder  string
	identitySync string
	insecure     bool
	resolve      map[string]string
	localAddress string
	ipVersion    string
	redirectMax  int
	showHeaders  bool
	selfcheck    bool
	fail         bool
}

func cmdRequest(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageErr(stderr, "request 需要 URL")
	}
	o := reqOpts{
		url: args[0], method: "GET", timeout: 30, redirectMax: 10,
		resolve: map[string]string{},
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		val := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch a {
		case "--profile":
			if o.profile, _ = val(); o.profile == "" {
				return usageErr(stderr, "--profile 需要预设名")
			}
		case "--ja3":
			if o.ja3, _ = val(); o.ja3 == "" {
				return usageErr(stderr, "--ja3 需要值")
			}
		case "--ja4":
			if o.ja4, _ = val(); o.ja4 == "" {
				return usageErr(stderr, "--ja4 需要值")
			}
		case "--ja4r":
			if o.ja4r, _ = val(); o.ja4r == "" {
				return usageErr(stderr, "--ja4r 需要值")
			}
		case "--clienthello-hex":
			if o.clientHello, _ = val(); o.clientHello == "" {
				return usageErr(stderr, "--clienthello-hex 需要值")
			}
		case "-X", "--method":
			if o.method, _ = val(); o.method == "" {
				return usageErr(stderr, "-X 需要方法名")
			}
		case "-H":
			h, ok := val()
			if !ok {
				return usageErr(stderr, "-H 需要 'k: v'")
			}
			name, v, found := strings.Cut(h, ":")
			if !found || strings.TrimSpace(name) == "" {
				return usageErr(stderr, "-H 需要 'k: v' 形态，收到 %q", h)
			}
			o.headers = append(o.headers, [2]string{strings.TrimSpace(name), strings.TrimSpace(v)})
		case "-d", "--data":
			if o.data, _ = val(); o.data == "" {
				return usageErr(stderr, "-d 需要值")
			}
		case "--json-body":
			o.jsonBody = true
		case "--timeout":
			v, ok := val()
			if !ok {
				return usageErr(stderr, "--timeout 需要秒数")
			}
			if _, err := fmt.Sscanf(v, "%d", &o.timeout); err != nil {
				return usageErr(stderr, "--timeout 需要整数秒，收到 %q", v)
			}
		case "--read-timeout":
			v, ok := val()
			if !ok {
				return usageErr(stderr, "--read-timeout 需要秒数")
			}
			if _, err := fmt.Sscanf(v, "%d", &o.readTimeout); err != nil {
				return usageErr(stderr, "--read-timeout 需要整数秒，收到 %q", v)
			}
		case "--proxy":
			if o.proxy, _ = val(); o.proxy == "" {
				return usageErr(stderr, "--proxy 需要 URL")
			}
		case "--http3":
			o.http3 = true
		case "--h3":
			o.h3 = true
		case "--header-order":
			if o.headerOrder, _ = val(); o.headerOrder == "" {
				return usageErr(stderr, "--header-order 需要值（preserve / input / random）")
			}
		case "--identity-sync":
			if o.identitySync, _ = val(); o.identitySync == "" {
				return usageErr(stderr, "--identity-sync 需要值（auto / off）")
			}
		case "--protocols":
			if o.protocols, _ = val(); o.protocols == "" {
				return usageErr(stderr, "--protocols 需要值（如 h1.1,h2 / h2 / h2,h3）")
			}
		case "--insecure":
			o.insecure = true
		case "--resolve":
			v, ok := val()
			if !ok {
				return usageErr(stderr, "--resolve 需要 host[:port]=IP")
			}
			host, ip, found := strings.Cut(v, "=")
			if !found || host == "" || ip == "" {
				return usageErr(stderr, "--resolve 需要 host[:port]=IP，收到 %q", v)
			}
			o.resolve[host] = ip
		case "--local-address":
			if o.localAddress, _ = val(); o.localAddress == "" {
				return usageErr(stderr, "--local-address 需要 IP")
			}
		case "--ipv4":
			o.ipVersion = "4"
		case "--ipv6":
			o.ipVersion = "6"
		case "--redirect-max":
			v, ok := val()
			if !ok {
				return usageErr(stderr, "--redirect-max 需要整数")
			}
			if _, err := fmt.Sscanf(v, "%d", &o.redirectMax); err != nil {
				return usageErr(stderr, "--redirect-max 需要整数，收到 %q", v)
			}
		case "-i", "--show-headers":
			o.showHeaders = true
		case "--selfcheck":
			o.selfcheck = true
		case "--fail":
			o.fail = true
		default:
			return usageErr(stderr, "request: 未知参数 %q", a)
		}
	}

	p, err := buildProfile(&o, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	// 协议选择（G8）：--protocols 与 --h3 二选一（引擎两者同时给会报错）。
	sessOpts := engine.SessionOptions{
		Proxy:              o.proxy,
		TimeoutMs:          o.timeout * 1000,
		ReadTimeoutMs:      o.readTimeout * 1000,
		RedirectMax:        o.redirectMax,
		InsecureSkipVerify: o.insecure,
		Resolve:            o.resolve,
		LocalAddress:       o.localAddress,
		IPVersion:          o.ipVersion,
		HeaderOrder:        o.headerOrder,
		IdentitySync:       o.identitySync,
	}
	switch {
	case o.protocols != "":
		for _, v := range strings.Split(o.protocols, ",") {
			if v = strings.TrimSpace(v); v != "" {
				sessOpts.Protocols = append(sessOpts.Protocols, v)
			}
		}
	case o.h3:
		h3on := true
		sessOpts.H3 = &h3on
	}
	sess, err := engine.NewSession(p, sessOpts)
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	defer sess.Close()

	headers := o.headers
	if o.jsonBody && !hasHeader(headers, "content-type") {
		headers = append(headers, [2]string{"content-type", "application/json"})
	}
	req := &engine.Request{
		Method:     o.method,
		URL:        o.url,
		Headers:    headers,
		ForceHTTP3: o.http3,
	}
	if o.data != "" {
		req.Body = []byte(o.data)
	}

	resp, err := sess.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if o.showHeaders {
		fmt.Fprintf(stdout, "HTTP/1.1 %d %s（%s）\n", resp.Status, resp.Reason(), resp.UsedProtocol)
		for _, kv := range resp.Headers {
			fmt.Fprintf(stdout, "%s: %s\n", kv[0], kv[1])
		}
		fmt.Fprintln(stdout)
	}
	if o.selfcheck {
		sc, err := json.Marshal(resp.SelfCheck)
		if err == nil {
			fmt.Fprintf(stderr, "selfcheck: %s\n", sc)
		}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(stderr, "geektls: 读 body: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		fmt.Fprintln(stdout)
	}
	if o.fail && !resp.OK() {
		return 1
	}
	return 0
}

func hasHeader(headers [][2]string, name string) bool {
	for _, kv := range headers {
		if strings.EqualFold(kv[0], name) {
			return true
		}
	}
	return false
}

// buildProfile 与绑定同一套构造入口 + 同一套自洽归一（profiles.NormalizeForReplay）。
func buildProfile(o *reqOpts, stderr io.Writer) (*profiles.Profile, error) {
	norm := func(p *profiles.Profile, warnings []profiles.Warning, err error) (*profiles.Profile, error) {
		if err != nil {
			return nil, err
		}
		for _, w := range warnings {
			fmt.Fprintf(stderr, "warn %s: %s\n", w.Code, w.Message)
		}
		for _, w := range profiles.NormalizeForReplay(p) {
			fmt.Fprintf(stderr, "warn %s: %s\n", w.Code, w.Message)
		}
		return p, nil
	}
	switch {
	case o.clientHello != "":
		p, w, err := profiles.FromClientHelloHex(o.clientHello)
		return norm(p, w, err)
	case o.ja3 != "":
		p, w, err := profiles.FromJA3(o.ja3)
		return norm(p, w, err)
	case o.ja4r != "":
		p, w, err := profiles.FromJA4R(o.ja4r)
		return norm(p, w, err)
	case o.ja4 != "":
		p, w, err := tlscore.ResolveJA4Profile(o.ja4)
		if err != nil {
			return nil, err
		}
		if strings.Contains(o.ja4, ",") {
			// 含逗号 = 用户给的 JA4R 原始列表（不是短哈希）⇒ 过自洽归一
			return norm(p, w, nil)
		}
		return p, nil
	}
	name := o.profile
	if name == "" {
		name = "chrome_133"
	}
	return profiles.Get(name)
}
