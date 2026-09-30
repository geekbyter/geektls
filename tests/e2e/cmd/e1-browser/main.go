// e1-browser：E1 级证据采集（真实浏览器 ground truth）。
//
// 为什么需要它：我们既有的 MATCH 全部是"同源自证"——profile 转写自 uTLS/tls-client，
// 再发给回读服务比对自算值，只能证明"我们发出的 == 我们想发的"。要证明
// "== 真浏览器"，必须让**真实浏览器**握手一次并抓下它的 ClientHello。
//
// 工作方式（全本地、无外网）：
//  1. 起一个本地 fp 采集端（gospider007/fp，独立解析器 + 自签证书）；
//  2. 启动本机真实浏览器（headless）访问该地址；
//  3. 采集端把解析结果回传给本进程（不依赖浏览器渲染/输出）；
//  4. 用**我们自己的** JA3/JA4 实现从原始 ClientHello 字节计算指纹；
//  5. 与指定（或按 UA 版本推断的）内置预设逐字段对照，报告差异；
//  6. 落盘为证据记录（含原始 ClientHello hex，可直接当后续标本/语料）。
//
// 用法（在 tests/e2e 目录下）：
//
//	go run ./cmd/e1-browser \
//	  -browser "C:\Program Files\Google\Chrome\Application\chrome.exe" \
//	  -name chrome_windows -out ../../profiles/evidence/browsers
//
// 注意：-ignore-certificate-errors 只影响证书校验，不改变 ClientHello 内容。
package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gospider007/fp"
	"github.com/gospider007/gtls"
	"github.com/gospider007/ja3"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

type captured struct {
	rawHex   string
	tlsSpec  *ja3.TlsSpec
	h2Spec   *ja3.H2Spec
	sni      string
	remote   string
	protocol string
}

type extRecord struct {
	Type uint16 `json:"type"`
	Data string `json:"data,omitempty"`
}

type tlsRecord struct {
	Ciphers    []uint16    `json:"ciphers"`
	Extensions []extRecord `json:"extensions"`
	Curves     []uint16    `json:"curves"`
	Points     []uint16    `json:"points"`
	Versions   []uint16    `json:"versions"`
	SigAlgs    []uint16    `json:"sig_algs"`
	ALPN       []string    `json:"alpn"`
}

type h2Record struct {
	Settings       [][2]uint32 `json:"settings"`
	WindowUpdate   uint32      `json:"window_update"`
	RegularHeaders [][2]string `json:"regular_headers"`
}

type computed struct {
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`
	JA4     string `json:"ja4"`
}

type record struct {
	Kind           string     `json:"kind"`
	Name           string     `json:"name"`
	Browser        string     `json:"browser"`
	BrowserVersion string     `json:"browser_version,omitempty"`
	CapturedAt     string     `json:"captured_at"`
	ALPN           string     `json:"alpn"`
	SNI            string     `json:"sni"`
	ClientHelloHex string     `json:"clienthello_hex"`
	TLS            *tlsRecord `json:"tls"`
	H2             *h2Record  `json:"http2,omitempty"`
	Computed       *computed  `json:"computed"`
	ComparedTo     string     `json:"compared_to,omitempty"`
	Diffs          []string   `json:"diffs"`
}

func main() {
	browser := flag.String("browser", "", "浏览器可执行文件路径（必填）")
	name := flag.String("name", "", "证据名（必填，用作文件名）")
	outDir := flag.String("out", "../../profiles/evidence/browsers", "输出目录")
	compare := flag.String("compare", "", "对照的内置预设名（默认按 UA 版本自动推断）")
	timeout := flag.Duration("timeout", 60*time.Second, "等待采集的超时")
	flag.Parse()

	if *browser == "" || *name == "" {
		fatal(fmt.Errorf("-browser 与 -name 必填"))
	}
	if _, err := os.Stat(*browser); err != nil {
		fatal(fmt.Errorf("浏览器不存在: %w", err))
	}

	caps := make(chan captured, 4)
	addr, stop := startOracle(caps)
	defer stop()
	url := fmt.Sprintf("https://localhost:%d/?e1=1", addr)

	cmd, err := launch(*browser, url)
	if err != nil {
		fatal(err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	var cap captured
	select {
	case cap = <-caps:
	case <-time.After(*timeout):
		fatal(fmt.Errorf("等待浏览器访问超时（%s）：%s", *timeout, url))
	}

	rec, err := buildRecord(*name, *browser, cap)
	if err != nil {
		fatal(err)
	}

	// 对照内置预设：优先显式指定，其次按 UA 里的主版本号推断。
	preset := *compare
	if preset == "" {
		preset = pickPreset(cap)
	}
	if preset != "" {
		rec.ComparedTo = preset
		rec.Diffs = comparePreset(preset, cap)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}
	path := filepath.Join(*outDir, *name+".json")
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		fatal(err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal(err)
	}

	fmt.Printf("wrote %s\n", path)
	fmt.Printf("  浏览器 : %s (%s)\n", rec.BrowserVersion, rec.Browser)
	fmt.Printf("  ALPN   : %s   SNI: %s\n", rec.ALPN, rec.SNI)
	fmt.Printf("  JA3    : %s\n", rec.Computed.JA3)
	fmt.Printf("  JA4    : %s\n", rec.Computed.JA4)
	if rec.ComparedTo != "" {
		if len(rec.Diffs) == 0 {
			fmt.Printf("  对照 %s：**完全一致**\n", rec.ComparedTo)
		} else {
			fmt.Printf("  对照 %s：%d 处差异\n", rec.ComparedTo, len(rec.Diffs))
			for _, d := range rec.Diffs {
				fmt.Printf("      - %s\n", d)
			}
		}
	} else {
		fmt.Printf("  对照：未指定且无法按 UA 推断预设\n")
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// startOracle 起本地 fp 采集端，返回端口与停止函数。
func startOracle(caps chan<- captured) (int, func()) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := fp.GetRawConn(r.Context())
		ts := raw.TLSSpec()
		c := captured{
			tlsSpec:  ts,
			h2Spec:   raw.H2Spec(),
			sni:      sniFromSpec(ts),
			remote:   r.RemoteAddr,
			protocol: r.Proto,
		}
		if ts != nil {
			// TlsSpec.Bytes() 返回 fp 在握手前抓下的**原始 ClientHello 字节**。
			c.rawHex = hex.EncodeToString(ts.Bytes())
		}
		caps <- c
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("captured\n"))
	})

	tlsConfig := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return gtls.GetCertificate(chi, nil, nil)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
	ln, err := fp.NewListen("localhost:0", handler, tlsConfig)
	if err != nil {
		fatal(fmt.Errorf("fp listen: %w", err))
	}
	srv := &http.Server{ConnContext: fp.ConnContext, Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcp.Port == 0 {
		fatal(fmt.Errorf("无法获取监听端口: %v", ln.Addr()))
	}
	return tcp.Port, func() { _ = ln.Close() }
}

// launch 用无头模式打开目标地址。--ignore-certificate-errors 只为接受本地自签证书，
// 不影响 ClientHello 内容；--user-data-dir 隔离，绝不碰用户真实配置。
func launch(browser, url string) (*exec.Cmd, error) {
	tmp, err := os.MkdirTemp("", "e1-profile-")
	if err != nil {
		return nil, err
	}
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--ignore-certificate-errors",
		"--user-data-dir=" + tmp,
		"--window-size=800,600",
		url,
	}
	cmd := exec.Command(browser, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动浏览器失败: %w", err)
	}
	return cmd, nil
}

// buildRecord 把一次采集整理为证据记录，并用我们自己的实现计算指纹。
func buildRecord(name, browser string, c captured) (*record, error) {
	if c.tlsSpec == nil {
		return nil, fmt.Errorf("fp 未解析出 TlsSpec")
	}
	rec := &record{
		Kind:           "e1_real_browser",
		Name:           name,
		Browser:        browser,
		BrowserVersion: browserVersion(browser),
		CapturedAt:     time.Now().UTC().Format(time.RFC3339),
		ALPN:           protoName(c.protocol),
		SNI:            c.sni,
		ClientHelloHex: c.rawHex,
		TLS: &tlsRecord{
			Ciphers:  c.tlsSpec.CipherSuites,
			Curves:   u16s(c.tlsSpec.Curves()),
			Points:   u8s(c.tlsSpec.Points()),
			Versions: u16s(c.tlsSpec.Versions()),
			SigAlgs:  u16s(c.tlsSpec.Algorithms()),
			ALPN:     c.tlsSpec.Protocols(),
		},
		Diffs: []string{},
	}
	for _, e := range c.tlsSpec.Extensions {
		rec.TLS.Extensions = append(rec.TLS.Extensions, extRecord{
			Type: e.Type,
			Data: hex.EncodeToString(e.Data),
		})
	}

	// 用我们自己的实现从**原始字节**计算指纹（同 check.go 的规范路径）。
	if c.rawHex != "" {
		p, _, err := profiles.FromClientHelloHex(c.rawHex)
		if err != nil {
			return nil, fmt.Errorf("FromClientHelloHex: %w", err)
		}
		if p.TLS != nil && p.TLS.Detail != nil {
			spec, err := tlscore.CompileDetail(p.TLS.Detail)
			if err != nil {
				return nil, fmt.Errorf("CompileDetail: %w", err)
			}
			ja3str := tlscore.ComputeJA3(spec)
			rec.Computed = &computed{
				JA3:     ja3str,
				JA3Hash: tlscore.JA3Hash(ja3str),
				JA4:     tlscore.ComputeJA4(spec),
			}
		}
	}

	if c.h2Spec != nil {
		var settings [][2]uint32
		for _, s := range c.h2Spec.Settings {
			if isGrease16(uint16(s.ID)) {
				continue
			}
			settings = append(settings, [2]uint32{uint32(s.ID), s.Val})
		}
		rec.H2 = &h2Record{
			Settings:       settings,
			WindowUpdate:   c.h2Spec.ConnFlow,
			RegularHeaders: sanitizeHeaders(c.h2Spec.OrderHeaders),
		}
	}
	return rec, nil
}

// sanitizeHeaders 把记录里的身份头归一成**有头浏览器**形态。
//
// 为什么必须做：采集链路用 `--headless=new`（见 launch），于是 UA 里会多出
// giveaway 令牌——`HeadlessChrome/153.0.0.0 … Edg/153.0.0.0`。无头与有头的
// ClientHello/H2 逐字段相同（已用真机抓包复核，见
// profiles/evidence/browsers/chrome_149_windows_peetws.json），但 UA 这样露出来
// 就是"一眼假"；生成器会把记录里的头原样写进预设，所以必须在记录这一层抹掉。
// （历史：chrome_149_windows / edge_153_windows 曾带着该令牌入库。）
func sanitizeHeaders(in [][2]string) [][2]string {
	out := make([][2]string, 0, len(in))
	for _, kv := range in {
		if strings.EqualFold(kv[0], "user-agent") {
			kv = [2]string{kv[0], strings.ReplaceAll(kv[1], "HeadlessChrome", "Chrome")}
		}
		out = append(out, kv)
	}
	return out
}

// pickPreset 从 H2 常规头里的 UA 推断内置预设（Chrome/Edge/Firefox + 主版本）。
func pickPreset(c captured) string {
	ua := ""
	if c.h2Spec != nil {
		for _, kv := range c.h2Spec.OrderHeaders {
			if strings.EqualFold(kv[0], "user-agent") {
				ua = kv[1]
			}
		}
	}
	if ua == "" {
		return ""
	}
	family := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		family = "edge_"
	case strings.Contains(ua, "Firefox/"):
		family = "firefox_"
	case strings.Contains(ua, "Chrome/"):
		family = "chrome_"
	default:
		return ""
	}
	re := regexp.MustCompile(`(?:Chrome|Edg|Firefox)/(\d+)`)
	m := re.FindStringSubmatch(ua)
	if m == nil {
		return ""
	}
	major := m[1]
	// 优先精确同主版本；否则取版本差最小的（同差取较大者）——跨版本对比的
	// 差异（新增扩展/新增 sig_alg）不是缺陷，工具应尽量选最接近的预设。
	var candidates []string
	for _, n := range profiles.List() {
		if !strings.HasPrefix(n, family) {
			continue
		}
		if n == family+major || strings.HasPrefix(n, family+major+"_") {
			return n
		}
		candidates = append(candidates, n)
	}
	best, bestGap := "", 0
	captureMajor := 0
	_, _ = fmt.Sscanf(major, "%d", &captureMajor)
	for _, n := range candidates {
		rest := strings.TrimPrefix(n, family)
		numPart := rest
		if i := strings.IndexByte(rest, '_'); i >= 0 {
			numPart = rest[:i]
		}
		v := 0
		if _, err := fmt.Sscanf(numPart, "%d", &v); err != nil {
			continue
		}
		gap := v - captureMajor
		if gap < 0 {
			gap = -gap
		}
		if best == "" || gap < bestGap || (gap == bestGap && v > captureMajor) {
			best, bestGap = n, gap
		}
	}
	return best
}

// comparePreset 把采集结果与内置预设逐字段对照（剔除 GREASE 后比较；扩展比集合，
// 因为 Chrome/Edge 每连接洗牌顺序，本身就是随机量）。
func comparePreset(name string, c captured) []string {
	p, err := profiles.Get(name)
	if err != nil || p.TLS == nil || p.TLS.Detail == nil {
		return []string{fmt.Sprintf("无法载入预设 %s: %v", name, err)}
	}
	spec, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		return []string{fmt.Sprintf("预设 %s 编译失败: %v", name, err)}
	}
	ja3parts := strings.Split(tlscore.ComputeJA3(spec), ",")
	if len(ja3parts) != 5 {
		return []string{fmt.Sprintf("预设 %s 的 JA3 形态异常", name)}
	}

	var diffs []string
	if got, want := dropGrease(c.tlsSpec.CipherSuites), dashU16(ja3parts[1]); !eqU16(got, want) {
		diffs = append(diffs, fmt.Sprintf("cipher 列表不同（实浏览器 %d 项 / 预设 %d 项）", len(got), len(want)))
	}
	gotExts := make([]uint16, 0, len(c.tlsSpec.Extensions))
	for _, e := range c.tlsSpec.Extensions {
		gotExts = append(gotExts, e.Type)
	}
	if !sameSet(dropGrease(gotExts), dashU16(ja3parts[2])) {
		diffs = append(diffs, "扩展集合不同："+setDiff(dropGrease(gotExts), dashU16(ja3parts[2])))
	}
	if got, want := dropGrease(u16s(c.tlsSpec.Curves())), dashU16(ja3parts[3]); !eqU16(got, want) {
		diffs = append(diffs, fmt.Sprintf("supported_groups 不同（实浏览器 %v / 预设 %v）", got, want))
	}
	if got, want := u8s(c.tlsSpec.Points()), dashU16(ja3parts[4]); !eqU16(got, want) {
		diffs = append(diffs, fmt.Sprintf("ec_point_formats 不同（实浏览器 %v / 预设 %v）", got, want))
	}
	if got, want := dropGrease(u16s(c.tlsSpec.Versions())), detailVersions(p); !eqU16(got, want) {
		diffs = append(diffs, fmt.Sprintf("supported_versions 不同（实浏览器 %v / 预设 %v）", got, want))
	}
	if got, want := dropGrease(u16s(c.tlsSpec.Algorithms())), detailSigAlgs(p); !eqU16(got, want) {
		diffs = append(diffs, fmt.Sprintf("signature_algorithms 不同（实浏览器 %v / 预设 %v）", got, want))
	}
	if got, want := c.tlsSpec.Protocols(), detailALPN(p); !eqStr(got, want) {
		diffs = append(diffs, fmt.Sprintf("ALPN 不同（实浏览器 %v / 预设 %v）", got, want))
	}
	if c.h2Spec != nil && p.HTTP2 != nil {
		var want [][2]uint32
		for _, kv := range p.HTTP2.Settings {
			if len(kv) == 2 {
				want = append(want, [2]uint32{kv[0], kv[1]})
			}
		}
		var got [][2]uint32
		for _, s := range c.h2Spec.Settings {
			if isGrease16(uint16(s.ID)) {
				continue
			}
			got = append(got, [2]uint32{uint32(s.ID), s.Val})
		}
		if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) || !samePairs(got, want) {
			diffs = append(diffs, fmt.Sprintf("H2 SETTINGS 不同（实浏览器 %v / 预设 %v）", got, want))
		}
		// 连接级 WINDOW_UPDATE：浏览器侧 0 表示抓包里根本没有该帧（增量 0 在 H2 是
		// 协议错误，客户端不会发），故与预设的三态一一对应。
		wf, gf := p.HTTP2.WindowUpdate, c.h2Spec.ConnFlow
		switch {
		case wf == nil && gf != 15663105:
			diffs = append(diffs, fmt.Sprintf("预设未指定 window_update（线上补 15663105），实浏览器为 %d", gf))
		case wf != nil && *wf != gf:
			diffs = append(diffs, fmt.Sprintf("H2 WINDOW_UPDATE 不同（实浏览器 %d / 预设 %d）", gf, *wf))
		}
		if id := p.HTTP2.FirstStreamID; id != 0 && id != c.h2Spec.StreamID {
			diffs = append(diffs, fmt.Sprintf("首个请求 stream_id 不同（实浏览器 %d / 预设 %d）", c.h2Spec.StreamID, id))
		}
	}
	return diffs
}

func browserVersion(path string) string {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	var versions []string
	for _, e := range entries {
		if e.IsDir() && re.MatchString(e.Name()) {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		return ""
	}
	sort.Strings(versions)
	return versions[len(versions)-1]
}

// --- 小工具 ---

func detailVersions(p *profiles.Profile) []uint16 {
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == 43 {
			return hexList(e.Versions)
		}
	}
	return nil
}

func detailSigAlgs(p *profiles.Profile) []uint16 {
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == 13 {
			return hexList(e.SigAlgs)
		}
	}
	return nil
}

func detailALPN(p *profiles.Profile) []string {
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == 16 {
			return e.ALPN
		}
	}
	return nil
}

// hexList 把 profile 的 hex 列表解析为数值，并剔除 GREASE（含 "grease" 占位与
// 字面 0x?a?a——后者在预设里是"记录下来的取值"，比较时应按 GREASE 语义剔除）。
func hexList(vals []string) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if strings.EqualFold(v, profiles.GreaseToken) {
			continue
		}
		var x uint32
		if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(v, "0x")), "%x", &x); err == nil {
			if isGrease16(uint16(x)) {
				continue
			}
			out = append(out, uint16(x))
		}
	}
	return out
}

// setDiff 只报两集合的对称差，避免把"顺序不同"误读成"内容不同"。
func setDiff(a, b []uint16) string {
	inB, inA := map[uint16]bool{}, map[uint16]bool{}
	for _, v := range b {
		inB[v] = true
	}
	for _, v := range a {
		inA[v] = true
	}
	var onlyA, onlyB []uint16
	for _, v := range a {
		if !inB[v] {
			onlyA = append(onlyA, v)
		}
	}
	for _, v := range b {
		if !inA[v] {
			onlyB = append(onlyB, v)
		}
	}
	return fmt.Sprintf("实浏览器独有 %v / 预设独有 %v（%d 项 vs %d 项）", onlyA, onlyB, len(a), len(b))
}

func u16s[T ~uint16](vs []T) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		out = append(out, uint16(v))
	}
	return out
}

func u8s(vs []uint8) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		out = append(out, uint16(v))
	}
	return out
}

// protoName 把 http.Request.Proto 映射为 ALPN 名。
func protoName(p string) string {
	switch p {
	case "HTTP/2.0":
		return "h2"
	case "HTTP/1.1":
		return "http/1.1"
	}
	return p
}

func isGrease16(v uint16) bool { return v>>8 == v&0xff && v&0xf == 0xa }

func dropGrease(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !isGrease16(v) {
			out = append(out, v)
		}
	}
	return out
}

func dashU16(s string) []uint16 {
	if s == "" {
		return nil
	}
	out := []uint16{}
	for _, part := range strings.Split(s, "-") {
		var x uint32
		if _, err := fmt.Sscanf(part, "%d", &x); err == nil {
			out = append(out, uint16(x))
		}
	}
	return out
}

func eqU16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func eqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameSet(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[uint16]int{}
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		m[v]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func samePairs(a, b [][2]uint32) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[[2]uint32]int{}
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		m[v]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

// sniFromSpec 从原始扩展字节里自解析 SNI（fp 的 TlsSpec.ServerName 恒为空）。
func sniFromSpec(ts *ja3.TlsSpec) string {
	if ts == nil {
		return ""
	}
	for _, e := range ts.Extensions {
		if e.Type != 0 {
			continue
		}
		data := []byte(e.Data)
		if len(data) < 2 {
			return ""
		}
		listLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if listLen > len(data) {
			listLen = len(data)
		}
		data = data[:listLen]
		for len(data) >= 3 {
			nameLen := int(data[1])<<8 | int(data[2])
			data = data[3:]
			if nameLen > len(data) {
				return ""
			}
			name := string(data[:nameLen])
			data = data[nameLen:]
			if name != "" {
				return name
			}
		}
	}
	return ""
}
