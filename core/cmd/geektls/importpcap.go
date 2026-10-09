// geektls import-pcap：从 Wireshark/tcpdump 的抓包文件里提取 TLS ClientHello
// 与 TCP SYN 形态，落成 E1p 记录（可直接喂 gen-profiles 生成预设，或喂
// check-profile / clienthello_hex 装载重放）。
//
// 设计取舍（2026-10-08，docs/12-pcap-import.md 的落地版）：
//   - **纯 Go 最小解析，不依赖 tshark**。这里只做"字节级搬运"——按 seq 重组
//     TCP 流、定位 `16 03 0x` record、取完整握手消息——**不做 TLS 字段级解析**
//     （那才是 docs/12 反对的自研 TLS 汇编）。换来的：离线可用、本机可测、
//     CI 无额外依赖；字段级深解（keylog 解密补 H2 面）按 docs/12 §7-2 留作
//     后续支线。
//   - 支持 pcap classic 与 pcapng（Wireshark 默认保存格式）；链路层覆盖
//     Ethernet（含 VLAN 单/多层）、Linux cooked（v1/v2，tcpdump -i any 产物）、
//     raw IP；IPv4/IPv6；其余链路类型**明确报错**（不猜测、不静默跳过）。
//   - 拒绝项照 docs/12 §4：resumption（CH 带非空 PSK(41) ⇒ 装载到别的目标必失败）、
//     缺 SYN 的流（tcp 节无法导出）、抓包有缺口的流（宁缺毋滥）、CH 跨 record
//     （罕见形态，明确报错而不是猜）。
//
// 用法：见 importPcapUsage。
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tlscore "github.com/geekbyter/geektls/core/tls"
)

const importPcapUsage = `geektls import-pcap — 从 Wireshark/tcpdump 抓包提取指纹记录（E1p）

用法：
  geektls import-pcap --pcap <文件> [选项]

选项：
  --pcap <文件>       pcap 或 pcapng（Wireshark 默认保存格式）
  --stream <n>        取第 n 条含 ClientHello 的流（默认 1）
  --all               导出全部含 ClientHello 的流（输出 JSON 数组）
  --tcp-only          不要求 ClientHello，只导 TCP 形态（SYN/TTL/窗口/选项）
  --ua "<UA 串>"      补 user-agent（pcap 里看不到 HTTP 头——它在 TLS 隧道内；
                      给了它，输出记录可直接喂 gen-profiles 生成预设）
  --name <记录名>     默认取 pcap 文件名（去扩展名）
  -o <文件>           输出到文件（默认 stdout）

说明：
  - 输出的 clienthello_hex 是 record 原始字节，可直接：
      geektls check-profile "$(jq -r .clienthello_hex out.json)"
      geektls request <url> --clienthello-hex "$(jq -r .clienthello_hex out.json)"
  - 拒绝的流会在 stderr 说明原因（resumption / 缺 SYN / 抓包缺口 / 无 CH）。
`

func importPcapUsageErr(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "geektls: "+format+"\n\n"+importPcapUsage, args...)
	return 2
}

func cmdImportPcap(args []string, stdout, stderr io.Writer) int {
	var (
		pcapPath, ua, name, outPath string
		streamN                     = 1
		all, tcpOnly                bool
	)
	for i := 0; i < len(args); i++ {
		next := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch args[i] {
		case "--pcap":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --pcap 需要文件路径")
			}
			pcapPath = v
		case "--stream":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --stream 需要数字")
			}
			n := 0
			if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
				return importPcapUsageErr(stderr, "import-pcap --stream 需要正整数（收到 %q）", v)
			}
			streamN = n
		case "--all":
			all = true
		case "--tcp-only":
			tcpOnly = true
		case "--ua":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --ua 需要 UA 串")
			}
			ua = v
		case "--name":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --name 需要记录名")
			}
			name = v
		case "-o":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap -o 需要文件路径")
			}
			outPath = v
		default:
			return importPcapUsageErr(stderr, "import-pcap: 未知参数 %q", args[i])
		}
	}
	if pcapPath == "" {
		return importPcapUsageErr(stderr, "import-pcap 需要 --pcap <文件>")
	}
	if all && streamN != 1 {
		return importPcapUsageErr(stderr, "--all 与 --stream 不能同时给")
	}
	if name == "" {
		base := filepath.Base(pcapPath)
		name = strings.TrimSuffix(base, filepath.Ext(base))
	}

	pkts, linkType, firstTS, err := readCaptureFile(pcapPath)
	if err != nil {
		fmt.Fprintf(stderr, "geektls: 读取 %s: %v\n", pcapPath, err)
		return 1
	}
	if len(pkts) == 0 {
		fmt.Fprintf(stderr, "geektls: %s 里没有数据包\n", pcapPath)
		return 1
	}

	flows := buildFlows(pkts, linkType)
	if len(flows) == 0 {
		fmt.Fprintf(stderr, "geektls: 没有解析出 TCP 流（链路类型 %d；支持：Ethernet/VLAN、Linux cooked、raw IP）\n", linkType)
		return 1
	}

	// 候选筛选：逐流给出"入选或拒绝原因"，错误信息按 docs/12 §7 的拒绝项口径。
	type candidate struct {
		flow *tcpFlow
		ch   []byte // nil = 未要求（--tcp-only）
	}
	var (
		cands  []candidate
		reason []string
	)
	for _, f := range flows {
		stream, serr := f.clientStream()
		if f.clientSYN == nil {
			reason = append(reason, fmt.Sprintf("%s → 缺 SYN（tcp 节无法导出）", f.label()))
			continue
		}
		if serr != nil {
			reason = append(reason, fmt.Sprintf("%s → %v", f.label(), serr))
			continue
		}
		if tcpOnly {
			cands = append(cands, candidate{flow: f})
			continue
		}
		ch, cerr := extractClientHelloRecord(stream)
		if cerr != nil {
			reason = append(reason, fmt.Sprintf("%s → %v", f.label(), cerr))
			continue
		}
		if clientHelloHasResumption(ch) {
			reason = append(reason, fmt.Sprintf("%s → CH 带非空 PSK(41)（resumption 形态，装载到别的目标必失败）", f.label()))
			continue
		}
		cands = append(cands, candidate{flow: f, ch: ch})
	}

	for _, r := range reason {
		fmt.Fprintf(stderr, "geektls: 跳过 %s\n", r)
	}
	if len(cands) == 0 {
		fmt.Fprintf(stderr, "geektls: 没有可导出的流（--tcp-only 可放宽 ClientHello 要求）\n")
		return 1
	}
	if !all && streamN > len(cands) {
		fmt.Fprintf(stderr, "geektls: --stream %d 超出范围（共 %d 条可导出的流）\n", streamN, len(cands))
		return 1
	}

	makeRecord := func(c candidate, idx int) (*pcapFingerprintRecord, error) {
		syn := c.flow.clientSYN
		rec := &pcapFingerprintRecord{
			Kind:   "e1p_pcap",
			Name:   name,
			Grade:  "E1p",
			Source: fmt.Sprintf("pcap:%s#%d", filepath.Base(pcapPath), idx),
			TCP: &recordTCP{
				TTL:          syn.ttl,
				MSS:          syn.mss,
				WindowSize:   syn.window,
				WindowScale:  syn.wscale,
				OptionsOrder: syn.optOrder,
				DF:           syn.df,
			},
		}
		if firstTS > 0 {
			rec.CapturedAt = time.Unix(firstTS, 0).UTC().Format(time.RFC3339)
		}
		if len(c.ch) > 0 {
			rec.ClientHelloHex = hex.EncodeToString(c.ch)
			if res, err := tlscore.CheckProfile(rec.ClientHelloHex); err == nil {
				rec.JA3, rec.JA3Hash, rec.JA4 = res.JA3, res.JA3Hash, res.JA4
			}
		}
		if ua != "" {
			// UA 只能由调用方补（HTTP 头在 TLS 隧道内，明文 pcap 看不到）。
			// 给了 UA 的记录可直接进 gen-profiles（它要求 kind=e1p_pcap/e1_real_browser + UA）。
			rec.HTTP2 = &recordHTTP2{RegularHeaders: [][2]string{{"user-agent", ua}}}
		}
		return rec, nil
	}

	var out []byte
	if all {
		recs := make([]*pcapFingerprintRecord, 0, len(cands))
		for i, c := range cands {
			rec, _ := makeRecord(c, i+1)
			recs = append(recs, rec)
		}
		out, err = json.MarshalIndent(recs, "", "  ")
	} else {
		rec, rerr := makeRecord(cands[streamN-1], streamN)
		if rerr != nil {
			fmt.Fprintf(stderr, "geektls: %v\n", rerr)
			return 1
		}
		out, err = json.MarshalIndent(rec, "", "  ")
	}
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	out = append(out, '\n')

	if outPath != "" {
		if err := os.WriteFile(outPath, out, 0o644); err != nil {
			fmt.Fprintf(stderr, "geektls: 写 %s: %v\n", outPath, err)
			return 1
		}
		fmt.Fprintf(stderr, "geektls: 已写入 %s（kind=e1p_pcap，grade=E1p）\n", outPath)
		return 0
	}
	_, _ = stdout.Write(out)
	return 0
}

// ---------- 抓包文件读取（pcap classic + pcapng） ----------

type capturedPacket struct {
	data []byte // 链路层帧字节
}

// readCaptureFile 返回全部帧、链路类型与首页时间（unix 秒，用于 captured_at）。
func readCaptureFile(path string) ([]capturedPacket, int, int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(b) < 4 {
		return nil, 0, 0, errors.New("文件太小，不是抓包文件")
	}
	if binary.BigEndian.Uint32(b[:4]) == 0x0a0d0d0a {
		return parsePcapng(b)
	}
	return parsePcapClassic(b)
}

func parsePcapClassic(b []byte) ([]capturedPacket, int, int64, error) {
	if len(b) < 24 {
		return nil, 0, 0, errors.New("pcap 全局头不完整")
	}
	var order binary.ByteOrder
	magicBE := binary.BigEndian.Uint32(b[:4])
	magicLE := binary.LittleEndian.Uint32(b[:4])
	switch {
	case magicBE == 0xa1b2c3d4 || magicBE == 0xa1b23c4d:
		order = binary.BigEndian
	case magicLE == 0xa1b2c3d4 || magicLE == 0xa1b23c4d:
		order = binary.LittleEndian
	default:
		return nil, 0, 0, fmt.Errorf("未知的文件 magic %08x（不是 pcap/pcapng）", magicBE)
	}
	linkType := int(order.Uint32(b[20:24]))
	var (
		pkts    []capturedPacket
		firstTS int64
	)
	off := 24
	for off+16 <= len(b) {
		tsSec := int64(order.Uint32(b[off : off+4]))
		incl := int(order.Uint32(b[off+8 : off+12]))
		off += 16
		if incl < 0 || off+incl > len(b) {
			return nil, 0, 0, errors.New("pcap 记录越界（文件被截断？）")
		}
		if firstTS == 0 {
			firstTS = tsSec
		}
		pkts = append(pkts, capturedPacket{data: b[off : off+incl]})
		off += incl
	}
	return pkts, linkType, firstTS, nil
}

func parsePcapng(b []byte) ([]capturedPacket, int, int64, error) {
	var order binary.ByteOrder = binary.LittleEndian // 由 SHB 的字节序标记确定
	linkType := -1
	var (
		pkts    []capturedPacket
		firstTS int64
	)
	off := 0
	for off+12 <= len(b) {
		blockType := binary.BigEndian.Uint32(b[off : off+4])
		blockLen := 0
		if blockType == 0x0a0d0d0a { // SHB：先定序，再按该序读长度
			bom := b[off+8 : off+12]
			switch {
			case binary.BigEndian.Uint32(bom) == 0x1a2b3c4d:
				order = binary.BigEndian
			case binary.LittleEndian.Uint32(bom) == 0x1a2b3c4d:
				order = binary.LittleEndian
			default:
				return nil, 0, 0, errors.New("pcapng Section Header 字节序标记异常")
			}
			blockLen = int(order.Uint32(b[off+4 : off+8]))
		} else {
			blockType = order.Uint32(b[off : off+4])
			blockLen = int(order.Uint32(b[off+4 : off+8]))
		}
		if blockLen < 12 || off+blockLen > len(b) {
			break // 截断/尾部垃圾：停止（宽容，前面的包已拿到）
		}
		body := b[off+8 : off+blockLen-4]
		switch blockType {
		case 0x00000001: // Interface Description Block
			if len(body) >= 2 && linkType == -1 {
				linkType = int(order.Uint16(body[0:2]))
			}
		case 0x00000006, 0x00000002: // Enhanced Packet Block / 旧版 Packet Block
			// 两者固定头都是 20 字节——EPB：iface(4)+tsHigh(4)+tsLow(4)+caplen(4)+origlen(4)；
			// PB：iface(2)+drops(2)+后四项同上。caplen 都在 body[12:16]，data 从 [20:] 起。
			if len(body) < 20 {
				break
			}
			caplen := int(order.Uint32(body[12:16]))
			if 20+caplen > len(body) {
				break
			}
			hi := int64(order.Uint32(body[4:8]))
			lo := int64(order.Uint32(body[8:12]))
			if firstTS == 0 {
				// 默认分辨率微秒（if_tsresol 的非常规取值不处理——captured_at 只是辅助字段）
				firstTS = (hi<<32 | lo) / 1_000_000
			}
			pkts = append(pkts, capturedPacket{data: body[20 : 20+caplen]})
		}
		off += blockLen
	}
	if linkType == -1 {
		return nil, 0, 0, errors.New("pcapng 里没有 Interface Description Block（空文件？）")
	}
	return pkts, linkType, firstTS, nil
}

// ---------- 链路层 / IP / TCP 解析 ----------

type tcpPacket struct {
	srcIP, dstIP     string
	srcPort, dstPort int
	ttl              int
	df               bool
	flags            uint8
	window           int
	seq              uint32
	mss, wscale      int
	optOrder         []string
	payload          []byte
}

const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

func parseFrame(linkType int, frame []byte) (tcpPacket, bool) {
	switch linkType {
	case 1: // Ethernet
		if len(frame) < 14 {
			return tcpPacket{}, false
		}
		et := int(binary.BigEndian.Uint16(frame[12:14]))
		off := 14
		for et == 0x8100 || et == 0x88a8 { // VLAN（常见单层；多层循环同样处理）
			if off+4 > len(frame) {
				return tcpPacket{}, false
			}
			et = int(binary.BigEndian.Uint16(frame[off+2 : off+4]))
			off += 4
		}
		return parseIP(frame[off:], et)
	case 113: // Linux cooked v1（tcpdump -i any）
		if len(frame) < 16 {
			return tcpPacket{}, false
		}
		return parseIP(frame[16:], int(binary.BigEndian.Uint16(frame[14:16])))
	case 276: // Linux cooked v2
		if len(frame) < 20 {
			return tcpPacket{}, false
		}
		return parseIP(frame[20:], int(binary.BigEndian.Uint16(frame[0:2])))
	case 101, 228, 229: // raw IP（DLT_RAW / RawIPv4 / RawIPv6）
		if len(frame) < 1 {
			return tcpPacket{}, false
		}
		switch frame[0] >> 4 {
		case 4:
			return parseIP(frame, 0x0800)
		case 6:
			return parseIP(frame, 0x86dd)
		}
		return tcpPacket{}, false
	default:
		return tcpPacket{}, false
	}
}

func parseIP(b []byte, etherType int) (tcpPacket, bool) {
	switch etherType {
	case 0x0800: // IPv4
		if len(b) < 20 || b[0]>>4 != 4 {
			return tcpPacket{}, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || ihl > len(b) {
			return tcpPacket{}, false
		}
		frag := binary.BigEndian.Uint16(b[6:8])
		if frag&0x1fff != 0 {
			return tcpPacket{}, false // 非首片（后续片无 TCP 头）
		}
		if b[9] != 6 {
			return tcpPacket{}, false // 非 TCP
		}
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if total >= ihl && total <= len(b) {
			b = b[:total]
		}
		p := tcpPacket{
			srcIP: net.IP(b[12:16]).String(),
			dstIP: net.IP(b[16:20]).String(),
			ttl:   int(b[8]),
			df:    frag&0x4000 != 0,
		}
		return parseTCP(b[ihl:], p)
	case 0x86dd: // IPv6
		if len(b) < 40 || b[0]>>4 != 6 {
			return tcpPacket{}, false
		}
		if b[6] != 6 {
			return tcpPacket{}, false // 有扩展头（不支持，如实跳过）
		}
		p := tcpPacket{
			srcIP: net.IP(b[8:24]).String(),
			dstIP: net.IP(b[24:40]).String(),
			ttl:   int(b[7]), // hop limit
			df:    false,     // IPv6 无 DF 位
		}
		return parseTCP(b[40:], p)
	}
	return tcpPacket{}, false
}

func parseTCP(b []byte, p tcpPacket) (tcpPacket, bool) {
	if len(b) < 20 {
		return tcpPacket{}, false
	}
	p.srcPort = int(binary.BigEndian.Uint16(b[0:2]))
	p.dstPort = int(binary.BigEndian.Uint16(b[2:4]))
	p.seq = binary.BigEndian.Uint32(b[4:8])
	p.window = int(binary.BigEndian.Uint16(b[14:16]))
	doff := int(b[12]>>4) * 4
	p.flags = b[13]
	if doff < 20 || doff > len(b) {
		return tcpPacket{}, false
	}
	p.mss, p.wscale, p.optOrder = parseTCPOptions(b[20:doff])
	p.payload = b[doff:]
	return p, true
}

// parseTCPOptions 解析 SYN 选项，名字与 core/tcp/raw_linux.go 的 optionsFor 对齐
// （mss/sack/ts/nop/ws）——这样导出的 options_order 能直接喂 profile.tcp。
func parseTCPOptions(b []byte) (mss, wscale int, order []string) {
	i := 0
	for i < len(b) {
		kind := b[i]
		if kind == 0 { // EOL：填充，不落到 options_order（真机 SYN 通常不带 EOL 记录）
			break
		}
		if kind == 1 { // NOP
			order = append(order, "nop")
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if l < 2 || i+l > len(b) {
			break
		}
		switch kind {
		case 2: // MSS
			order = append(order, "mss")
			if l == 4 {
				mss = int(binary.BigEndian.Uint16(b[i+2 : i+4]))
			}
		case 3: // Window scale
			order = append(order, "ws")
			if l == 3 {
				wscale = int(b[i+2])
			}
		case 4:
			order = append(order, "sack")
		case 8:
			order = append(order, "ts")
		default:
			order = append(order, fmt.Sprintf("kind-%d", kind)) // 未知选项如实带出
		}
		i += l
	}
	return mss, wscale, order
}

// ---------- TCP 流重组 ----------

type endpoint struct {
	ip   string
	port int
}

type flowKey struct {
	a, b endpoint // 排序后的一对端点（保证双向同键）
}

type tcpSeg struct {
	rel     int64 // 相对序列号（相对 client SYN 的 seq+1）
	payload []byte
}

type tcpFlow struct {
	clientEP  endpoint
	clientSYN *tcpPacket
	segs      []tcpSeg
}

func (f *tcpFlow) label() string {
	return fmt.Sprintf("%s:%d", f.clientEP.ip, f.clientEP.port)
}

func keyOf(p tcpPacket) flowKey {
	e1 := endpoint{p.srcIP, p.srcPort}
	e2 := endpoint{p.dstIP, p.dstPort}
	if e1.ip < e2.ip || (e1.ip == e2.ip && e1.port <= e2.port) {
		return flowKey{a: e1, b: e2}
	}
	return flowKey{a: e2, b: e1}
}

func buildFlows(pkts []capturedPacket, linkType int) []*tcpFlow {
	byKey := map[flowKey]*tcpFlow{}
	var order []flowKey
	parsed := make([]tcpPacket, 0, len(pkts))
	for _, cp := range pkts {
		p, ok := parseFrame(linkType, cp.data)
		if !ok {
			continue
		}
		k := keyOf(p)
		if byKey[k] == nil {
			byKey[k] = &tcpFlow{}
			order = append(order, k)
		}
		// client 端 = 发 SYN 不发 ACK 的那端（首包）
		if p.flags&flagSYN != 0 && p.flags&flagACK == 0 {
			f := byKey[k]
			if f.clientSYN == nil {
				q := p
				f.clientSYN = &q
				f.clientEP = endpoint{p.srcIP, p.srcPort}
			}
		}
		parsed = append(parsed, p)
	}
	// 第二遍：收集 client→server 方向的 payload（相对 SYN 的 seq+1）
	for _, p := range parsed {
		f := byKey[keyOf(p)]
		if f == nil || f.clientSYN == nil {
			continue
		}
		if p.srcIP != f.clientEP.ip || p.srcPort != f.clientEP.port {
			continue
		}
		if len(p.payload) == 0 {
			continue
		}
		rel := int64(p.seq-f.clientSYN.seq) - 1
		f.segs = append(f.segs, tcpSeg{rel: rel, payload: p.payload})
	}
	out := make([]*tcpFlow, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}

// clientStream 按 seq 重组 client 方向字节流；乱序容忍、重传去重；
// **有缺口直接报错**（宁缺毋滥：缺口可能截断 ClientHello，拼出半份更危险）。
func (f *tcpFlow) clientStream() ([]byte, error) {
	if f.clientSYN == nil {
		return nil, errors.New("缺 SYN（tcp 节无法导出）")
	}
	if len(f.segs) == 0 {
		return nil, errors.New("client 方向没有数据段")
	}
	segs := append([]tcpSeg(nil), f.segs...)
	sort.Slice(segs, func(i, j int) bool { return segs[i].rel < segs[j].rel })
	var out bytes.Buffer
	next := int64(0)
	for _, s := range segs {
		if s.rel > next {
			return nil, fmt.Errorf("抓包有缺口（相对偏移 %d 处缺 %d 字节）", next, s.rel-next)
		}
		if int64(len(s.payload)) <= next-s.rel {
			continue // 完全重复（重传）
		}
		out.Write(s.payload[next-s.rel:])
		next = s.rel + int64(len(s.payload))
	}
	return out.Bytes(), nil
}

// ---------- ClientHello 提取（字节级；不做字段级 TLS 解析） ----------

// extractClientHelloRecord 在重组后的流里定位 `16 03 0x` record，返回
// **完整 record 字节**（含 5 字节 record 头）——即 clienthello_hex 的语义。
func extractClientHelloRecord(stream []byte) ([]byte, error) {
	for i := 0; i+5 <= len(stream); i++ {
		if stream[i] != 0x16 || stream[i+1] != 0x03 || stream[i+2] < 0x01 || stream[i+2] > 0x04 {
			continue
		}
		l := int(stream[i+3])<<8 | int(stream[i+4])
		if l == 0 || i+5+l > len(stream) {
			return nil, fmt.Errorf("record 截断（需要 %d 字节，流里只剩 %d）", 5+l, len(stream)-i)
		}
		body := stream[i+5 : i+5+l]
		if body[0] != 0x01 { // 不是 ClientHello（如 ServerHello/别的 handshake）：继续扫
			continue
		}
		if len(body) < 4 {
			return nil, errors.New("ClientHello 头截断")
		}
		hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		if 4+hsLen > len(body) {
			return nil, fmt.Errorf("ClientHello 跨 record（需要 %d 字节，单 record 只有 %d）——罕见形态未支持",
				4+hsLen, len(body))
		}
		return stream[i : i+5+l], nil
	}
	return nil, errors.New("流里没有 ClientHello")
}

// clientHelloHasResumption 判断 CH record 是否带**非空** pre_shared_key(41)
// （= resumption/0-RTT 形态，装载到别的目标必失败，docs/12 §4-1 的拒绝项）。
// 空 payload 的 41 是我们引擎的"占位"形态，不算 resumption。
func clientHelloHasResumption(chRecord []byte) bool {
	if len(chRecord) < 9 {
		return false
	}
	hs := chRecord[5:] // 跳过 record 头
	if len(hs) < 4 {
		return false
	}
	body := hs[4:]
	off := 2 + 32 // legacy_version + random
	if off+1 > len(body) {
		return false
	}
	off += 1 + int(body[off]) // session_id
	if off+2 > len(body) {
		return false
	}
	off += 2 + int(binary.BigEndian.Uint16(body[off:])) // cipher_suites
	if off+1 > len(body) {
		return false
	}
	off += 1 + int(body[off]) // compression_methods
	if off+2 > len(body) {
		return false
	}
	total := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	end := off + total
	if end > len(body) {
		end = len(body)
	}
	for off+4 <= end {
		typ := int(binary.BigEndian.Uint16(body[off:]))
		l := int(binary.BigEndian.Uint16(body[off+2:]))
		off += 4
		if off+l > len(body) {
			return false
		}
		if typ == 41 && l > 0 {
			return true
		}
		off += l
	}
	return false
}

// ---------- E1p 记录（输出 schema） ----------

// pcapFingerprintRecord 与 profiles/evidence/browsers/*.json 同族；
// kind=e1p_pcap、grade=E1p 与 E1 记录区分（gen-profiles 两者都接受）。
type pcapFingerprintRecord struct {
	Kind           string       `json:"kind"`
	Name           string       `json:"name,omitempty"`
	Grade          string       `json:"grade"`
	Source         string       `json:"source"`
	CapturedAt     string       `json:"captured_at,omitempty"`
	ClientHelloHex string       `json:"clienthello_hex,omitempty"`
	JA3            string       `json:"ja3,omitempty"`
	JA3Hash        string       `json:"ja3_hash,omitempty"`
	JA4            string       `json:"ja4,omitempty"`
	TCP            *recordTCP   `json:"tcp,omitempty"`
	HTTP2          *recordHTTP2 `json:"http2,omitempty"`
}

// recordTCP 与 profiles.TCPProfile 的观测字段对齐（不含 mode 等控制项——
// 那是"怎么实现"，不是"抓到了什么"）。
type recordTCP struct {
	TTL          int      `json:"ttl,omitempty"`
	MSS          int      `json:"mss,omitempty"`
	WindowSize   int      `json:"window_size,omitempty"`
	WindowScale  int      `json:"window_scale,omitempty"`
	OptionsOrder []string `json:"options_order,omitempty"`
	DF           bool     `json:"df,omitempty"`
}

type recordHTTP2 struct {
	RegularHeaders [][2]string `json:"regular_headers"`
}
