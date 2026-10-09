// import-pcap 的合成抓包测试：不依赖 tshark / 真实 pcap——
// 帧与文件全部在测试里按字节构造，覆盖：
//   - pcap classic 与 pcapng 两种容器
//   - CH 跨 TCP 段 + 乱序到达（重组与排序）
//   - SYN 选项/TTL/窗口/DF 的导出
//   - 四类拒绝：resumption（非空 PSK 41）/ 缺 SYN / 抓包缺口 / 无 CH
//   - --ua / --all / --tcp-only 的行为
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- 合成帧 ----------

func ip4Frame(srcIP, dstIP string, sport, dport int, seq, ack uint32, flags uint8, win, ttl int, df bool, opts, payload []byte) []byte {
	tcpHdr := 20 + len(opts)
	tcpSeg := make([]byte, tcpHdr)
	binary.BigEndian.PutUint16(tcpSeg[0:], uint16(sport))
	binary.BigEndian.PutUint16(tcpSeg[2:], uint16(dport))
	binary.BigEndian.PutUint32(tcpSeg[4:], seq)
	binary.BigEndian.PutUint32(tcpSeg[8:], ack)
	tcpSeg[12] = byte(tcpHdr/4) << 4
	tcpSeg[13] = flags
	binary.BigEndian.PutUint16(tcpSeg[14:], uint16(win))
	copy(tcpSeg[20:], opts)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+tcpHdr+len(payload)))
	if df {
		binary.BigEndian.PutUint16(ip[6:], 0x4000)
	}
	ip[8] = byte(ttl)
	ip[9] = 6 // TCP
	copy(ip[12:16], net.ParseIP(srcIP).To4())
	copy(ip[16:20], net.ParseIP(dstIP).To4())

	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00 // IPv4
	return append(append(append(eth, ip...), tcpSeg...), payload...)
}

// synOpts：MSS 1460 + NOP + wscale 8 + NOP NOP + SACK（真机 Chrmo/Windows 同款形状）。
func synOpts() []byte {
	return []byte{
		0x02, 0x04, 0x05, 0xb4,
		0x01,
		0x03, 0x03, 0x08,
		0x01, 0x01,
		0x04, 0x02,
	}
}

// buildCH 造结构合法的最小 ClientHello record（16 03 01 开头）；
// psk=true 时带非空 pre_shared_key(41)（resumption 形态）。
func buildCH(psk bool) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0xAB}, 32)...) // random
	body = append(body, 0x00)                              // session_id len
	body = append(body, 0x00, 0x02, 0x13, 0x01)            // cipher_suites
	body = append(body, 0x01, 0x00)                        // compression
	var ext []byte
	if psk {
		ext = append(ext, 0x00, 0x29, 0x00, 0x05, 0x00, 0x03, 0x01, 0x02, 0x03)
	} else {
		ext = append(ext, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// ---------- 合成抓包文件 ----------

func writePcapClassic(frames ...[]byte) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(hdr[4:], 2)
	binary.LittleEndian.PutUint32(hdr[8:], 4)
	binary.LittleEndian.PutUint32(hdr[20:], 1) // linktype Ethernet
	b.Write(hdr)
	for i, f := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		b.Write(rec)
		b.Write(f)
	}
	return b.Bytes()
}

func writePcapng(frames ...[]byte) []byte {
	var b bytes.Buffer
	shb := make([]byte, 16)
	binary.LittleEndian.PutUint32(shb[0:], 0x1a2b3c4d)
	binary.LittleEndian.PutUint32(shb[4:], 1) // version 1.0
	binary.LittleEndian.PutUint32(shb[8:], 0xffffffff)
	binary.LittleEndian.PutUint32(shb[12:], 0xffffffff)
	writeNgBlock(&b, 0x0a0d0d0a, shb)

	idb := make([]byte, 8)
	binary.LittleEndian.PutUint16(idb[0:], 1) // linktype Ethernet
	binary.LittleEndian.PutUint32(idb[4:], 65535)
	writeNgBlock(&b, 0x00000001, idb)

	for i, f := range frames {
		pad := (4 - len(f)%4) % 4
		body := make([]byte, 20+len(f)+pad)
		binary.LittleEndian.PutUint32(body[8:], uint32(1700000000+i)) // ts low（µs 分辨率下低 32 位）
		binary.LittleEndian.PutUint32(body[12:], uint32(len(f)))      // caplen
		binary.LittleEndian.PutUint32(body[16:], uint32(len(f)))      // origlen
		copy(body[20:], f)
		writeNgBlock(&b, 0x00000006, body) // EPB
	}
	return b.Bytes()
}

func writeNgBlock(b *bytes.Buffer, typ uint32, body []byte) {
	total := 12 + len(body)
	w := make([]byte, 8)
	binary.LittleEndian.PutUint32(w[0:], typ)
	binary.LittleEndian.PutUint32(w[4:], uint32(total))
	b.Write(w)
	b.Write(body)
	tail := make([]byte, 4)
	binary.LittleEndian.PutUint32(tail, uint32(total))
	b.Write(tail)
}

// sessionFrames 造一条完整会话：SYN(带选项) + SYN-ACK + ACK + CH 分两段（乱序）。
func sessionFrames(ch []byte, sport int) [][]byte {
	const (
		src = "192.168.1.10"
		dst = "93.184.216.34"
	)
	half := len(ch) / 2
	return [][]byte{
		ip4Frame(src, dst, sport, 443, 1000, 0, flagSYN, 64240, 64, true, synOpts(), nil),
		ip4Frame(dst, src, 443, sport, 5000, 1001, flagSYN|flagACK, 65535, 57, false, nil, nil),
		ip4Frame(src, dst, sport, 443, 1001, 5001, flagACK, 64240, 64, false, nil, nil),
		// 后一段先到（乱序），测 seq 排序
		ip4Frame(src, dst, sport, 443, 1001+uint32(half), 5001, flagACK, 64240, 64, false, nil, ch[half:]),
		ip4Frame(src, dst, sport, 443, 1001, 5001, flagACK, 64240, 64, false, nil, ch[:half]),
	}
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------- 测试 ----------

func TestImportPcapClassic(t *testing.T) {
	ch := buildCH(false)
	path := writeTemp(t, "cap.pcap", writePcapClassic(sessionFrames(ch, 51423)...))

	var stdout, stderr bytes.Buffer
	if code := cmdImportPcap([]string{"--pcap", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var rec pcapFingerprintRecord
	if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
		t.Fatalf("输出不是 JSON: %v\n%s", err, stdout.String())
	}
	if rec.Kind != "e1p_pcap" || rec.Grade != "E1p" {
		t.Errorf("kind/grade = %q/%q, want e1p_pcap/E1p", rec.Kind, rec.Grade)
	}
	if rec.ClientHelloHex != hex.EncodeToString(ch) {
		t.Errorf("clienthello_hex 不一致\n got %s\nwant %s", rec.ClientHelloHex, hex.EncodeToString(ch))
	}
	if rec.TCP == nil {
		t.Fatal("缺 tcp 节")
	}
	if rec.TCP.MSS != 1460 || rec.TCP.WindowScale != 8 || rec.TCP.WindowSize != 64240 ||
		rec.TCP.TTL != 64 || !rec.TCP.DF {
		t.Errorf("tcp 节 = %+v（want mss=1460 ws=8 win=64240 ttl=64 df=true）", rec.TCP)
	}
	wantOrder := "mss,nop,ws,nop,nop,sack"
	if got := strings.Join(rec.TCP.OptionsOrder, ","); got != wantOrder {
		t.Errorf("options_order = %q, want %q", got, wantOrder)
	}
}

func TestImportPcapng(t *testing.T) {
	ch := buildCH(false)
	path := writeTemp(t, "cap.pcapng", writePcapng(sessionFrames(ch, 52000)...))

	var stdout, stderr bytes.Buffer
	if code := cmdImportPcap([]string{"--pcap", path, "--ua", "Mozilla/5.0 Test/1.0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var rec pcapFingerprintRecord
	if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
		t.Fatalf("输出不是 JSON: %v\n%s", err, stdout.String())
	}
	if rec.ClientHelloHex != hex.EncodeToString(ch) {
		t.Errorf("pcapng 的 clienthello_hex 不一致")
	}
	if rec.HTTP2 == nil || len(rec.HTTP2.RegularHeaders) != 1 ||
		rec.HTTP2.RegularHeaders[0][0] != "user-agent" {
		t.Errorf("--ua 应写入 http2.regular_headers（gen-profiles 的 UA 来源），got %+v", rec.HTTP2)
	}
	if rec.Name != "cap" {
		t.Errorf("默认记录名 = %q, want cap（文件名去扩展）", rec.Name)
	}
	if !strings.Contains(rec.Source, "#1") {
		t.Errorf("source = %q, want 含 #1", rec.Source)
	}
}

func TestImportPcapRejects(t *testing.T) {
	src, dst := "192.168.1.10", "93.184.216.34"
	chOK := buildCH(false)

	t.Run("resumption", func(t *testing.T) {
		frames := sessionFrames(buildCH(true), 51423)
		path := writeTemp(t, "r.pcap", writePcapClassic(frames...))
		var stdout, stderr bytes.Buffer
		if code := cmdImportPcap([]string{"--pcap", path}, &stdout, &stderr); code != 1 {
			t.Fatalf("resumption 流应被拒绝（exit=1），got %d，stdout=%s", code, stdout.String())
		}
		if !strings.Contains(stderr.String(), "resumption") {
			t.Errorf("stderr 应说明 resumption 原因：%s", stderr.String())
		}
	})

	t.Run("missing SYN", func(t *testing.T) {
		frames := sessionFrames(chOK, 51423)
		path := writeTemp(t, "nosyn.pcap", writePcapClassic(frames[1:]...)) // 丢首包 SYN
		var stdout, stderr bytes.Buffer
		if code := cmdImportPcap([]string{"--pcap", path}, &stdout, &stderr); code != 1 {
			t.Fatalf("缺 SYN 应被拒绝，got %d", code)
		}
		if !strings.Contains(stderr.String(), "缺 SYN") {
			t.Errorf("stderr 应说明缺 SYN：%s", stderr.String())
		}
	})

	t.Run("gap", func(t *testing.T) {
		// 只有第二段（第一段丢失）⇒ 流首相对偏移 > 0，报缺口
		frames := [][]byte{
			ip4Frame(src, dst, 51423, 443, 1000, 0, flagSYN, 64240, 64, true, synOpts(), nil),
			ip4Frame(dst, src, 443, 51423, 5000, 1001, flagSYN|flagACK, 65535, 57, false, nil, nil),
			ip4Frame(src, dst, 51423, 443, 1001+10, 5001, flagACK, 64240, 64, false, nil, chOK),
		}
		path := writeTemp(t, "gap.pcap", writePcapClassic(frames...))
		var stdout, stderr bytes.Buffer
		if code := cmdImportPcap([]string{"--pcap", path}, &stdout, &stderr); code != 1 {
			t.Fatalf("缺口流应被拒绝，got %d", code)
		}
		if !strings.Contains(stderr.String(), "缺口") {
			t.Errorf("stderr 应说明缺口：%s", stderr.String())
		}
	})

	t.Run("no ClientHello", func(t *testing.T) {
		junk := bytes.Repeat([]byte{0xDE, 0xAD}, 40)
		frames := sessionFrames(junk, 51423)
		path := writeTemp(t, "junk.pcap", writePcapClassic(frames...))
		var stdout, stderr bytes.Buffer
		if code := cmdImportPcap([]string{"--pcap", path}, &stdout, &stderr); code != 1 {
			t.Fatalf("无 CH 应被拒绝，got %d", code)
		}
		if !strings.Contains(stderr.String(), "没有 ClientHello") {
			t.Errorf("stderr 应说明无 CH：%s", stderr.String())
		}
	})
}

func TestImportPcapTCPOnly(t *testing.T) {
	junk := bytes.Repeat([]byte{0x11}, 20)
	frames := sessionFrames(junk, 51423)
	path := writeTemp(t, "t.pcap", writePcapClassic(frames...))

	var stdout, stderr bytes.Buffer
	if code := cmdImportPcap([]string{"--pcap", path, "--tcp-only"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--tcp-only 应成功（不要求 CH），exit=%d stderr=%s", code, stderr.String())
	}
	var rec pcapFingerprintRecord
	if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ClientHelloHex != "" {
		t.Errorf("--tcp-only 不应带 clienthello_hex")
	}
	if rec.TCP == nil || rec.TCP.MSS != 1460 {
		t.Errorf("--tcp-only 应导出 tcp 节，got %+v", rec.TCP)
	}
}

func TestImportPcapAllAndStream(t *testing.T) {
	ch1, ch2 := buildCH(false), buildCH(false)
	ch2[len(ch2)-1] ^= 0xFF // 让两条流的 CH 不同，便于区分
	frames := append(sessionFrames(ch1, 51001), sessionFrames(ch2, 51002)...)
	path := writeTemp(t, "two.pcap", writePcapClassic(frames...))

	var stdout, stderr bytes.Buffer
	if code := cmdImportPcap([]string{"--pcap", path, "--all"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--all exit=%d stderr=%s", code, stderr.String())
	}
	var recs []pcapFingerprintRecord
	if err := json.Unmarshal(stdout.Bytes(), &recs); err != nil {
		t.Fatalf("--all 应输出 JSON 数组: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("--all 应导出 2 条，got %d", len(recs))
	}

	// --stream 2 只取第二条
	stdout.Reset()
	stderr.Reset()
	if code := cmdImportPcap([]string{"--pcap", path, "--stream", "2"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--stream 2 exit=%d stderr=%s", code, stderr.String())
	}
	var one pcapFingerprintRecord
	if err := json.Unmarshal(stdout.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if one.ClientHelloHex != hex.EncodeToString(ch2) {
		t.Errorf("--stream 2 应取第二条流的 CH")
	}

	// --stream 越界
	stdout.Reset()
	stderr.Reset()
	if code := cmdImportPcap([]string{"--pcap", path, "--stream", "9"}, &stdout, &stderr); code != 1 {
		t.Errorf("--stream 越界应 exit=1, got %d", code)
	}
}

func TestParseTCPOptions(t *testing.T) {
	mss, ws, order := parseTCPOptions(synOpts())
	if mss != 1460 || ws != 8 {
		t.Errorf("mss/ws = %d/%d, want 1460/8", mss, ws)
	}
	if got := strings.Join(order, ","); got != "mss,nop,ws,nop,nop,sack" {
		t.Errorf("order = %q", got)
	}
	// 未知 kind 如实带出（按其长度跳过载荷）；ts 识别；EOL 终止
	b := []byte{0x02, 0x04, 0x01, 0x40, 0x1e, 0x02, 0x08, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0xff}
	mss2, _, order2 := parseTCPOptions(b)
	if mss2 != 320 {
		t.Errorf("mss = %d, want 320", mss2)
	}
	if got := strings.Join(order2, ","); got != "mss,kind-30,ts" {
		t.Errorf("order = %q, want mss,kind-30,ts", got)
	}
}

func TestExtractClientHelloRecord(t *testing.T) {
	ch := buildCH(false)
	got, err := extractClientHelloRecord(ch)
	if err != nil || !bytes.Equal(got, ch) {
		t.Fatalf("提取失败/不一致: err=%v", err)
	}
	// CH 跨 record：hs 长度字段大于 record 容量 ⇒ 明确报错
	bad := []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x64}
	bad = append(bad, make([]byte, 16)...)
	if _, err := extractClientHelloRecord(bad); err == nil || !strings.Contains(err.Error(), "跨 record") {
		t.Errorf("跨 record 应报错，got %v", err)
	}
	// 前导噪声（非 record 起始）也要能扫到
	noisy := append([]byte{0x00, 0xFF, 0x16}, ch...)
	got2, err := extractClientHelloRecord(noisy)
	if err != nil {
		t.Errorf("应扫到 record 并成功，got %v", err)
	} else if !bytes.Equal(got2, ch) {
		t.Errorf("扫到的 record 应与原 CH 相同")
	}
}
