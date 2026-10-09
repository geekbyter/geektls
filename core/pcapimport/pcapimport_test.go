// core/pcapimport 的合成抓包测试：不依赖 tshark / 真实 pcap——
// 帧与抓包字节全部在测试里按字节构造（与 CLI 层 importpcap_test.go 同一套
// 合成器：那里回归 CLI 壳的行为与输出，这里回归核语义）。
package pcapimport

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
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

// synOpts：MSS 1460 + NOP + wscale 8 + NOP NOP + SACK（真机 Chrome/Windows 同款形状）。
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

// sessionFrames 造一条完整会话：SYN(带选项) + SYN-ACK + ACK + CH 分两段（乱序）。
func sessionFrames(ch []byte, sport int) [][]byte {
	half := len(ch) / 2
	return [][]byte{
		ip4Frame("192.168.1.10", "93.184.216.34", sport, 443, 1000, 0, flagSYN, 64240, 64, true, synOpts(), nil),
		ip4Frame("93.184.216.34", "192.168.1.10", 443, sport, 5000, 1001, flagSYN|flagACK, 65535, 57, false, nil, nil),
		ip4Frame("192.168.1.10", "93.184.216.34", sport, 443, 1001, 5001, flagACK, 64240, 64, false, nil, nil),
		// 后一段先到（乱序），测 seq 排序
		ip4Frame("192.168.1.10", "93.184.216.34", sport, 443, 1001+uint32(half), 5001, flagACK, 64240, 64, false, nil, ch[half:]),
		ip4Frame("192.168.1.10", "93.184.216.34", sport, 443, 1001, 5001, flagACK, 64240, 64, false, nil, ch[:half]),
	}
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
	binary.LittleEndian.PutUint32(shb[4:], 1)
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
		binary.LittleEndian.PutUint32(body[8:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(body[12:], uint32(len(f)))
		binary.LittleEndian.PutUint32(body[16:], uint32(len(f)))
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

// ---------- 测试 ----------

func TestImportClassic(t *testing.T) {
	ch := buildCH(false)
	res, err := Import(writePcapClassic(sessionFrames(ch, 51423)...), Options{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(res.Records) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("records=%d skipped=%d, want 1/0", len(res.Records), len(res.Skipped))
	}
	rec := res.Records[0]
	if rec.Kind != "e1p_pcap" || rec.Grade != "E1p" {
		t.Errorf("kind/grade = %q/%q", rec.Kind, rec.Grade)
	}
	if rec.ClientHelloHex != hex.EncodeToString(ch) {
		t.Errorf("clienthello_hex 不一致（乱序重组失败？）")
	}
	if rec.JA3 == "" || rec.JA4 == "" {
		t.Errorf("核应自算 JA3/JA4（经 tlscore.CheckProfile），got %q/%q", rec.JA3, rec.JA4)
	}
	if rec.TCP == nil || rec.TCP.MSS != 1460 || rec.TCP.WindowScale != 8 ||
		rec.TCP.WindowSize != 64240 || rec.TCP.TTL != 64 || !rec.TCP.DF {
		t.Fatalf("tcp 节 = %+v", rec.TCP)
	}
	if got := strings.Join(rec.TCP.OptionsOrder, ","); got != "mss,nop,ws,nop,nop,sack" {
		t.Errorf("options_order = %q", got)
	}
	if rec.Name != "pcap" || rec.Source != "pcap:pcap#1" {
		t.Errorf("默认 name/source = %q/%q, want pcap / pcap:pcap#1", rec.Name, rec.Source)
	}
}

func TestImportPcapngContainer(t *testing.T) {
	ch := buildCH(false)
	res, err := Import(writePcapng(sessionFrames(ch, 52000)...), Options{
		Name: "cap", SourceBase: "cap.pcapng", UA: "Mozilla/5.0 Test/1.0",
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	rec := res.Records[0]
	if rec.ClientHelloHex != hex.EncodeToString(ch) {
		t.Errorf("pcapng 的 clienthello_hex 不一致")
	}
	if rec.HTTP2 == nil || len(rec.HTTP2.RegularHeaders) != 1 ||
		rec.HTTP2.RegularHeaders[0][0] != "user-agent" {
		t.Errorf("ua 应写入 http2.regular_headers，got %+v", rec.HTTP2)
	}
	if rec.CapturedAt == "" {
		t.Errorf("captured_at 应由首页时间生成")
	}
}

func TestImportRejects(t *testing.T) {
	t.Run("resumption", func(t *testing.T) {
		res, err := Import(writePcapClassic(sessionFrames(buildCH(true), 51423)...), Options{})
		if err != nil {
			t.Fatalf("全拒不应是 error: %v", err)
		}
		if len(res.Records) != 0 || len(res.Skipped) != 1 {
			t.Fatalf("records=%d skipped=%v", len(res.Records), res.Skipped)
		}
		if !strings.Contains(res.Skipped[0], "resumption") {
			t.Errorf("skipped 应说明 resumption：%q", res.Skipped[0])
		}
	})

	t.Run("missing SYN", func(t *testing.T) {
		frames := sessionFrames(buildCH(false), 51423)
		res, err := Import(writePcapClassic(frames[1:]...), Options{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(res.Records) != 0 || !strings.Contains(res.Skipped[0], "缺 SYN") {
			t.Errorf("skipped = %v", res.Skipped)
		}
	})

	t.Run("gap", func(t *testing.T) {
		frames := [][]byte{
			ip4Frame("192.168.1.10", "93.184.216.34", 51423, 443, 1000, 0, flagSYN, 64240, 64, true, synOpts(), nil),
			ip4Frame("93.184.216.34", "192.168.1.10", 443, 51423, 5000, 1001, flagSYN|flagACK, 65535, 57, false, nil, nil),
			ip4Frame("192.168.1.10", "93.184.216.34", 51423, 443, 1001+10, 5001, flagACK, 64240, 64, false, nil, buildCH(false)),
		}
		res, err := Import(writePcapClassic(frames...), Options{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(res.Records) != 0 || !strings.Contains(res.Skipped[0], "缺口") {
			t.Errorf("skipped = %v", res.Skipped)
		}
	})

	t.Run("no ClientHello", func(t *testing.T) {
		junk := bytes.Repeat([]byte{0xDE, 0xAD}, 40)
		res, err := Import(writePcapClassic(sessionFrames(junk, 51423)...), Options{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(res.Records) != 0 || !strings.Contains(res.Skipped[0], "没有 ClientHello") {
			t.Errorf("skipped = %v", res.Skipped)
		}
	})
}

func TestImportTCPOnly(t *testing.T) {
	junk := bytes.Repeat([]byte{0x11}, 20)
	res, err := Import(writePcapClassic(sessionFrames(junk, 51423)...), Options{TCPOnly: true})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records=%d", len(res.Records))
	}
	if res.Records[0].ClientHelloHex != "" {
		t.Errorf("tcp-only 不应带 clienthello_hex")
	}
	if res.Records[0].TCP == nil || res.Records[0].TCP.MSS != 1460 {
		t.Errorf("tcp 节 = %+v", res.Records[0].TCP)
	}
}

func TestImportAllAndStream(t *testing.T) {
	ch1, ch2 := buildCH(false), buildCH(false)
	ch2[len(ch2)-1] ^= 0xFF
	frames := append(sessionFrames(ch1, 51001), sessionFrames(ch2, 51002)...)
	data := writePcapClassic(frames...)

	all, err := Import(data, Options{All: true})
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(all.Records) != 2 {
		t.Fatalf("all 应 2 条，got %d", len(all.Records))
	}
	one, err := Import(data, Options{Stream: 2})
	if err != nil {
		t.Fatalf("stream 2: %v", err)
	}
	if one.Records[0].ClientHelloHex != hex.EncodeToString(ch2) {
		t.Errorf("stream 2 应取第二条流的 CH")
	}
	if _, err := Import(data, Options{Stream: 9}); err == nil {
		t.Errorf("stream 越界应报错")
	}
}

func TestImportBadFile(t *testing.T) {
	if _, err := Import([]byte{0x01, 0x02}, Options{}); err == nil {
		t.Errorf("太小文件应报错")
	}
	if _, err := Import(bytes.Repeat([]byte{0x00}, 64), Options{}); err == nil {
		t.Errorf("坏 magic 应报错")
	}
}

// buildCHWithSNI 在标准 CH 上加 server_name(0) 扩展（SNI 提取用例）。
func buildCHWithSNI(host string) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0xAB}, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	name := []byte(host)
	sn := []byte{0x00, byte(2 + 3 + len(name))}
	sn = append(sn, 0x00, byte(len(name)>>8), byte(len(name)))
	sn = append(sn, name...)
	ext := []byte{0x00, 0x00, 0x00, byte(len(sn))}
	ext = append(ext, sn...)
	ext = append(ext, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestImportSNIAndWarnings(t *testing.T) {
	res, err := Import(writePcapClassic(sessionFrames(buildCHWithSNI("tls.peet.ws"), 51423)...), Options{SourceBase: "cap"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	rec := res.Records[0]
	if rec.SNI != "tls.peet.ws" {
		t.Fatalf("SNI = %q", rec.SNI)
	}
	if len(rec.Warnings) != 1 {
		t.Fatalf("want missing_ua warning, got %v", rec.Warnings)
	}
	res2, err := Import(writePcapClassic(sessionFrames(buildCHWithSNI("tls.peet.ws"), 51424)...), Options{SourceBase: "cap", UA: "Mozilla/5.0 T"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Records[0].Warnings) != 0 {
		t.Fatalf("UA given: no warning expected, got %v", res2.Records[0].Warnings)
	}
}
