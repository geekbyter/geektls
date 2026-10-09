package geektls

import (
	"encoding/binary"
	"testing"
)

func frameForTest(srcIP, dstIP [4]byte, sport, dport int, seq, ack uint32, flags uint8, win, ttl int, df bool, opts, payload []byte) []byte {
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
	ip[9] = 6
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	return append(append(append(eth, ip...), tcpSeg...), payload...)
}

func synOptsForTest() []byte {
	return []byte{0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02}
}

func buildCHForTest(psk bool, seed byte) []byte {
	body := []byte{0x03, 0x03}
	for i := 0; i < 32; i++ {
		body = append(body, seed)
	}
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	var ext []byte
	if psk {
		ext = append(ext, 0x00, 0x29, 0x00, 0x05, 0x00, 0x03, 0x01, 0x02, 0x03)
	} else {
		ext = append(ext, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func sessionForTest(ch []byte, sport int) [][]byte {
	src := [4]byte{192, 168, 1, 10}
	dst := [4]byte{93, 184, 216, 34}
	half := len(ch) / 2
	return [][]byte{
		frameForTest(src, dst, sport, 443, 1000, 0, 0x02, 64240, 64, true, synOptsForTest(), nil),
		frameForTest(dst, src, 443, sport, 5000, 1001, 0x12, 65535, 57, false, nil, nil),
		frameForTest(src, dst, sport, 443, 1001, 5001, 0x10, 64240, 64, false, nil, nil),
		frameForTest(src, dst, sport, 443, 1001+uint32(half), 5001, 0x10, 64240, 64, false, nil, ch[half:]),
		frameForTest(src, dst, sport, 443, 1001, 5001, 0x10, 64240, 64, false, nil, ch[:half]),
	}
}

func pcapBytesForTest(frames ...[]byte) []byte {
	var b []byte
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(hdr[4:], 2)
	binary.LittleEndian.PutUint32(hdr[8:], 4)
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	b = append(b, hdr...)
	for i, f := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		b = append(b, rec...)
		b = append(b, f...)
	}
	return b
}

func TestImportPcapBytes(t *testing.T) {
	ch := buildCHForTest(false, 0xAB)
	res, err := ImportPcapBytes(pcapBytesForTest(sessionForTest(ch, 51423)...), &PcapOptions{UA: "Mozilla/5.0 Test"}, "cap")
	if err != nil {
		t.Fatalf("ImportPcapBytes: %v", err)
	}
	if len(res.Records) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("records=%d skipped=%d", len(res.Records), len(res.Skipped))
	}
	rec := res.Records[0]
	if rec.Grade != "E1p" || rec.TCP == nil || rec.TCP.MSS != 1460 {
		t.Fatalf("record = %+v", rec)
	}
	if rec.JA4 == "" {
		t.Fatalf("JA4 should be computed")
	}
	if rec.HTTP2 == nil || len(rec.HTTP2.RegularHeaders) != 1 {
		t.Fatalf("ua should land in http2.regular_headers: %+v", rec.HTTP2)
	}
}

func TestNewSessionFromClientHelloHex(t *testing.T) {
	ch := buildCHForTest(false, 0xAB)
	res, err := ImportPcapBytes(pcapBytesForTest(sessionForTest(ch, 51423)...), nil, "cap")
	if err != nil {
		t.Fatal(err)
	}
	s, warns, err := NewSessionFromClientHelloHex(res.Records[0].ClientHelloHex, nil)
	if err != nil {
		t.Fatalf("NewSessionFromClientHelloHex: %v", err)
	}
	defer s.Close()
	if warns == nil {
		warns = nil
	}
	ja3s, _, err := NewSessionFromJA3("771,4865-4866-4867,0-23-65281,29-23-24,0", nil)
	if err != nil {
		t.Fatalf("NewSessionFromJA3: %v", err)
	}
	defer ja3s.Close()
	ja4s, _, err := NewSessionFromJA4R("t13d1516h2_1301,1302,1303,c02b,c02f_0005,000a,000b,002b,0033_0403,0804,0401", nil)
	if err != nil {
		t.Fatalf("NewSessionFromJA4R: %v", err)
	}
	defer ja4s.Close()
}
