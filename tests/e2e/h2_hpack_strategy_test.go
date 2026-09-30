package e2e

// T-HPACK：HPACK 编码特征的线上断言（二期 T1）。
//
// 在 L1 帧采集器（h2_capture_test.go）基础上下沉一层：不解码头部值，
// 而是逐字节解析 HPACK block 的**表示形式**——indexed / incremental
// indexing / without indexing / never indexed / table size update，
// 以及每个字符串的 Huffman 位。四档 hpack_strategy（generic/chrome/
// firefox/safari）各一条用例，另含 chrome 档的动表复用（第二请求
// :authority 应命中动态表走 indexed）。

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"

	h2core "github.com/geekbyter/geektls/core/h2"
	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

// hpackFeat 是一个头字段的线上编码特征。
type hpackFeat struct {
	Name        string // 与 DecodeFull 对齐（按序）
	Repr        string // indexed / incr / noidx / never / tsu
	NameHuffman bool
	ValHuffman  bool
}

// parseHpackBlock 逐字节解析 HPACK block 的表示形式序列（跳过 tsu，
// 但记录其出现）。fields 为 DecodeFull 的解码结果（按序对齐取名）。
func parseHpackBlock(block []byte, fields []hpack.HeaderField) ([]hpackFeat, error) {
	var feats []hpackFeat
	fi := 0
	i := 0
	for i < len(block) {
		b := block[i]
		switch {
		case b&0x80 != 0: // indexed
			idx, n := hpackVarint(block[i:], 7)
			_ = idx
			i += n
			feats = append(feats, hpackFeat{Repr: "indexed"})
		case b&0xc0 == 0x40: // literal with incremental indexing
			i++
			i = skipHpackLiteral(block, i, 6, &hpackFeat{Repr: "incr"}, &feats)
		case b&0xe0 == 0x20: // dynamic table size update
			_, n := hpackVarint(block[i:], 5)
			i += n
			feats = append(feats, hpackFeat{Repr: "tsu"})
		case b&0xf0 == 0x10: // never indexed
			i++
			i = skipHpackLiteral(block, i, 4, &hpackFeat{Repr: "never"}, &feats)
		default: // 0000xxxx literal without indexing
			i++
			i = skipHpackLiteral(block, i, 4, &hpackFeat{Repr: "noidx"}, &feats)
		}
		if i <= 0 || i > len(block) {
			return nil, fmt.Errorf("hpack parse stuck at %d", i)
		}
	}
	// 对齐名字（tsu 不占字段位）
	out := feats[:0]
	for _, f := range feats {
		if f.Repr == "tsu" {
			out = append(out, f)
			continue
		}
		if fi >= len(fields) {
			return nil, fmt.Errorf("字段数多于 DecodeFull 结果")
		}
		f.Name = fields[fi].Name
		fi++
		out = append(out, f)
	}
	if fi != len(fields) {
		return nil, fmt.Errorf("字段数 %d 与 DecodeFull %d 不齐", fi, len(fields))
	}
	return out, nil
}

// hpackVarint 解 n 位前缀 varint，返回值与消耗字节数。
func hpackVarint(buf []byte, n byte) (uint64, int) {
	k := uint64((1 << n) - 1)
	v := uint64(buf[0]) & k
	i := 1
	if v < k {
		return v, i
	}
	m := uint(0)
	for i < len(buf) {
		b := buf[i]
		i++
		v += uint64(b&0x7f) << m
		m += 7
		if b&0x80 == 0 {
			break
		}
	}
	return v, i
}

// hpackString 读一个 HPACK 字符串，返回是否 Huffman 与消耗字节数。
func hpackString(buf []byte) (huff bool, n int) {
	if len(buf) == 0 {
		return false, 0
	}
	huff = buf[0]&0x80 != 0
	l, ln := hpackVarint(buf, 7)
	return huff, ln + int(l)
}

// skipHpackLiteral 解析 literal 表示（名称可索引可内联），记录特征并返回新游标。
// prefix 是名称索引的 varint 前缀位数（调用前游标已过首字节，索引从首字节
// 低位开始——这里传入首字节所在位置-1 的补偿在调用点处理）。
func skipHpackLiteral(block []byte, i, prefix int, feat *hpackFeat, feats *[]hpackFeat) int {
	// 名称索引 varint 的首字节是上一步消费的 opcode 字节；重新解析：
	// 游标 i 指向 opcode 之后，名称索引从 opcode 的低 prefix 位开始，
	// 可能延续到后续字节。简化：从 i-1 重读 varint。
	idx, n := hpackVarint(block[i-1:], byte(prefix))
	i = i - 1 + n
	if idx == 0 { // 内联名称字符串
		huff, sn := hpackString(block[i:])
		feat.NameHuffman = huff
		i += sn
	}
	huff, sn := hpackString(block[i:])
	feat.ValHuffman = huff
	i += sn
	*feats = append(*feats, *feat)
	return i
}

// captureHpackBlocks 起 TLS 管道服务端，采集前 wantBlocks 个 HEADERS block
// 的原始 HPACK 字节（含每次的解码字段）。
type hpackBlockCapture struct {
	Raw    []byte
	Fields []hpack.HeaderField
}

func captureHpackBlocks(t *testing.T, strategy string, paths []string) []hpackBlockCapture {
	t.Helper()
	serverCfg := loopbackServerConfig(t)

	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.HTTP2.HpackStrategy = strategy

	tlsSpec, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	type result struct {
		blocks []hpackBlockCapture
		err    error
	}
	serverDone := make(chan result, 1)
	go func() {
		srv := tls.Server(serverConn, serverCfg)
		if err := srv.Handshake(); err != nil {
			serverDone <- result{err: err}
			return
		}
		blocks, err := readNHeaderBlocks(srv, len(paths))
		serverDone <- result{blocks, err}
		io.Copy(io.Discard, srv)
	}()

	uconn, err := tlscore.Handshake(clientConn, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}, tlsSpec)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	cc, err := h2core.NewClientConn(uconn, p.HTTP2)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	for _, path := range paths {
		go func(pth string) {
			_, _ = h2core.Do(cc, "GET", "https://example.com"+pth,
				[][2]string{{"user-agent", "geektls-hpack-capture"}}, nil)
		}(path)
	}

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server side: %v", res.err)
	}
	return res.blocks
}

// readNHeaderBlocks 读 preface + 逐帧解析，收齐 n 个 HEADERS block。
func readNHeaderBlocks(conn net.Conn, n int) ([]hpackBlockCapture, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	preface := make([]byte, 24)
	if _, err := io.ReadFull(conn, preface); err != nil {
		return nil, err
	}
	decoder := hpack.NewDecoder(4096, nil)
	var out []hpackBlockCapture
	var cur []byte
	for len(out) < n {
		hdr := make([]byte, 9)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return nil, err
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		ftype, flags := hdr[3], hdr[4]
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
		switch ftype {
		case 0x1: // HEADERS
			if flags&0x8 != 0 {
				padLen := int(payload[0])
				payload = payload[1 : len(payload)-padLen]
			}
			if flags&0x20 != 0 {
				payload = payload[5:]
			}
			cur = append(cur, payload...)
			if flags&0x4 != 0 {
				fields, err := decoder.DecodeFull(cur)
				if err != nil {
					return nil, fmt.Errorf("hpack decode: %w", err)
				}
				out = append(out, hpackBlockCapture{Raw: cur, Fields: fields})
				cur = nil
			}
		case 0x9: // CONTINUATION
			cur = append(cur, payload...)
			if flags&0x4 != 0 {
				fields, err := decoder.DecodeFull(cur)
				if err != nil {
					return nil, fmt.Errorf("hpack decode: %w", err)
				}
				out = append(out, hpackBlockCapture{Raw: cur, Fields: fields})
				cur = nil
			}
		}
	}
	return out, nil
}

func featOf(t *testing.T, feats []hpackFeat, name string) hpackFeat {
	t.Helper()
	for _, f := range feats {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("字段 %s 不在特征列表: %+v", name, feats)
	return hpackFeat{}
}

func hasTSU(feats []hpackFeat) bool {
	for _, f := range feats {
		if f.Repr == "tsu" {
			return true
		}
	}
	return false
}

// TestHpackStrategyFourModes：四档策略的线上 HPACK 特征断言。
func TestHpackStrategyFourModes(t *testing.T) {
	// :path=/x?y=1 非静态表精确值（避免静态命中干扰表示形式判定）
	blocks := captureHpackBlocks(t, "generic", []string{"/x?y=1"})
	gen, err := parseHpackBlock(blocks[0].Raw, blocks[0].Fields)
	if err != nil {
		t.Fatal(err)
	}
	// generic（上游默认）：伪头也进动表——:authority 与 :path 都是 incr
	if f := featOf(t, gen, ":authority"); f.Repr != "incr" {
		t.Errorf("generic :authority = %s, want incr", f.Repr)
	}
	if f := featOf(t, gen, ":path"); f.Repr != "incr" {
		t.Errorf("generic :path = %s, want incr（上游把伪头也入动表）", f.Repr)
	}

	for _, strategy := range []string{"chrome", "firefox"} {
		blocks := captureHpackBlocks(t, strategy, []string{"/x?y=1"})
		feats, err := parseHpackBlock(blocks[0].Raw, blocks[0].Fields)
		if err != nil {
			t.Fatalf("%s: %v", strategy, err)
		}
		// QUICHE DefaultPolicy / Firefox 抓包同形：:authority 入动表，
		// 其余伪头 no-index，常规头入动表
		if f := featOf(t, feats, ":authority"); f.Repr != "incr" {
			t.Errorf("%s :authority = %s, want incr", strategy, f.Repr)
		}
		if f := featOf(t, feats, ":path"); f.Repr != "noidx" {
			t.Errorf("%s :path = %s, want noidx", strategy, f.Repr)
		}
		if f := featOf(t, feats, "user-agent"); f.Repr != "incr" {
			t.Errorf("%s user-agent = %s, want incr", strategy, f.Repr)
		}
		if f := featOf(t, feats, ":method"); f.Repr != "indexed" {
			t.Errorf("%s :method GET 应静态命中 indexed, got %s", strategy, f.Repr)
		}
		// 对默认 4096 表的服务端不发 table size update
		if hasTSU(feats) {
			t.Errorf("%s 不应有 table size update", strategy)
		}
		// UA 值更长，Huffman 位应置位
		if f := featOf(t, feats, "user-agent"); !f.ValHuffman {
			t.Errorf("%s user-agent 值应 Huffman 编码", strategy)
		}
	}

	blocks = captureHpackBlocks(t, "safari", []string{"/x?y=1"})
	saf, err := parseHpackBlock(blocks[0].Raw, blocks[0].Fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range saf {
		if f.Repr == "incr" {
			t.Errorf("safari 档不应有动表插入: %+v", f)
		}
	}
}

// TestHpackStrategyDynamicReuse：chrome 档第二请求的 :authority 应命中
// 动态表（indexed）——动表插入的收益路径；safari 档不动表则仍 literal。
func TestHpackStrategyDynamicReuse(t *testing.T) {
	blocks := captureHpackBlocks(t, "chrome", []string{"/a", "/b"})
	second, err := parseHpackBlock(blocks[1].Raw, blocks[1].Fields)
	if err != nil {
		t.Fatal(err)
	}
	if f := featOf(t, second, ":authority"); f.Repr != "indexed" {
		t.Errorf("chrome 第二请求 :authority = %s, want indexed（动表命中）", f.Repr)
	}

	blocks = captureHpackBlocks(t, "safari", []string{"/a", "/b"})
	second, err = parseHpackBlock(blocks[1].Raw, blocks[1].Fields)
	if err != nil {
		t.Fatal(err)
	}
	if f := featOf(t, second, ":authority"); f.Repr == "indexed" {
		t.Errorf("safari 档不动表，第二请求 :authority 不应 indexed")
	}
}
