package engine

// permessage-deflate（RFC 7692）测试。对端只用 stdlib flate 的常规用法，不调用
// core 里的压缩/解压实现——否则"两边错得一致"也能过：
//   · 收方向：对端把消息压进同一个（takeover）或各自独立（no takeover）的
//     DEFLATE 流，我方必须在 RSV1 / 分片 / no_context_takeover 各形态下解回原文；
//   · 发方向：把我方发出的各条压缩块原样拼接（每条补回空块尾），交给一个普通
//     flate.NewReader 整体解开 ⇒ 证明我方发的是一条合法的连续 DEFLATE 流，
//     而不是"只有自家解压器认得"的私有格式；
//   · 失败方向：没协商却来 RSV1、RSV2/RSV3、控制帧带 RSV1、对端回声我方没请求的
//     参数、不支持的扩展、被限制压缩窗口——都必须当场报错，不能静默返回错数据。

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// --- 对端最小 WS 实现（与 engine 的帧层无关） ---

type wsPeer struct {
	conn    net.Conn
	br      *bufio.Reader
	seen    map[string]string // 我方握手头（小写名 → 值）
	order   []string
	extEcho string // 101 里要带的 Sec-WebSocket-Extensions 值
}

type peerOutcome struct {
	chunks [][]byte // 对端逐帧读到的我方载荷
	err    error
}

type peerRun struct {
	url  string
	p    *wsPeer
	errC chan peerOutcome
}

// startWSPeer 起一个 wss 对端：握手回 101（可选带扩展回声），然后跑 dialog。
// dialog 的（读到的帧载荷, 错误）通过 errC 交给测试断言；dialog 传 nil 表示只握手。
func startWSPeer(t *testing.T, extEcho string, dialog func(*wsPeer) ([][]byte, error)) *peerRun {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	p := &wsPeer{seen: map[string]string{}, extEcho: extEcho}
	errC := make(chan peerOutcome, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errC <- peerOutcome{err: err}
			return
		}
		p.conn, p.br = conn, bufio.NewReader(conn)
		if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			errC <- peerOutcome{err: err}
			return
		}
		if err := p.handshake(); err != nil {
			errC <- peerOutcome{err: err}
			return
		}
		if dialog == nil {
			errC <- peerOutcome{}
			return
		}
		chunks, err := dialog(p)
		errC <- peerOutcome{chunks: chunks, err: err}
	}()
	return &peerRun{url: "wss://" + ln.Addr().String() + "/ws", p: p, errC: errC}
}

// wait 取 dialog 的结论。对端自己有 8s 读写超时，这里只是不让测试永远挂着。
func (r *peerRun) wait(t *testing.T) peerOutcome {
	t.Helper()
	select {
	case o := <-r.errC:
		return o
	case <-time.After(12 * time.Second):
		t.Fatal("peer: 超时未返回")
	}
	return peerOutcome{}
}

func (p *wsPeer) handshake() error {
	line, err := p.br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "GET ") {
		return fmt.Errorf("peer: 请求行不对 %q %v", line, err)
	}
	var wsKey string
	for {
		h, err := p.br.ReadString('\n')
		if err != nil {
			return err
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		name, val, _ := strings.Cut(h, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		p.order = append(p.order, name)
		if _, dup := p.seen[name]; dup {
			return fmt.Errorf("peer: 握手头重复 %q", name)
		}
		p.seen[name] = strings.TrimSpace(val)
		if name == "sec-websocket-key" {
			wsKey = strings.TrimSpace(val)
		}
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAcceptKey(wsKey) + "\r\n"
	if p.extEcho != "" {
		resp += "Sec-WebSocket-Extensions: " + p.extEcho + "\r\n"
	}
	resp += "\r\n"
	_, err = p.conn.Write([]byte(resp))
	return err
}

// readFrame 读我方（客户端）发的帧：必须 masked。
func (p *wsPeer) readFrame() (fin, rsv1 bool, op int, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(p.br, hdr[:]); err != nil {
		return
	}
	fin, rsv1 = hdr[0]&0x80 != 0, hdr[0]&0x40 != 0
	op = int(hdr[0] & 0x0f)
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var e [2]byte
		if _, err = io.ReadFull(p.br, e[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err = io.ReadFull(p.br, e[:]); err != nil {
			return
		}
		if n = binary.BigEndian.Uint64(e[:]); n > 1<<20 {
			err = fmt.Errorf("peer: 帧过大 %d", n)
			return
		}
	}
	if !masked {
		err = fmt.Errorf("peer: 客户端帧没 mask")
		return
	}
	var mask [4]byte
	if _, err = io.ReadFull(p.br, mask[:]); err != nil {
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(p.br, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return
}

// writeFrame 发一条对端（服务端）帧：不 mask。
func (p *wsPeer) writeFrame(fin, rsv1 bool, op int, payload []byte) error {
	_, err := p.conn.Write(wsRawFrame(fin, rsv1, false, false, op, payload))
	return err
}

// wsRawFrame 手工拼一个服务端帧（含各 RSV 位，用于造违规帧）。
func wsRawFrame(fin, rsv1, rsv2, rsv3 bool, op int, payload []byte) []byte {
	b0 := byte(op)
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}
	if rsv2 {
		b0 |= 0x20
	}
	if rsv3 {
		b0 |= 0x10
	}
	out := []byte{b0}
	n := len(payload)
	switch {
	case n <= 125:
		out = append(out, byte(n))
	case n <= 0xffff:
		out = append(out, 126, byte(n>>8), byte(n))
	default:
		out = append(out, 127)
		var e [8]byte
		binary.BigEndian.PutUint64(e[:], uint64(n))
		out = append(out, e[:]...)
	}
	return append(out, payload...)
}

// --- 对端压缩器/解压器：只用 stdlib 的常规用法，不做任何 core 特有的把戏 ---

const peerTail = "\x00\x00\xff\xff"

// peerComp 是"标准 sender"：持续 writer + Flush，剥掉结尾空块后按帧发出。
// takeover=false 时每条消息 Close 收流，下一条从全新流开始。
type peerComp struct {
	buf      *bytes.Buffer
	w        *flate.Writer
	takeover bool
}

func newPeerComp(takeover bool) (*peerComp, error) {
	b := &bytes.Buffer{}
	w, err := flate.NewWriter(b, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	return &peerComp{buf: b, w: w, takeover: takeover}, nil
}

func (c *peerComp) next(msg string) ([]byte, error) {
	c.buf.Reset()
	if _, err := c.w.Write([]byte(msg)); err != nil {
		return nil, err
	}
	if c.takeover {
		if err := c.w.Flush(); err != nil {
			return nil, err
		}
		out := bytes.Clone(c.buf.Bytes())
		return out[:len(out)-len(peerTail)], nil // 去掉结尾空块，上下文留给下一条
	}
	if err := c.w.Close(); err != nil {
		return nil, err
	}
	out := bytes.Clone(c.buf.Bytes())
	w, err := flate.NewWriter(c.buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	c.w = w
	return out, nil
}

// peerInflateOne 独立解开我方发出的一条压缩块（补回空块尾）。
// 没有 final block 时 Go 报 ErrUnexpectedEOF —— 那是"读完了"的正常信号。
func peerInflateOne(chunk []byte) (string, error) {
	rc := flate.NewReader(bytes.NewReader(append(bytes.Clone(chunk), peerTail...)))
	defer rc.Close()
	out, err := io.ReadAll(rc)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}
	return string(out), nil
}

// peerInflateStream 把我方发出的多条压缩块拼成一条连续流再整体解压：
// 证明 takeover 下我方发的确实是"同一个 DEFLATE 流的连续片段"。
func peerInflateStream(chunks [][]byte) (string, error) {
	var stream []byte
	for _, ch := range chunks {
		stream = append(stream, ch...)
		stream = append(stream, peerTail...)
	}
	rc := flate.NewReader(bytes.NewReader(stream))
	defer rc.Close()
	out, err := io.ReadAll(rc)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}
	return string(out), nil
}

// dialPeer 连到对端并按需带 offer。
func dialPeer(t *testing.T, url string, compress bool, headers [][2]string) *WSConn {
	t.Helper()
	s := testSession(t, "chrome_133")
	ws, err := s.DialWS(&WSRequest{URL: url, Compress: compress, Headers: headers})
	if err != nil {
		t.Fatalf("DialWS: %v", err)
	}
	t.Cleanup(func() { ws.Close(0) })
	return ws
}

// deflateMsgs 三条互相引用的消息：m2/m3 大量重复 m1 的字面，
// 不保留上下文就解不开（正是 context takeover 要验的点）。
func deflateMsgs() (m1, m2, m3 string) {
	base := "geektls permessage-deflate 第一条消息，带足够长度让后面的引用有意义 " +
		strings.Repeat("alpha-bravo ", 8)
	return base, base + " —— 这条几乎全是重复，压缩收益最大",
		"第三条：" + base + strings.Repeat("alpha-bravo ", 4) + " tail"
}

// --- 用例 ---

// TestWSDeflateContextTakeover：双向 takeover。对端连续压 3 条（后两条大量引用前文），
// 我方逐条解回；反向我方连发 3 条，对端把块拼接后用独立 flate 流整体解压，
// 结果必须正好是三条明文的首尾相接。
func TestWSDeflateContextTakeover(t *testing.T) {
	m1, m2, m3 := deflateMsgs()

	run := startWSPeer(t, wsDeflateName, func(p *wsPeer) ([][]byte, error) {
		cmp, err := newPeerComp(true)
		if err != nil {
			return nil, err
		}
		for _, m := range []string{m1, m2, m3} {
			b, err := cmp.next(m)
			if err != nil {
				return nil, err
			}
			if err := p.writeFrame(true, true, WSOpText, b); err != nil {
				return nil, err
			}
		}
		var chunks [][]byte
		for i := 0; i < 3; i++ {
			fin, rsv1, op, payload, err := p.readFrame()
			if err != nil {
				return nil, err
			}
			if !fin || !rsv1 || op != WSOpText {
				return nil, fmt.Errorf("peer: 期望 fin+rsv1+text，得到 fin=%v rsv1=%v op=%d", fin, rsv1, op)
			}
			chunks = append(chunks, payload)
		}
		return chunks, nil
	})

	ws := dialPeer(t, run.url, true, nil)
	for i, want := range []string{m1, m2, m3} {
		op, got, err := ws.Recv(5000)
		if err != nil {
			t.Fatalf("Recv#%d: %v", i+1, err)
		}
		if op != WSOpText || string(got) != want {
			t.Fatalf("Recv#%d 解回不符：op=%d len=%d want=%d", i+1, op, len(got), len(want))
		}
	}
	for i, m := range []string{m1, m2, m3} {
		if err := ws.Send(WSOpText, []byte(m)); err != nil {
			t.Fatalf("Send#%d: %v", i+1, err)
		}
	}
	out := run.wait(t)
	if out.err != nil {
		t.Fatalf("peer: %v", out.err)
	}
	got, err := peerInflateStream(out.chunks)
	if err != nil {
		t.Fatalf("我方发出的压缩块拼起来不是合法 DEFLATE 流: %v", err)
	}
	if got != m1+m2+m3 {
		t.Fatalf("发方向解压结果不符：len got=%d want=%d", len(got), len(m1+m2+m3))
	}
}

// TestWSDeflateNoContextTakeover：两侧都关掉跨消息上下文（我方 offer 里带参数，
// 对端原样回声）。此时每条消息必须是各自独立的 DEFLATE 流——双向都验。
func TestWSDeflateNoContextTakeover(t *testing.T) {
	offer := wsDeflateName + "; server_no_context_takeover; client_no_context_takeover"
	n1 := "第一条独立流 " + strings.Repeat("独立", 10)
	n2 := "第二条独立流：即使内容与第一条高度重复，也不许引用它的窗口 " + n1

	run := startWSPeer(t, offer, func(p *wsPeer) ([][]byte, error) {
		cmp, err := newPeerComp(false)
		if err != nil {
			return nil, err
		}
		for _, m := range []string{n1, n2} {
			b, err := cmp.next(m)
			if err != nil {
				return nil, err
			}
			if err := p.writeFrame(true, true, WSOpText, b); err != nil {
				return nil, err
			}
		}
		want := []string{n1, n2}
		for i := 0; i < 2; i++ {
			fin, rsv1, op, payload, err := p.readFrame()
			if err != nil {
				return nil, err
			}
			if !fin || !rsv1 || op != WSOpText {
				return nil, fmt.Errorf("peer: 帧形态不对 fin=%v rsv1=%v op=%d", fin, rsv1, op)
			}
			got, err := peerInflateOne(payload) // 独立参照：单条自己就得可解
			if err != nil {
				return nil, fmt.Errorf("第 %d 条不是独立的流: %w", i+1, err)
			}
			if got != want[i] {
				return nil, fmt.Errorf("第 %d 条独立解压结果不符", i+1)
			}
		}
		return nil, nil
	})

	// compress=false + 手写 offer：参数是我方先请求的，对端才允许回声。
	ws := dialPeer(t, run.url, false, [][2]string{{"sec-websocket-extensions", offer}})
	for i, want := range []string{n1, n2} {
		op, got, err := ws.Recv(5000)
		if err != nil {
			t.Fatalf("Recv#%d: %v", i+1, err)
		}
		if op != WSOpText || string(got) != want {
			t.Fatalf("Recv#%d 解回不符", i+1)
		}
	}
	for _, m := range []string{n1, n2} {
		if err := ws.Send(WSOpText, []byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	if out := run.wait(t); out.err != nil {
		t.Fatalf("peer: %v", out.err)
	}
}

// TestWSDeflateFragmented：一条压缩消息分 3 帧（RSV1 只在首帧，RFC 7692 §6.2.2），
// 中间插一个 ping 检验"控制帧不打断压缩上下文"；我方自动回的 pong 必须不带 RSV1。
func TestWSDeflateFragmented(t *testing.T) {
	msg := "分片的压缩消息：" + strings.Repeat("这段文本会被切成三块发送 ", 6)
	next := "分片之后的下一条：仍然引用上一条的窗口 " + msg[:len(msg)/2]

	run := startWSPeer(t, wsDeflateName, func(p *wsPeer) ([][]byte, error) {
		cmp, err := newPeerComp(true)
		if err != nil {
			return nil, err
		}
		b, err := cmp.next(msg)
		if err != nil {
			return nil, err
		}
		third := len(b) / 3
		if err := p.writeFrame(false, true, WSOpText, b[:third]); err != nil {
			return nil, err
		}
		if err := p.writeFrame(true, false, WSOpPing, []byte("probe")); err != nil {
			return nil, err
		}
		if err := p.writeFrame(false, false, WSOpContinuation, b[third:2*third]); err != nil {
			return nil, err
		}
		if err := p.writeFrame(true, false, WSOpContinuation, b[2*third:]); err != nil {
			return nil, err
		}
		// 分片消息期间客户端应只回了 pong，随后是我方发的那条完整消息。
		_, rsv1, op, payload, err := p.readFrame()
		if err != nil {
			return nil, err
		}
		if op != WSOpPong || rsv1 || string(payload) != "probe" {
			return nil, fmt.Errorf("peer: pong 不对 op=%d rsv1=%v payload=%q", op, rsv1, payload)
		}
		fin2, rsv1b, op2, _, err := p.readFrame()
		if err != nil {
			return nil, err
		}
		if !fin2 || !rsv1b || op2 != WSOpText {
			return nil, fmt.Errorf("peer: 我方那条没压（fin=%v rsv1=%v op=%d）", fin2, rsv1b, op2)
		}
		b2, err := cmp.next(next) // 同一个流继续压
		if err != nil {
			return nil, err
		}
		return nil, p.writeFrame(true, true, WSOpBinary, b2)
	})

	ws := dialPeer(t, run.url, true, nil)
	op, got, err := ws.Recv(5000)
	if err != nil {
		t.Fatalf("Recv(分片): %v", err)
	}
	if op != WSOpText || string(got) != msg {
		t.Fatalf("分片重组结果不符：op=%d len=%d want=%d", op, len(got), len(msg))
	}
	if err := ws.Send(WSOpText, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	op, got, err = ws.Recv(5000)
	if err != nil {
		t.Fatalf("Recv(分片后): %v", err)
	}
	if op != WSOpBinary || string(got) != next {
		t.Fatalf("分片之后的 takeover 不对：op=%d len=%d want=%d", op, len(got), len(next))
	}
	if out := run.wait(t); out.err != nil {
		t.Fatalf("peer: %v", out.err)
	}
}

// TestWSDeflateEmptyMessage：空载荷不压缩（RSV1=0），也免得对端去补尾。
func TestWSDeflateEmptyMessage(t *testing.T) {
	run := startWSPeer(t, wsDeflateName, func(p *wsPeer) ([][]byte, error) {
		fin, rsv1, op, payload, err := p.readFrame()
		if err != nil {
			return nil, err
		}
		if !fin || rsv1 || op != WSOpText || len(payload) != 0 {
			return nil, fmt.Errorf("peer: 空消息不该带 RSV1: fin=%v rsv1=%v op=%d len=%d",
				fin, rsv1, op, len(payload))
		}
		return nil, nil
	})
	ws := dialPeer(t, run.url, true, nil)
	if err := ws.Send(WSOpText, nil); err != nil {
		t.Fatal(err)
	}
	if out := run.wait(t); out.err != nil {
		t.Fatalf("peer: %v", out.err)
	}
}

// TestWSDeflateHandshakeReject：握手层的"宁可失败，也不能静默返回错数据"。
func TestWSDeflateHandshakeReject(t *testing.T) {
	cases := []struct {
		name     string
		compress bool
		offer    string // 非空则手写 offer 头
		echo     string
		wantErr  string
	}{
		{"没 offer 却被协商", false, "", wsDeflateName, "没发对应 offer"},
		{"回声了我方没请求的参数", true, "", wsDeflateName + "; server_no_context_takeover", "回声了我方没请求的参数"},
		{"只给裸名,回声却带窗口限制", true, "", wsDeflateName + "; client_max_window_bits=12", "回声了我方没请求的参数"},
		{"我方压缩窗口被限到 12 bit", false, wsDeflateName + "; client_max_window_bits=12",
			wsDeflateName + "; client_max_window_bits=12", "client_max_window_bits"},
		{"对端窗口参数越界", false, wsDeflateName + "; server_max_window_bits=16",
			wsDeflateName + "; server_max_window_bits=16", "越界"},
		{"不支持的扩展", false, "", "x-custom-framing", "不支持的扩展"},
		{"畸形扩展头", false, "", "permessage-deflate; =1", "参数形态非法"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := startWSPeer(t, c.echo, nil)
			s := testSession(t, "chrome_133")
			var headers [][2]string
			if c.offer != "" {
				headers = append(headers, [2]string{"sec-websocket-extensions", c.offer})
			}
			_, err := s.DialWS(&WSRequest{URL: run.url, Compress: c.compress, Headers: headers})
			if err == nil {
				t.Fatalf("应当失败（echo=%q），却连上了", c.echo)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("错误不含 %q：%v", c.wantErr, err)
			}
		})
	}
}

// TestWSDeflateWindowBareOfferAccepted：真 Chrome 的 offer 是裸 client_max_window_bits；
// 服务端裸回声 = "接受默认窗口"（RFC 7692 §7.1.2.1），我方 stdlib 正好是 15 bit ⇒ 必须能用。
func TestWSDeflateWindowBareOfferAccepted(t *testing.T) {
	offer := wsDeflateName + "; client_max_window_bits"
	const text = "裸参数回声也要能用"
	run := startWSPeer(t, offer, func(p *wsPeer) ([][]byte, error) {
		cmp, err := newPeerComp(true)
		if err != nil {
			return nil, err
		}
		b, err := cmp.next(text)
		if err != nil {
			return nil, err
		}
		if err := p.writeFrame(true, true, WSOpText, b); err != nil {
			return nil, err
		}
		_, rsv1, _, payload, err := p.readFrame()
		if err != nil {
			return nil, err
		}
		if !rsv1 {
			return nil, fmt.Errorf("peer: 协商成功了却不压")
		}
		got, err := peerInflateOne(payload)
		if err != nil {
			return nil, err
		}
		if got != text {
			return nil, fmt.Errorf("peer: 我方 15 bit 窗口的流独立解出来不对")
		}
		return nil, nil
	})
	ws := dialPeer(t, run.url, false, [][2]string{{"sec-websocket-extensions", offer}})
	op, got, err := ws.Recv(5000)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if op != WSOpText || string(got) != text {
		t.Fatalf("解回不符：op=%d %q", op, got)
	}
	if err := ws.Send(WSOpText, []byte(text)); err != nil {
		t.Fatal(err)
	}
	if out := run.wait(t); out.err != nil {
		t.Fatalf("peer: %v", out.err)
	}
}

// TestWSDeflateBadFrames：帧层 RSV 规则（直接喂手工帧，不必走完整握手）。
func TestWSDeflateBadFrames(t *testing.T) {
	takeover := newWSInflater(true)
	if takeover == nil {
		t.Fatal("stdlib 解压接口变更")
	}
	cases := []struct {
		name    string
		inflate *wsInflater
		frame   []byte
		wantErr string
	}{
		{"未协商却来 RSV1", nil, wsRawFrame(true, true, false, false, WSOpText, []byte("compressed")),
			"未协商 permessage-deflate"},
		{"RSV2 非 0", takeover, wsRawFrame(true, false, true, false, WSOpText, []byte("x")), "RSV2/RSV3"},
		{"RSV3 非 0", takeover, wsRawFrame(true, false, false, true, WSOpBinary, []byte("x")), "RSV2/RSV3"},
		{"控制帧带 RSV1", takeover, wsRawFrame(true, true, false, false, WSOpPing, []byte("x")), "控制帧"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := &WSConn{br: bufio.NewReader(bytes.NewReader(c.frame)), inflate: c.inflate}
			if _, _, _, _, err := conn.readFrame(); err == nil ||
				!strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("期望含 %q 的错误，得到 %v", c.wantErr, err)
			}
		})
	}
}

// TestParseWsExtensions：扩展头解析（引号内的逗号/分号不参与切分）。
func TestParseWsExtensions(t *testing.T) {
	got, err := parseWsExtensions(`permessage-deflate; client_max_window_bits=15; x="a,b;c", another-ext`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].name != wsDeflateName || got[1].name != "another-ext" {
		t.Fatalf("扩展切分不对: %+v", got)
	}
	if got[0].params["x"] != "a,b;c" {
		t.Fatalf("引号值被切开: %q", got[0].params["x"])
	}
	if got[0].params["client_max_window_bits"] != "15" {
		t.Fatalf("参数值不对: %+v", got[0].params)
	}
	if _, err := parseWsExtensions("permessage-deflate; =1"); err == nil {
		t.Fatal("畸形参数应当报错")
	}
}

// TestWSDeflateOfferHeaderShape：compress=true 合成出的头——只出现一次、值为裸
// permessage-deflate、排在 sec-websocket-key 之后（Chrome 形态）；
// 对端没接受时不启用压缩器。
func TestWSDeflateOfferHeaderShape(t *testing.T) {
	run := startWSPeer(t, "", nil)
	ws := dialPeer(t, run.url, true, nil)
	if ws.deflate != nil || ws.inflate != nil {
		t.Fatal("对端没接受扩展却启用了压缩器")
	}
	if out := run.wait(t); out.err != nil {
		t.Fatalf("peer: %v", out.err)
	}
	if n := strings.Count(strings.Join(run.p.order, ","), "sec-websocket-extensions"); n != 1 {
		t.Fatalf("offer 头出现 %d 次", n)
	}
	if v := run.p.seen["sec-websocket-extensions"]; v != wsDeflateName {
		t.Fatalf("offer 值不对: %q", v)
	}
	iExt, iKey := -1, -1
	for i, h := range run.p.order {
		switch h {
		case "sec-websocket-extensions":
			iExt = i
		case "sec-websocket-key":
			iKey = i
		}
	}
	if iExt < iKey {
		t.Fatalf("头序不对：extensions@%d 应在 key@%d 之后", iExt, iKey)
	}
}

// TestWSNoOfferNoHeader：compress=false 且没手写头时，握手不带 extensions
// （默认不发是本库的诚实边界：没有逐浏览器 WS 握手实测证据就不乱发）。
func TestWSNoOfferNoHeader(t *testing.T) {
	run := startWSPeer(t, "", nil)
	dialPeer(t, run.url, false, nil)
	if out := run.wait(t); out.err != nil {
		t.Fatalf("peer: %v", out.err)
	}
	if _, ok := run.p.seen["sec-websocket-extensions"]; ok {
		t.Fatal("没请求压缩却发了 extensions 头")
	}
}
