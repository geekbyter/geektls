package engine

// WebSocket（wss://，RFC 6455）。
//
// 握手走 geektls 自己的拨号 + TLS 指纹链路（connectALPN 强制 http/1.1——
// Upgrade 在 h2 上无效；H2 上的 WS（RFC 8441）不做，见 capability-matrix）。
// Upgrade 请求头序受控：默认对齐真 Chrome 的 WS 握手头序
//（host → connection → upgrade → origin? → 身份/用户头 →
// sec-websocket-version → sec-websocket-key → sec-websocket-extensions?），
// profile.http1.header_order 非空时整体再过一遍排序器（可自定义）。
// 帧层自实现（stdlib）：text/binary/ping/pong/close、客户端 masking
//（RFC 强制）、分片重组、控制帧 125 字节限制、UTF-8 宽松（不校验，原样透传）。
// ping 自动回 pong；连接不进连接池（长连接语义）。
// permessage-deflate（RFC 7692）已实现：要不要 offer 由 WSRequest.compress
// （或调用方自己写的那个头）决定；只有握手真的协商成功才压/解，RSV 位与对端
// 回声的参数都按 RFC 校验——"对端压缩了我们却当明文返回"是绝不允许的失败模式。

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/geektls/core/profiles"
)

// WS opcode（RFC 6455 §5.2）。
const (
	WSOpContinuation = 0
	WSOpText         = 1
	WSOpBinary       = 2
	WSOpClose        = 8
	WSOpPing         = 9
	WSOpPong         = 10
)

// WSConn 是一条已建立 WebSocket 连接（写串行化；读单消费者）。
// deflate/inflate 非 nil 表示握手协商成了 permessage-deflate（RFC 7692）：
// 发数据帧前压缩并置 RSV1，收数据帧时按 RSV1 解压。
type WSConn struct {
	uconn   net.Conn // *utls.UConn
	br      *bufio.Reader
	wmu     sync.Mutex
	closed  bool
	deflate *wsDeflater
	inflate *wsInflater
}

// WSRequest 是 ws 连接请求（FFI 的 url_json 映射到它）。
type WSRequest struct {
	URL       string      `json:"url"`
	Headers   [][2]string `json:"headers,omitempty"`
	TimeoutMs int         `json:"timeout_ms,omitempty"` // 拨号+握手超时
	// Compress=true 时在握手头里补 `sec-websocket-extensions: permessage-deflate`
	// （不带参数：见 wsdeflate.go 里对 client_max_window_bits 的说明）。
	// 已经手写该头的，以手写的为准，这里不重复加。
	Compress bool `json:"compress,omitempty"`
}

// DialWS 建立 WebSocket 连接：wss 走指纹链路（握手走同 profile 的
// ClientHello），ws（明文，G5）只做 TCP——帧层与 TLS 无关，两条路径
// 共用同一套帧实现，差别只在拨号那一步。→ Upgrade 握手 → 校验 101 + accept key。
func (s *Session) DialWS(wr *WSRequest) (*WSConn, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("engine: session closed")
	}
	u, err := url.Parse(wr.URL)
	if err != nil {
		return nil, fmt.Errorf("engine: bad url: %w", err)
	}
	plain := false
	switch u.Scheme {
	case "wss":
	case "ws":
		plain = true
	default:
		return nil, fmt.Errorf("engine: ws 仅支持 ws:// 与 wss://（got %q）", u.Scheme)
	}

	scheme := "https"
	if plain {
		scheme = "http"
	}
	// req 是"给拨号/代理链路看的等价 HTTP URL"（ws/wss 只差 scheme）。
	req := &Request{URL: scheme + "://" + u.Host + u.RequestURI(), TimeoutMs: wr.TimeoutMs}

	var tc *transportConn
	if plain {
		tc, err = s.connectPlain(req, u)
	} else {
		// ALPN 收窄到 http/1.1：只改 cfg.NextProtos 没用（uTLS 线上发的是
		// ClientHello 扩展里的协议列表），必须把 detail 的 ALPN 扩展也收窄——
		// 否则服务端按扩展内容协商出 h2，Upgrade 在 h2 上无效。
		detail := *s.profile.TLS.Detail
		exts := make([]profiles.Extension, len(detail.Extensions))
		copy(exts, detail.Extensions)
		for i, e := range exts {
			if e.Type == 16 {
				e.ALPN = []string{"http/1.1"}
				exts[i] = e
			}
		}
		detail.Extensions = exts
		tc, err = s.connectALPN(req, u, []string{"http/1.1"}, &detail)
	}
	if err != nil {
		return nil, err
	}

	// Sec-WebSocket-Key：16 随机字节 base64
	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		tc.uconn.Close()
		return nil, err
	}
	wsKey := base64.StdEncoding.EncodeToString(keyRaw[:])

	// 头序：Chrome 式默认序 + profile header_order 可覆盖
	// 不原地改 wr.Headers：调用方可能拿同一个请求再拨一次。
	hdrs := wr.Headers
	if wr.Compress {
		// 合成 offer；调用方自己写了这个头就以他的为准（不重复、不覆盖）。
		offered := false
		for _, kv := range hdrs {
			if equalFoldASCII(kv[0], "sec-websocket-extensions") {
				offered = true
			}
		}
		if !offered {
			hdrs = append(append([][2]string(nil), hdrs...),
				[2]string{"sec-websocket-extensions", wsDeflateName})
		}
	}
	var identHeaders, extHeaders [][2]string
	headers := [][2]string{
		{"connection", "Upgrade"},
		{"upgrade", "websocket"},
	}
	for _, kv := range hdrs {
		if equalFoldASCII(kv[0], "origin") {
			headers = append(headers, kv) // origin 紧跟 upgrade（Chrome 序）
			continue
		}
		// sec-websocket-extensions 单独挪到 key 之后（Chrome 握手就是这个相对序）；
		// 留在用户头的位置会让它跑到 key 前面。
		if equalFoldASCII(kv[0], "sec-websocket-extensions") {
			extHeaders = append(extHeaders, kv)
			continue
		}
		identHeaders = append(identHeaders, kv)
	}
	// G9：WS 握手同样过身份自洽（告警无处承载，丢弃——WSConn 没有 warnings 字段）
	ident, _ := s.applyIdentity(identHeaders)
	headers = append(headers, ident...)
	headers = append(headers, [2]string{"sec-websocket-version", "13"})
	headers = append(headers, [2]string{"sec-websocket-key", wsKey})
	headers = append(headers, extHeaders...) // 扩展声明固定在 key 之后（Chrome 序）
	// 去重（identity 注入的重复项）并按 header_case 整形 + header_order 排序
	seen := map[string]bool{}
	var dedup [][2]string
	for _, kv := range headers {
		k := strings.ToLower(kv[0])
		if seen[k] {
			continue
		}
		seen[k] = true
		dedup = append(dedup, kv)
	}
	ordered := s.orderH1Headers(s.profile, dedup, u)

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	for _, kv := range ordered {
		fmt.Fprintf(&b, "%s: %s\r\n", kv[0], kv[1])
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(tc.uconn, b.String()); err != nil {
		tc.uconn.Close()
		return nil, fmt.Errorf("engine: ws write handshake: %w", err)
	}

	br := bufio.NewReader(tc.uconn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		tc.uconn.Close()
		return nil, fmt.Errorf("engine: ws read handshake response: %w", err)
	}
	if resp.StatusCode != 101 {
		tc.uconn.Close()
		return nil, fmt.Errorf("engine: ws handshake: status %d, want 101", resp.StatusCode)
	}
	want := wsAcceptKey(wsKey)
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != want {
		tc.uconn.Close()
		return nil, fmt.Errorf("engine: ws handshake: bad accept key %q (want %q)", got, want)
	}
	// 协商结果：只有对端真的按我们的 offer 接受了 permessage-deflate 才启用压缩。
	// 认不出来的扩展、我方没请求却被回声的参数都在这里失败，不会"先连着看"。
	st, err := negotiateWsDeflate(offeredExtHeader(ordered, wsDeflateName),
		resp.Header.Get("Sec-WebSocket-Extensions"))
	if err != nil {
		tc.uconn.Close()
		return nil, err
	}
	wc := &WSConn{uconn: tc.uconn, br: br}
	if st != nil {
		if wc.inflate = newWSInflater(st.serverTakeover); wc.inflate == nil {
			tc.uconn.Close()
			return nil, fmt.Errorf("engine: ws 无法启用 permessage-deflate 解压（stdlib 解压接口变更）")
		}
		if wc.deflate = newWSDeflater(st.clientTakeover); wc.deflate == nil {
			tc.uconn.Close()
			return nil, fmt.Errorf("engine: ws 无法启用 permessage-deflate 压缩（stdlib 压缩接口变更）")
		}
	}
	return wc, nil
}

// wsAcceptKey = base64(sha1(key + GUID))（RFC 6455 §4.2.2）。
func wsAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Send 发一帧（客户端必带 masking；控制帧 payload ≤125 且不允许多片）。
func (c *WSConn) Send(opcode int, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return fmt.Errorf("engine: ws closed")
	}
	if opcode >= 8 {
		if len(payload) > 125 {
			return fmt.Errorf("engine: ws control frame payload %d > 125", len(payload))
		}
	}
	// permessage-deflate：数据帧整条压缩（控制帧按 RFC 7692 §6.2.2 永不压缩，
	// RSV1 必须为 0）。本方法一帧就是一条完整消息（FIN=1），压缩结果直接进载荷。
	rsv1 := false
	if c.deflate != nil && opcode < 8 && len(payload) > 0 {
		if comp := c.deflate.deflate(payload); len(comp) > 0 {
			payload, rsv1 = comp, true
		}
	}
	var hdr []byte
	first := byte(0x80) // FIN=1
	if rsv1 {
		first |= 0x40 // RSV1 = permessage-deflate
	}
	hdr = append(hdr, first|byte(opcode))
	n := len(payload)
	switch {
	case n <= 125:
		hdr = append(hdr, 0x80|byte(n)) // MASK=1
	case n <= 0xffff:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	if _, err := c.uconn.Write(hdr); err != nil {
		return fmt.Errorf("engine: ws write header: %w", err)
	}
	if n > 0 {
		masked := make([]byte, n)
		for i, b := range payload {
			masked[i] = b ^ mask[i%4]
		}
		if _, err := c.uconn.Write(masked); err != nil {
			return fmt.Errorf("engine: ws write payload: %w", err)
		}
	}
	return nil
}

// Recv 收一条完整消息（分片重组；ping 自动回 pong、pong 吞掉、close 回关）。
// 返回（opcode, payload）：data 帧为 WSOpText/WSOpBinary；收到对端 close
// 返回 WSOpClose + 状态码负载。timeoutMs>0 时设读超时（超时返回
// *net.OpError Timeout 错误）。
func (c *WSConn) Recv(timeoutMs int) (int, []byte, error) {
	if timeoutMs > 0 {
		c.uconn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
		defer c.uconn.SetReadDeadline(time.Time{})
	}
	var (
		msgOp  int
		msgBuf []byte
		inMsg  bool
		// compMsg：这条分片消息是压缩的（RSV1 只出现在首帧，RFC 7692 §6.2.2，
		// 所以要跟着整条消息走，而不是逐帧判断）。
		compMsg bool
	)
	for {
		fin, op, rsv1, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch {
		case op == WSOpPing:
			if err := c.Send(WSOpPong, payload); err != nil {
				return 0, nil, err
			}
		case op == WSOpPong:
			// 吞掉（应用层要 ping/pong 探活可另发 ping）
		case op == WSOpClose:
			if !c.closed {
				c.Send(WSOpClose, payload) // 回关（尽力）
				c.closed = true
			}
			return WSOpClose, payload, nil
		case op == WSOpText || op == WSOpBinary:
			if inMsg {
				return 0, nil, fmt.Errorf("engine: ws 协议错误：分片消息中来了新消息")
			}
			if fin {
				if rsv1 {
					payload, err = c.inflateOne(payload)
					if err != nil {
						return 0, nil, err
					}
				}
				return op, payload, nil
			}
			inMsg, msgOp, compMsg = true, op, rsv1
			msgBuf = append([]byte(nil), payload...)
		case op == WSOpContinuation:
			if !inMsg {
				return 0, nil, fmt.Errorf("engine: ws 协议错误：孤立的 continuation 帧")
			}
			if rsv1 {
				return 0, nil, fmt.Errorf("engine: ws 协议错误：continuation 帧带了 RSV1")
			}
			msgBuf = append(msgBuf, payload...)
			if fin {
				if compMsg {
					msgBuf, err = c.inflateOne(msgBuf)
					if err != nil {
						return 0, nil, err
					}
				}
				return msgOp, msgBuf, nil
			}
		default:
			return 0, nil, fmt.Errorf("engine: ws 未知 opcode %d", op)
		}
	}
}

// inflateOne 解一条完整消息的压缩载荷（未协商扩展时是恒等检查）。
func (c *WSConn) inflateOne(chunk []byte) ([]byte, error) {
	if c.inflate == nil {
		return nil, fmt.Errorf("engine: ws 对端发了 RSV1（压缩）帧，但握手没协商 permessage-deflate")
	}
	out, err := c.inflate.inflate(chunk)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readFrame 读并解析一帧（服务端帧必须不 mask；mask 的按 RFC 容错解开）。
// rsv1 单独返回：它是"这条消息被 permessage-deflate 压过"的唯一信号。
func (c *WSConn) readFrame() (fin bool, opcode int, rsv1 bool, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(c.br, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	rsv1 = hdr[0]&0x40 != 0
	opcode = int(hdr[0] & 0x0f)
	if hdr[0]&0x30 != 0 {
		// RSV2/RSV3：只有协商了对应扩展才允许非 0，而我们只谈 permessage-deflate。
		err = fmt.Errorf("engine: ws 协议错误：RSV2/RSV3 非 0（0x%02x），没有协商过用到它们的扩展", hdr[0])
		return
	}
	if rsv1 && opcode >= 8 {
		err = fmt.Errorf("engine: ws 协议错误：控制帧（opcode=%d）带了 RSV1", opcode)
		return
	}
	if rsv1 && c.inflate == nil {
		err = fmt.Errorf("engine: ws 协议错误：收到 RSV1 帧但握手未协商 permessage-deflate")
		return
	}
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	if opcode >= 8 && (n > 125 || !fin) {
		err = fmt.Errorf("engine: ws 控制帧违规（opcode=%d len=%d fin=%v）", opcode, n, fin)
		return
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return
		}
	}
	if n > 64<<20 { // 64MB 防御上限
		err = fmt.Errorf("engine: ws 帧过大 %d", n)
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

// Close 发 close 帧并关连接（幂等）。
func (c *WSConn) Close(code int) error {
	if c.closed {
		return nil
	}
	var payload []byte
	if code > 0 {
		payload = make([]byte, 2)
		binary.BigEndian.PutUint16(payload, uint16(code))
	}
	sendErr := c.Send(WSOpClose, payload)
	c.closed = true
	if err := c.uconn.Close(); err != nil && sendErr == nil {
		return err
	}
	return sendErr
}
