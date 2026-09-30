package engine

// permessage-deflate（RFC 7692）——WebSocket 帧载荷的 DEFLATE 扩展。
//
// 为什么"能不能解"排在"发不发那个头"前面：offer 头由调用方/profile 决定（本库
// 不默认发，见 ws.go 的注释），但对端一旦在 101 里协商成功，之后的数据帧就带
// RSV1 + 压缩载荷。没有这一层，recv() 会把压缩字节当文本原样返回——静默给出错
// 数据，比报错更糟。
//
// stdlib 的 compress/flate 没有"跨消息保留窗口"的入口：decompressor.Reset(r, dict)
// 会把历史清空，只把 dict 当预置字典用。而 context takeover 要的正是"上一条消息
// 的明文还在窗口里"。这里把已解出的明文尾巴（≤32768B，RFC 1951 的距离上限）当
// dict 传回去——每条消息的压缩块都以空 stored block 结束（字节对齐），所以"增量 +
// 补尾"喂进去是合法流（这条不变量由 ws_deflate_test.go 的对端实测钉住）。

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// wsDeflateName 是唯一支持的扩展名（RFC 6455 的扩展注册表里也只有它有实际部署）。
	wsDeflateName = "permessage-deflate"
	// wsDeflateTail 是每条消息结尾的"空 stored block"（BFINAL=0，RFC 7692 §7.2.1）。
	// 发送侧把它剥掉（窗口要接着用，不能在此收流），接收侧在消息结束时补回去，
	// 让 inflate 停在字节边界上。
	wsDeflateTail = "\x00\x00\xff\xff"
	// wsDeflateFinalTail 是同形的 BFINAL=1 块：对端按"每条消息独立收流"发时见到它。
	wsDeflateFinalTail = "\x01\x00\x00\xff\xff"
	// 压缩窗口的上限：stdlib flate 写侧恒用 32KB 窗口（不可配置），即 15 bit。
	wsDeflateWinBits = 15
	// 单条压缩消息的解压上限（防御：压缩炸弹）。
	wsDeflateInflateMax = 64 << 20
)

// wsDeflateOffer 是我们在握手 Offer 里对 permessage-deflate 的声明。
// 本库只发不带参数的 `permessage-deflate`：`client_max_window_bits` 的语义是
// "服务端可以把我方压缩窗口压到 N bit"，而 stdlib 的压缩器窗口不可配置——
// 不在 offer 里承诺做不到的事（调用方手写带该参数的 offer 时，见 negotiate 的报错）。
type wsDeflateOffer struct {
	name   string
	params map[string]string // 参数名 → 值；无值参数（如裸 client_max_window_bits）留空串
}

// parseWsExtensions 解析 Sec-WebSocket-Extensions 头：
// "ext1; p1=v1; p2, ext2" —— 逗号分扩展、分号分参数，双引号内不切分。
func parseWsExtensions(header string) ([]wsDeflateOffer, error) {
	var out []wsDeflateOffer
	for _, seg := range splitOutsideQuotes(header, ',') {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		parts := splitOutsideQuotes(seg, ';')
		offer := wsDeflateOffer{name: strings.ToLower(strings.TrimSpace(parts[0])), params: map[string]string{}}
		if offer.name == "" {
			return nil, fmt.Errorf("engine: ws 扩展头形态非法 %q", header)
		}
		for _, p := range parts[1:] {
			name, val, _ := strings.Cut(strings.TrimSpace(p), "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				return nil, fmt.Errorf("engine: ws 扩展参数形态非法 %q", seg)
			}
			offer.params[name] = strings.Trim(strings.TrimSpace(val), `"`)
		}
		out = append(out, offer)
	}
	return out, nil
}

// splitOutsideQuotes 按 sep 切分，但不切进双引号内部（参数值可以带引号）。
func splitOutsideQuotes(s string, sep byte) []string {
	var out []string
	inQuote, esc, start := false, false, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inQuote:
			esc = true
		case c == '"':
			inQuote = !inQuote
		case c == sep && !inQuote:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// wsDeflateState 是协商结果（nil = 本次连接不启用扩展）。
type wsDeflateState struct {
	// serverTakeover：对端跨消息保留压缩上下文（它没回
	// server_no_context_takeover 时即为保留，RFC 7692 §7.1.1）。
	serverTakeover bool
	// clientTakeover：我方跨消息保留上下文（没协商 client_no_context_takeover 时保留）。
	clientTakeover bool
}

// offeredHeaderOf 从握手实际发出的头里取我方对某扩展的 offer 原文。
func offeredExtHeader(headers [][2]string, name string) string {
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "sec-websocket-extensions") &&
			strings.Contains(strings.ToLower(kv[1]), name) {
			return kv[1]
		}
	}
	return ""
}

// negotiateWsDeflate 按 RFC 7692 §7.1/§9 核对 101 回包里的协商结果。
// offered（我方请求头里的值，可为空）决定了服务端**允许**回声哪些参数：
// 回声了我们没请求的东西就直接失败，而不是"看起来能用再说"。
func negotiateWsDeflate(offered, accepted string) (*wsDeflateState, error) {
	if strings.TrimSpace(accepted) == "" {
		return nil, nil // 没协商 ⇒ 纯 RFC 6455
	}
	acc, err := parseWsExtensions(accepted)
	if err != nil {
		return nil, err
	}
	off, err := parseWsExtensions(offered)
	if err != nil {
		return nil, err
	}
	var mine *wsDeflateOffer
	for i := range off {
		if off[i].name == wsDeflateName {
			mine = &off[i]
		}
	}
	st := &wsDeflateState{serverTakeover: true, clientTakeover: true}
	for _, a := range acc {
		if a.name != wsDeflateName {
			return nil, fmt.Errorf("engine: ws 对端协商了不支持的扩展 %q（只实现 %s）",
				a.name, wsDeflateName)
		}
		if mine == nil {
			return nil, fmt.Errorf("engine: ws 对端协商了 %s，但我方握手没发对应 offer"+
				"（请求头与回包不一致，不能当成没协商继续收）", wsDeflateName)
		}
		for name, val := range a.params {
			if _, ok := mine.params[name]; !ok {
				return nil, fmt.Errorf("engine: ws 对端回声了我方没请求的参数 %q（回包 %q）",
					name, accepted)
			}
			switch name {
			case "server_no_context_takeover":
				st.serverTakeover = false
			case "client_no_context_takeover":
				st.clientTakeover = false
			case "client_max_window_bits":
				// 它限定的是**我方压缩器**的窗口，而 stdlib flate 写侧恒 32KB（15 bit）。
				// 回声不带值 = 服务端接受默认（15 bit，RFC 7692 §7.1.2.1），我方正好用这个。
				if val == "" {
					continue
				}
				bits, err := strconv.Atoi(val)
				if err != nil || bits < 9 || bits > wsDeflateWinBits {
					return nil, fmt.Errorf("engine: ws client_max_window_bits=%q 无法处理："+
						"我方压缩窗口不可配置（只认 %d）；offer 里去掉该参数即可继续",
						val, wsDeflateWinBits)
				}
				if bits != wsDeflateWinBits {
					return nil, fmt.Errorf("engine: ws 对端把我方压缩窗口限到 %d bit，"+
						"stdlib flate 写侧恒 32KB(15 bit) ⇒ 发出去的流不保证合规；"+
						"offer 里去掉 client_max_window_bits 即可继续", bits)
				}
			case "server_max_window_bits":
				// 限定对端压缩器 ⇒ 我方 inflate 9..15 bit 都吃得下，只校验取值。
				if val != "" {
					bits, err := strconv.Atoi(val)
					if err != nil || bits < 9 || bits > wsDeflateWinBits {
						return nil, fmt.Errorf("engine: ws server_max_window_bits=%q 越界（9..%d）",
							val, wsDeflateWinBits)
					}
				}
			}
		}
	}
	return st, nil
}

// wsInflater 解对端发来的压缩载荷。
type wsInflater struct {
	rc       flateResetter
	hist     []byte // context takeover 的预置窗口（已解出的明文尾巴）
	takeover bool
}

// flateResetter 是 stdlib 解压对象的复用入口（NewReader 返回的 ReadCloser
// 同时实现了它；这里声明成接口以免把 *io.ReadCloser 到处传）。
type flateResetter interface {
	io.Reader
	Reset(r io.Reader, dict []byte) error
}

func newWSInflater(takeover bool) *wsInflater {
	rc, ok := flate.NewReader(bytes.NewReader(nil)).(flateResetter)
	if !ok { // stdlib 保证实现；走到这里说明 Go 换了实现，宁可报错也别退化成"当明文收"
		return nil
	}
	return &wsInflater{rc: rc, takeover: takeover}
}

// inflate 解一条消息的全部压缩载荷（分片消息要调用方先拼好）。
func (z *wsInflater) inflate(chunk []byte) ([]byte, error) {
	if len(chunk) == 0 {
		return nil, nil
	}
	var dict []byte
	if z.takeover {
		dict = z.hist
	}
	buf := make([]byte, 0, len(chunk)+len(wsDeflateTail))
	buf = append(buf, chunk...)
	buf = append(buf, wsDeflateTail...)
	if err := z.rc.Reset(bytes.NewReader(buf), dict); err != nil {
		return nil, fmt.Errorf("engine: ws inflate reset: %w", err)
	}
	var out bytes.Buffer
	_, err := io.Copy(&out, io.LimitReader(z.rc, wsDeflateInflateMax))
	switch err {
	case nil, io.EOF, io.ErrUnexpectedEOF:
		// 补上去的 tail 让 inflate 走到"下一个块头"才撞墙：ErrUnexpectedEOF
		// 是这条消息读完了的正常信号（Go 的 flate 在没有 final block 时就这么报）。
	default:
		return nil, fmt.Errorf("engine: ws inflate: %w", err)
	}
	if out.Len() == wsDeflateInflateMax {
		return nil, fmt.Errorf("engine: ws inflate 超出 %d 上限", wsDeflateInflateMax)
	}
	if z.takeover {
		z.hist = appendWindow(z.hist, out.Bytes())
	}
	return out.Bytes(), nil
}

// appendWindow 维护"最近 32KB 明文"作为下条消息的预置字典。
func appendWindow(hist, next []byte) []byte {
	if len(next) >= wsDeflateWinBytes {
		return append([]byte(nil), next[len(next)-wsDeflateWinBytes:]...)
	}
	out := append(hist, next...)
	if len(out) > wsDeflateWinBytes {
		out = out[len(out)-wsDeflateWinBytes:]
	}
	return out
}

// wsDeflateWinBytes 是 deflate 距离窗口上限（RFC 1951：32768B）。
const wsDeflateWinBytes = 32768

// wsDeflater 压缩我方发出的每条消息。
type wsDeflater struct {
	buf      *wsOutBuf
	w        *flate.Writer
	takeover bool
}

// wsOutBuf 是 flate.Writer 的输出汇：每次 deflate 前清空，取走增量后即可回收，
// 所以长期连接的内存不会随消息数增长（压缩上下文在 w 里，不在这段字节里）。
type wsOutBuf struct{ data []byte }

func (b *wsOutBuf) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func newWSDeflater(takeover bool) *wsDeflater {
	b := &wsOutBuf{}
	// BestSpeed：WS 消息通常短，级别 6 的额外 CPU 换不来什么；
	// 对端不感知（DEFLATE 自描述），窗口仍是 stdlib 的 32KB。
	w, err := flate.NewWriter(b, flate.BestSpeed)
	if err != nil {
		return nil
	}
	return &wsDeflater{buf: b, w: w, takeover: takeover}
}

// deflate 返回该消息的压缩载荷（已剥掉结尾的空 stored block）。
func (d *wsDeflater) deflate(msg []byte) []byte {
	if len(msg) == 0 {
		return nil // 空消息没必要压缩（RSV1=0 发出去更省，也免去对端补尾）
	}
	d.buf.data = d.buf.data[:0]
	// flate.Writer 的 Write/Flush 只在底层写入出错时返回错误；这里的汇不会失败，
	// 除非它内部扩容失败（OOM）——那时压缩结果本来也不存在。
	if _, err := d.w.Write(msg); err != nil {
		return nil
	}
	if err := d.w.Flush(); err != nil {
		return nil
	}
	out := trimWsDeflateTail(append([]byte(nil), d.buf.data...))
	if !d.takeover {
		d.w.Reset(d.buf) // 下一条消息从头开始（对端也不会带着我们的上下文解）
	}
	return out
}

// trimWsDeflateTail 去掉结尾的空块标记。两种形态都要认：BFINAL=0 的 sync 块
// （context takeover 继续用）与 BFINAL=1 的收流块（对端 reset 时用）。
func trimWsDeflateTail(b []byte) []byte {
	if bytes.HasSuffix(b, []byte(wsDeflateFinalTail)) {
		return b[:len(b)-len(wsDeflateFinalTail)]
	}
	if bytes.HasSuffix(b, []byte(wsDeflateTail)) {
		return b[:len(b)-len(wsDeflateTail)]
	}
	return b
}
