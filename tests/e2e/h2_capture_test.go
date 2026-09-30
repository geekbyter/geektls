package e2e

// L1 H2 帧采集器（P2-T5）：预设的 http2 节 → fhttp 线上帧 → 服务端裸读帧字节
// 解析（SETTINGS 序列/序、WINDOW_UPDATE 增量、HEADERS hpack 解码出伪头序），
// 与预设期望值逐项断言。

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"

	h2core "github.com/geektls/core/h2"
	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

type h2Capture struct {
	Settings     [][2]uint32
	WindowUpdate uint32
	// ConnFlowSeen 表示前几帧里是否真的出现过**连接级**（stream 0）WINDOW_UPDATE。
	// 预设写 &0（不发）时必须为 false；写 nil 时引擎补默认值，必须为 true。
	ConnFlowSeen bool
	// StreamID 是首个 HEADERS 帧的 stream id（预设未指定 first_stream_id 时为 1）。
	StreamID    uint32
	PseudoOrder []string
}

// readClientPreface 读取并校验 H2 client preface + 逐帧解析，
// 直到收齐首个 HEADERS 帧的伪头序为止。
func readClientPreface(conn net.Conn) (*h2Capture, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	preface := make([]byte, 24)
	if _, err := io.ReadFull(conn, preface); err != nil {
		return nil, fmt.Errorf("read preface: %w", err)
	}
	if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return nil, fmt.Errorf("bad preface: %q", preface)
	}

	cap := &h2Capture{}
	decoder := hpack.NewDecoder(4096, nil)
	var hpackPayload []byte

	decodeHeaders := func() error {
		fields, err := decoder.DecodeFull(hpackPayload)
		if err != nil {
			return fmt.Errorf("hpack decode: %w", err)
		}
		for _, hf := range fields {
			if len(hf.Name) > 0 && hf.Name[0] == ':' {
				cap.PseudoOrder = append(cap.PseudoOrder, hf.Name)
			}
		}
		return nil
	}

	for {
		hdr := make([]byte, 9)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return nil, fmt.Errorf("read frame header: %w", err)
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		ftype, flags := hdr[3], hdr[4]
		streamID := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, fmt.Errorf("read frame payload: %w", err)
		}

		switch ftype {
		case 0x4: // SETTINGS
			if flags&0x1 != 0 { // ACK
				continue
			}
			for i := 0; i+6 <= len(payload); i += 6 {
				cap.Settings = append(cap.Settings, [2]uint32{
					uint32(binary.BigEndian.Uint16(payload[i:])),
					binary.BigEndian.Uint32(payload[i+2:]),
				})
			}
		case 0x8: // WINDOW_UPDATE
			// 只记连接级（stream 0）的那一帧：流级 WINDOW_UPDATE 是读数据时的
			// 补充额度，与预设的 window_update 不是一回事。
			if streamID == 0 {
				cap.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
				cap.ConnFlowSeen = true
			}
		case 0x1: // HEADERS
			if cap.StreamID == 0 {
				cap.StreamID = streamID
			}
			if flags&0x8 != 0 { // PADDED
				padLen := int(payload[0])
				payload = payload[1 : len(payload)-padLen]
			}
			if flags&0x20 != 0 { // PRIORITY
				payload = payload[5:]
			}
			hpackPayload = append(hpackPayload, payload...)
			if flags&0x4 != 0 { // END_HEADERS
				return cap, decodeHeaders()
			}
		case 0x9: // CONTINUATION
			hpackPayload = append(hpackPayload, payload...)
			if flags&0x4 != 0 {
				return cap, decodeHeaders()
			}
		}
	}
}

// captureH2Frames 用 p 的 tls/http2 节在 loopback TLS 上建 H2 连接、发出第一个
// 请求，并返回服务端裸读的帧序列。服务端不写响应，所以 Do 挂在后台 goroutine 里
// ——帧已经发出并被采集，这正是本测试要的东西。
func captureH2Frames(t *testing.T, p *profiles.Profile) *h2Capture {
	t.Helper()

	serverCfg := loopbackServerConfig(t)
	tlsSpec, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	type result struct {
		cap *h2Capture
		err error
	}
	serverDone := make(chan result, 1)
	go func() {
		srv := tls.Server(serverConn, serverCfg)
		if err := srv.Handshake(); err != nil {
			serverDone <- result{err: err}
			return
		}
		c, err := readClientPreface(srv)
		serverDone <- result{c, err}
		// 采集完成后继续排空，让客户端的后续帧不阻塞。
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
	go func() {
		_, _ = h2core.Do(cc, "GET", "https://example.com/",
			[][2]string{{"user-agent", "geektls-h2-capture"}}, nil)
	}()

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server side: %v", res.err)
	}
	return res.cap
}

// TestH2FrameCapture 全预设的 http2 节 → 线上帧断言。
func TestH2FrameCapture(t *testing.T) {
	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			if p.HTTP2 == nil {
				t.Skip("preset has no http2 section")
			}
			cap := captureH2Frames(t, p)

			// 断言 1：SETTINGS 值与顺序
			wantSettings := settingsOf(p.HTTP2)
			if fmt.Sprint(cap.Settings) != fmt.Sprint(wantSettings) {
				t.Errorf("settings = %v, want %v", cap.Settings, wantSettings)
			}

			// 断言 2：连接级 WINDOW_UPDATE 的三态（nil/&0/&N）在线上各是什么形态
			if want := flowOnWire(p.HTTP2.WindowUpdate); want == 0 {
				if cap.ConnFlowSeen {
					t.Errorf("预设 window_update=0（不发），线上却出现连接级 WINDOW_UPDATE +%d", cap.WindowUpdate)
				}
			} else if !cap.ConnFlowSeen || cap.WindowUpdate != want {
				t.Errorf("window_update 帧 = seen:%v inc:%d, want inc %d", cap.ConnFlowSeen, cap.WindowUpdate, want)
			}

			// 断言 3：伪头序
			wantPseudo, _ := h2core.PseudoHeaderOrder(p.HTTP2.PseudoHeaderOrder)
			if fmt.Sprint(cap.PseudoOrder) != fmt.Sprint(wantPseudo) {
				t.Errorf("pseudo header order = %v, want %v", cap.PseudoOrder, wantPseudo)
			}

			// 断言 4：首个请求的 stream id（预设未指定 ⇒ 1）
			if wantID := firstStreamID(p.HTTP2); cap.StreamID != wantID {
				t.Errorf("首个 HEADERS 的 stream_id = %d, want %d", cap.StreamID, wantID)
			}

			t.Logf("%s settings=%v window=%d stream=%d pseudo=%v", name, cap.Settings, cap.WindowUpdate, cap.StreamID, cap.PseudoOrder)
		})
	}
}

// firstStreamID 给预设在线上使用的第一个请求 stream id。
func firstStreamID(p *profiles.HTTP2Profile) uint32 {
	if p == nil || p.FirstStreamID == 0 {
		return 1
	}
	return p.FirstStreamID
}

// TestH2FrameCaptureTriState 把 window_update 的三态与 first_stream_id 钉在线上：
// 预设里写 &0 就真的不发连接级 WINDOW_UPDATE，写 first_stream_id=3 首个 HEADERS
// 就真的是流 3。全库预设都不带这两档（都是 nil/0），所以这一段是**唯一**覆盖
// 它们的线上断言，也是导入器将来产出这类预设时的守门。
func TestH2FrameCaptureTriState(t *testing.T) {
	base, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	if base.HTTP2 == nil {
		t.Fatal("chrome_133 没有 http2 节")
	}

	for _, tc := range []struct {
		name         string
		window       *uint32
		firstStream  uint32
		wantSeen     bool
		wantInc      uint32
		wantStreamID uint32
	}{
		{"nil=引擎默认", nil, 0, true, 15663105, 1},
		{"&0=不发", profiles.U32(0), 0, false, 0, 1},
		{"&N=照抄", profiles.U32(33488897), 0, true, 33488897, 1},
		{"first_stream_id=3", nil, 3, true, 15663105, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := *base
			h2 := *base.HTTP2
			h2.WindowUpdate = tc.window
			h2.FirstStreamID = tc.firstStream
			p.HTTP2 = &h2

			cap := captureH2Frames(t, &p)
			if cap.ConnFlowSeen != tc.wantSeen {
				t.Errorf("连接级 WINDOW_UPDATE 帧 seen = %v, want %v", cap.ConnFlowSeen, tc.wantSeen)
			}
			if tc.wantSeen && cap.WindowUpdate != tc.wantInc {
				t.Errorf("window_update 增量 = %d, want %d", cap.WindowUpdate, tc.wantInc)
			}
			if cap.StreamID != tc.wantStreamID {
				t.Errorf("首个 HEADERS 的 stream_id = %d, want %d", cap.StreamID, tc.wantStreamID)
			}
			// SETTINGS 不该被这两个字段带着走（同一 profile 的其他部分不变）。
			if fmt.Sprint(cap.Settings) != fmt.Sprint(settingsOf(base.HTTP2)) {
				t.Errorf("settings = %v, want %v", cap.Settings, settingsOf(base.HTTP2))
			}
		})
	}
}

// settingsOf 把预设的 [[id,value],...] 归一成捕获帧里的 [][2]uint32。
func settingsOf(p *profiles.HTTP2Profile) [][2]uint32 {
	out := make([][2]uint32, 0, len(p.Settings))
	for _, kv := range p.Settings {
		out = append(out, [2]uint32{kv[0], kv[1]})
	}
	return out
}
