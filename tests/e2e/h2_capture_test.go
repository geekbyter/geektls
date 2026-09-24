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
	PseudoOrder  []string
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
			cap.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
		case 0x1: // HEADERS
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

// TestH2FrameCapture 全预设的 http2 节 → 线上帧断言。
func TestH2FrameCapture(t *testing.T) {
	serverCfg := loopbackServerConfig(t)

	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			if p.HTTP2 == nil {
				t.Skip("preset has no http2 section")
			}

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
			// 服务端不写合法响应帧，Do 会一直等响应——放后台，帧已发出即被采集。
			go func() {
				_, _ = h2core.Do(cc, "GET", "https://example.com/",
					[][2]string{{"user-agent", "geektls-h2-capture"}}, nil)
			}()

			res := <-serverDone
			if res.err != nil {
				t.Fatalf("server side: %v", res.err)
			}
			cap := res.cap

			// 断言 1：SETTINGS 值与顺序
			wantSettings := make([][2]uint32, 0, len(p.HTTP2.Settings))
			for _, kv := range p.HTTP2.Settings {
				wantSettings = append(wantSettings, [2]uint32{kv[0], kv[1]})
			}
			if fmt.Sprint(cap.Settings) != fmt.Sprint(wantSettings) {
				t.Errorf("settings = %v, want %v", cap.Settings, wantSettings)
			}

			// 断言 2：WINDOW_UPDATE 增量
			if cap.WindowUpdate != p.HTTP2.WindowUpdate {
				t.Errorf("window_update = %d, want %d", cap.WindowUpdate, p.HTTP2.WindowUpdate)
			}

			// 断言 3：伪头序
			wantPseudo, _ := h2core.PseudoHeaderOrder(p.HTTP2.PseudoHeaderOrder)
			if fmt.Sprint(cap.PseudoOrder) != fmt.Sprint(wantPseudo) {
				t.Errorf("pseudo header order = %v, want %v", cap.PseudoOrder, wantPseudo)
			}

			t.Logf("%s settings=%v window=%d pseudo=%v", name, cap.Settings, cap.WindowUpdate, cap.PseudoOrder)
		})
	}
}
