package main

// /ws：最小 RFC 6455 回声端点（h1 Upgrade；engine 侧强制 ALPN http/1.1）。
// text/binary 原样回显；ping 回 pong；close 回关。

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
)

func wsAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsEchoHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "not a websocket upgrade", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(r.Header.Get("Sec-Websocket-Key")) + "\r\n\r\n")
	if err := brw.Flush(); err != nil {
		return
	}
	br := brw.Reader

	for {
		fin, op, payload, err := wsReadFrame(br)
		if err != nil {
			return
		}
		_ = fin
		switch op {
		case 1, 2: // text/binary echo
			if err := wsWriteFrame(brw, op, payload); err != nil {
				return
			}
		case 9: // ping → pong
			if err := wsWriteFrame(brw, 10, payload); err != nil {
				return
			}
		case 8: // close → 回关
			wsWriteFrame(brw, 8, payload)
			return
		}
		if err := brw.Flush(); err != nil {
			return
		}
	}
}

func wsReadFrame(br *bufio.Reader) (bool, int, []byte, error) {
	var hdr [2]byte
	if _, err := readAll(br, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	op := int(hdr[0] & 0x0f)
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7f)
	if n == 126 {
		var ext [2]byte
		readAll(br, ext[:])
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if n == 127 {
		var ext [8]byte
		readAll(br, ext[:])
		n = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	if masked {
		readAll(br, mask[:])
	}
	payload := make([]byte, n)
	if _, err := readAll(br, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, op, payload, nil
}

func wsWriteFrame(brw *bufio.ReadWriter, op int, payload []byte) error {
	hdr := []byte{0x80 | byte(op)}
	n := len(payload)
	switch {
	case n <= 125:
		hdr = append(hdr, byte(n))
	case n <= 0xffff:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	if _, err := brw.Write(hdr); err != nil {
		return err
	}
	_, err := brw.Write(payload)
	return err
}

func readAll(br *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := br.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
