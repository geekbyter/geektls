package tlscore

// P7-T3 fuzz：CheckProfile 统一入口 + 畸形 ServerHello 打握手路径，零 panic。

import (
	"bytes"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

var checkSeeds = []string{
	`{"name":"x","tls":{"detail":{"ciphers":["0x1301"],"extensions":[{"type":0,"sni":"a.com"}]}}}`,
	`{"ja3":"771,4865-4866,0-10-11,29-23,0"}`,
	`{"ja4r":"t13d1516h2_1301_000a_0403"}`,
	`{"clienthello_hex":"160301004b010000470303"}`,
	"771,4865-4866-4867,0-10-11,29-23,0",
	"t13d1516h2_002f,0035_000a_0403",
	"",
	"not-a-fingerprint",
	`{"tls":{}}`,
	`{`,
	"💣",
}

func FuzzCheckProfile(f *testing.F) {
	for _, s := range checkSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// 契约：结构化 error 或 CheckResult，绝不 panic
		_, _ = CheckProfile(input)
	})
}

// FuzzHandshakeMalformedServer 用随机字节冒充 ServerHello 打握手路径：
// 必须返回结构化错误，绝不 panic、绝不挂死（带超时）。
func FuzzHandshakeMalformedServer(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 512))
	f.Add(bytes.Repeat([]byte{0x00}, 128))
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x02})

	f.Fuzz(func(t *testing.T, serverBytes []byte) {
		if len(serverBytes) > 1<<16 {
			return
		}
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			// 不管客户端发什么，直接灌垃圾
			serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			serverConn.Write(serverBytes)
			time.Sleep(50 * time.Millisecond)
		}()

		p, _ := profiles.Get("chrome_133")
		spec, err := CompileDetail(p.TLS.Detail)
		if err != nil {
			t.Fatal(err)
		}
		uconn := utls.UClient(clientConn, &utls.Config{
			InsecureSkipVerify: true,
		}, utls.HelloCustom)
		if err := uconn.ApplyPreset(spec); err != nil {
			t.Fatal(err)
		}
		uconn.SetDeadline(time.Now().Add(2 * time.Second))
		// 契约：返回 error（任何形态），绝不 panic
		_ = uconn.Handshake()
		<-done
	})
}
