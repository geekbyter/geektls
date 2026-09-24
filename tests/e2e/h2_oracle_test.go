//go:build external

// H2 外部 oracle（P2-T5）：对每个预设真打 tls.peet.ws/api/all，
// 回读服务端视角的 akamai_fingerprint 与 sent_frames，与预设期望 diff。
// 只打印报告不硬断言。运行：go test -tags external ./... -run TestExternalOracleH2 -v

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	h2core "github.com/geektls/core/h2"
	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// expectedAkamai 是各预设 http2 节的期望值（与预设 JSON 保持同步）。
func expectedAkamai(p *profiles.Profile) string {
	s := ""
	for i, kv := range p.HTTP2.Settings {
		if i > 0 {
			s += ";"
		}
		s += fmt.Sprintf("%d:%d", kv[0], kv[1])
	}
	pseudo := ""
	for i, c := range p.HTTP2.PseudoHeaderOrder {
		if i > 0 {
			pseudo += ","
		}
		pseudo += c
	}
	return fmt.Sprintf("%s|%d|0|%s", s, p.HTTP2.WindowUpdate, pseudo)
}

type h2OracleResponse struct {
	HTTP2 *struct {
		AkamaiFingerprint string `json:"akamai_fingerprint"`
		SentFrames        []struct {
			FrameType string `json:"frame_type"`
		} `json:"sent_frames"`
	} `json:"http2"`
}

func TestExternalOracleH2(t *testing.T) {
	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			tlsSpec, err := tlscore.CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatal(err)
			}

			conn, err := net.DialTimeout("tcp", oracleHost+":443", 10*time.Second)
			if err != nil {
				t.Skipf("oracle unreachable: %v", err)
			}
			defer conn.Close()
			uconn, err := tlscore.Handshake(conn, &utls.Config{
				ServerName:         oracleHost,
				InsecureSkipVerify: true, // 本机 CA bundle 问题，oracle 只读指纹
			}, tlsSpec)
			if err != nil {
				t.Fatalf("handshake with oracle: %v", err)
			}
			if uconn.ConnectionState().NegotiatedProtocol != "h2" {
				t.Fatalf("ALPN negotiated %q, want h2", uconn.ConnectionState().NegotiatedProtocol)
			}

			cc, err := h2core.NewClientConn(uconn, p.HTTP2)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := h2core.Do(cc, "GET", "https://"+oracleHost+"/api/all", nil, nil)
			if err != nil {
				t.Fatalf("H2 request: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if err != nil {
				t.Fatal(err)
			}

			var got h2OracleResponse
			if err := json.Unmarshal(body, &got); err != nil || got.HTTP2 == nil {
				t.Fatalf("oracle response has no http2 section: %v\n%.500s", err, body)
			}

			want := expectedAkamai(p)
			fmt.Printf("== %s ==\n", name)
			fmt.Printf("  akamai self=%s\n         orac=%s  %s\n",
				want, got.HTTP2.AkamaiFingerprint, mark(want == got.HTTP2.AkamaiFingerprint))
			frames := ""
			for _, f := range got.HTTP2.SentFrames {
				frames += f.FrameType + " "
			}
			fmt.Printf("  frames: %s\n", frames)
		})
	}
}
