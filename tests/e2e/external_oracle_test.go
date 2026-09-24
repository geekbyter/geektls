//go:build external

// 外部 oracle 验证（L3）：对每个预设真实拨号 tls.peet.ws/api/all，
// 回读服务端视角的 ja3/ja4 与自算值 diff。
//
// 默认不跑（build tag external）：本机/CI 网络可用时
//   go test -tags external ./... -run TestExternalOracle -v
// 结果只打印报告不硬断言（tls.peet.ws 的解析行为可能随版本变化）。

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

const oracleHost = "tls.peet.ws"

type oracleResponse struct {
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`
	JA4     string `json:"ja4"`
	// 新版 api/all 把指纹嵌套在 tls 键下
	TLS *struct {
		JA3     string `json:"ja3"`
		JA3Hash string `json:"ja3_hash"`
		JA4     string `json:"ja4"`
	} `json:"tls"`
}

func (r *oracleResponse) resolve() (ja3, ja3Hash, ja4 string) {
	if r.TLS != nil && r.TLS.JA4 != "" {
		return r.TLS.JA3, r.TLS.JA3Hash, r.TLS.JA4
	}
	return r.JA3, r.JA3Hash, r.JA4
}

func TestExternalOracle(t *testing.T) {
	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := tlscore.CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatal(err)
			}

			conn, err := net.DialTimeout("tcp", oracleHost+":443", 10*time.Second)
			if err != nil {
				t.Skipf("oracle unreachable: %v", err)
			}
			defer conn.Close()
			uconn, err := tlscore.Handshake(conn, &utls.Config{ServerName: oracleHost}, spec)
			if err != nil {
				t.Fatalf("handshake with oracle: %v", err)
			}

			body := httpGet(t, uconn, oracleHost, "/api/all")
			var raw oracleResponse
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatalf("oracle response not JSON: %v\n%s", err, body)
			}
			gotJA3, gotJA3Hash, gotJA4 := raw.resolve()
			if gotJA4 == "" {
				t.Fatalf("oracle response has no ja4 field:\n%s", body)
			}

			wantJA3 := tlscore.ComputeJA3(spec)
			wantJA4 := tlscore.ComputeJA4(spec)
			fmt.Printf("== %s ==\n", name)
			fmt.Printf("  ja4  self=%s\n       orac=%s  %s\n", wantJA4, gotJA4, mark(wantJA4 == gotJA4))
			fmt.Printf("  ja3h self=%s\n       orac=%s  %s\n", tlscore.JA3Hash(wantJA3), gotJA3Hash, mark(tlscore.JA3Hash(wantJA3) == gotJA3Hash))
			fmt.Printf("  ja3  self=%s\n       orac=%s\n", wantJA3, gotJA3)
		})
	}
}

func mark(ok bool) string {
	if ok {
		return "MATCH"
	}
	return "DIFF"
}

// httpGet 在已握手的 TLS 连接上发最小 HTTP/1.1 请求并读出 body
// （处理 Content-Length 与 chunked 两种常见形态，仅够 oracle 用）。
func httpGet(t *testing.T, conn net.Conn, host, path string) []byte {
	t.Helper()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	head, rest, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		t.Fatalf("bad HTTP response: %q", raw[:min(len(raw), 200)])
	}
	if strings.Contains(strings.ToLower(string(head)), "chunked") {
		return unchunk(t, rest)
	}
	return rest
}

func unchunk(t *testing.T, b []byte) []byte {
	t.Helper()
	var out []byte
	for len(b) > 0 {
		line, rest, ok := strings.Cut(string(b), "\r\n")
		if !ok {
			t.Fatalf("bad chunk header")
		}
		var n int
		if _, err := fmt.Sscanf(line, "%x", &n); err != nil {
			t.Fatalf("bad chunk size %q", line)
		}
		if n == 0 {
			return out
		}
		b = []byte(rest)
		if len(b) < n+2 {
			t.Fatalf("short chunk")
		}
		out = append(out, b[:n]...)
		b = b[n+2:]
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
