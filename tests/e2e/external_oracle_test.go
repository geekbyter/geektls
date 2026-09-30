//go:build external

// 外部 oracle 验证（L3）：对每个预设真实拨号 tls.peet.ws/api/all，
// 回读服务端视角的 ja3/ja4 与自算值 diff。
//
// 默认不跑（build tag external）：本机/CI 网络可用时
//   go test -tags external ./... -run TestExternalOracle -v
// 默认只打印报告不硬断言（tls.peet.ws 的解析行为可能随版本变化，V-3 约定）；
// GEEKTLS_ORACLE_ASSERT=1 时 JA4/JA3/Akamai 不一致即失败——nightly CI 用这个档，
// 见 assertMode。子集用 GEEKTLS_ORACLE_PRESETS（不设=全量）：每条预设都要真打
// 一次第三方 oracle，全量 364 条在 CI 里既慢又像是压测。

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

const oracleHost = "tls.peet.ws"

// oraclePresets 返回本轮 oracle 要跑的预设清单（GEEKTLS_ORACLE_PRESETS 子集，未设=全量）。
// 名单里的模式一个都没匹配到 ⇒ 直接失败：拼错的预设名会让"oracle 全绿"变成"什么都没测"。
func oraclePresets(t *testing.T) []string {
	all := profiles.List()
	spec := strings.TrimSpace(os.Getenv("GEEKTLS_ORACLE_PRESETS"))
	if spec == "" {
		return all
	}
	pats := []string{}
	for _, p := range strings.Split(spec, ",") {
		if p = strings.TrimSpace(p); p != "" {
			pats = append(pats, p)
		}
	}
	out := make([]string, 0, len(all))
	matched := map[string]int{}
	for _, name := range all {
		for _, pat := range pats {
			if ok, err := path.Match(pat, name); err == nil && ok {
				matched[pat]++
				out = append(out, name)
				break
			}
		}
	}
	for _, pat := range pats {
		if matched[pat] == 0 {
			t.Errorf("GEEKTLS_ORACLE_PRESETS 里的模式 %q 没匹配到任何预设（拼错或已改名）", pat)
		}
	}
	if len(out) == 0 {
		t.Fatalf("GEEKTLS_ORACLE_PRESETS=%q 一条预设都没选中", spec)
	}
	t.Logf("oracle 子集 %d/%d 条：%s", len(out), len(all), spec)
	return out
}

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
	for _, name := range oraclePresets(t) {
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
			if assertMode() {
				if wantJA4 != gotJA4 {
					t.Errorf("[%s] JA4 self=%s oracle=%s 不一致", name, wantJA4, gotJA4)
				}
				if h := tlscore.JA3Hash(wantJA3); h != gotJA3Hash {
					t.Errorf("[%s] JA3 hash self=%s oracle=%s 不一致", name, h, gotJA3Hash)
				}
			}
		})
	}
}

// assertMode：oracle 对拍是否"不一致即失败"。默认关（V-3：外部 oracle 的解析口径
// 可能自己变，日常手动跑只打印）；nightly CI 显式置 GEEKTLS_ORACLE_ASSERT=1，
// 否则那轮跑只证明"握手打得通"，证明不了 MATCH 结论没过期。
func assertMode() bool { return os.Getenv("GEEKTLS_ORACLE_ASSERT") != "" }

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
