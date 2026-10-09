//go:build external

// H3 外部 oracle 回读（T2.2）：强制 h3（不回落）打 tls.peet.ws/api/all，从
// **服务端视角**回读 QUIC 内层 ClientHello 的 JA4（q 变体），与本侧 selfcheck
// （T2.1：core/engine 的 H3 selfcheck）对拍。
//
// 证据链（三重）：
//  1. resp.UsedProtocol == "h3"——本侧强制档必须走 H3（引擎保证 force 不回落）；
//  2. 回读 ja4 以 "q" 开头——服务端确实收到 QUIC 内层 hello（q 变体只可能来自
//     QUIC，这是比 http_version 字段更硬的不变量）；
//  3. 回读 ja4 == selfcheck.JA4——"我们报告实际发出的" == "服务端实际收到的"
//     （assertMode 门控，与其它 oracle 同一 V-3 口径；nightly 置 ASSERT=1 硬断言）。
//
// 网络失败的归因（防误红）：先跑**本地环回** H3 预检（同一 engine+h3core 栈）——
// 本地失败 = 栈/环境问题（红）；本地通过而外部不可达 = 出网 UDP 被挡或端点不
// 支持 h3（skip + 警示）。本机实测（2026-10-08 公司网）：UDP 443 出网被挡
// （h3 竞速回落 h2 本身正常）⇒ 本测试只能在 CI（nightly oracle job）验证。
//
// 子集口径：GEEKTLS_ORACLE_PRESETS 与其它 oracle 测试一致（默认子集里
// firefox/safari 无 http3 节，会打印跳过——H3 oracle 只测声明 H3 能力的预设）。
//
// 运行：go test -tags external . -run TestExternalOracleH3 -v

package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	fhttp "github.com/geekbyter/geektls/core/third_party/fhttp"
	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/http3"
	utlsb "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"

	"github.com/geekbyter/geektls/core/engine"
	"github.com/geekbyter/geektls/core/profiles"
)

type h3OracleResponse struct {
	HTTPVersion string `json:"http_version"`
	TLS         *struct {
		JA4 string `json:"ja4"`
	} `json:"tls"`
}

func TestExternalOracleH3(t *testing.T) {
	h3On := true

	// ---- 本地环回预检：同一 engine + h3core 栈，排除"本机 h3/UDP 环回坏了"----
	localAddr, localSess := startLocalH3EchoWithSession(t, &h3On)
	defer localSess.Close()
	if resp, err := localSess.Do(&engine.Request{
		URL: "https://" + localAddr + "/x", ForceHTTP3: true,
	}); err != nil {
		t.Fatalf("本地环回 H3 预检失败（本机 h3 栈/环回异常，与 oracle 侧无关）: %v", err)
	} else {
		resp.Body.Close()
	}

	for _, name := range oraclePresets(t) {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			if p.HTTP3 == nil || !p.HTTP3.Enabled {
				t.Skipf("[%s] 无 http3 节（H3 oracle 只测声明 H3 能力的预设）", name)
			}

			s, err := engine.NewSession(p, engine.SessionOptions{
				InsecureSkipVerify: true, // oracle 只读指纹
				H3:                 &h3On,
				TimeoutMs:          20000,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			resp, err := s.Do(&engine.Request{URL: "https://" + oracleHost + "/api/all", ForceHTTP3: true})
			if err != nil {
				t.Skipf("H3 到 oracle 不可达（本地预检已通过；出网 UDP 被挡或端点不支持 h3）: %v", err)
			}
			defer resp.Body.Close()
			if resp.UsedProtocol != "h3" {
				t.Fatalf("强制档回落为 %s（force_http3 必须不回落）", resp.UsedProtocol)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			var raw h3OracleResponse
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatalf("oracle response not JSON: %v\n%.300s", err, body)
			}
			if raw.TLS == nil || raw.TLS.JA4 == "" {
				t.Fatalf("oracle 未回报 tls.ja4:\n%.500s", body)
			}

			got := resp.SelfCheck.JA4
			fmt.Printf("== %s ==\n", name)
			fmt.Printf("  ja4  self=%s\n       orac=%s  %s\n", got, raw.TLS.JA4, mark(got == raw.TLS.JA4))
			fmt.Printf("  http_version=%s  used=%s\n", raw.HTTPVersion, resp.UsedProtocol)

			if raw.HTTPVersion == "" {
				t.Logf("警示：oracle 未回报 http_version 字段（端点格式可能改版）")
			} else if !strings.Contains(strings.ToLower(raw.HTTPVersion), "3") {
				t.Errorf("oracle http_version=%q：服务端视角不是 H3", raw.HTTPVersion)
			}
			if !strings.HasPrefix(raw.TLS.JA4, "q") {
				t.Errorf("oracle ja4=%q 非 QUIC 变体：服务端并未收到 QUIC 内层 hello", raw.TLS.JA4)
			}
			if got == "" {
				t.Fatalf("selfcheck.ja4 为空（T2.1 的 H3 selfcheck 未生效）")
			}
			if assertMode() && got != raw.TLS.JA4 {
				t.Errorf("[%s] H3 JA4 self=%s oracle=%s 不一致（selfcheck 报告 vs 服务端回读）", name, got, raw.TLS.JA4)
			}
		})
	}
}

// startLocalH3EchoWithSession 起一个本地 H3 echo 服务器，返回（地址, 预检会话）。
// 预检会话用 chrome_133_windows（h3 节完整），并剥 ECH——bogdanfinn H3 服务端
// 不接受 ECH（同 core/engine 测试注释），剥掉只测互操作。
func startLocalH3EchoWithSession(t *testing.T, h3On *bool) (string, *engine.Session) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "h3-precheck"},
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

	mux := fhttp.NewServeMux()
	mux.HandleFunc("/x", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "ok")
	})
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		Handler: mux,
		TLSConfig: http3.ConfigureTLSConfig(&utlsb.Config{
			Certificates: []utlsb.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{"h3"},
		}),
	}
	go srv.Serve(udp)
	t.Cleanup(func() { srv.Close(); udp.Close() })

	p, err := profiles.Get("chrome_133_windows")
	if err != nil {
		t.Fatal(err)
	}
	var noECH []profiles.Extension
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type != 65037 {
			noECH = append(noECH, e)
		}
	}
	p.TLS.Detail.Extensions = noECH
	s, err := engine.NewSession(p, engine.SessionOptions{
		InsecureSkipVerify: true,
		H3:                 h3On,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("127.0.0.1:%d", udp.LocalAddr().(*net.UDPAddr).Port), s
}
