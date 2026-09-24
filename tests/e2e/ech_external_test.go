//go:build external

// P7-T1 真 ECH 外部验证：
// ① DNS HTTPS 记录解析目标域的 ECHConfigList；
// ② profile 注入 mode=real ECH → tlscore 握手 → 断言服务端接受 ECH
//    （ConnectionState.ECHAccepted）+ 握手协商 TLS1.3。
//
// 目标：cloudflare-ech.com（公开 ECH 测试域）。运行：
//   go test -tags external -run TestRealECH -v

package e2e

import (
	"fmt"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// queryHTTPSRecord 用最小 DNS 客户端查 domain 的 HTTPS(65) 记录，
// 提取 ech(key 5) 参数值（ECHConfigList）。
func queryHTTPSRecord(t *testing.T, domain string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 5*time.Second)
	if err != nil {
		t.Skipf("DNS unreachable: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	qname, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1337, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: qname, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	for _, ans := range resp.Answers {
		https, ok := ans.Body.(*dnsmessage.HTTPSResource)
		if !ok {
			continue
		}
		// ech = SVCParamKey 5
		if v, ok := https.GetParam(5); ok {
			return v
		}
	}
	return nil
}

func TestRealECHLive(t *testing.T) {
	const domain = "cloudflare-ech.com"

	echList := queryHTTPSRecord(t, domain)
	if len(echList) == 0 {
		t.Skip("no ECH config in DNS HTTPS record (server policy changed?)")
	}
	t.Logf("ECHConfigList: %d bytes", len(echList))

	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	// 把预设的 ECH GREASE 换成真 ECH
	for i := range p.TLS.Detail.Extensions {
		if p.TLS.Detail.Extensions[i].Type == 65037 {
			p.TLS.Detail.Extensions[i].ECH = &profiles.ECHConfig{
				Mode:          "real",
				ConfigListHex: fmt.Sprintf("%x", echList),
			}
		}
	}

	spec, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}

	addr := domain + ":443"
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		t.Skipf("cannot resolve %s: %v", domain, err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ips[0].String(), "443"), 10*time.Second)
	if err != nil {
		t.Skipf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	uconn, err := tlscore.Handshake(conn, &utls.Config{
		ServerName:                     domain,
		InsecureSkipVerify:             true, // 本机 CA 问题；ECH 接受与否与证书链无关
		NextProtos:                     []string{"h2", "http/1.1"},
		EncryptedClientHelloConfigList: echList,
	}, spec)
	if err != nil {
		t.Fatalf("real ECH handshake: %v", err)
	}
	defer uconn.Close()

	state := uconn.ConnectionState()
	t.Logf("negotiated version=%#04x alpn=%q ECHAccepted=%v",
		state.Version, state.NegotiatedProtocol, state.ECHAccepted)
	if !state.ECHAccepted {
		t.Error("server did NOT accept ECH (ECHAccepted=false)")
	}
	if state.Version != utls.VersionTLS13 {
		t.Errorf("version = %#04x, want TLS1.3", state.Version)
	}
}
