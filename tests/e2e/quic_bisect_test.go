package e2e

// 二分定位：QUIC 内层 hello 哪些扩展/字段让握手发不出包。

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	quic "github.com/bogdanfinn/quic-go-utls"
	utlsb "github.com/bogdanfinn/utls"

	h3core "github.com/geektls/core/h3"
	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

// tryQUICHello 用给定 detail 发 Initial，返回是否抓到了包。
func tryQUICHello(t *testing.T, d *profiles.Detail) error {
	t.Helper()
	spec, err := tlscore.CompileDetail(d)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	bspec, err := h3core.SpecToBogdan(spec)
	if err != nil {
		return fmt.Errorf("convert: %w", err)
	}

	sniffer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sniffer.Close()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	qcfg := &quic.Config{ClientHelloSpec: bspec}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		quic.DialEarly(ctx, udp, sniffer.LocalAddr(), &utlsb.Config{
			InsecureSkipVerify: true, NextProtos: []string{"h3"}, OmitEmptyPsk: true,
		}, qcfg)
	}()

	sniffer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65535)
	n, _, err := sniffer.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("no packet: %v", err)
	}
	// 校验能解密
	dcidLen := int(buf[5])
	if _, err := decryptInitialAt(buf[:n], 0, initialKeys(buf[6:6+dcidLen])); err != nil {
		return fmt.Errorf("packet arrived but decrypt failed: %v", err)
	}
	return nil
}

func TestQUICHelloBisect(t *testing.T) {
	p, _ := profiles.Get("chrome_133")
	p.TLS.Detail.ExtensionPermutation = false

	full := p.TLS.Detail.Extensions
	// 最小集
	minimal := []profiles.Extension{
		{Type: 0, SNI: "auto"},
		{Type: 16, ALPN: []string{"h3"}},
		{Type: 43, Versions: []string{"0x0304"}},
		{Type: 51, KeyShares: []string{"X25519"}},
		{Type: 13, SigAlgs: []string{"0x0403", "0x0804", "0x0401"}},
	}

	d := &profiles.Detail{Ciphers: []string{"0x1301"}, Extensions: minimal}
	if err := tryQUICHello(t, d); err != nil {
		t.Fatalf("minimal spec failed: %v", err)
	}
	t.Log("minimal spec OK")

	// 逐个追加（65037 ECH 单独在末尾验证——预期失败，是钳制的理由）
	for i, e := range full {
		if e.Type == 65037 {
			continue
		}
		// 跳过最小集已含的
		dup := false
		for _, m := range minimal {
			if m.Type == e.Type {
				dup = true
			}
		}
		if dup {
			continue
		}
		d := &profiles.Detail{
			Ciphers:    []string{"0x1301"},
			Extensions: append(append([]profiles.Extension{}, minimal...), e),
		}
		if err := tryQUICHello(t, d); err != nil {
			t.Errorf("adding ext[%d] type=%d broke it: %v", i, e.Type, err)
		} else {
			t.Logf("ext type=%d OK", e.Type)
		}
	}

	// 65037（ECH GREASE）不钳制时必须失败——这是 clampSpecForQUIC 剥除它的
	// 理由（bogdanfinn/utls 的 ECH 负载生成依赖 TCP record 层）。若上游未来
	// 修复，此测试会翻绿提醒我们去掉钳制。
	for i, e := range full {
		if e.Type != 65037 {
			continue
		}
		d := &profiles.Detail{
			Ciphers:    []string{"0x1301"},
			Extensions: append(append([]profiles.Extension{}, minimal...), e),
		}
		if err := tryQUICHello(t, d); err == nil {
			t.Logf("ext[%d] type=65037 now works unclamped — consider dropping the clamp", i)
		} else {
			t.Logf("ext type=65037 still breaks QUIC hello unclamped (expected): %v", err)
		}
	}
}
