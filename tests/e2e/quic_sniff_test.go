package e2e

// P4-T6 验收：本地 UDP 嗅探客户端 Initial 报文，解密重组后断言 transport
// params 与 profile.http3 一致；同时观测 Initial datagram 布局（T4 证据）。

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	quic "github.com/bogdanfinn/quic-go-utls"
	utlsb "github.com/bogdanfinn/utls"
	utls "github.com/refraction-networking/utls"

	h3core "github.com/geektls/core/h3"
	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

func tpVarint(params map[uint64][]byte, id uint64) (uint64, bool) {
	v, ok := params[id]
	if !ok {
		return 0, false
	}
	r := &varintReader{b: v}
	n, err := r.read()
	if err != nil {
		return 0, false
	}
	return n, true
}

func TestQUICInitialSniff(t *testing.T) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.TLS.Detail.ExtensionPermutation = false // 本测试要逐位断言扩展顺序，关掉洗牌
	p.HTTP3 = &profiles.HTTP3Profile{
		Enabled: true,
		TransportParams: map[string]uint64{
			"max_idle_timeout":                    30000,
			"initial_max_data":                    10485760,
			"initial_max_stream_data_bidi_remote": 6291456,
			"initial_max_streams_bidi":            100,
			"initial_max_streams_uni":             103,
		},
	}
	qcfg, err := h3core.QUICConfigFromProfile(p)
	if err != nil {
		t.Fatal(err)
	}

	// 假服务端：只听不回，抓客户端 Initial
	sniffer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sniffer.Close()
	addr := sniffer.LocalAddr().(*net.UDPAddr)

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	dialErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := quic.DialEarly(ctx, udp, addr, &utlsb.Config{
			InsecureSkipVerify: true, NextProtos: []string{"h3"}, OmitEmptyPsk: true,
			ServerName: "localhost", // 驱动 SNI auto（QUIC 里 ServerName 与对端地址解耦）
		}, qcfg)
		if err != nil {
			dialErr <- err
			return
		}
		if conn != nil {
			conn.CloseWithError(0, "done")
		}
		dialErr <- nil
	}()

	// 收若干 datagram，重组 crypto 流直到 ClientHello 完整
	var keys quicInitialKeys
	var keysSet bool
	var reasm cryptoStreamReassembler
	var dgramLens []int
	var totalPackets int

	sniffer.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	for {
		n, _, err := sniffer.ReadFromUDP(buf)
		if err != nil {
			select {
			case derr := <-dialErr:
				if derr != nil {
					t.Fatalf("sniff: %v (dial error: %v)", err, derr)
				}
			default:
			}
			t.Fatalf("sniff: %v", err)
		}
		dgram := make([]byte, n)
		copy(dgram, buf[:n])
		dgramLens = append(dgramLens, n)

		if !keysSet {
			// DCID 从首个包解析（dcid len 在 offset 5）
			dcidLen := int(dgram[5])
			keys = initialKeys(dgram[6 : 6+dcidLen])
			keysSet = true
		}

		off := 0
		for off < n {
			pkt, err := decryptInitialAt(dgram, off, keys)
			if err != nil {
				t.Fatalf("decrypt at %d: %v", off, err)
			}
			if pkt == nil || pkt.NextOffset <= off {
				break
			}
			off = pkt.NextOffset
			totalPackets++
			for _, f := range pkt.CryptoFrames {
				reasm.add(f)
			}
		}
		if _, _, complete := reasm.assembled(); complete {
			break
		}
	}

	cryptoBytes, total, _ := reasm.assembled()
	t.Logf("initial datagrams: %v, packets: %d, crypto stream %d/%d bytes",
		dgramLens, totalPackets, len(cryptoBytes), total)

	// T4 观测点 1：Initial datagram 必须 ≥1200（QUIC 强制最小 UDP 负载）
	if dgramLens[0] < 1200 {
		t.Errorf("first initial datagram = %d bytes, want >= 1200", dgramLens[0])
	}

	chProfile, err := clientHelloFromCrypto(cryptoBytes)
	if err != nil {
		t.Fatalf("parse clienthello: %v", err)
	}

	var foundTP bool
	for _, e := range chProfile.TLS.Detail.Extensions {
		if e.Type != 57 { // quic_transport_parameters
			continue
		}
		foundTP = true
		raw, err := hex.DecodeString(e.Data)
		if err != nil {
			t.Fatal(err)
		}
		params, err := parseQUICTransportParams(raw)
		if err != nil {
			t.Fatal(err)
		}

		// T6 断言：profile 驱动值
		if v, ok := tpVarint(params, 0x1); !ok || v != 30000 {
			t.Errorf("max_idle_timeout = %d,%v, want 30000", v, ok)
		}
		if v, ok := tpVarint(params, 0x4); !ok || v != 10485760 {
			t.Errorf("initial_max_data = %d,%v, want 10485760", v, ok)
		}
		// quic-go 三个 stream window 共值（capability 文档记录的粒度损失）
		for _, id := range []uint64{0x5, 0x6, 0x7} {
			if v, ok := tpVarint(params, id); !ok || v != 6291456 {
				t.Errorf("tp %#x = %d,%v, want 6291456", id, v, ok)
			}
		}
		if v, ok := tpVarint(params, 0x8); !ok || v != 100 {
			t.Errorf("initial_max_streams_bidi = %d,%v, want 100", v, ok)
		}
		if v, ok := tpVarint(params, 0x9); !ok || v != 103 {
			t.Errorf("initial_max_streams_uni = %d,%v, want 103", v, ok)
		}

		// GREASE transport parameter（id = 27+31k）必须存在
		greaseFound := false
		for id := range params {
			if id >= 27 && (id-27)%31 == 0 {
				greaseFound = true
			}
		}
		if !greaseFound {
			t.Error("no GREASE transport parameter")
		}
		t.Logf("transport params on wire: %d entries", len(params))
	}
	if !foundTP {
		t.Fatal("no quic_transport_parameters extension (57) in QUIC client hello")
	}

	// T4 观测点 2 / 本轮主验收：内层 ClientHello 必须是 tls.detail 编译产物
	//（vendor patch 生效的线上字节证据）。
	inner := chProfile.TLS.Detail
	if inner == nil {
		t.Fatal("inner clienthello parse failed")
	}

	// 1) ALPN h3
	var alpnFound bool
	for _, e := range inner.Extensions {
		if e.Type == 16 {
			alpnFound = true
			if len(e.ALPN) != 1 || e.ALPN[0] != "h3" {
				t.Errorf("inner ALPN = %v, want [h3]", e.ALPN)
			}
		}
	}
	if !alpnFound {
		t.Error("no ALPN in inner clienthello")
	}

	// 2) JA4（q 标志）：parsed == 期望（spec 经 QUIC 化 + transport params 扩展）
	detailQUIC := *p.TLS.Detail // 浅拷贝；ECH 换合成 payload 但类型 65037 保留
	var extsQUIC []profiles.Extension
	for _, e := range detailQUIC.Extensions {
		if e.Type == 16 || e.Type == 17513 || e.Type == 17613 {
			e.ALPN = []string{"h3"} // 与 clampSpecForQUIC 一致
		}
		extsQUIC = append(extsQUIC, e)
	}
	detailQUIC.Extensions = extsQUIC
	spec1, err := tlscore.CompileDetail(&detailQUIC)
	if err != nil {
		t.Fatal(err)
	}
	spec1.Extensions = append(spec1.Extensions, &utls.GenericExtension{Id: 57})
	spec2, err := tlscore.CompileDetail(inner)
	if err != nil {
		t.Fatal(err)
	}
	ja4Want := tlscore.ComputeJA4QUIC(spec1)
	ja4Got := tlscore.ComputeJA4QUIC(spec2)
	if ja4Got != ja4Want {
		t.Errorf("inner JA4 mismatch:\n  want %s\n  got  %s", ja4Want, ja4Got)
	}
	t.Logf("inner clienthello JA4(QUIC) = %s", ja4Got)
	t.Logf("same preset over TCP     = %s", tlscore.ComputeJA4(spec1))

	// 3) 扩展线上顺序：剔除 57（quic-go 注入）后与 detail 数组序一致（GREASE 归一化）
	var gotOrder []uint16
	for _, e := range inner.Extensions {
		if e.Type == 57 {
			continue
		}
		gotOrder = append(gotOrder, normGreaseType(e.Type))
	}
	var wantOrder []uint16
	for _, e := range detailQUIC.Extensions {
		if e.Type == 41 {
			continue // 空 PSK 占位线上省略（OmitEmptyPsk）
		}
		wantOrder = append(wantOrder, normGreaseType(e.Type))
	}
	if fmt.Sprint(gotOrder) != fmt.Sprint(wantOrder) {
		t.Errorf("inner extension order mismatch:\n  want %v\n  got  %v", wantOrder, gotOrder)
	}

	// 4) cipher 序一致（GREASE 归一化后）
	if len(inner.Ciphers) != len(p.TLS.Detail.Ciphers) {
		t.Fatalf("inner cipher count %d, want %d", len(inner.Ciphers), len(p.TLS.Detail.Ciphers))
	}
}

func normGreaseType(v uint16) uint16 {
	if v>>8 == v&0xff && v&0xf == 0xa {
		return 2570
	}
	return v
}
