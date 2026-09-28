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
			"initial_max_data":                    15728640,
			"initial_max_stream_data_bidi_remote": 6291456,
			"initial_max_streams_bidi":            100,
			"initial_max_streams_uni":             103,
		},
		// QUIC 内层 CH 形态（实测驱动，Chrome 149 E1）：本测试用完整形态，
		// 与内置预设的 http3 节保持一致。
		InnerHelloDropExtensions: []uint16{5, 18},
		InnerHelloExtraSigAlgs:   []string{"0x0201"},
		InnerHelloDropGrease:     true,
	}
	qcfg, err := h3core.QUICConfigFromProfile(p)
	if err != nil {
		t.Fatal(err)
	}

	chProfile, dgramLens := sniffInnerClientHello(t, qcfg)
	_ = dgramLens

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
		// 15728640 = 真机实测值（Chrome 149 E1；原 E4 构造值 10485760 偏小）
		if v, ok := tpVarint(params, 0x4); !ok || v != 15728640 {
			t.Errorf("initial_max_data = %d,%v, want 15728640（E1 实测）", v, ok)
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
		ordered, err := parseQUICTransportParamsOrdered(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, tp := range ordered {
			if v, ok := tpVarint(map[uint64][]byte{tp.ID: tp.Val}, tp.ID); ok && len(tp.Val) <= 8 {
				t.Logf("    我方 tp %#x = %d (len=%d)", tp.ID, v, len(tp.Val))
			} else {
				t.Logf("    我方 tp %#x = hex:%s (len=%d)", tp.ID, hex.EncodeToString(tp.Val), len(tp.Val))
			}
		}
		t.Logf("transport params on wire: %d entries", len(params))
	}
	if !foundTP {
		t.Fatal("no quic_transport_parameters extension (57) in QUIC client hello")
	}

	// 我方线上形态（用于与真 Chrome 的 E1 记录逐项对照，见 docs/07 §6.1）。
	var extTypes []uint16
	for _, e := range chProfile.TLS.Detail.Extensions {
		extTypes = append(extTypes, normGreaseType(e.Type))
	}
	t.Logf("我方 内层 CH ciphers(%d) = %v", len(chProfile.TLS.Detail.Ciphers), chProfile.TLS.Detail.Ciphers)
	t.Logf("我方 内层 CH exts(%d)    = %v", len(extTypes), extTypes)

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
	// 期望值取自**真机实测**（E1：Chrome 149 / Windows，
	// profiles/evidence/browsers/chrome_windows_h3.json），而不是"我们自己算的"——
	// clamp 的裁剪规则一旦漂移（少剔/多剔扩展、漏加 0x0201、GREASE 没剔干净），
	// 这里立刻报错。
	ja4Got := tlscore.ComputeJA4QUIC(spec2)
	const ja4Chrome149QUIC = "q13d0311h3_55b375c5d22e_653d80c3fe9d"
	if ja4Got != ja4Chrome149QUIC {
		t.Errorf("inner JA4 与真机不一致:\n  want(E1) %s\n  got      %s", ja4Chrome149QUIC, ja4Got)
	}
	t.Logf("inner clienthello JA4(QUIC) = %s（E1 目标 %s）", ja4Got, ja4Chrome149QUIC)
	t.Logf("same preset over TCP     = %s", tlscore.ComputeJA4(spec1))

	// 3) 扩展线上顺序：QUIC 内层按实测规则裁剪过（剔 TLS1.2 语义扩展 + GREASE，
	//    57 由 clamp 追加在末尾），因此期望值按同一规则过滤后比较。
	//    （顺序本身仍等于 detail 数组序——洗牌在 compile 阶段完成。）
	quicDropped := map[uint16]bool{5: true, 11: true, 18: true, 23: true, 35: true, 65281: true}
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
		if quicDropped[e.Type] || normGreaseType(e.Type) == 2570 {
			continue // QUIC 内层实测不含这些
		}
		wantOrder = append(wantOrder, normGreaseType(e.Type))
	}
	// 注意：gotOrder 已跳过 57（QUIC 专有），wantOrder 也不应含它。
	if fmt.Sprint(gotOrder) != fmt.Sprint(wantOrder) {
		t.Errorf("inner extension order mismatch:\n  want %v\n  got  %v", wantOrder, gotOrder)
	}

	// 4) ciphers：QUIC 只允许 TLS1.3，且实测真机不发 GREASE cipher ⇒ 恰好 3 个。
	if len(inner.Ciphers) != 3 {
		t.Fatalf("inner cipher count %d, want 3（TLS1.3 套件）: %v", len(inner.Ciphers), inner.Ciphers)
	}
}

func normGreaseType(v uint16) uint16 {
	if v>>8 == v&0xff && v&0xf == 0xa {
		return 2570
	}
	return v
}

// sniffInnerClientHello 起假 UDP 服务端抓客户端 Initial，解密重组出内层
// ClientHello 并解析（TestQUICInitialSniff 与 TestQUICTransportParamsRaw 共用）。
func sniffInnerClientHello(t *testing.T, qcfg *quic.Config) (*profiles.Profile, []int) {
	t.Helper()

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

	// T4 观测点：Initial datagram 必须 ≥1200（QUIC 强制最小 UDP 负载）
	if dgramLens[0] < 1200 {
		t.Errorf("first initial datagram = %d bytes, want >= 1200", dgramLens[0])
	}

	chProfile, err := clientHelloFromCrypto(cryptoBytes)
	if err != nil {
		t.Fatalf("parse clienthello: %v", err)
	}
	return chProfile, dgramLens
}

// TestQUICTransportParamsRaw T4-1 验收：transport_params_raw（blob 直通）的
// 顺序、非标参数、GREASE 参数位置全部按 profile 原样上 wire。
func TestQUICTransportParamsRaw(t *testing.T) {
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.TLS.Detail.ExtensionPermutation = false
	p.HTTP3 = &profiles.HTTP3Profile{
		Enabled: true,
		TransportParamsRaw: [][]any{
			{8.0, 100.0},               // initial_max_streams_bidi（故意提前，验证顺序可控）
			{4660.0, "hex:deadbeef"},   // 非标参数 0x1234
			{1.0, 30000.0},             // max_idle_timeout
			{4.0, 10485760.0},          // initial_max_data
			{5.0, 6291456.0},           // initial_max_stream_data_bidi_local
			{6.0, 6291456.0},           // initial_max_stream_data_bidi_remote
			{7.0, 6291456.0},           // initial_max_stream_data_uni
			{9.0, 103.0},               // initial_max_streams_uni
			{"grease", 8.0},            // GREASE 参数放末尾（默认 quic-go 恒首位，此处验证位置可控）
		},
	}
	qcfg, err := h3core.QUICConfigFromProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if qcfg.TransportParamsOverride == nil {
		t.Fatal("TransportParamsOverride not set (vendor patch #7 not wired)")
	}
	// 行为一致性：已知流控键值应映射回 quic.Config
	if qcfg.MaxIdleTimeout != 30*time.Second {
		t.Errorf("MaxIdleTimeout = %v, want 30s（raw tp 应映射回 Config）", qcfg.MaxIdleTimeout)
	}
	if qcfg.MaxIncomingStreams != 100 {
		t.Errorf("MaxIncomingStreams = %v, want 100", qcfg.MaxIncomingStreams)
	}

	chProfile, _ := sniffInnerClientHello(t, qcfg)

	var raw []byte
	found := false
	for _, e := range chProfile.TLS.Detail.Extensions {
		if e.Type != 57 {
			continue
		}
		found = true
		raw, err = hex.DecodeString(e.Data)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatal("no quic_transport_parameters extension (57)")
	}

	ordered, err := parseQUICTransportParamsOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}

	var gotIDs []uint64
	var greaseID uint64
	greaseLen := -1
	vals := map[uint64][]byte{}
	for _, tp := range ordered {
		if tp.ID >= 27 && (tp.ID-27)%31 == 0 {
			greaseID, greaseLen = tp.ID, len(tp.Val)
			continue
		}
		gotIDs = append(gotIDs, tp.ID)
		vals[tp.ID] = tp.Val
	}
	wantIDs := []uint64{8, 0x1234, 1, 4, 5, 6, 7, 9}
	if fmt.Sprint(gotIDs) != fmt.Sprint(wantIDs) {
		t.Errorf("tp order = %v, want %v", gotIDs, wantIDs)
	}
	for id, want := range map[uint64]uint64{8: 100, 1: 30000, 4: 10485760, 5: 6291456, 6: 6291456, 7: 6291456, 9: 103} {
		if v, ok := tpVarint(vals, id); !ok || v != want {
			t.Errorf("tp %#x = %d,%v, want %d", id, v, ok, want)
		}
	}
	if got := hex.EncodeToString(vals[0x1234]); got != "deadbeef" {
		t.Errorf("non-standard tp 0x1234 = %s, want deadbeef", got)
	}
	if greaseID == 0 {
		t.Error("no GREASE transport parameter")
	}
	if greaseLen != 8 {
		t.Errorf("grease tp body len = %d, want 8", greaseLen)
	}
	if ordered[len(ordered)-1].ID != greaseID {
		t.Errorf("grease tp not last（位置不可控）: ids=%v", func() []uint64 {
			var ids []uint64
			for _, tp := range ordered {
				ids = append(ids, tp.ID)
			}
			return ids
		}())
	}
	t.Logf("ordered transport params on wire: %v（grease id=%#x）", gotIDs, greaseID)
}
