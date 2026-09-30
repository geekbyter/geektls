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

	quic "github.com/geekbyter/geektls/core/third_party/quic-go-utls"
	utlsb "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"
	utls "github.com/refraction-networking/utls"

	h3core "github.com/geekbyter/geektls/core/h3"
	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
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

	chProfile, dgramLens, _ := sniffInnerClientHello(t, qcfg)
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
// 返回的 pkts 是观测到的全部长头包（含布局信息：PADDING 位置 / 包类型），
// 供 initial_layout 断言使用。
func sniffInnerClientHello(t *testing.T, qcfg *quic.Config) (*profiles.Profile, []int, []*initialPacket) {
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
	var pkts []*initialPacket

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
			pkts = append(pkts, pkt)
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
		dgramLens, len(pkts), len(cryptoBytes), total)

	// T4 观测点：Initial datagram 必须 ≥1200（QUIC 强制最小 UDP 负载）
	if dgramLens[0] < 1200 {
		t.Errorf("first initial datagram = %d bytes, want >= 1200", dgramLens[0])
	}

	chProfile, err := clientHelloFromCrypto(cryptoBytes)
	if err != nil {
		t.Fatalf("parse clienthello: %v", err)
	}
	return chProfile, dgramLens, pkts
}

// TestQUICInitialPacketSize 断言 profile.http3.initial_packet_size 是**填充下限**
// （floor）而不是"精确尺寸"：
//   - 下限 > 自然尺寸 ⇒ 补到下限（1350 ⇒ 1350）；
//   - 下限 ≤ 自然尺寸 ⇒ 按自然尺寸发（真机形态：Chrome 只在需要时补到 1200，
//     首包 1230B 即自然尺寸）；
//   - 不设 = 下限 1200（协议下限），与显式 1200 逐字节相同。
func TestQUICInitialPacketSize(t *testing.T) {
	first := func(size int) int {
		t.Helper()
		p, err := profiles.Get("chrome_133")
		if err != nil {
			t.Fatal(err)
		}
		p.HTTP3 = &profiles.HTTP3Profile{Enabled: true, InitialPacketSize: size}
		qcfg, err := h3core.QUICConfigFromProfile(p)
		if err != nil {
			t.Fatalf("initial_packet_size=%d: %v", size, err)
		}
		_, lens, _ := sniffInnerClientHello(t, qcfg)
		return lens[0]
	}

	if got := first(1350); got != 1350 {
		t.Errorf("下限 1350（> 自然尺寸）时首 datagram = %d，want 1350", got)
	}
	def, lo := first(0), first(1200)
	t.Logf("首 datagram：不设 = %d，显式 1200 = %d，显式 1350 = 1350", def, lo)
	if def != lo {
		t.Errorf("不设时首 datagram = %d，显式 1200 = %d，want 相同（不设 = 下限 1200）", def, lo)
	}
	if def < 1200 {
		t.Errorf("首 datagram = %d < 1200（QUIC 要求客户端每个含 Initial 的 datagram ≥1200）", def)
	}

	// 越界值：在 QUICConfigFromProfile 就报错，而不是被上游静默夹到 1452
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.HTTP3 = &profiles.HTTP3Profile{Enabled: true, InitialPacketSize: 1500}
	if _, err := h3core.QUICConfigFromProfile(p); err == nil {
		t.Error("initial_packet_size=1500 应当报错（不静默夹取）")
	}
}

// sniffFirstDatagram 用给定的拨号函数发一次首飞，返回客户端首个 UDP 报文原样
// （不解密：只看长头字段）。没有真服务端 ⇒ 拨号必然失败，本函数测的就是首飞报文。
func sniffFirstDatagram(t *testing.T, dial func(ctx context.Context, addr net.Addr) error) []byte {
	t.Helper()
	sniffer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sniffer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var dialErr error
	go func() {
		defer close(done)
		dialErr = dial(ctx, sniffer.LocalAddr())
	}()

	if err := sniffer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, _, rerr := sniffer.ReadFromUDP(buf)
	cancel()
	<-done // 等拨号收尾，避免调用方在拨号中途 Close
	if rerr != nil {
		t.Fatalf("没等到首飞报文：%v（拨号侧：%v）", rerr, dialErr)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

// scidLenOf 读长头首包的 SCID 长度：dgram[5] = DCID 长度（裸字节，不是 varint），
// 其后是 DCID，再 1 字节是 SCID 长度。
func scidLenOf(t *testing.T, d []byte) int {
	t.Helper()
	if len(d) < 7 || d[0]&0x80 == 0 {
		t.Fatalf("不是长头包（%d 字节，首字节 %#x）", len(d), d[0])
	}
	dcidLen := int(d[5])
	if len(d) < 6+dcidLen+1 {
		t.Fatalf("报文太短：DCID 声明 %d 字节，总长 %d", dcidLen, len(d))
	}
	return int(d[6+dcidLen])
}

// TestQUICConnectionIDLength 断言 profile.http3.connection_id_length 真的决定首飞
// 的 SCID 长度（patch #10）。两层分开测，都是确定性断言：
//  1. **h3 接线**（不起网络）：NewTransport 把 profile 值映射到 http3.Transport 上的
//     转发字段（0 ⇒ 长度 0 + 允许零长；不设 ⇒ 零值 = 上游默认 4 字节）；
//  2. **线上生效**（UDP 嗅探）：非单次用途的 quic.Transport 上用新字段，首飞 SCID
//     长度确实为 0；不开该字段时仍是 4（上游行为回归守门）；8 ⇒ 8。
func TestQUICConnectionIDLength(t *testing.T) {
	zero, eight := 0, 8

	// —— 1) 接线层 ——
	wiring := func(v *int) (int, bool) {
		t.Helper()
		p, err := profiles.Get("chrome_133")
		if err != nil {
			t.Fatal(err)
		}
		p.HTTP3 = &profiles.HTTP3Profile{Enabled: true, ConnectionIDLength: v}
		tr, err := h3core.NewTransport(p, h3core.TLSSettings{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("connection_id_length=%v: %v", v, err)
		}
		defer tr.Close()
		return tr.QUICConnectionIDLength, tr.QUICAllowZeroLengthConnectionIDs
	}
	if n, allow := wiring(&zero); n != 0 || !allow {
		t.Errorf("connection_id_length=0 ⇒ 转发字段 (%d, allowZero=%v)，want (0, true)", n, allow)
	}
	if n, allow := wiring(&eight); n != 8 || allow {
		t.Errorf("connection_id_length=8 ⇒ 转发字段 (%d, allowZero=%v)，want (8, false)", n, allow)
	}
	if n, allow := wiring(nil); n != 0 || allow {
		t.Errorf("不设 ⇒ 转发字段 (%d, allowZero=%v)，want 零值 (0, false) = 上游默认 4 字节", n, allow)
	}

	// —— 2) 线上层：fork 新字段真的改变首飞长头包的 SCID 长度 ——
	scid := func(length int, allow bool) int {
		t.Helper()
		p, err := profiles.Get("chrome_133")
		if err != nil {
			t.Fatal(err)
		}
		p.HTTP3 = &profiles.HTTP3Profile{Enabled: true}
		qcfg, err := h3core.QUICConfigFromProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		tr := &quic.Transport{
			Conn:                         udp,
			ConnectionIDLength:           length,
			AllowZeroLengthConnectionIDs: allow,
		}
		d := sniffFirstDatagram(t, func(ctx context.Context, addr net.Addr) error {
			_, err := tr.DialEarly(ctx, addr, &utlsb.Config{
				InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "localhost",
				OmitEmptyPsk: true,
			}, qcfg)
			return err
		})
		return scidLenOf(t, d)
	}

	if got := scid(0, true); got != 0 {
		t.Errorf("ConnectionIDLength=0 + AllowZeroLength 时首飞 SCID = %d 字节，want 0（Chrome 形态）", got)
	}
	if got := scid(0, false); got != 4 {
		t.Errorf("不开 AllowZeroLength 时首飞 SCID = %d 字节，want 4（上游行为，回归守门）", got)
	}
	if got := scid(8, false); got != 8 {
		t.Errorf("ConnectionIDLength=8 时首飞 SCID = %d 字节，want 8", got)
	}

	bad := 21
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.HTTP3 = &profiles.HTTP3Profile{Enabled: true, ConnectionIDLength: &bad}
	if _, err := h3core.QUICConfigFromProfile(p); err == nil {
		t.Error("connection_id_length=21 应当报错（不静默夹取）")
	}
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
			{8.0, 100.0},             // initial_max_streams_bidi（故意提前，验证顺序可控）
			{4660.0, "hex:deadbeef"}, // 非标参数 0x1234
			{1.0, 30000.0},           // max_idle_timeout
			{4.0, 10485760.0},        // initial_max_data
			{5.0, 6291456.0},         // initial_max_stream_data_bidi_local
			{6.0, 6291456.0},         // initial_max_stream_data_bidi_remote
			{7.0, 6291456.0},         // initial_max_stream_data_uni
			{9.0, 103.0},             // initial_max_streams_uni
			{3.0, 1472.0},            // max_udp_payload_size（Q2/patch #9：Chrome 真值，行为映射回 Config）
			{32.0, 65536.0},          // max_datagram_frame_size（Q2/patch #9：接收上限同步放宽）
			{"grease", 8.0},          // GREASE 参数放末尾（默认 quic-go 恒首位，此处验证位置可控）
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
	if qcfg.MaxUDPPayloadSize != 1472 || qcfg.DatagramFrameSize != 65536 {
		t.Errorf("patch #9 映射缺失：MaxUDPPayloadSize=%d DatagramFrameSize=%d, want 1472/65536",
			qcfg.MaxUDPPayloadSize, qcfg.DatagramFrameSize)
	}

	chProfile, _, _ := sniffInnerClientHello(t, qcfg)

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
	wantIDs := []uint64{8, 0x1234, 1, 4, 5, 6, 7, 9, 3, 32}
	if fmt.Sprint(gotIDs) != fmt.Sprint(wantIDs) {
		t.Errorf("tp order = %v, want %v", gotIDs, wantIDs)
	}
	for id, want := range map[uint64]uint64{8: 100, 1: 30000, 4: 10485760, 5: 6291456, 6: 6291456, 7: 6291456, 9: 103, 3: 1472, 32: 65536} {
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
