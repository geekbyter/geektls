package e2e

// Q1 验收（2026-09-30，vendor patch #8）：profile.http3.initial_layout 真生效——
// PADDING 在包内位置 / CRYPTO 分片表 / clienthello scrambling 开关 / coalesce
// 阈值，全部由嗅探器在线上 Initial 字节上断言；不设 initial_layout 的默认路径
// 保持上游形态（回归守门）。

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	quic "github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3"
	utlsb "github.com/bogdanfinn/utls"

	h3core "github.com/geektls/core/h3"
	"github.com/geektls/core/profiles"
)

// layoutQUICConfig：chrome_133 + QUIC 内层形态（E1 实测裁剪）+ 指定布局。
func layoutQUICConfig(t *testing.T, layout *profiles.H3InitialLayout) *quic.Config {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.TLS.Detail.ExtensionPermutation = false
	p.HTTP3 = &profiles.HTTP3Profile{
		Enabled:                  true,
		InitialLayout:            layout,
		InnerHelloDropExtensions: []uint16{5, 18},
		InnerHelloExtraSigAlgs:   []string{"0x0201"},
		InnerHelloDropGrease:     true,
	}
	qcfg, err := h3core.QUICConfigFromProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	return qcfg
}

// cryptoFrameSeq 把抓到的所有 Initial 包的 CRYPTO 帧压平成 (offset, len) 序列。
// quic-go 默认会洗牌包内控制帧顺序（反固化），所以这里按 offset 排序——
// 分片/乱序的证据看 offset 覆盖，不看到达顺序。
func cryptoFrameSeq(pkts []*initialPacket) [][2]int {
	var out [][2]int
	for _, p := range pkts {
		if p.Type != "initial" {
			continue
		}
		for _, f := range p.CryptoFrames {
			out = append(out, [2]int{int(f.Offset), len(f.Data)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// paddedInitial 返回第一个带 PADDING 的 Initial 包（CH 填满首包时，
// 填充落在后续包上）。
func paddedInitial(t *testing.T, pkts []*initialPacket) *initialPacket {
	t.Helper()
	for _, p := range pkts {
		if p.Type == "initial" && p.PaddingBytes > 0 {
			return p
		}
	}
	t.Fatal("没有抓到带 PADDING 的 Initial 包")
	return nil
}

func TestQUICInitialLayout(t *testing.T) {
	// 1) 默认路径（nil layout）——上游形态守门：PADDING 在 CRYPTO **之前**，
	//    且 scrambling 开着 ⇒ 包内 CRYPTO 帧按到达序有空洞（先跳过 SNI 中段再补发）。
	t.Run("默认路径=上游形态", func(t *testing.T) {
		_, _, pkts := sniffInnerClientHello(t, layoutQUICConfig(t, nil))
		pp := paddedInitial(t, pkts)
		if !pp.PaddingBeforeCrypto || pp.PaddingAfterCrypto {
			t.Errorf("默认路径 padding 位置变了：before=%v after=%v（上游应为前=true/后=false）——默认路径必须逐字节不变",
				pp.PaddingBeforeCrypto, pp.PaddingAfterCrypto)
		}
		// scrambling 证据：某个包内相邻 CRYPTO 帧（到达序）存在 offset 空洞
		gap := false
		for _, p := range pkts {
			if p.Type != "initial" {
				continue
			}
			for i := 1; i < len(p.CryptoFrames); i++ {
				prev, cur := p.CryptoFrames[i-1], p.CryptoFrames[i]
				if uint64(int(prev.Offset)+len(prev.Data)) != cur.Offset {
					gap = true
				}
			}
		}
		if !gap {
			seq := cryptoFrameSeq(pkts)
			t.Errorf("默认路径 scrambling 应当造成包内 CRYPTO 空洞/乱序，实测序列 %v", seq)
		}
		t.Logf("默认路径：padding 在前，包内 scramble 空洞可见")
	})

	// 2) Chrome 形态：padding "end" + disable_scramble ⇒ PADDING 在包尾，
	//    CRYPTO 单片、offset 严格连续（真机 E1 形态：chrome_windows_h3.json
	//    首 datagram 1230B，CH 单片按包空间填充）。
	t.Run("chrome形态_padding尾_无scramble", func(t *testing.T) {
		_, lens, pkts := sniffInnerClientHello(t, layoutQUICConfig(t, &profiles.H3InitialLayout{
			Padding:         "end",
			DisableScramble: true,
		}))
		pp := paddedInitial(t, pkts)
		if pp.PaddingBeforeCrypto || !pp.PaddingAfterCrypto {
			t.Errorf("padding 应全部在 CRYPTO 之后：before=%v after=%v bytes=%d",
				pp.PaddingBeforeCrypto, pp.PaddingAfterCrypto, pp.PaddingBytes)
		}
		seq := cryptoFrameSeq(pkts)
		next := 0
		for i, f := range seq {
			if f[0] != next {
				t.Fatalf("关 scramble 后 CRYPTO 应严格连续，第 %d 帧 offset=%d, want %d（全序 %v）", i, f[0], next, seq)
			}
			next = f[0] + f[1]
		}
		t.Logf("chrome 形态：datagrams=%v，CRYPTO 连续序列 %v，padding 在尾（%d 字节）", lens, seq, pp.PaddingBytes)
	})

	// 3) CRYPTO 分片表：前 N 片严格按表切出（offset 连续、长度=表值）。
	t.Run("crypto_fragments分片表", func(t *testing.T) {
		want := []uint32{300, 250, 400}
		_, _, pkts := sniffInnerClientHello(t, layoutQUICConfig(t, &profiles.H3InitialLayout{
			CryptoFragments: want,
		}))
		seq := cryptoFrameSeq(pkts)
		if len(seq) < len(want) {
			t.Fatalf("CRYPTO 帧数 %d < 分片表长度 %d：%v", len(seq), len(want), seq)
		}
		next := 0
		for i, w := range want {
			if seq[i][0] != next || seq[i][1] != int(w) {
				t.Errorf("分片[%d] = (offset %d, len %d), want (%d, %d)；全序 %v",
					i, seq[i][0], seq[i][1], next, w, seq)
			}
			next += int(w)
		}
		t.Logf("分片表 %v 上线序列：%v", want, seq)
	})

	// 4) 校验拒绝：padding 取值 / 退役占位 / 空分片。
	t.Run("非法值在配置期报错", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			layout *profiles.H3InitialLayout
		}{
			{"padding取值", &profiles.H3InitialLayout{Padding: "middle"}},
			{"退役的coalesce占位", &profiles.H3InitialLayout{Coalesce: true}},
			{"coalesce_min_size越界", &profiles.H3InitialLayout{CoalesceMinSize: 70000}},
			{"空分片", &profiles.H3InitialLayout{CryptoFragments: []uint32{0}}},
		} {
			pj := []byte(`{"name":"t","http3":{"enabled":true,"initial_layout":` + layoutJSON(tc.layout) + `}}`)
			if _, err := profiles.Parse(pj); err == nil {
				t.Errorf("%s：Parse 应报错", tc.name)
			}
		}
	})
}

func layoutJSON(l *profiles.H3InitialLayout) string {
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// --- coalesce 阈值：真服务端 + UDP 中继抓客户端第二飞 ---

// relaySniff 转发 client↔server 的 UDP 并记录 client→server 的 datagram 副本。
type relaySniff struct {
	mu      sync.Mutex
	dgrams  [][]byte
	server  *net.UDPAddr
	conn    *net.UDPConn
	closeCh chan struct{}
}

func newRelaySniff(t *testing.T, server *net.UDPAddr) *relaySniff {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	r := &relaySniff{server: server, conn: c, closeCh: make(chan struct{})}
	t.Cleanup(func() { close(r.closeCh); c.Close() })
	go r.loop()
	return r
}

func (r *relaySniff) loop() {
	buf := make([]byte, 65535)
	var clientAddr *net.UDPAddr
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		if src.String() == r.server.String() {
			if clientAddr != nil {
				r.conn.WriteToUDP(data, clientAddr)
			}
			continue
		}
		clientAddr = src
		r.mu.Lock()
		r.dgrams = append(r.dgrams, data)
		r.mu.Unlock()
		r.conn.WriteToUDP(data, r.server)
	}
}

func (r *relaySniff) captured() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.dgrams...)
}

// 调试：返回服务端地址字符串。
func (r *relaySniff) serverStr() string { return r.server.String() }

// classifyDatagram 把一个 datagram 里的长头包类型列出来（Initial 顺带解密，
// 密钥由首包 DCID 推导）。遇短头包停止。keys 未初始化时用首个 datagram 初始化。
func classifyDatagram(dgram []byte, keys *quicInitialKeys, keysSet *bool) []string {
	var types []string
	if !*keysSet {
		if len(dgram) < 7 || dgram[0]&0x80 == 0 {
			return types
		}
		dcidLen := int(dgram[5])
		*keys = initialKeys(dgram[6 : 6+dcidLen])
		*keysSet = true
	}
	off := 0
	for off < len(dgram) {
		if dgram[off]&0x80 == 0 {
			types = append(types, "1rtt")
			break
		}
		pkt, err := decryptInitialAt(dgram, off, *keys)
		if err != nil || pkt == nil || pkt.NextOffset <= off {
			break
		}
		types = append(types, pkt.Type)
		off = pkt.NextOffset
	}
	return types
}

// TestQUICCoalesceThreshold：coalesce_min_size 控制 Initial+Handshake 是否合入
// 同一 datagram。默认（128）下客户端第二飞 = [Initial ACK + Handshake Finished]
// 合并包；-1（禁用）时拆成两个 datagram。回环 fork http3 服务端 + UDP 中继实证。
func TestQUICCoalesceThreshold(t *testing.T) {
	run := func(t *testing.T, minSize int) [][]string {
		t.Helper()
		// fork http3 服务端（自签证书；客户端 InsecureSkipVerify）
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "coalesce-test"},
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
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		srv := &http3.Server{
			TLSConfig: http3.ConfigureTLSConfig(&utlsb.Config{
				Certificates: []utlsb.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
				NextProtos:   []string{"h3"},
			}),
		}
		go srv.Serve(udp)
		defer srv.Close()

		relay := newRelaySniff(t, udp.LocalAddr().(*net.UDPAddr))

		// 客户端：剥 ECH（bogdanfinn QUIC 服务端不认 ECH 扩展，见 h3_test.go 同口径）
		p, err := profiles.Get("chrome_133")
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
		p.HTTP3 = &profiles.HTTP3Profile{
			Enabled:       true,
			InitialLayout: &profiles.H3InitialLayout{CoalesceMinSize: minSize},
		}
		qcfg, err := h3core.QUICConfigFromProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		if minSize != 0 && qcfg.InitialLayout == nil {
			t.Fatal("InitialLayout 没有接进 quic.Config（vendor patch #8 未生效）")
		}

		udp2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer udp2.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := quic.DialEarly(ctx, udp2, relay.conn.LocalAddr().(*net.UDPAddr), &utlsb.Config{
			InsecureSkipVerify: true, NextProtos: []string{"h3"}, OmitEmptyPsk: true,
			ServerName: "localhost",
		}, qcfg)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		// DialEarly 在客户端拿到 1-RTT 密钥时就返回；第二飞（Initial ACK +
		// Handshake Finished）是异步发出的，等它真正上线再快照。
		// 注意快照必须在 CloseWithError 之前——关闭会发出一个 coalesced
		// CONNECTION_CLOSE datagram（[initial handshake 1rtt]），会污染断言。
		time.Sleep(300 * time.Millisecond)
		captured := relay.captured()
		conn.CloseWithError(0, "done")

		var keys quicInitialKeys
		var keysSet bool
		var out [][]string
		for _, d := range captured {
			types := classifyDatagram(d, &keys, &keysSet)
			t.Logf("  client→server datagram %dB: %v", len(d), types)
			out = append(out, types)
		}
		return out
	}

	hasBoth := func(flights [][]string) bool {
		for _, f := range flights {
			var init, hs bool
			for _, typ := range f {
				init = init || typ == "initial"
				hs = hs || typ == "handshake"
			}
			if init && hs {
				return true
			}
		}
		return false
	}

	def := run(t, 0)
	if !hasBoth(def) {
		t.Errorf("默认阈值下应存在 Initial+Handshake 合并 datagram，实测序列：%v", def)
	} else {
		t.Logf("默认阈值：客户端 datagram 类型序列 %v（合并可见）", def)
	}

	off := run(t, -1)
	if hasBoth(off) {
		t.Errorf("coalesce_min_size=-1 时不应再出现 Initial+Handshake 合并 datagram，实测：%v", off)
	}
	var sawHandshakeOnly bool
	for _, f := range off {
		if len(f) == 1 && f[0] == "handshake" {
			sawHandshakeOnly = true
		}
	}
	if !sawHandshakeOnly {
		t.Errorf("禁用合并后应存在独立的 Handshake datagram，实测序列：%v", off)
	}
	if !hasBoth(off) && sawHandshakeOnly {
		t.Logf("coalesce_min_size=-1：客户端 datagram 类型序列 %v（Initial/Handshake 已拆分）", off)
	}
}
