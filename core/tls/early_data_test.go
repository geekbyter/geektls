package tlscore

// 0-RTT / early_data 的**指纹侧边界**（审计 A10 的结案依据，实测于本地 std 服务端）。
//
// 结论两句话：
//  1. **能声明**：`early_data`(42) 走未识别类型的透传路径（GenericExtension），
//     预设里写 `{"type": 42}` 就会出现在线上 CH，JA3 扩展段多一枚 42、
//     JA4 的扩展计数随之 +1（17→18）——"长得像开了 0-RTT 的客户端"这件事本来就可控，
//     这正是本库的主旨，不需要任何栈改动。
//  2. **不能只声明**：RFC 8446 §4.2.10 要求 early_data 必须与 PSK 同现，
//     而我们的 pre_shared_key 占位在**无票据时线上省略**（见 presets 的 psk 处理），
//     于是"只带 42"的 CH 会被标准服务端拒（Go: `client sent unexpected early data`）。
//     真 0-RTT 首飞还要求 extension 0 排在**最前**且带会话绑定的 binder 字节 ⇒ 不可
//     跨目标转录/回放（docs/12 §"拒绝项"同一口径）。
//
// 所以本库**不做** 0-RTT 的协议侧：TCP 侧无钩子（docs/07 G2b、docs/08 L1 已取证），
// H3 侧前提（QUIC 会话缓存）在 spec 模式下是 no-op 且无可补导出面（docs/06 P7-T2）。
// 本测试钉住"可声明 + 只声明必被拒"这半个事实，防止把它误当成一个可打开的会话开关。

import (
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

func TestEarlyDataExtensionIsDeclarable(t *testing.T) {
	p, err := profiles.Get("chrome_154_windows")
	if err != nil {
		t.Fatal(err)
	}
	base, err := CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}

	// 在 key_share(51) 之前插一枚 42（真 Chrome 的 0-RTT 首飞就在这个相对位置）。
	d := *p.TLS.Detail
	exts := make([]profiles.Extension, 0, len(d.Extensions)+1)
	for _, e := range d.Extensions {
		if e.Type == 51 {
			exts = append(exts, profiles.Extension{Type: 42})
		}
		exts = append(exts, e)
	}
	d.Extensions = exts
	spec, err := CompileDetail(&d)
	if err != nil {
		t.Fatalf("带 early_data 的 detail 编译失败: %v", err)
	}

	// 1) JA3 扩展段含 42（该预设开了扩展洗牌，只比"有没有"，不比顺序）。
	ja3 := ComputeJA3(spec)
	fields := strings.Split(ja3, ",")
	if len(fields) < 3 {
		t.Fatalf("JA3 形态不对: %s", ja3)
	}
	found := false
	for _, id := range strings.Split(fields[2], "-") {
		if id == "42" {
			found = true
		}
	}
	if !found {
		t.Errorf("JA3 扩展段没有 42: %s", fields[2])
	}
	for _, id := range strings.Split(strings.Split(ComputeJA3(base), ",")[2], "-") {
		if id == "42" {
			t.Error("基线 JA3 里就有 42（预设本身声明了？本测试的前提不成立）")
		}
	}

	// 2) JA4：协议/SNI/密文数/ALPN 段不变，扩展计数 +1，尾部哈希随扩展变。
	baseJA4, gotJA4 := ComputeJA4(base), ComputeJA4(spec)
	if len(baseJA4) < 10 || len(gotJA4) < 10 {
		t.Fatalf("JA4 形态不对: %s / %s", baseJA4, gotJA4)
	}
	if baseJA4[:6] != gotJA4[:6] || baseJA4[8:10] != gotJA4[8:10] {
		t.Errorf("JA4 前缀除扩展计数外应一致: %s vs %s", baseJA4, gotJA4)
	}
	if baseJA4[6:8] != "17" || gotJA4[6:8] != "18" {
		t.Errorf("JA4 扩展计数应 17→18，实得 %s→%s（%s / %s）",
			baseJA4[6:8], gotJA4[6:8], baseJA4, gotJA4)
	}
	// JA4 = 前缀(协议/SNI/密文数/扩展数/ALPN) _ 密文集哈希 _ 扩展+SNI 哈希。
	// 只加一枚扩展 ⇒ 密文集哈希不动、扩展哈希必动。
	if strings.Split(baseJA4, "_")[1] != strings.Split(gotJA4, "_")[1] {
		t.Errorf("密文集不该随扩展变化而变: %s vs %s", baseJA4, gotJA4)
	}
	if strings.Split(baseJA4, "_")[2] == strings.Split(gotJA4, "_")[2] {
		t.Errorf("加了扩展后扩展哈希不该不变: %s", gotJA4)
	}

	// 3) 线上字节：42 以零负载出现，且能被 hex 解析器原样读回（转录/回放路径可用）。
	serverCfg := newTestServerConfig(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	srvErr := make(chan error, 1)
	go func() {
		srv := tls.Server(serverConn, serverCfg)
		srvErr <- srv.Handshake()
		_ = srv.Close()
	}()
	rec := &recordingConn{Conn: clientConn}
	uconn, clientErr := Handshake(rec, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}, spec)
	if uconn != nil {
		_ = uconn.Close()
	}
	srvErrVal := <-srvErr

	parsed, warnings, err := profiles.FromClientHelloHex(hex.EncodeToString(rec.buf.Bytes()))
	if err != nil {
		t.Fatalf("FromClientHelloHex: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("hex 解析不该有告警: %+v", warnings)
	}
	var has42 bool
	for _, e := range parsed.TLS.Detail.Extensions {
		if e.Type == 42 {
			has42 = true
			if e.Data != "" {
				t.Errorf("early_data 应是零负载，实得 data=%q", e.Data)
			}
		}
	}
	if !has42 {
		t.Errorf("线上 CH 解析回来的扩展里没有 42: %+v", parsed.TLS.Detail.Extensions)
	}

	// 4) **只**声明 early_data 必被标准服务端拒（这是"不能当开关打开"的实证）。
	if srvErrVal == nil || !strings.Contains(srvErrVal.Error(), "early data") {
		t.Errorf("std 服务端应因 unexpected early data 拒绝，实得: %v", srvErrVal)
	}
	if clientErr == nil {
		t.Error("客户端侧应看到握手失败（服务端拒了 42）")
	} else if !strings.Contains(clientErr.Error(), "unsupported extension") {
		t.Errorf("客户端错误应为 unsupported extension，实得: %v", clientErr)
	}
	t.Logf("边界实证：声明 42 ⇒ JA4 %s→%s；服务端=%v；客户端=%v",
		baseJA4, gotJA4, srvErrVal, clientErr)
}
