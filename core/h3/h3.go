// Package h3 封装 bogdanfinn/quic-go-utls 的 HTTP/3 客户端（P4）。
//
// 能力边界（详见 docs/p4-h3-capability.md）：
//   - H3 层：settings（值+顺序）、伪头序、GREASE 帧、datagrams —— 全控
//   - QUIC transport params：值可控子集经 quic.Config 映射（见下）；顺序/
//     非标参数/部分固定值不可控（需 fork internal/wire，见文档）
//   - QUIC 内层 TLS ClientHello：bogdanfinn/utls 默认 hello（spec 不可注入）
package h3

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	quic "github.com/geekbyter/geektls/core/third_party/quic-go-utls"
	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/http3"
	utlsb "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"

	h2core "github.com/geekbyter/geektls/core/h2"
	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

// transportParamsToQUICConfig 把 profile.http3.transport_params 映射到
// quic.Config 能控制的字段。返回无法表达的键列表（调用方记录/告警）。
//
// 注意：quic-go 的三个 stream 窗口参数共用 InitialStreamReceiveWindow 一个值，
// 三者不一致时取 bidi_local > bidi_remote > uni 的优先级（粒度损失，见
// docs/p4-h3-capability.md）。
func transportParamsToQUICConfig(tp map[string]uint64, cfg *quic.Config) []string {
	var unsupported []string
	for k, v := range tp {
		switch k {
		case "max_idle_timeout":
			cfg.MaxIdleTimeout = time.Duration(v) * time.Millisecond
		case "initial_max_data":
			cfg.InitialConnectionReceiveWindow = v
		case "initial_max_streams_bidi":
			cfg.MaxIncomingStreams = int64(v)
		case "initial_max_streams_uni":
			cfg.MaxIncomingUniStreams = int64(v)
		case "initial_max_stream_data_bidi_local",
			"initial_max_stream_data_bidi_remote",
			"initial_max_stream_data_uni":
			// 下面统一处理（确定性优先级，避免 map 遍历乱序）
		default:
			unsupported = append(unsupported, k)
		}
	}
	for _, k := range []string{
		"initial_max_stream_data_bidi_local",
		"initial_max_stream_data_bidi_remote",
		"initial_max_stream_data_uni",
	} {
		if v, ok := tp[k]; ok {
			cfg.InitialStreamReceiveWindow = v
			break
		}
	}
	return unsupported
}

// QUICConfigFromProfile 把 profile 映射为 quic.Config（NewTransport 与
// 测试共用）。tls.detail 经 tlscore 编译 + bogdanfinn 类型转换后注入为
// QUIC 内层握手的 ClientHelloSpec（vendor patch，见 third_party/GEEKTLS_PATCHES.md）。
// transport params 不可表达的键被忽略（清单见 docs/p4-h3-capability.md）。
func QUICConfigFromProfile(p *profiles.Profile) (*quic.Config, error) {
	qcfg := &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: 3 * time.Second, // 失败时回落 H2 前的等待上限（默认 5s 太长）
	}

	// QUIC 内层 TLS ClientHello：与 TCP 侧同一 tls.detail
	if p.TLS != nil && p.TLS.Detail != nil {
		spec, err := tlscore.CompileDetail(p.TLS.Detail)
		if err != nil {
			return nil, fmt.Errorf("h3: compile tls detail: %w", err)
		}
		bspec, err := SpecToBogdan(spec)
		if err != nil {
			return nil, fmt.Errorf("h3: spec convert: %w", err)
		}
		clampSpecForQUIC(bspec, p.HTTP3)
		qcfg.ClientHelloSpec = bspec
	}

	h3p := p.HTTP3
	if h3p == nil {
		return qcfg, nil
	}
	if h3p.QUICVersion != "" {
		v, err := profiles.ParseHex16(h3p.QUICVersion)
		if err != nil {
			return nil, fmt.Errorf("h3: quic_version: %w", err)
		}
		qcfg.Versions = []quic.Version{quic.Version(v)}
	}
	// 首个 Initial datagram 的填充**下限**（floor）：不足则补到它，自然尺寸更大就
	// 按自然尺寸发。语义是"至少这么多"而不是"精确这么多"——QUIC 只要求客户端每个
	// 含 Initial 的 datagram ≥1200，真机（Chrome 149 实测首包 1230B）也只在需要时补，
	// 所以不设时下限 = 1200（不再是上游 quic-go 的"填到 1280"）。
	// 上游 Config.InitialPacketSize 会把值静默夹到 1200..1452；越界在这里直接报错。
	floor := 1200
	if h3p.InitialPacketSize != 0 {
		if h3p.InitialPacketSize < 1200 || h3p.InitialPacketSize > 1452 {
			return nil, fmt.Errorf("h3: initial_packet_size %d 越界（want 1200..1452 = 填充下限）", h3p.InitialPacketSize)
		}
		floor = h3p.InitialPacketSize
	}
	qcfg.InitialPacketSize = uint16(floor) // 上游会夹到 1200..1452；上面已验，不静默改值

	// SCID 长度（patch #10）：决定长头包里的 source connection ID，也是 0x0f
	//（initial_source_connection_id）声明合法性的前提。nil = 上游默认 4；0 = Chrome
	// 形态的空 SCID；1..20 自定义。范围在这里校验（NewTransport 与测试共用本函数）。
	scidLen := -1
	if h3p.ConnectionIDLength != nil {
		if *h3p.ConnectionIDLength < 0 || *h3p.ConnectionIDLength > 20 {
			return nil, fmt.Errorf("h3: connection_id_length %d 越界（want 0..20；nil = 上游默认 4）", *h3p.ConnectionIDLength)
		}
		scidLen = *h3p.ConnectionIDLength
	}

	if len(h3p.TransportParamsRaw) > 0 {
		if len(h3p.TransportParams) > 0 {
			// 两种形态同时设置时不许静默选一边（Q2 冲突规则）。
			return nil, fmt.Errorf("h3: transport_params 与 transport_params_raw 互斥（raw 优先的静默覆盖已禁止）；请只保留一种")
		}
		// T4-1 blob 直通：有序/非标/GREASE 全控（vendor patch #7），
		// 同时做客户端合法性/行为一致性校验并把已知键值映射回 quic.Config。
		tps, err := buildTransportParamsRaw(h3p.TransportParamsRaw)
		if err != nil {
			return nil, err
		}
		qcfg.TransportParamsOverride = tps
		if err := applyKnownRawTP(tps, qcfg, scidLen); err != nil {
			return nil, err
		}
	} else if len(h3p.TransportParams) > 0 {
		transportParamsToQUICConfig(h3p.TransportParams, qcfg)
	}
	if l := h3p.InitialLayout; l != nil {
		// Initial 布局（vendor patch #8）：PADDING 位置 / CRYPTO 分片表 /
		// coalesce 阈值。合法性已在 profiles.Parse 校验过。
		layout := &quic.InitialLayoutConfig{
			PaddingEnd:                   l.Padding == "end",
			DisableClientHelloScrambling: l.DisableScramble,
		}
		switch {
		case l.CoalesceMinSize < 0:
			layout.CoalesceMinSize = 0xffff // 事实上禁用合并
		case l.CoalesceMinSize > 0:
			layout.CoalesceMinSize = uint16(l.CoalesceMinSize)
		}
		if len(l.CryptoFragments) > 0 {
			layout.DisableClientHelloScrambling = true // 分片表与 scrambling 互斥，以表为准
			layout.CryptoFragments = l.CryptoFragments
		}
		qcfg.InitialLayout = layout
	}
	return qcfg, nil
}

// NewTransport 按 profile 构建 H3 Transport（实现 fhttp RoundTripper）。
// TLSSettings 是 H3 握手的 TLS 侧参数（与 TCP 侧 dial.go 的 utls.Config 同源）。
type TLSSettings struct {
	InsecureSkipVerify bool
	RootCAs            *x509.CertPool      // nil = 系统信任库
	Certificates       []utlsb.Certificate // mTLS 客户端证书
	// SessionCache：QUIC 会话票据缓存（0-RTT/会话复用，T1）。nil = 不缓存
	// （utls 语义：无 cache 即不存票）。配合 vendor patch（utls-bogdanfinn
	// 的 UQUICConn 会话事件 + quic-go-utls 的 StoreSession 委托）生效。
	SessionCache utlsb.ClientSessionCache
}

func NewTransport(p *profiles.Profile, tlsOpts TLSSettings) (*http3.Transport, error) {
	tlsCfg := &utlsb.Config{
		InsecureSkipVerify: tlsOpts.InsecureSkipVerify,
		RootCAs:            tlsOpts.RootCAs,
		Certificates:       tlsOpts.Certificates,
		NextProtos:         []string{"h3"},
		OmitEmptyPsk:       true, // 无票据时线上省略空 PSK 扩展（预设带 41 占位）
		ClientSessionCache: tlsOpts.SessionCache,
	}
	qcfg, err := QUICConfigFromProfile(p)
	if err != nil {
		return nil, err
	}

	h3p := p.HTTP3
	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      qcfg,
		EnableDatagrams: true, // Chrome 开 H3_DATAGRAM
	}
	if h3p != nil && h3p.ConnectionIDLength != nil {
		// SCID 长度（patch #10）：0 = Chrome 形态的空 SCID，也是 0x0f
		//（initial_source_connection_id）空值声明的前提。范围已在
		// QUICConfigFromProfile 校验过，这里只做映射。
		tr.QUICConnectionIDLength = *h3p.ConnectionIDLength
		tr.QUICAllowZeroLengthConnectionIDs = *h3p.ConnectionIDLength == 0
	}
	if h3p == nil {
		return tr, nil
	}

	if len(h3p.Settings) > 0 {
		settings := make(map[uint64]uint64, len(h3p.Settings))
		order := make([]uint64, 0, len(h3p.Settings))
		for i, kv := range h3p.Settings {
			if len(kv) != 2 {
				return nil, fmt.Errorf("h3: settings[%d] must be [id, value]", i)
			}
			settings[uint64(kv[0])] = uint64(kv[1])
			order = append(order, uint64(kv[0]))
		}
		tr.AdditionalSettings = settings
		tr.AdditionalSettingsOrder = order
	}

	if len(h3p.PseudoHeaderOrder) > 0 {
		mapped, err := h2core.PseudoHeaderOrder(h3p.PseudoHeaderOrder)
		if err != nil {
			return nil, err
		}
		tr.PseudoHeaderOrder = mapped
	}

	tr.SendGreaseFrames = h3p.GreaseFrames
	if h3p.PriorityParam > 0 {
		tr.PriorityParam = h3p.PriorityParam
	}
	return tr, nil
}

// clampSpecForQUIC 把 TCP 侧编译产物裁剪为 **QUIC 内层 ClientHello** 形态。
//
// 实测依据（2026-09-24 E1：真 Chrome 149 / Windows，采集见 tests/e2e/e1_h3_test.go，
// 记录 profiles/evidence/browsers/chrome_windows_h3.json）：
//   - ciphers 恰为 3 个 TLS1.3 套件（无 TLS1.2 套件、无 GREASE cipher）
//   - 扩展 11 项 = TCP 的 16 项剔 6 个 TLS1.2 语义扩展（5/11/18/23/35/65281）+ 增 57
//   - supported_groups / key_shares / supported_versions **均无 GREASE**
//   - signature_algorithms = TCP 的 8 项 + 末尾追加 0x0201（rsa_pkcs1_sha1）
//   - **扩展顺序逐连接随机**（两次抓包顺序完全不同）⇒ 无需另设顺序，
//     沿用已有的 extension_permutation 洗牌即可
//
// 分工：11/23/35/65281 属 TLS1.2 语义，对所有浏览器都该剔（硬编码）；
// 5(status_request) 与 18(SCT) 在 TLS1.3 里仍有意义，Chrome 在 QUIC 上不发属
// **实现选择**，由 profile 的 http3.inner_hello_drop_extensions 提供。
//
// 其余原有行为保留：ALPN/ALPS 重写为 h3；ECH GREASE 换合成 payload
// （bogdanfinn/utls 原生生成在 QUIC 下静默失败，bisect 实测）；扩展 57 换成
// QUICTransportParametersExtension 并保证插在 PSK 之前。
func clampSpecForQUIC(spec *utlsb.ClientHelloSpec, h3p *profiles.HTTP3Profile) {
	spec.TLSVersMin = utlsb.VersionTLS13
	spec.TLSVersMax = utlsb.VersionTLS13

	dropGrease := h3p != nil && h3p.InnerHelloDropGrease
	extraDrop := map[uint16]bool{}
	var extraSigAlgs []string
	if h3p != nil {
		for _, id := range h3p.InnerHelloDropExtensions {
			extraDrop[id] = true
		}
		extraSigAlgs = h3p.InnerHelloExtraSigAlgs
	}

	// ciphers：QUIC 强制 TLS1.3 ⇒ 只保留 1.3 套件（GREASE 占位按 profile 决定）。
	var ciphers []uint16
	for _, c := range spec.CipherSuites {
		if isGreaseUint16H3(c) {
			if !dropGrease {
				ciphers = append(ciphers, c)
			}
			continue
		}
		switch c {
		case utlsb.TLS_AES_128_GCM_SHA256, utlsb.TLS_AES_256_GCM_SHA384, utlsb.TLS_CHACHA20_POLY1305_SHA256:
			ciphers = append(ciphers, c)
		}
	}
	spec.CipherSuites = ciphers

	hasQTP := false
	out := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		switch ext := e.(type) {
		case *utlsb.SupportedPointsExtension:
			continue // 11：TLS1.3 无 ec_point_formats 语义
		case *utlsb.ExtendedMasterSecretExtension:
			continue // 23：TLS1.2 专属
		case *utlsb.SessionTicketExtension:
			continue // 35：TLS1.3 用 PSK 恢复，实测 QUIC 不发
		case *utlsb.StatusRequestExtension:
			if extraDrop[5] {
				continue // 实测 Chrome QUIC 不发（TLS1.3 本可发，属实现选择）
			}
			out = append(out, e)
		case *utlsb.SCTExtension:
			if extraDrop[18] {
				continue // 同上
			}
			out = append(out, e)
		case *utlsb.UtlsGREASEExtension:
			if dropGrease {
				continue
			}
			out = append(out, e)
		case *utlsb.SupportedVersionsExtension:
			var v []uint16
			for _, ver := range ext.Versions {
				if ver == utlsb.VersionTLS13 || (!dropGrease && isGreaseUint16H3(ver)) {
					v = append(v, ver)
				}
			}
			ext.Versions = v
			out = append(out, e)
		case *utlsb.GREASEEncryptedClientHelloExtension:
			// bogdanfinn/utls 的 ECH 负载生成在 QUIC 下静默失败（依赖 TCP
			// record 层）；但 Chrome 的 QUIC hello 同样带 ECH GREASE——
			// 直接按线上格式合成等效 payload（见 echGreasePayload）。
			out = append(out, &utlsb.GenericExtension{Id: 65037, Data: echGreasePayload()})
		case *utlsb.GenericExtension:
			switch {
			case ext.Id == 57:
				// transport params 必须走 QUICTransportParametersExtension
				// 类型（裸字节由 vendor patch 在握手时填充）
				out = append(out, &utlsb.QUICTransportParametersExtension{})
				hasQTP = true
			case ext.Id == 65281:
				// renegotiation_info：TLS1.2 专属（编译期以 GenericExtension 透传）
			case extraDrop[ext.Id]:
			case dropGrease && isGreaseUint16H3(ext.Id):
			default:
				out = append(out, e)
			}
		case *utlsb.ALPNExtension:
			// QUIC 只有 h3（真实 Chrome QUIC hello 形态）
			ext.AlpnProtocols = []string{"h3"}
			out = append(out, e)
		case *utlsb.ApplicationSettingsExtension:
			ext.SupportedProtocols = []string{"h3"} // ALPS 跟随协议族
			out = append(out, e)
		case *utlsb.ApplicationSettingsExtensionNew:
			ext.SupportedProtocols = []string{"h3"}
			out = append(out, e)
		case *utlsb.SupportedCurvesExtension:
			if dropGrease {
				kept := ext.Curves[:0]
				for _, c := range ext.Curves {
					if !isGreaseUint16H3(uint16(c)) {
						kept = append(kept, c)
					}
				}
				ext.Curves = kept
			}
			out = append(out, e)
		case *utlsb.KeyShareExtension:
			if dropGrease {
				kept := ext.KeyShares[:0]
				for _, ks := range ext.KeyShares {
					if !isGreaseUint16H3(uint16(ks.Group)) {
						kept = append(kept, ks)
					}
				}
				ext.KeyShares = kept
			}
			out = append(out, e)
		case *utlsb.SignatureAlgorithmsExtension:
			// 实测 Chrome 把 QUIC 特有算法追加在**末尾**（0x0201 在最后一项）。
			for _, h := range extraSigAlgs {
				v, err := profiles.ParseHex16(h)
				if err != nil {
					continue
				}
				scheme := utlsb.SignatureScheme(v)
				dup := false
				for _, s := range ext.SupportedSignatureAlgorithms {
					if s == scheme {
						dup = true
						break
					}
				}
				if !dup {
					ext.SupportedSignatureAlgorithms = append(ext.SupportedSignatureAlgorithms, scheme)
				}
			}
			out = append(out, e)
		default:
			out = append(out, e)
		}
	}
	if !hasQTP {
		// PSK 扩展必须恒在最后：插到尾部 PSK 之前
		qtp := &utlsb.QUICTransportParametersExtension{}
		if n := len(out); n > 0 {
			if _, isPSK := out[n-1].(*utlsb.UtlsPreSharedKeyExtension); isPSK {
				out = append(out[:n-1], qtp, out[n-1])
				spec.Extensions = out
				return
			}
		}
		out = append(out, qtp)
	}
	spec.Extensions = out
}

func isGreaseUint16H3(v uint16) bool { return v>>8 == v&0xff && v&0xf == 0xa }

// echGreasePayload 合成 ECH GREASE 负载，结构对齐真实浏览器（Chrome/Edge 抓包实证）：
//
//	outer(0x00) | kdf HKDF-SHA256(0x0001) | aead AES-128-GCM(0x0001) |
//	config_id(1B 随机) | enc_len(0x0020) | enc(32B 随机) | payload_len | payload(随机)
//
// 总长 = 42 + payloadLen；payloadLen 从 Chrome 的候选集 {144,176,208,240} 随机取
// （抓包实测 176，总长 218）。
func echGreasePayload() []byte {
	payloadLens := []int{144, 176, 208, 240}
	seed := make([]byte, 1)
	if _, err := rand.Read(seed); err != nil {
		seed[0] = 0
	}
	payloadLen := payloadLens[int(seed[0])%len(payloadLens)]

	configID := make([]byte, 1)
	enc := make([]byte, 32)
	payload := make([]byte, payloadLen)
	rand.Read(configID)
	rand.Read(enc)
	rand.Read(payload)

	out := []byte{
		0x00,       // outer: client hello
		0x00, 0x01, // kdf_id: HKDF-SHA256
		0x00, 0x01, // aead_id: AES-128-GCM
		configID[0], // config_id（GREASE 随机）
		0x00, 0x20,  // enc_len = 32
	}
	out = append(out, enc...)
	out = append(out, byte(payloadLen>>8), byte(payloadLen))
	return append(out, payload...)
}
