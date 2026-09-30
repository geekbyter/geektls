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

	quic "github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3"
	utlsb "github.com/bogdanfinn/utls"

	h2core "github.com/geektls/core/h2"
	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
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
	// 首个 Initial datagram 的尺寸（= PADDING 填到多少）。上游 quic-go 的
	// Config.InitialPacketSize 本来就把值夹到 1200..1452，但那会**静默改值**；
	// 越界在这里直接报错，免得"设了 1500 却发出 1452"这种事查半天。
	if h3p.InitialPacketSize != 0 {
		if h3p.InitialPacketSize < 1200 || h3p.InitialPacketSize > 1452 {
			return nil, fmt.Errorf("h3: initial_packet_size %d 越界（want 1200..1452，0 = 上游默认 1280）", h3p.InitialPacketSize)
		}
		qcfg.InitialPacketSize = uint16(h3p.InitialPacketSize) // 上文已限 1200..1452
	}
	if len(h3p.TransportParamsRaw) > 0 {
		// T4-1 blob 直通：有序/非标/GREASE 全控（vendor patch #7），
		// 同时把已知流控键值映射回 quic.Config 保证行为一致。
		tps, err := buildTransportParamsRaw(h3p.TransportParamsRaw)
		if err != nil {
			return nil, err
		}
		qcfg.TransportParamsOverride = tps
		applyKnownRawTP(tps, qcfg)
	} else if len(h3p.TransportParams) > 0 {
		transportParamsToQUICConfig(h3p.TransportParams, qcfg)
	}
	return qcfg, nil
}

// NewTransport 按 profile 构建 H3 Transport（实现 fhttp RoundTripper）。
// TLSSettings 是 H3 握手的 TLS 侧参数（与 TCP 侧 dial.go 的 utls.Config 同源）。
type TLSSettings struct {
	InsecureSkipVerify bool
	RootCAs            *x509.CertPool      // nil = 系统信任库
	Certificates       []utlsb.Certificate // mTLS 客户端证书
}

func NewTransport(p *profiles.Profile, tlsOpts TLSSettings) (*http3.Transport, error) {
	tlsCfg := &utlsb.Config{
		InsecureSkipVerify: tlsOpts.InsecureSkipVerify,
		RootCAs:            tlsOpts.RootCAs,
		Certificates:       tlsOpts.Certificates,
		NextProtos:         []string{"h3"},
		OmitEmptyPsk:       true, // 无票据时线上省略空 PSK 扩展（预设带 41 占位）
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
