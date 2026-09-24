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
		clampSpecForQUIC(bspec)
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
	if len(h3p.TransportParams) > 0 {
		transportParamsToQUICConfig(h3p.TransportParams, qcfg)
	}
	return qcfg, nil
}

// NewTransport 按 profile 构建 H3 Transport（实现 fhttp RoundTripper）。
func NewTransport(p *profiles.Profile, insecureSkipVerify bool) (*http3.Transport, error) {
	tlsCfg := &utlsb.Config{
		InsecureSkipVerify: insecureSkipVerify,
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

// clampSpecForQUIC QUIC 只允许 TLS 1.3：supported_versions 过滤为
// GREASE+0x0304（真实 Chrome QUIC hello 形态），版本上下限收紧；ALPN/ALPS
// 重写为 h3；ECH GREASE 换合成 payload（bogdanfinn/utls 原生生成在 QUIC
// 下静默失败，bisect 实测）。
func clampSpecForQUIC(spec *utlsb.ClientHelloSpec) {
	spec.TLSVersMin = utlsb.VersionTLS13
	spec.TLSVersMax = utlsb.VersionTLS13
	hasQTP := false
	out := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		switch ext := e.(type) {
		case *utlsb.SupportedVersionsExtension:
			var v []uint16
			for _, ver := range ext.Versions {
				if ver == utlsb.VersionTLS13 || isGreaseUint16H3(ver) {
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
			if ext.Id == 57 {
				// transport params 必须走 QUICTransportParametersExtension
				// 类型（裸字节由 vendor patch 在握手时填充）
				out = append(out, &utlsb.QUICTransportParametersExtension{})
				hasQTP = true
			} else {
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

// echGreasePayload 合成 ECH GREASE 负载（与 BoringSSL/Chrome 线上格式一致）：
// outer(0) | KDF HKDF-SHA256(0x0001) | AEAD AES-128-GCM(0x0001) | config_id |
// enc_len(0) | payload_len | 随机 payload。
// 长度从 BoringSSL 的候选集 {144,176,208,240} 随机挑一个。
func echGreasePayload() []byte {
	lens := []int{144, 176, 208, 240}
	choice := make([]byte, 2)
	if _, err := rand.Read(choice); err != nil {
		choice = []byte{0, 0}
	}
	payloadLen := lens[int(choice[0])%len(lens)] - 16 // 减 16 字节 AEAD 标签（对齐 BoringSSL 注释 "+16"）
	if payloadLen < 0 {
		payloadLen = 128
	}

	payload := make([]byte, payloadLen)
	rand.Read(payload)

	out := []byte{0x00, 0x00, 0x01, 0x00, 0x01, choice[1], 0x00, 0x00,
		byte(payloadLen >> 8), byte(payloadLen)}
	return append(out, payload...)
}
