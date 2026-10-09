package h3

// spec_convert.go：refraction-networking/utls 的 ClientHelloSpec →
// bogdanfinn/utls 的同构类型（QUIC 内层握手用）。
//
// 两 fork 同源，扩展类型同名同字段，逐类型机械转换；未知类型报错（不静默
// 丢指纹内容）。GREASE ECH 因字段类型依赖各自 dicttls 包，统一重建为
// bogdanfinn 的 BoringGREASEECH()（我们编译器本来就只产这个形态）。

import (
	"fmt"

	utlsb "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"
	utls "github.com/refraction-networking/utls"
)

// SpecToBogdan 转换 ClientHelloSpec。
func SpecToBogdan(spec *utls.ClientHelloSpec) (*utlsb.ClientHelloSpec, error) {
	if spec == nil {
		return nil, nil
	}
	out := &utlsb.ClientHelloSpec{
		TLSVersMin:         spec.TLSVersMin,
		TLSVersMax:         spec.TLSVersMax,
		CompressionMethods: append([]uint8(nil), spec.CompressionMethods...),
	}
	out.CipherSuites = append([]uint16(nil), spec.CipherSuites...)
	for i, e := range spec.Extensions {
		conv, err := convertExtension(e)
		if err != nil {
			return nil, fmt.Errorf("spec convert: extension %d (%T): %w", i, e, err)
		}
		out.Extensions = append(out.Extensions, conv)
	}
	return out, nil
}

func convertExtension(e utls.TLSExtension) (utlsb.TLSExtension, error) {
	switch ext := e.(type) {
	case *utls.UtlsGREASEExtension:
		return &utlsb.UtlsGREASEExtension{Value: ext.Value, Body: ext.Body}, nil
	case *utls.SNIExtension:
		return &utlsb.SNIExtension{ServerName: ext.ServerName}, nil
	case *utls.StatusRequestExtension:
		return &utlsb.StatusRequestExtension{}, nil
	case *utls.SupportedCurvesExtension:
		curves := make([]utlsb.CurveID, 0, len(ext.Curves))
		for _, c := range ext.Curves {
			curves = append(curves, utlsb.CurveID(c))
		}
		return &utlsb.SupportedCurvesExtension{Curves: curves}, nil
	case *utls.SupportedPointsExtension:
		return &utlsb.SupportedPointsExtension{SupportedPoints: ext.SupportedPoints}, nil
	case *utls.SignatureAlgorithmsExtension:
		return &utlsb.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigSchemes(ext.SupportedSignatureAlgorithms)}, nil
	case *utls.ALPNExtension:
		return &utlsb.ALPNExtension{AlpnProtocols: ext.AlpnProtocols}, nil
	case *utls.SCTExtension:
		return &utlsb.SCTExtension{}, nil
	case *utls.UtlsPaddingExtension:
		return &utlsb.UtlsPaddingExtension{
			PaddingLen:    ext.PaddingLen,
			WillPad:       ext.WillPad,
			GetPaddingLen: ext.GetPaddingLen, // 函数签名两边一致
		}, nil
	case *utls.ExtendedMasterSecretExtension:
		return &utlsb.ExtendedMasterSecretExtension{}, nil
	case *utls.UtlsCompressCertExtension:
		algos := make([]utlsb.CertCompressionAlgo, 0, len(ext.Algorithms))
		for _, a := range ext.Algorithms {
			algos = append(algos, utlsb.CertCompressionAlgo(a))
		}
		return &utlsb.UtlsCompressCertExtension{Algorithms: algos}, nil
	case *utls.FakeRecordSizeLimitExtension:
		return &utlsb.FakeRecordSizeLimitExtension{Limit: ext.Limit}, nil
	case *utls.FakeDelegatedCredentialsExtension:
		return &utlsb.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: sigSchemes(ext.SupportedSignatureAlgorithms)}, nil
	case *utls.SessionTicketExtension:
		return &utlsb.SessionTicketExtension{
			Session:     nil, // SessionState 两边类型不同源；P7 会话复用时再适配
			Ticket:      ext.Ticket,
			Initialized: ext.Initialized,
		}, nil
	case *utls.SupportedVersionsExtension:
		return &utlsb.SupportedVersionsExtension{Versions: append([]uint16(nil), ext.Versions...)}, nil
	case *utls.PSKKeyExchangeModesExtension:
		return &utlsb.PSKKeyExchangeModesExtension{Modes: append([]uint8(nil), ext.Modes...)}, nil
	case *utls.UtlsPreSharedKeyExtension:
		// 空占位转换：票据状态不跨 fork（QUIC 会话缓存本就是 no-op，见 patch 文档）
		return &utlsb.UtlsPreSharedKeyExtension{}, nil
	case *utls.SignatureAlgorithmsCertExtension:
		return &utlsb.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: sigSchemes(ext.SupportedSignatureAlgorithms)}, nil
	case *utls.KeyShareExtension:
		shares := make([]utlsb.KeyShare, 0, len(ext.KeyShares))
		for _, ks := range ext.KeyShares {
			shares = append(shares, utlsb.KeyShare{Group: utlsb.CurveID(ks.Group), Data: ks.Data})
		}
		return &utlsb.KeyShareExtension{KeyShares: shares}, nil
	case *utls.ApplicationSettingsExtension:
		return &utlsb.ApplicationSettingsExtension{SupportedProtocols: ext.SupportedProtocols}, nil
	case *utls.ApplicationSettingsExtensionNew:
		return &utlsb.ApplicationSettingsExtensionNew{SupportedProtocols: ext.SupportedProtocols}, nil
	case *utls.GREASEEncryptedClientHelloExtension:
		// T5.1：保形状转换——原实现一律归一为 BoringGREASEECH()（Chrome），
		// 会让 Firefox 形状（aead=3）的 QUIC 内层 65037 退回 Chrome 形状。
		return greaseECHToBogdan(ext), nil
	case *utls.GenericExtension:
		return &utlsb.GenericExtension{Id: ext.Id, Data: ext.Data}, nil
	}
	return nil, fmt.Errorf("unsupported extension type %T", e)
}

// greaseECHToBogdan 保形状转换（T5.1）：两个 fork 的 GREASE ECH 字段同构
// （CandidateCipherSuites[{KdfId,AeadId}] + CandidatePayloadLens，底层都是
// IANA 值）。未设置字段（configId/EncapsulatedKey 等）保持零值，随机行为
// 与转换前一致。
func greaseECHToBogdan(e *utls.GREASEEncryptedClientHelloExtension) *utlsb.GREASEEncryptedClientHelloExtension {
	out := &utlsb.GREASEEncryptedClientHelloExtension{
		CandidatePayloadLens: append([]uint16(nil), e.CandidatePayloadLens...),
	}
	for _, cs := range e.CandidateCipherSuites {
		out.CandidateCipherSuites = append(out.CandidateCipherSuites, utlsb.HPKESymmetricCipherSuite{
			KdfId:  uint16(cs.KdfId), // 两 fork 底层同为 IANA 值（uint16）
			AeadId: uint16(cs.AeadId),
		})
	}
	return out
}

func sigSchemes(in []utls.SignatureScheme) []utlsb.SignatureScheme {
	out := make([]utlsb.SignatureScheme, 0, len(in))
	for _, s := range in {
		out = append(out, utlsb.SignatureScheme(s))
	}
	return out
}

// SpecForJA4 把 QUIC 内层 ClientHelloSpec（bogdanfinn 类型，clampSpecForQUIC
// 之后）转换为 tlscore 自算口径的同构 spec（refraction 类型），供 engine 的
// H3 selfcheck 报告「QUIC 内层 ClientHello 的实际形态」（T2.1）。
//
// 只做逐类型机械转换（convertExtension 的反向），**不做任何形态决策**——裁剪
// 已经在 clampSpecForQUIC 完成，本函数零规则、零漂移面。语义要点：
//   - tlscore 的 JA3/JA4 计算只依赖：cipher 列表、扩展「类型序列」、sig_algs、
//     SNI 与 ALPN 的类型/值 ⇒ 多数扩展只需 ID 保真；
//   - QUICTransportParametersExtension(57) 在 refraction 侧未被
//     extensionTypeID 识别 ⇒ 转 GenericExtension{Id: 57} 保 ID；
//   - 未初始化的 PSK 占位转 refraction 零值 UtlsPreSharedKeyExtension：
//     tlscore.effectiveExtensions 对未初始化 PSK 按「无票据线上省略」剔除，
//     与 QUIC 侧 OmitEmptyPsk 的线上行为一致（扩展计数不虚增）；
//   - 未知类型跳过（selfcheck 是附加信息，尽力而为、不阻断请求）。
func SpecForJA4(spec *utlsb.ClientHelloSpec) *utls.ClientHelloSpec {
	if spec == nil {
		return nil
	}
	out := &utls.ClientHelloSpec{
		TLSVersMin:         spec.TLSVersMin,
		TLSVersMax:         spec.TLSVersMax,
		CipherSuites:       append([]uint16(nil), spec.CipherSuites...),
		CompressionMethods: append([]uint8(nil), spec.CompressionMethods...),
	}
	for _, e := range spec.Extensions {
		if conv := extForJA4(e); conv != nil {
			out.Extensions = append(out.Extensions, conv)
		}
	}
	return out
}

func extForJA4(e utlsb.TLSExtension) utls.TLSExtension {
	switch ext := e.(type) {
	case *utlsb.UtlsGREASEExtension:
		return &utls.UtlsGREASEExtension{Value: ext.Value, Body: ext.Body}
	case *utlsb.SNIExtension:
		return &utls.SNIExtension{ServerName: ext.ServerName}
	case *utlsb.StatusRequestExtension:
		return &utls.StatusRequestExtension{}
	case *utlsb.SupportedCurvesExtension:
		curves := make([]utls.CurveID, 0, len(ext.Curves))
		for _, c := range ext.Curves {
			curves = append(curves, utls.CurveID(c))
		}
		return &utls.SupportedCurvesExtension{Curves: curves}
	case *utlsb.SupportedPointsExtension:
		return &utls.SupportedPointsExtension{SupportedPoints: ext.SupportedPoints}
	case *utlsb.SignatureAlgorithmsExtension:
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: sigSchemesFromBogdan(ext.SupportedSignatureAlgorithms),
		}
	case *utlsb.ALPNExtension:
		return &utls.ALPNExtension{AlpnProtocols: append([]string(nil), ext.AlpnProtocols...)}
	case *utlsb.SCTExtension:
		return &utls.SCTExtension{}
	case *utlsb.UtlsPaddingExtension:
		return &utls.UtlsPaddingExtension{
			PaddingLen:    ext.PaddingLen,
			WillPad:       ext.WillPad,
			GetPaddingLen: ext.GetPaddingLen, // 函数签名两边一致（见本文件顶部注释）
		}
	case *utlsb.ExtendedMasterSecretExtension:
		return &utls.ExtendedMasterSecretExtension{}
	case *utlsb.UtlsCompressCertExtension:
		algos := make([]utls.CertCompressionAlgo, 0, len(ext.Algorithms))
		for _, a := range ext.Algorithms {
			algos = append(algos, utls.CertCompressionAlgo(a))
		}
		return &utls.UtlsCompressCertExtension{Algorithms: algos}
	case *utlsb.FakeRecordSizeLimitExtension:
		return &utls.FakeRecordSizeLimitExtension{Limit: ext.Limit}
	case *utlsb.FakeDelegatedCredentialsExtension:
		return &utls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: sigSchemesFromBogdan(ext.SupportedSignatureAlgorithms),
		}
	case *utlsb.SessionTicketExtension:
		// Session 字段两边类型不同源；selfcheck 只关心扩展存在与类型。
		return &utls.SessionTicketExtension{Ticket: ext.Ticket, Initialized: ext.Initialized}
	case *utlsb.SupportedVersionsExtension:
		return &utls.SupportedVersionsExtension{Versions: append([]uint16(nil), ext.Versions...)}
	case *utlsb.PSKKeyExchangeModesExtension:
		return &utls.PSKKeyExchangeModesExtension{Modes: append([]uint8(nil), ext.Modes...)}
	case *utlsb.UtlsPreSharedKeyExtension:
		// 零值 = 未初始化 ⇒ 被 effectiveExtensions 剔除（见函数注释）。
		return &utls.UtlsPreSharedKeyExtension{}
	case *utlsb.SignatureAlgorithmsCertExtension:
		return &utls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: sigSchemesFromBogdan(ext.SupportedSignatureAlgorithms),
		}
	case *utlsb.KeyShareExtension:
		shares := make([]utls.KeyShare, 0, len(ext.KeyShares))
		for _, ks := range ext.KeyShares {
			shares = append(shares, utls.KeyShare{Group: utls.CurveID(ks.Group), Data: ks.Data})
		}
		return &utls.KeyShareExtension{KeyShares: shares}
	case *utlsb.ApplicationSettingsExtension:
		return &utls.ApplicationSettingsExtension{SupportedProtocols: ext.SupportedProtocols}
	case *utlsb.ApplicationSettingsExtensionNew:
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: ext.SupportedProtocols}
	case *utlsb.QUICTransportParametersExtension:
		return &utls.GenericExtension{Id: 57} // 见函数注释
	case *utlsb.GenericExtension:
		return &utls.GenericExtension{Id: ext.Id, Data: ext.Data}
	}
	return nil // 未知类型：跳过（不让 selfcheck 阻断请求）
}

func sigSchemesFromBogdan(in []utlsb.SignatureScheme) []utls.SignatureScheme {
	out := make([]utls.SignatureScheme, 0, len(in))
	for _, s := range in {
		out = append(out, utls.SignatureScheme(s))
	}
	return out
}
