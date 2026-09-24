package h3

// spec_convert.go：refraction-networking/utls 的 ClientHelloSpec →
// bogdanfinn/utls 的同构类型（QUIC 内层握手用）。
//
// 两 fork 同源，扩展类型同名同字段，逐类型机械转换；未知类型报错（不静默
// 丢指纹内容）。GREASE ECH 因字段类型依赖各自 dicttls 包，统一重建为
// bogdanfinn 的 BoringGREASEECH()（我们编译器本来就只产这个形态）。

import (
	"fmt"

	utlsb "github.com/bogdanfinn/utls"
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
		return utlsb.BoringGREASEECH(), nil
	case *utls.GenericExtension:
		return &utlsb.GenericExtension{Id: ext.Id, Data: ext.Data}, nil
	}
	return nil, fmt.Errorf("unsupported extension type %T", e)
}

func sigSchemes(in []utls.SignatureScheme) []utlsb.SignatureScheme {
	out := make([]utlsb.SignatureScheme, 0, len(in))
	for _, s := range in {
		out = append(out, utlsb.SignatureScheme(s))
	}
	return out
}
