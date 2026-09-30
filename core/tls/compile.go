package tlscore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	mrand "math/rand"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/geekbyter/geektls/core/profiles"
)

// CompileDetail 把 profile 的 tls.detail 编译为 utls.ClientHelloSpec。
// 扩展严格按 detail.Extensions 数组顺序输出；ExtensionPermutation 为 true 时
// 用随机种子洗牌（Chrome 式：GREASE/padding/PSK 位置不变）。
//
// 便捷字段（detail 级的 cert_compression/alps/record_size_limit/
// delegated_credentials）只在 Extensions 数组缺少对应扩展类型时生效，
// 编译产物追加到扩展列表末尾——顺序敏感场景应直接写 Extensions 数组。
func CompileDetail(d *profiles.Detail) (*utls.ClientHelloSpec, error) {
	rng, err := cryptoSeededRand()
	if err != nil {
		return nil, err
	}
	return CompileDetailSeeded(d, rng)
}

// CompileDetailSeeded 同 CompileDetail，但洗牌用注入的 rng（测试确定性）。
func CompileDetailSeeded(d *profiles.Detail, rng *mrand.Rand) (*utls.ClientHelloSpec, error) {
	if d == nil {
		return nil, fmt.Errorf("compile: detail is nil")
	}

	spec := &utls.ClientHelloSpec{
		CompressionMethods: []uint8{0}, // null compression（浏览器默认）
	}

	// --- ciphers ---
	for i, c := range d.Ciphers {
		v, err := compileUint16Token(c)
		if err != nil {
			return nil, fmt.Errorf("compile: ciphers[%d]: %w", i, err)
		}
		spec.CipherSuites = append(spec.CipherSuites, v)
	}
	if d.Grease != nil && d.Grease.Ciphers && !hasGreaseCipher(spec.CipherSuites) {
		spec.CipherSuites = append([]uint16{utls.GREASE_PLACEHOLDER}, spec.CipherSuites...)
	}

	// --- extensions（严格保序） ---
	seen := map[uint16]bool{}
	for i := range d.Extensions {
		ext, err := compileExtension(&d.Extensions[i], rng)
		if err != nil {
			return nil, fmt.Errorf("compile: extensions[%d] (type=%d): %w", i, d.Extensions[i].Type, err)
		}
		spec.Extensions = append(spec.Extensions, ext)
		seen[d.Extensions[i].Type] = true
	}
	if err := appendConvenienceExtensions(d, spec, seen, rng); err != nil {
		return nil, err
	}
	if d.Grease != nil && d.Grease.Extensions && !hasGreaseExtension(spec.Extensions) {
		// Value 必须给随机 GREASE 值：uTLS 的 UtlsGREASEExtension.Read 把 Value
		// 原样写出，零值会被写成扩展 type 0（= SNI），必须避免。
		spec.Extensions = append([]utls.TLSExtension{&utls.UtlsGREASEExtension{Value: randomGrease(rng)}}, spec.Extensions...)
	}

	if d.ExtensionPermutation {
		shuffleExtensions(spec.Extensions, rng)
	}
	return spec, nil
}

// compileUint16Token 解析 "0x1301" 或 "grease" 占位。
// 字面 GREASE 值（0x?a?a）在 ciphers/groups/versions/key_share 上按 P1-T3 语义
// 原样透传（用户可指定确切 GREASE 值）——这些字段由 uTLS 在握手期把
// GREASE_PLACEHOLDER 换成随机值。
// **例外**：sig_algs 与扩展 type 的 GREASE 值一律在编译期重取（见 randomGrease），
// 因为 uTLS 对这两处不做握手期替换，钉死值会退化成常量特征。
func compileUint16Token(s string) (uint16, error) {
	if s == profiles.GreaseToken {
		return utls.GREASE_PLACEHOLDER, nil
	}
	return profiles.ParseHex16(s)
}

// randomGrease 取一个随机 GREASE 值（RFC 8701：0x?a?a，共 16 个候选）。
//
// 为什么要在编译期自己取值：实测（grease_rerandomize_test.go）uTLS 只在
// ciphers / curves / supported_versions / key_share 四处于握手期替换
// GREASE_PLACEHOLDER，signature_algorithms 与扩展 type 是**原样写出**的。
// CompileDetail 每次拨号调用一次，因此这里取值即等价于"逐连接重随机化"。
func randomGrease(rng *mrand.Rand) uint16 {
	return uint16(0x0a0a + 0x1010*rng.Intn(16))
}

func hasGreaseCipher(ciphers []uint16) bool {
	for _, c := range ciphers {
		if c == utls.GREASE_PLACEHOLDER {
			return true
		}
	}
	return false
}

func hasGreaseExtension(exts []utls.TLSExtension) bool {
	for _, e := range exts {
		if _, ok := e.(*utls.UtlsGREASEExtension); ok {
			return true
		}
	}
	return false
}

// shuffleExtensions 做 Chrome 式洗牌：GREASE/padding/pre_shared_key 位置不变
// （与 utls.ShuffleChromeTLSExtensions 同策略，但 rng 可注入，保证测试确定性）。
func shuffleExtensions(exts []utls.TLSExtension, rng *mrand.Rand) {
	skip := func(e utls.TLSExtension) bool {
		switch e.(type) {
		case *utls.UtlsGREASEExtension, *utls.UtlsPaddingExtension, *utls.UtlsPreSharedKeyExtension:
			return true
		}
		return false
	}
	rng.Shuffle(len(exts), func(i, j int) {
		if skip(exts[i]) || skip(exts[j]) {
			return
		}
		exts[i], exts[j] = exts[j], exts[i]
	})
}

func cryptoSeededRand() (*mrand.Rand, error) {
	seed, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, fmt.Errorf("compile: seed rng: %w", err)
	}
	return mrand.New(mrand.NewSource(seed.Int64())), nil
}

// appendConvenienceExtensions 把 detail 级便捷字段编译为扩展并追加，
// 跳过数组里已出现的类型。
func appendConvenienceExtensions(d *profiles.Detail, spec *utls.ClientHelloSpec, seen map[uint16]bool, rng *mrand.Rand) error {
	if len(d.CertCompression) > 0 && !seen[27] {
		algos, err := certCompressionAlgos(d.CertCompression)
		if err != nil {
			return fmt.Errorf("compile: cert_compression: %w", err)
		}
		spec.Extensions = append(spec.Extensions, &utls.UtlsCompressCertExtension{Algorithms: algos})
	}
	if d.ALPS && !seen[17513] {
		spec.Extensions = append(spec.Extensions, &utls.ApplicationSettingsExtension{
			SupportedProtocols: []string{"h2"},
		})
	}
	if d.RecordSizeLimit != nil && !seen[28] {
		spec.Extensions = append(spec.Extensions, &utls.FakeRecordSizeLimitExtension{Limit: *d.RecordSizeLimit})
	}
	if len(d.DelegatedCreds) > 0 && !seen[34] {
		schemes, err := sigSchemes(d.DelegatedCreds, rng)
		if err != nil {
			return fmt.Errorf("compile: delegated_credentials: %w", err)
		}
		spec.Extensions = append(spec.Extensions, &utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: schemes})
	}
	return nil
}

// compileExtension 按扩展号映射到 uTLS 的 TLSExtension 实现；
// 未识别类型用 GenericExtension 透传 data（hex）。
func compileExtension(e *profiles.Extension, rng *mrand.Rand) (utls.TLSExtension, error) {
	switch e.Type {
	case 0: // server_name
		// "auto" 是运行时占位：engine 层握手前必须填入实际 host
		// （空 ServerName 的 SNIExtension 会被 uTLS 在线上省略，见 Len/Read 语义）。
		sni := e.SNI
		if sni == "auto" {
			sni = ""
		}
		return &utls.SNIExtension{ServerName: sni}, nil
	case 5:
		return &utls.StatusRequestExtension{}, nil
	case 10: // supported_groups
		curves := make([]utls.CurveID, 0, len(e.Groups))
		for i, g := range e.Groups {
			c, err := groupToken(g)
			if err != nil {
				return nil, fmt.Errorf("groups[%d]: %w", i, err)
			}
			curves = append(curves, c)
		}
		return &utls.SupportedCurvesExtension{Curves: curves}, nil
	case 11: // ec_point_formats
		return &utls.SupportedPointsExtension{SupportedPoints: e.PointFormats}, nil
	case 13: // signature_algorithms
		schemes, err := sigSchemes(e.SigAlgs, rng)
		if err != nil {
			return nil, err
		}
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: schemes}, nil
	case 16: // ALPN
		return &utls.ALPNExtension{AlpnProtocols: e.ALPN}, nil
	case 18: // SCT
		return &utls.SCTExtension{}, nil
	case 21: // padding
		// hex 回放路径：data 非空时原样保留 padding 字节，不套 padding_to 策略。
		if e.Data != "" {
			data, err := hexBytes(e.Data)
			if err != nil {
				return nil, err
			}
			return &utls.GenericExtension{Id: 21, Data: data}, nil
		}
		// 实测填充长度（Safari 抓包给的字节数）：按该长度写全零负载。
		if e.PaddingLen > 0 {
			return &utls.GenericExtension{Id: 21, Data: make([]byte, e.PaddingLen)}, nil
		}
		// JA3/JA4R 有损入口的裸 21（无 padding_to）：策略不可知，
		// 以"存在但零负载"形式保留（GenericExtension），保住 JA3/JA4 往返一致。
		if e.PaddingTo == 0 {
			return &utls.GenericExtension{Id: 21}, nil
		}
		return &utls.UtlsPaddingExtension{GetPaddingLen: paddingAligner(e.PaddingTo)}, nil
	case 23: // extended_master_secret
		return &utls.ExtendedMasterSecretExtension{}, nil
	case 27: // compress_certificate
		algos, err := certCompressionAlgos(e.CertCompression)
		if err != nil {
			return nil, err
		}
		return &utls.UtlsCompressCertExtension{Algorithms: algos}, nil
	case 28: // record_size_limit
		data, err := hexBytes(e.Data)
		if err != nil {
			return nil, err
		}
		if len(data) == 2 {
			return &utls.FakeRecordSizeLimitExtension{Limit: uint16(data[0])<<8 | uint16(data[1])}, nil
		}
		return nil, fmt.Errorf("record_size_limit wants 2-byte hex data, got %d bytes", len(data))
	case 34: // delegated_credentials
		schemes, err := sigSchemes(e.SigAlgs, rng)
		if err != nil {
			return nil, err
		}
		return &utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: schemes}, nil
	case 35: // session_ticket（注意：IANA 上 23 = extended_master_secret）
		return &utls.SessionTicketExtension{}, nil
	case 43: // supported_versions
		versions := make([]uint16, 0, len(e.Versions))
		for i, v := range e.Versions {
			n, err := compileUint16Token(v)
			if err != nil {
				return nil, fmt.Errorf("versions[%d]: %w", i, err)
			}
			versions = append(versions, n)
		}
		return &utls.SupportedVersionsExtension{Versions: versions}, nil
	case 45: // psk_key_exchange_modes
		return &utls.PSKKeyExchangeModesExtension{Modes: e.PSKModes}, nil
	case 41: // pre_shared_key
		// 空占位：无票据时 Len()==0 线上省略；有缓存票据时 uTLS 在握手时填充。
		// 会话复用要求 spec 里显式带它（否则 uTLS initPskExt 会 panic）。
		return &utls.UtlsPreSharedKeyExtension{}, nil
	case 50: // signature_algorithms_cert
		schemes, err := sigSchemes(e.SigAlgs, rng)
		if err != nil {
			return nil, err
		}
		return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: schemes}, nil
	case 51: // key_share
		shares := make([]utls.KeyShare, 0, len(e.KeyShares))
		for i, ks := range e.KeyShares {
			g, err := groupToken(ks)
			if err != nil {
				return nil, fmt.Errorf("key_shares[%d]: %w", i, err)
			}
			// Data 留空：uTLS 握手时生成；GREASE 位按 uTLS 约定给单字节 0。
			// 注意：除了占位符本身，hex 回放带入的**字面 GREASE 组**（如 0x6a6a）
			// 也必须给哑数据——否则 uTLS 会按真实曲线生成密钥失败，key_share 列表
			// 残缺，服务端 HRR/decode 失败（corpus 对拍 chrome_137-143/safari 实证）。
			share := utls.KeyShare{Group: g}
			if g == utls.GREASE_PLACEHOLDER || isGreaseUint16(uint16(g)) {
				share.Data = []byte{0}
			}
			shares = append(shares, share)
		}
		return &utls.KeyShareExtension{KeyShares: shares}, nil
	case 17513: // application_settings (ALPS，旧 codepoint；Chrome ≤131)
		protos := e.ALPN
		if len(protos) == 0 {
			protos = []string{"h2"}
		}
		return &utls.ApplicationSettingsExtension{SupportedProtocols: protos}, nil
	case 17613: // application_settings 新 codepoint（Chrome 133+）
		protos := e.ALPN
		if len(protos) == 0 {
			protos = []string{"h2"}
		}
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: protos}, nil
	case 65037: // encrypted_client_hello (0xfe0d)
		// hex 回放路径：data 非空时原样透传（ECH 负载不透明，不可复用也需保字节）。
		if e.Data != "" {
			data, err := hexBytes(e.Data)
			if err != nil {
				return nil, err
			}
			return &utls.GenericExtension{Id: e.Type, Data: data}, nil
		}
		if e.ECH == nil {
			return nil, fmt.Errorf("ech config is required for extension 65037")
		}
		switch e.ECH.Mode {
		case "grease":
			return utls.BoringGREASEECH(), nil
		case "real":
			// 真 ECH：扩展槽仍是 BoringGREASEECH 形态——config 里注入
			// EncryptedClientHelloConfigList 后 uTLS 会在 marshal 时把它
			// 换成真正的加密负载（engine 层负责注入，见 dial.go）。
			return utls.BoringGREASEECH(), nil
		default:
			return nil, fmt.Errorf("ech.mode %q unsupported in P1 (only \"grease\")", e.ECH.Mode)
		}
	default:
		// type 本身是 GREASE 值（0x?a?a）→ GREASE 扩展占位。
		if isGreaseUint16(e.Type) {
			body, err := hexBytes(e.Data)
			if err != nil {
				return nil, err
			}
			// GreaseRandom=true：线上 type 每连接重取随机 GREASE 值（真浏览器行为，G12）。
			// 默认 false：字面 GREASE 值按 P1-T3 原样透传（用户可钉死确切值），
			// 该语义由 TestGreaseAllRFC8701Values 钉住。
			// body 语义不变：Chrome 首个 GREASE 扩展空 body，第二个带 1 字节 0x00。
			id := e.Type
			if e.GreaseRandom {
				id = randomGrease(rng)
			}
			return &utls.UtlsGREASEExtension{Value: id, Body: body}, nil
		}
		// 未识别类型：GenericExtension 透传 data。
		data, err := hexBytes(e.Data)
		if err != nil {
			return nil, err
		}
		return &utls.GenericExtension{Id: e.Type, Data: data}, nil
	}
}

// isGreaseUint16 判断 RFC 8701 GREASE 值（0x?a?a，两字节相同且低半字节为 0xa）。
func isGreaseUint16(v uint16) bool {
	return v>>8 == v&0xff && v&0xf == 0xa
}

// groupToken 解析组名（"X25519"）/"grease"/"0x" hex 为 CurveID。
// 字面 GREASE 值（如 hex 回放带入的 "0x6a6a"）按 P1-T3 语义原样返回；
// key_share 的哑数据补齐在编译 KeyShareExtension 时按组值处理（见 case 51）。
func groupToken(s string) (utls.CurveID, error) {
	if s == profiles.GreaseToken {
		return utls.CurveID(utls.GREASE_PLACEHOLDER), nil
	}
	if v, ok := profiles.NamedGroups[s]; ok {
		return utls.CurveID(v), nil
	}
	if v, err := profiles.ParseHex16(s); err == nil {
		return utls.CurveID(v), nil
	}
	return 0, fmt.Errorf("unknown group %q", s)
}

func sigSchemes(hexes []string, rng *mrand.Rand) ([]utls.SignatureScheme, error) {
	schemes := make([]utls.SignatureScheme, 0, len(hexes))
	for i, h := range hexes {
		v, err := compileUint16Token(h)
		if err != nil {
			return nil, fmt.Errorf("sig_algs[%d]: %w", i, err)
		}
		// GREASE 位（"grease" 或字面 0x?a?a）在编译期取随机值：uTLS 不对
		// signature_algorithms 做握手期占位符替换（实测恒为 0x0a0a），
		// 照搬占位符会退化成常量特征。
		if isGreaseUint16(v) {
			schemes = append(schemes, utls.SignatureScheme(randomGrease(rng)))
			continue
		}
		schemes = append(schemes, utls.SignatureScheme(v))
	}
	return schemes, nil
}

func certCompressionAlgos(names []string) ([]utls.CertCompressionAlgo, error) {
	algos := make([]utls.CertCompressionAlgo, 0, len(names))
	for _, n := range names {
		switch n {
		case "brotli":
			algos = append(algos, utls.CertCompressionBrotli)
		case "zlib":
			algos = append(algos, utls.CertCompressionZlib)
		case "zstd":
			algos = append(algos, utls.CertCompressionZstd)
		default:
			return nil, fmt.Errorf("unknown cert compression %q", n)
		}
	}
	return algos, nil
}

// hexBytes 解析 hex 字符串（可带 0x 前缀，可为空）。
func hexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex data: %v", err)
	}
	return b, nil
}

// paddingAligner 生成"总长对齐到 to"的 padding 策略（BoringSSL 风格：
// 仅当未填充长度 >255 且 < to 时填充；to=512 即 Chrome 行为）。
func paddingAligner(to int) func(clientHelloUnpaddedLen int) (int, bool) {
	return func(unpadded int) (int, bool) {
		if to <= 4 || unpadded <= 0xff || unpadded >= to {
			return 0, false
		}
		pad := to - unpadded
		if pad >= 4+1 {
			pad -= 4 // 扩展头自身 4 字节
		} else {
			pad = 1
		}
		return pad, true
	}
}
