package tlscore

// 自算 JA3/JA4 回读器（P1-T6）。只算这两个指纹（BSD 许可范围，00 文档 §7）；
// JA4H/JA4T 等 JA4+ 方法不做。
//
// JA4 规则按 FoxIO 官方技术文档（docs 引用：ja4/technical_details/JA4.md）：
// GREASE 全剔除；扩展计数含 SNI/ALPN；扩展 hash 列表剔除 SNI(0000)/ALPN(0010)；
// sig_algs 按原始顺序接在排序扩展列表后，无 sig_algs 则不带下划线。

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ja3LegacyVersion uTLS 线上 legacy_version 恒为 0x0303（TLS 1.3 时代的兼容值），
// ClientHelloSpec 不携带该字段，JA3 第一段按此常量计算。
const ja3LegacyVersion = 771

// ComputeJA3 返回 JA3 full string（version,ciphers-extensions-groups-points，
// 十进制破折号连接，GREASE 剔除）。md5 由 JA3Hash 计算。
func ComputeJA3(spec *utls.ClientHelloSpec) string {
	ciphers := make([]string, 0, len(spec.CipherSuites))
	for _, c := range spec.CipherSuites {
		if isGreaseUint16(c) {
			continue
		}
		ciphers = append(ciphers, fmt.Sprintf("%d", c))
	}

	var exts, groups, points []string
	effExts, _ := effectiveExtensions(spec)
	for _, e := range effExts {
		id, ok := extensionTypeID(e)
		if !ok || isGreaseUint16(id) {
			continue
		}
		exts = append(exts, fmt.Sprintf("%d", id))
		switch ext := e.(type) {
		case *utls.SupportedCurvesExtension:
			for _, g := range ext.Curves {
				if !isGreaseUint16(uint16(g)) {
					groups = append(groups, fmt.Sprintf("%d", g))
				}
			}
		case *utls.SupportedPointsExtension:
			for _, p := range ext.SupportedPoints {
				points = append(points, fmt.Sprintf("%d", p))
			}
		}
	}

	return strings.Join([]string{
		fmt.Sprintf("%d", ja3LegacyVersion),
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(groups, "-"),
		strings.Join(points, "-"),
	}, ",")
}

// JA3Hash 计算 JA3 full string 的 MD5（hex 小写）。
func JA3Hash(ja3 string) string {
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

// ComputeJA4 返回 FoxIO JA4 指纹（TCP 变体，首字符 "t"）。
func ComputeJA4(spec *utls.ClientHelloSpec) string {
	return computeJA4(spec, "t")
}

// ComputeJA4QUIC 返回 QUIC 变体（首字符 "q"）——QUIC 内层 ClientHello 用。
func ComputeJA4QUIC(spec *utls.ClientHelloSpec) string {
	return computeJA4(spec, "q")
}

func computeJA4(spec *utls.ClientHelloSpec, protoFlag string) string {
	var (
		ciphers    []uint16
		extIDs     []uint16
		sigAlgs    []uint16
		sniPresent bool
		alpnCode   = "00"
		maxVersion uint16
		hasVersion bool
	)

	for _, c := range spec.CipherSuites {
		if !isGreaseUint16(c) {
			ciphers = append(ciphers, c)
		}
	}
	effExts, _ := effectiveExtensions(spec)
	for _, e := range effExts {
		id, ok := extensionTypeID(e)
		if !ok || isGreaseUint16(id) {
			continue
		}
		extIDs = append(extIDs, id)
		switch ext := e.(type) {
		case *utls.SNIExtension:
			// 扩展存在即记 d：SNI "auto" 在 check 时未解析为具体 host，
			// 但 profile 的意图是域名（空 ServerName 在线上省略的场景由 engine 保证不发生）。
			sniPresent = true
		case *utls.ALPNExtension:
			alpnCode = ja4ALPNCode(ext.AlpnProtocols)
		case *utls.SignatureAlgorithmsExtension:
			for _, s := range ext.SupportedSignatureAlgorithms {
				if !isGreaseUint16(uint16(s)) {
					sigAlgs = append(sigAlgs, uint16(s))
				}
			}
		case *utls.SupportedVersionsExtension:
			for _, v := range ext.Versions {
				if !isGreaseUint16(v) && (!hasVersion || v > maxVersion) {
					maxVersion, hasVersion = v, true
				}
			}
		}
	}
	if !hasVersion {
		maxVersion = 0x0303 // 无 supported_versions 时按 legacy_version（uTLS 恒 0x0303）
	}

	sniFlag := "i"
	if sniPresent {
		sniFlag = "d"
	}
	a := fmt.Sprintf("%s%s%s%02d%02d%s",
		protoFlag, ja4VersionCode(maxVersion), sniFlag, minInt(len(ciphers), 99), minInt(len(extIDs), 99), alpnCode)

	return a + "_" + ja4CipherHash(ciphers) + "_" + ja4ExtensionHash(extIDs, sigAlgs)
}

func ja4VersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// ja4ALPNCode 取首个 ALPN 值的首末字符；非 ASCII 字母数字时取 hex 表示的首末字符。
func ja4ALPNCode(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(p))
	return h[:1] + h[len(h)-1:]
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

// HashJA4R 把 JA4 raw 指纹（排序后的明文段）折算为标准 JA4（hash 段）。
// JA4R: a_<ciphers_sorted>_<extensions_sorted>_<sigalgs>；
// JA4:  a_sha256(ciphers)[:12]_sha256(extensions[_sigalgs])[:12]。
func HashJA4R(ja4r string) (string, error) {
	sections := strings.Split(strings.TrimSpace(ja4r), "_")
	if len(sections) != 4 {
		return "", fmt.Errorf("ja4r: want 4 sections, got %d", len(sections))
	}
	b := "000000000000"
	if sections[1] != "" {
		b = sha256Trunc12(sections[1])
	}
	c := "000000000000"
	if sections[2] != "" {
		s := sections[2]
		if sections[3] != "" {
			s += "_" + sections[3]
		}
		c = sha256Trunc12(s)
	}
	return sections[0] + "_" + b + "_" + c, nil
}

// ja4CipherHash 排序后 cipher 列表 csv 的 sha256 前 12 字符；空列表为全零。
func ja4CipherHash(ciphers []uint16) string {
	if len(ciphers) == 0 {
		return "000000000000"
	}
	hexes := make([]string, 0, len(ciphers))
	for _, c := range ciphers {
		hexes = append(hexes, fmt.Sprintf("%04x", c))
	}
	sort.Strings(hexes)
	return sha256Trunc12(strings.Join(hexes, ","))
}

// ja4ExtensionHash 排序扩展列表（剔除 SNI/ALPN）+ 原始序 sig_algs 的 sha256 前 12 字符。
func ja4ExtensionHash(extIDs, sigAlgs []uint16) string {
	hexes := make([]string, 0, len(extIDs))
	for _, id := range extIDs {
		if id == 0 || id == 16 { // SNI/ALPN 已在 a 段捕获
			continue
		}
		hexes = append(hexes, fmt.Sprintf("%04x", id))
	}
	if len(hexes) == 0 {
		return "000000000000"
	}
	sort.Strings(hexes)
	s := strings.Join(hexes, ",")
	if len(sigAlgs) > 0 {
		algs := make([]string, 0, len(sigAlgs))
		for _, a := range sigAlgs {
			algs = append(algs, fmt.Sprintf("%04x", a))
		}
		s += "_" + strings.Join(algs, ",")
	}
	return sha256Trunc12(s)
}

func sha256Trunc12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extensionTypeID 在 spec 层取扩展的线上 type（不能依赖 Read：SNI 空名、
// padding 未武装时 Len==0）。未知类型返回 ok=false，调用方按剔除处理。
func extensionTypeID(e utls.TLSExtension) (uint16, bool) {
	switch ext := e.(type) {
	case *utls.SNIExtension:
		return 0, true
	case *utls.StatusRequestExtension:
		return 5, true
	case *utls.SupportedCurvesExtension:
		return 10, true
	case *utls.SupportedPointsExtension:
		return 11, true
	case *utls.SignatureAlgorithmsExtension:
		return 13, true
	case *utls.ALPNExtension:
		return 16, true
	case *utls.SCTExtension:
		return 18, true
	case *utls.UtlsPaddingExtension:
		return 21, true
	case *utls.ExtendedMasterSecretExtension:
		return 23, true
	case *utls.UtlsCompressCertExtension:
		return 27, true
	case *utls.FakeRecordSizeLimitExtension:
		return 28, true
	case *utls.FakeDelegatedCredentialsExtension:
		return 34, true
	case *utls.SessionTicketExtension:
		return 35, true
	case *utls.SupportedVersionsExtension:
		return 43, true
	case *utls.PSKKeyExchangeModesExtension:
		return 45, true
	case *utls.UtlsPreSharedKeyExtension:
		return 41, true
	case *utls.SignatureAlgorithmsCertExtension:
		return 50, true
	case *utls.KeyShareExtension:
		return 51, true
	case *utls.ApplicationSettingsExtension:
		return 17513, true
	case *utls.ApplicationSettingsExtensionNew:
		return 17613, true
	case *utls.GREASEEncryptedClientHelloExtension:
		return 65037, true
	case *utls.UtlsGREASEExtension:
		return ext.Value, true
	case *utls.GenericExtension:
		return ext.Id, true
	}
	return 0, false
}
