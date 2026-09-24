package tlscore

// CheckProfile：gtls_check_profile 的核心实现（不发包，离线构造 + 自算回读）。
// 放在 tlscore 而非 ffi 包，保证纯 Go 可测（ffi 包需要 cgo）。

import (
	"encoding/json"
	"fmt"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/geektls/core/profiles"
)

// CheckResult 是 gtls_check_profile 的返回载荷。
type CheckResult struct {
	JA3      string             `json:"ja3"`
	JA3Hash  string             `json:"ja3_hash"`
	JA4      string             `json:"ja4"`
	WireLen  int                `json:"wire_len"` // 估算的 ClientHello record 总长（session id 按 32 字节计）
	Warnings []profiles.Warning `json:"warnings"`
}

// CheckProfile 统一处理四种入参：完整 profile JSON、{"ja3"/"ja4r"/"clienthello_hex":...}
// 包装 JSON、裸 JA3 串、裸 JA4R 串。
func CheckProfile(input string) (*CheckResult, error) {
	p, warnings, err := profileFromInput(input)
	if err != nil {
		return nil, err
	}
	if p.TLS == nil || p.TLS.Detail == nil {
		return nil, fmt.Errorf("profile has no tls.detail to compile")
	}
	spec, err := CompileDetail(p.TLS.Detail)
	if err != nil {
		return nil, err
	}

	ja3 := ComputeJA3(spec)
	if warnings == nil {
		warnings = []profiles.Warning{}
	}
	return &CheckResult{
		JA3:      ja3,
		JA3Hash:  JA3Hash(ja3),
		JA4:      ComputeJA4(spec),
		WireLen:  estimateClientHelloLen(spec),
		Warnings: warnings,
	}, nil
}

func profileFromInput(input string) (*profiles.Profile, []profiles.Warning, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, nil, fmt.Errorf("empty input")
	}

	if strings.HasPrefix(s, "{") {
		// 先试便捷入口包装：{"ja3":...} / {"ja4r":...} / {"clienthello_hex":...}
		var probe struct {
			JA3            string `json:"ja3"`
			JA4R           string `json:"ja4r"`
			ClientHelloHex string `json:"clienthello_hex"`
		}
		if err := json.Unmarshal([]byte(s), &probe); err != nil {
			return nil, nil, fmt.Errorf("malformed JSON: %v", err)
		}
		switch {
		case probe.JA3 != "":
			return profiles.FromJA3(probe.JA3)
		case probe.JA4R != "":
			return profiles.FromJA4R(probe.JA4R)
		case probe.ClientHelloHex != "":
			return profiles.FromClientHelloHex(probe.ClientHelloHex)
		}

		// 完整 profile JSON；tls 节内也可带便捷入口。
		p, err := profiles.Parse([]byte(s))
		if err != nil {
			return nil, nil, err
		}
		if p.TLS != nil && p.TLS.Detail == nil {
			switch {
			case p.TLS.JA3 != "":
				return profiles.FromJA3(p.TLS.JA3)
			case p.TLS.JA4R != "":
				return profiles.FromJA4R(p.TLS.JA4R)
			case p.TLS.ClientHelloHex != "":
				return profiles.FromClientHelloHex(p.TLS.ClientHelloHex)
			}
		}
		return p, nil, nil
	}

	// 裸串：JA4R 形如 t13d1516h2_...；JA3 形如 771,4865-...-23-...。
	if isJA4RShape(s) {
		return profiles.FromJA4R(s)
	}
	if isJA3Shape(s) {
		return profiles.FromJA3(s)
	}
	return nil, nil, fmt.Errorf("input is neither profile JSON, JA3, nor JA4R")
}

func isJA4RShape(s string) bool {
	if len(s) < 10 {
		return false
	}
	if s[0] != 't' && s[0] != 'q' && s[0] != 'd' {
		return false
	}
	if s[3] != 'd' && s[3] != 'i' {
		return false
	}
	for _, c := range s[1:3] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return strings.Contains(s, "_")
}

func isJA3Shape(s string) bool {
	if strings.ContainsAny(s, "_ ") {
		return false
	}
	sections := strings.Split(s, ",")
	if len(sections) != 5 {
		return false
	}
	for _, c := range sections[0] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(sections[0]) > 0
}

// estimateClientHelloLen 估算 ClientHello 的 TLS record 总长。
// session id 按 uTLS 默认的 32 字节随机值计；padding 策略按其 functor 对
// 未填充总长求值。这是估算值：真实值以握手时 uTLS 序列化为准。
func estimateClientHelloLen(spec *utls.ClientHelloSpec) int {
	exts, unpadded := effectiveExtensions(spec)
	body := unpadded
	for _, e := range exts {
		if pad, ok := e.(*utls.UtlsPaddingExtension); ok && !pad.WillPad && pad.GetPaddingLen != nil {
			n, _ := pad.GetPaddingLen(unpadded)
			body += 4 + n
			continue
		}
		body += extSpecLen(e)
	}
	return 5 + 4 + body // record 头 + handshake 头
}

// effectiveExtensions 返回线上实际会出现的扩展列表与未填充总长：
// padding 扩展的 WillPad 要到握手时按总长决定，spec 阶段用 functor 对
// 未填充总长求值，不会填充时剔除该扩展（否则自算 JA3/JA4 与线上不一致）。
func effectiveExtensions(spec *utls.ClientHelloSpec) ([]utls.TLSExtension, int) {
	unpadded := clientHelloBaseLen(spec)
	for _, e := range spec.Extensions {
		if _, ok := e.(*utls.UtlsPaddingExtension); ok {
			continue
		}
		unpadded += extSpecLen(e)
	}
	out := make([]utls.TLSExtension, 0, len(spec.Extensions))
	for _, e := range spec.Extensions {
		if pad, ok := e.(*utls.UtlsPaddingExtension); ok && !pad.WillPad {
			if pad.GetPaddingLen == nil {
				continue
			}
			if _, will := pad.GetPaddingLen(unpadded); !will {
				continue
			}
		}
		// 未初始化的 PSK 扩展（无缓存票据）线上省略，不计入指纹
		if psk, ok := e.(*utls.UtlsPreSharedKeyExtension); ok && !psk.IsInitialized() {
			continue
		}
		out = append(out, e)
	}
	return out, unpadded
}

// clientHelloBaseLen 是扩展之前的 ClientHello body 长度
// （legacy_version + random + session_id + ciphers + compression + 扩展总长字段）。
func clientHelloBaseLen(spec *utls.ClientHelloSpec) int {
	return 2 + 32 + // legacy_version + random
		1 + 32 + // session_id（uTLS 默认随机 32 字节）
		2 + 2*len(spec.CipherSuites) +
		1 + len(spec.CompressionMethods) +
		2 // extensions 总长度字段
}

// extSpecLen 是扩展在 spec 阶段的线上长度；key_share 的密钥此时尚未生成，
// 按组的公钥长度补算。
func extSpecLen(e utls.TLSExtension) int {
	if ks, ok := e.(*utls.KeyShareExtension); ok {
		return keyShareExtLen(ks)
	}
	return e.Len()
}

// keyShareExtLen 估算 key_share 扩展长度：spec 阶段密钥未生成（Data 为空），
// 按组的公钥长度补算。
func keyShareExtLen(e *utls.KeyShareExtension) int {
	inner := 0
	for _, ks := range e.KeyShares {
		inner += 4 + keyShareDataLen(ks.Group, len(ks.Data))
	}
	return 4 + 2 + inner
}

func keyShareDataLen(group utls.CurveID, actual int) int {
	if actual > 0 {
		return actual
	}
	switch group {
	case utls.GREASE_PLACEHOLDER:
		return 1
	case utls.X25519:
		return 32
	case utls.X25519MLKEM768:
		return 1184 + 32 // ML-KEM-768 封装钥 + X25519 公钥
	case utls.CurveP256:
		return 65
	case utls.CurveP384:
		return 97
	case utls.CurveP521:
		return 133
	}
	return 0
}
