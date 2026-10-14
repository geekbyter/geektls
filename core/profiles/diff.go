package profiles

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// DiffClientHellos 对比两份 ClientHello record（hex，含 5 字节 record 头），返回
// 人类可读的差异列表（空 = 归一化后一致）。用于"抓包复刻是否保真"的对拍：
//
//   - 随机项在比较前掩码：GREASE 的 cipher/扩展值（每次连接本就重取）；
//   - 扩展**长度**逐项对齐（ECH / padding 这类"长度即特征"的差异不会漏掉，
//     即便语义字段相同）；
//   - 结构按语义字段比较：cipher 序、扩展序、SNI / groups / ALPN / versions /
//     key_share 组 / sig_algs / padding / cert_compression / 未知扩展透传载荷。
//
// 刻意不做的事：不比对 client_random / session_id / key_share 公钥 / ECH 随机载荷
// 的字节值（真浏览器每次连接都不同），也不解释未知扩展的载荷语义（只比对字节）。
func DiffClientHellos(aHex, bHex string) ([]string, error) {
	pa, _, err := FromClientHelloHex(aHex)
	if err != nil {
		return nil, fmt.Errorf("a: %w", err)
	}
	pb, _, err := FromClientHelloHex(bHex)
	if err != nil {
		return nil, fmt.Errorf("b: %w", err)
	}
	if pa.TLS == nil || pa.TLS.Detail == nil || pb.TLS == nil || pb.TLS.Detail == nil {
		return nil, fmt.Errorf("解析结果缺 tls.detail")
	}
	la, err := rawExtLens(aHex)
	if err != nil {
		return nil, fmt.Errorf("a: %w", err)
	}
	lb, err := rawExtLens(bHex)
	if err != nil {
		return nil, fmt.Errorf("b: %w", err)
	}

	var diffs []string
	da, db := pa.TLS.Detail, pb.TLS.Detail
	if da.LegacyVersion != db.LegacyVersion {
		diffs = append(diffs, fmt.Sprintf("legacy_version: %s vs %s", da.LegacyVersion, db.LegacyVersion))
	}
	if len(da.Ciphers) != len(db.Ciphers) {
		diffs = append(diffs, fmt.Sprintf("ciphers 数量: %d vs %d", len(da.Ciphers), len(db.Ciphers)))
	}
	for i := 0; i < min2(len(da.Ciphers), len(db.Ciphers)); i++ {
		ca, cb := maskCipher(da.Ciphers[i]), maskCipher(db.Ciphers[i])
		if ca != cb {
			diffs = append(diffs, fmt.Sprintf("cipher[%d]: %s vs %s", i, ca, cb))
		}
	}
	if len(da.Extensions) != len(db.Extensions) {
		diffs = append(diffs, fmt.Sprintf("扩展数量: %d vs %d", len(da.Extensions), len(db.Extensions)))
	}
	for i := 0; i < min2(len(da.Extensions), len(db.Extensions)); i++ {
		ea, eb := da.Extensions[i], db.Extensions[i]
		ta, tb := maskExtType(ea.Type), maskExtType(eb.Type)
		if ta != tb {
			diffs = append(diffs, fmt.Sprintf("ext[%d] 类型: %s vs %s", i, ta, tb))
			continue
		}
		if i < len(la) && i < len(lb) && la[i] != lb[i] {
			diffs = append(diffs, fmt.Sprintf("ext[%d](%s) 长度: %d vs %d", i, ta, la[i], lb[i]))
		}
		if s := diffExtension(ea, eb); s != "" {
			diffs = append(diffs, fmt.Sprintf("ext[%d](%s): %s", i, ta, s))
		}
	}
	return diffs, nil
}

// rawExtLens 取每个扩展的**线上载荷长度**（按出现顺序）——纯字节解析，不依赖
// 语义字段，用于捕捉"语义相同但长度不同"的形态差异。
func rawExtLens(hexStr string) ([]uint16, error) {
	raw, err := hex.DecodeString(strings.NewReplacer(
		" ", "", "0x", "", "0X", "", "\n", "", "\t", "").Replace(hexStr))
	if err != nil || len(raw) < 9 {
		return nil, fmt.Errorf("hex 无法解析")
	}
	body := raw[9:] // record(5) + handshake 头(4)
	if len(body) < 2+32+1 {
		return nil, fmt.Errorf("ClientHello 过短")
	}
	off := 2 + 32
	sidLen := int(body[off])
	off += 1 + sidLen
	if off+2 > len(body) {
		return nil, fmt.Errorf("ClientHello 截断")
	}
	csLen := int(body[off])<<8 | int(body[off+1])
	off += 2 + csLen
	if off+1 > len(body) {
		return nil, fmt.Errorf("ClientHello 截断")
	}
	compLen := int(body[off])
	off += 1 + compLen
	if off+2 > len(body) {
		return nil, fmt.Errorf("ClientHello 截断")
	}
	extTotal := int(body[off])<<8 | int(body[off+1])
	off += 2
	end := off + extTotal
	if end > len(body) {
		end = len(body)
	}
	var lens []uint16
	for off+4 <= end {
		l := int(body[off+2])<<8 | int(body[off+3])
		off += 4
		lens = append(lens, uint16(l))
		off += l
	}
	return lens, nil
}

// maskCipher 把 GREASE cipher 值掩码为 "GREASE"（值每次连接重取，不参与对拍）。
func maskCipher(s string) string {
	if v, ok := parseSpecHex16(s); ok && isGreaseVal(v) {
		return "GREASE"
	}
	if strings.EqualFold(strings.TrimSpace(s), "grease") {
		return "GREASE"
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// maskExtType 把 GREASE 扩展类型掩码为 "GREASE"。
func maskExtType(t0 uint16) string {
	if isGreaseVal(t0) {
		return "GREASE"
	}
	return fmt.Sprintf("0x%04x", t0)
}

// diffExtension 逐字段比较两个扩展的语义载荷；无差异返回 ""。
func diffExtension(a, b Extension) string {
	switch {
	case a.SNI != b.SNI:
		return fmt.Sprintf("sni %q vs %q", a.SNI, b.SNI)
	case !eqStrSlice(a.Groups, b.Groups):
		return fmt.Sprintf("groups %v vs %v", a.Groups, b.Groups)
	case !eqU8Slice(a.PointFormats, b.PointFormats):
		return fmt.Sprintf("points %v vs %v", a.PointFormats, b.PointFormats)
	case !eqStrSlice(a.SigAlgs, b.SigAlgs):
		return fmt.Sprintf("sig_algs %v vs %v", a.SigAlgs, b.SigAlgs)
	case !eqStrSlice(a.ALPN, b.ALPN):
		return fmt.Sprintf("alpn %v vs %v", a.ALPN, b.ALPN)
	case a.PaddingTo != b.PaddingTo || a.PaddingLen != b.PaddingLen:
		return fmt.Sprintf("padding to=%d len=%d vs to=%d len=%d", a.PaddingTo, a.PaddingLen, b.PaddingTo, b.PaddingLen)
	case !eqStrSlice(a.CertCompression, b.CertCompression):
		return fmt.Sprintf("cert_compression %v vs %v", a.CertCompression, b.CertCompression)
	case !eqStrSlice(a.Versions, b.Versions):
		return fmt.Sprintf("versions %v vs %v", a.Versions, b.Versions)
	case !eqU8Slice(a.PSKModes, b.PSKModes):
		return fmt.Sprintf("psk_modes %v vs %v", a.PSKModes, b.PSKModes)
	case !eqStrSlice(a.KeyShares, b.KeyShares):
		return fmt.Sprintf("key_share 组 %v vs %v", a.KeyShares, b.KeyShares)
	case echMode(a) != echMode(b):
		return fmt.Sprintf("ech mode %q vs %q", echMode(a), echMode(b))
	case a.GreaseRandom != b.GreaseRandom:
		return fmt.Sprintf("grease_random %v vs %v", a.GreaseRandom, b.GreaseRandom)
	case a.Data != b.Data:
		return fmt.Sprintf("data %s vs %s", shortHex(a.Data), shortHex(b.Data))
	}
	return ""
}

func echMode(e Extension) string {
	if e.ECH == nil {
		return ""
	}
	return e.ECH.Mode
}

func shortHex(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "…"
}

func eqStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func eqU8Slice(a, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
