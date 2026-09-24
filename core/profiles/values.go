package profiles

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// parseHex16 解析 "0x1301" 形式的 uint16；要求 0x 前缀，1–4 位十六进制。
func parseHex16(s string) (uint16, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return 0, fmt.Errorf("value %q must be hex with 0x prefix", s)
	}
	v, err := strconv.ParseUint(s[2:], 16, 16)
	if err != nil {
		return 0, fmt.Errorf("value %q is not a valid uint16 hex: %v", s, err)
	}
	return uint16(v), nil
}

// ParseHex16 是 parseHex16 的导出版本，供编译器（core/tls）复用。
func ParseHex16(s string) (uint16, error) { return parseHex16(s) }

func knownCertCompression(name string) bool {
	switch name {
	case "brotli", "zlib", "zstd":
		return true
	}
	return false
}

// NamedGroups 是 supported_groups / key_share 里允许的组名 → IANA 值。
var NamedGroups = map[string]uint16{
	"X25519":         29,
	"X25519MLKEM768": 4588,
	"P-256":          23,
	"secp256r1":      23,
	"P-384":          24,
	"secp384r1":      24,
	"P-521":          25,
	"secp521r1":      25,
	"ffdhe2048":      256,
	"ffdhe3072":      257,
}

// ParseHexBytes 解析可选 0x 前缀的 hex 串（config_list 场景允许空格）。
func ParseHexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}
