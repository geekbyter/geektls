// Package profiles 定义 geektls 的 profile JSON schema（docs/03-profile-format.md）。
//
// P1 仅 tls.detail 生效（编译为 ClientHelloSpec，见 core/tls/compile.go）；
// 其余各节解析保留字段，标注 later phases。clienthello_hex/ja3/ja4r
// 三个便捷入口在 P1-T5 落地为 detail 的编译器。
package profiles

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Profile 是一份完整客户端指纹的规范形式。
type Profile struct {
	Name     string           `json:"name"`
	Extends  string           `json:"extends,omitempty"`
	TLS      *TLSProfile      `json:"tls,omitempty"`
	HTTP2    *HTTP2Profile    `json:"http2,omitempty"`    // P2
	HTTP3    *HTTP3Profile    `json:"http3,omitempty"`    // P4
	TCP      *TCPProfile      `json:"tcp,omitempty"`      // P6
	HTTP1    *HTTP1Profile    `json:"http1,omitempty"`    // P3
	Behavior *BehaviorProfile `json:"behavior,omitempty"` // P3
}

// TLSProfile 的三种便捷入口互斥且优先于 Detail（P1-T5 编译为 Detail）。
type TLSProfile struct {
	ClientHelloHex string `json:"clienthello_hex,omitempty"` // P1-T5
	JA3            string `json:"ja3,omitempty"`             // P1-T5
	JA4R           string `json:"ja4r,omitempty"`            // P1-T5

	Detail *Detail `json:"detail,omitempty"`
}

// Detail 是 ClientHello 的逐字段描述（P1-T2 生效）。
type Detail struct {
	LegacyVersion string      `json:"legacy_version,omitempty"` // "0x0303"
	Ciphers       []string    `json:"ciphers,omitempty"`        // hex 串或 "grease"，有序
	Extensions    []Extension `json:"extensions,omitempty"`     // 数组 = 线上顺序

	// ExtensionPermutation 为 true 时 Extensions 是基准顺序，
	// 每次连接做 Chrome 式洗牌（GREASE/padding/PSK 位置不变）。
	ExtensionPermutation bool `json:"extension_permutation,omitempty"`

	// ExtensionsSorted 为 true 表示扩展顺序是 JA4R 排序值而非真实线上顺序
	//（JA4R 有损入口置位；编译照常按给定顺序输出，测试断言时不得当作指纹级保真）。
	ExtensionsSorted bool `json:"extensions_sorted,omitempty"`

	// Grease 控制 ciphers/extensions/groups 三处是否注入 GREASE 占位。
	// 显式写 "grease" 字面量的位置优先于此开关。
	Grease *GreaseControl `json:"grease,omitempty"`

	CertCompression []string `json:"cert_compression,omitempty"`      // "brotli"/"zlib"/"zstd"
	ALPS            bool     `json:"alps,omitempty"`                  // application_settings (17513)
	RecordSizeLimit *uint16  `json:"record_size_limit,omitempty"`     // 扩展 28
	DelegatedCreds  []string `json:"delegated_credentials,omitempty"` // 扩展 34 的 sig_algs 列表
}

// Grease 三处 GREASE 注入开关。
type GreaseControl struct {
	Ciphers    bool `json:"ciphers,omitempty"`
	Extensions bool `json:"extensions,omitempty"`
	Groups     bool `json:"groups,omitempty"`
}

// Extension 是一个 ClientHello 扩展；Type 为扩展号，其余字段按类型取用。
type Extension struct {
	Type uint16 `json:"type"`

	// type 0：SNI。"auto" = 运行时取目标 host。
	SNI string `json:"sni,omitempty"`
	// type 10：supported_groups。元素为组名或 "grease"。
	Groups []string `json:"groups,omitempty"`
	// type 11：ec_point_formats。
	PointFormats []uint8 `json:"point_formats,omitempty"`
	// type 13/34/50：hex 字符串列表，如 "0x0403"。
	SigAlgs []string `json:"sig_algs,omitempty"`
	// type 16 / ALPS：协议列表。
	ALPN []string `json:"alpn,omitempty"`
	// type 21：padding 对齐总长（Chrome 风格 512）。
	PaddingTo int `json:"padding_to,omitempty"`
	// type 27：证书压缩算法名列表（"brotli"/"zlib"/"zstd"）。
	CertCompression []string `json:"cert_compression,omitempty"`
	// type 43：supported_versions，hex 列表，可含 "grease"。
	Versions []string `json:"versions,omitempty"`
	// type 45：psk_key_exchange_modes（如 [1] = psk_dhe_ke）。
	PSKModes []uint8 `json:"psk_modes,omitempty"`
	// type 51：key_share 组名列表，可含 "grease"。
	KeyShares []string `json:"key_shares,omitempty"`
	// type 65037 (0xfe0d)：ECH。
	ECH *ECHConfig `json:"ech,omitempty"`

	// 未识别 type 的透传负载（hex 字符串，经 GenericExtension 发出）。
	Data string `json:"data,omitempty"`
}

// ECHConfig：mode "grease"（随机 GREASE 负载，保真用）或 "real"（真 ECH，
// 需配 config_list_hex=ECHConfigList 序列化 hex，通常来自目标域 DNS HTTPS
// 记录的 ech 参数）。QUIC 侧见 h3.clampSpecForQUIC。
type ECHConfig struct {
	Mode          string `json:"mode"`                      // "grease" / "real"
	ConfigListHex string `json:"config_list_hex,omitempty"` // mode=real 必填
}

// --- 以下各节 P1 只解析不生效 ---

// HTTP2Profile（P2）。
type HTTP2Profile struct {
	Settings          [][]uint32   `json:"settings,omitempty"` // [[id, value],...] 有序；id 可为 GREASE 值
	SettingsGrease    bool         `json:"settings_grease,omitempty"`
	WindowUpdate      uint32       `json:"window_update,omitempty"`       // 连接级 WINDOW_UPDATE 增量
	PseudoHeaderOrder []string     `json:"pseudo_header_order,omitempty"` // 短码 m/a/s/p
	Priorities        []H2Priority `json:"priorities,omitempty"`
	HpackStrategy     string       `json:"hpack_strategy,omitempty"` // 保留，P2 未细分
}

// H2Priority 是一个 priority 帧（03 文档示例的数组形 [[3,true,0,255]] 改为
// 对象形：数组里混布尔无法静态类型化）。
type H2Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	StreamDep uint32 `json:"stream_dep"`
	Weight    uint8  `json:"weight"` // 0-255（线上值 = +1）
}

// HTTP3Profile（P4）。
type HTTP3Profile struct {
	Enabled           bool              `json:"enabled,omitempty"`
	QUICVersion       string            `json:"quic_version,omitempty"` // "0x00000001"
	TransportParams   map[string]uint64 `json:"transport_params,omitempty"`
	InitialLayout     *H3InitialLayout  `json:"initial_layout,omitempty"` // P4-T4 结论：quic-go 不可控，见 capability 文档
	GreaseFrames      bool              `json:"grease_frames,omitempty"`
	Settings          [][]uint32        `json:"settings,omitempty"`
	PseudoHeaderOrder []string          `json:"pseudo_header_order,omitempty"`
	PriorityParam     uint32            `json:"priority_param,omitempty"` // Chrome 的 PRIORITY 帧参数（如 984832）
	H2RaceMs          int               `json:"h2_race_ms,omitempty"`     // H2/H3 竞速：H3 起跑后多少 ms 内无响应头则并发 H2
}

// H3InitialLayout（P4）。
type H3InitialLayout struct {
	Padding  string `json:"padding,omitempty"`
	Coalesce bool   `json:"coalesce,omitempty"`
}

// TCPProfile（P6；平台允许时才生效）。
type TCPProfile struct {
	TTL          int      `json:"ttl,omitempty"`
	MSS          int      `json:"mss,omitempty"`
	WindowSize   int      `json:"window_size,omitempty"`
	WindowScale  int      `json:"window_scale,omitempty"`
	OptionsOrder []string `json:"options_order,omitempty"`
}

// HTTP1Profile（P3）。
type HTTP1Profile struct {
	HeaderOrder []string `json:"header_order,omitempty"`
	HeaderCase  string   `json:"header_case,omitempty"` // "preserve"/"lower"/"title"
}

// BehaviorProfile（P3）。
type BehaviorProfile struct {
	RedirectMax       int  `json:"redirect_max,omitempty"`
	CookieJar         bool `json:"cookie_jar,omitempty"`
	SessionResumption bool `json:"session_resumption,omitempty"`
}

// Parse 解析并校验 profile JSON。返回的 error 是 *ParseError（结构化，不 panic）。
func Parse(data []byte) (*Profile, error) {
	var p Profile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, &ParseError{Field: "", Msg: fmt.Sprintf("malformed JSON: %v", err)}
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseError 是结构化的 profile 校验错误。
type ParseError struct {
	Field string // 出错的字段路径，如 "tls.detail.ciphers[2]"
	Msg   string
}

func (e *ParseError) Error() string {
	if e.Field == "" {
		return e.Msg
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Msg)
}

func (p *Profile) validate() error {
	if p.TLS == nil || p.TLS.Detail == nil {
		return nil
	}
	return p.TLS.Detail.validate()
}

func (d *Detail) validate() error {
	if d.LegacyVersion != "" {
		if _, err := parseHex16(d.LegacyVersion); err != nil {
			return &ParseError{Field: "tls.detail.legacy_version", Msg: err.Error()}
		}
	}
	for i, c := range d.Ciphers {
		if c == GreaseToken {
			continue
		}
		if _, err := parseHex16(c); err != nil {
			return &ParseError{Field: fmt.Sprintf("tls.detail.ciphers[%d]", i), Msg: err.Error()}
		}
	}
	for i, e := range d.Extensions {
		if err := e.validate(); err != nil {
			return &ParseError{Field: fmt.Sprintf("tls.detail.extensions[%d](type=%d)", i, e.Type), Msg: err.Error()}
		}
	}
	for i, a := range d.CertCompression {
		if !knownCertCompression(a) {
			return &ParseError{Field: fmt.Sprintf("tls.detail.cert_compression[%d]", i),
				Msg: fmt.Sprintf("unknown cert compression %q (want brotli/zlib/zstd)", a)}
		}
	}
	return nil
}

func (e *Extension) validate() error {
	hexLists := []struct {
		name string
		vals []string
	}{
		{"sig_algs", e.SigAlgs},
		{"versions", e.Versions},
	}
	for _, l := range hexLists {
		for i, v := range l.vals {
			if v == GreaseToken {
				continue
			}
			if _, err := parseHex16(v); err != nil {
				return fmt.Errorf("%s[%d]: %v", l.name, i, err)
			}
		}
	}
	groupLists := []struct {
		name string
		vals []string
	}{
		{"groups", e.Groups},
		{"key_shares", e.KeyShares},
	}
	for _, l := range groupLists {
		for i, v := range l.vals {
			if v == GreaseToken {
				continue
			}
			if _, ok := NamedGroups[v]; ok {
				continue
			}
			if _, err := parseHex16(v); err != nil {
				return fmt.Errorf("%s[%d]: unknown group %q (want a name in NamedGroups, \"grease\", or 0x hex)", l.name, i, v)
			}
		}
	}
	if e.PaddingTo < 0 || e.PaddingTo > 65535 {
		return fmt.Errorf("padding_to %d out of range", e.PaddingTo)
	}
	for i, a := range e.CertCompression {
		if !knownCertCompression(a) {
			return fmt.Errorf("cert_compression[%d]: unknown algorithm %q", i, a)
		}
	}
	if e.ECH != nil {
		switch e.ECH.Mode {
		case "grease":
		case "real":
			if e.ECH.ConfigListHex == "" {
				return fmt.Errorf("ech.mode \"real\" requires config_list_hex")
			}
			if _, err := ParseHexBytes(e.ECH.ConfigListHex); err != nil {
				return fmt.Errorf("ech.config_list_hex: %v", err)
			}
		default:
			return fmt.Errorf("ech.mode %q unsupported (want \"grease\"/\"real\")", e.ECH.Mode)
		}
	}
	return nil
}

// GreaseToken 是 ciphers/groups/extensions/versions 列表里的 GREASE 字面量。
const GreaseToken = "grease"
