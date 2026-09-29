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
	Identity *IdentityProfile `json:"identity,omitempty"` // T2-1

	// Grade / Source 是**证据等级**与其出处（第三方导入用）。
	//
	// 约定：**留空 = 本项目自测**（E1 真机抓包 / E1r 字段级实测 / E2 本机可复现）；
	// "E3" = 第三方配置集导入，**未经我们实测**。回归测试里所有"E1 断言"
	// （真机实测的 JA3/JA4、身份头顺序、HEADERS priority 等）都必须跳过 E3，
	// 否则等于用第三方的猜测去"验证"第三方的猜测。
	Grade  string `json:"grade,omitempty"`
	Source string `json:"source,omitempty"`
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

	// type 21：padding 的**实测字节数**（全零负载）。Safari 实测 390 / 394：
	// 与 padding_to 的区别——padding_to 是"对齐到总长"的策略（我们自算），
	// padding_len 是"抓包实测到多少字节就写多少"（数据驱动）。
	// 二者互斥：Data 非空时原样透传；否则优先 PaddingLen；再否则用 PaddingTo 策略。
	PaddingLen int `json:"padding_len,omitempty"`

	// GreaseRandom 为 true 时，该扩展是"随机 GREASE 扩展"：线上 type 每次连接
	// 重取随机值（真浏览器行为）。启用时 Type 仍须是一个 GREASE 值（0x?a?a），
	// 以便与真实扩展号区分与校验。
	// 默认 false = 字面 GREASE 值按 P1-T3 原样透传（用户可钉死确切 GREASE 值）。
	GreaseRandom bool `json:"grease_random,omitempty"`

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
	// HeadersPriority：HEADERS 帧**内嵌**的 priority（见 H2HeadersPriority 注释）。
	// nil = 用 fhttp 默认值（= Chrome 实测量形状）。
	HeadersPriority *H2HeadersPriority `json:"headers_priority,omitempty"`
	// HpackStrategy：HPACK 编码策略（T-HPACK，2026-09-28 起生效）：
	// ""/generic = 上游默认（一切皆可入动表）；chrome/firefox = 伪头仅 :authority 入动表、
	// 常规头 incremental indexing；safari = 全 literal 保守近似。
	// 生效路径：core/h2 → vendor fork Transport.HpackStrategy（见 third_party/fhttp/GEEKTLS_PATCHES.md）。
	HpackStrategy string `json:"hpack_strategy,omitempty"`
}

// H2Priority 是一个 priority 帧（03 文档示例的数组形 [[3,true,0,255]] 改为
// 对象形：数组里混布尔无法静态类型化）。
type H2Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	StreamDep uint32 `json:"stream_dep"`
	Weight    uint8  `json:"weight"` // 0-255（线上值 = +1）
}

// H2HeadersPriority 是 **HEADERS 帧内嵌**的 priority（RFC 7540 §6.3），
// 与 H2Priority（独立 PRIORITY 帧）不同：真 Chrome/Firefox 都**不发**独立
// PRIORITY 帧，而是把 priority 写在请求 HEADERS 里（线上 flags 置 0x20）。
//
// 实测（2026-09-24，tls.peet.ws；peet 报的 weight = 线上值 +1）：
//
//	Chrome 149 / Edge：exclusive=true,  stream_dep=0, weight=255（peet 报 256）
//	Firefox 156（普通+无痕两次）：exclusive=false, stream_dep=0, weight=41（peet 报 42）
//
// 字段为 nil 时用 fhttp 的默认值（exclusive=true/weight=255，即 Chrome 形状）；
// Safari 未实测 ⇒ 保持 nil，缺口记在 docs/07 G11。
type H2HeadersPriority struct {
	Exclusive bool   `json:"exclusive"`
	StreamDep uint32 `json:"stream_dep,omitempty"`
	Weight    uint8  `json:"weight"` // 0-255（线上值；浏览器/peet 报数 = +1）
}

// HTTP3Profile（P4）。
type HTTP3Profile struct {
	Enabled           bool              `json:"enabled,omitempty"`
	QUICVersion       string            `json:"quic_version,omitempty"` // "0x00000001"
	TransportParams   map[string]uint64 `json:"transport_params,omitempty"`
	// TransportParamsRaw（T4-1，blob 直通）：有序 QUIC transport parameters，
	// 每项 [id, value]；id 为数值或 "grease"（随机 GREASE id + value 长度的随机数据），
	// value 为数值（按 varint 编码）或 "hex:..."（原始字节）。
	// 设置后优先于 TransportParams（map 形态被忽略）；数组顺序即线上顺序，
	// 可表达非标参数与任意顺序（整块有序直通，非逐项 setter）。
	TransportParamsRaw [][]any         `json:"transport_params_raw,omitempty"`
	InitialLayout      *H3InitialLayout `json:"initial_layout,omitempty"` // P4-T4 结论：quic-go 不可控，见 capability 文档

	// --- QUIC 内层 ClientHello 的 TLS1.3 形态（实测驱动，见 docs/07-capability-gaps.md §6.1）---
	// 真实浏览器在 QUIC 上只发 TLS1.3 有意义的扩展，且不发任何 TLS 层 GREASE。
	// 协议最小剔除（11/23/35/65281）在 core/h3 里硬编码；以下三项表达**实现选择**。
	//
	// InnerHelloDropExtensions：在协议最小剔除之外，额外剔除的扩展号。
	//   Chrome 149 (Windows) 实测 = [5, 18]（status_request / SCT：TLS1.3 里本可发，Chrome QUIC 不发）。
	InnerHelloDropExtensions []uint16 `json:"inner_hello_drop_extensions,omitempty"`
	// InnerHelloExtraSigAlgs：QUIC 内层追加的签名算法（追加在末尾）。
	//   Chrome 149 实测 = ["0x0201"]（rsa_pkcs1_sha1）。
	InnerHelloExtraSigAlgs []string `json:"inner_hello_extra_sig_algs,omitempty"`
	// InnerHelloDropGrease：QUIC 内层是否完全不发 TLS 层 GREASE
	//   （Chrome 149 实测 true：cipher / 扩展 / group / key_share / version 五处全无）。
	InnerHelloDropGrease bool `json:"inner_hello_drop_grease,omitempty"`
	GreaseFrames       bool             `json:"grease_frames,omitempty"`
	Settings           [][]uint32       `json:"settings,omitempty"`
	PseudoHeaderOrder  []string         `json:"pseudo_header_order,omitempty"`
	PriorityParam      uint32           `json:"priority_param,omitempty"` // Chrome 的 PRIORITY 帧参数（如 984832）
	H2RaceMs           int              `json:"h2_race_ms,omitempty"`     // H2/H3 竞速：H3 起跑后多少 ms 内无响应头则并发 H2
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

// IdentityProfile（T2-1）：profile 携带的缺省请求头身份（UA/UA-CH 等），
// 解决"TLS 指纹是 chrome_150 但 user-agent 却是 Go-http-client"的身份分裂。
// 语义：engine 在 H1/H2/H3 三条路径统一注入；用户请求里同名头（大小写不敏感）
// 优先于本表；本表内部顺序即线上顺序。
type IdentityProfile struct {
	Headers [][2]string `json:"headers,omitempty"` // 有序缺省请求头 [[name, value],...]
}

// BehaviorProfile（P3）。
type BehaviorProfile struct {
	RedirectMax       int  `json:"redirect_max,omitempty"`
	CookieJar         bool `json:"cookie_jar,omitempty"`
	SessionResumption bool `json:"session_resumption,omitempty"`
	// ConnectionPool：per-origin 连接复用（二期阶段 5）。nil = 默认开启；
	// 显式 false 回到"每请求一条新连接"的旧行为（CONTRACT-FREEZE #5 的解除开关）。
	ConnectionPool *bool `json:"connection_pool,omitempty"`
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
	if p.Identity != nil {
		for i, kv := range p.Identity.Headers {
			if kv[0] == "" {
				return &ParseError{Field: "identity.headers", Msg: fmt.Sprintf("entry %d has empty name", i)}
			}
			if kv[0][0] == ':' {
				return &ParseError{Field: "identity.headers", Msg: fmt.Sprintf("entry %d %q is a pseudo-header (not allowed)", i, kv[0])}
			}
		}
	}
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
	if e.GreaseRandom && !IsGrease(e.Type) {
		return fmt.Errorf("grease_random requires a GREASE type (0x?a?a), got %#04x", e.Type)
	}
	return nil
}

// GreaseToken 是 ciphers/groups/extensions/versions 列表里的 GREASE 字面量。
const GreaseToken = "grease"

// IsGrease 判断 RFC 8701 GREASE 值（0x?a?a：两字节相同且低半字节为 0xa）。
func IsGrease(v uint16) bool {
	return v>>8 == v&0xff && v&0xf == 0xa
}
