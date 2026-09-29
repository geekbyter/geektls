package profiles

// 三种便捷入口（JA3 / JA4R / ClientHello hex）→ 规范 detail 的编译器。
//
// 语义承 03 文档 §2：规范形式是 detail；便捷入口有损时必须在 warnings 明示，
// 字段无依据时宁可报错/留空也不伪造。

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Warning 描述入口编译的信息损失，随 FFI 的 check_profile 输出。
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func warnf(code, format string, args ...any) Warning {
	return Warning{Code: code, Message: fmt.Sprintf(format, args...)}
}

// --- JA3 ---

// FromJA3 解析 JA3 full string（version,ciphers-extensions-groups-points，
// 逗号分段、破折号分项、十进制）为 profile。
//
// JA3 是有损入口：扩展只有 type 没有负载（sig_algs/key_share/ALPN/
// supported_versions 等全缺），GREASE 位置信息丢失——warnings 如实标注。
func FromJA3(ja3 string) (*Profile, []Warning, error) {
	sections := strings.Split(strings.TrimSpace(ja3), ",")
	if len(sections) != 5 {
		return nil, nil, &ParseError{Field: "ja3",
			Msg: fmt.Sprintf("want 5 comma-separated sections, got %d", len(sections))}
	}
	lists := make([][]uint16, 5)
	for i, sec := range sections {
		vals, err := parseDashDecimals(sec)
		if err != nil {
			return nil, nil, &ParseError{Field: fmt.Sprintf("ja3.section[%d]", i), Msg: err.Error()}
		}
		lists[i] = vals
	}
	if len(lists[0]) != 1 {
		return nil, nil, &ParseError{Field: "ja3.section[0]",
			Msg: "version section must contain exactly one value"}
	}

	var warnings []Warning
	warnings = append(warnings,
		warnf("grease_lost", "JA3 strips GREASE values/positions; replay will not reproduce them"),
		warnf("extension_payloads_lost",
			"JA3 carries only extension type ids: sig_algs/key_share/ALPN/supported_versions/padding payloads are unknown and will be empty"),
	)

	d := &Detail{
		LegacyVersion: fmt.Sprintf("0x%04x", lists[0][0]),
	}
	for _, c := range lists[1] {
		d.Ciphers = append(d.Ciphers, fmt.Sprintf("0x%04x", c))
	}

	groupsHex := hexStrings(lists[3])
	points := uint8s(lists[4])
	payloadDefaulted := false
	for _, extID := range lists[2] {
		e := Extension{Type: extID}
		switch extID {
		case 10:
			e.Groups = groupsHex // supported_groups 负载可还原
		case 11:
			e.PointFormats = points // ec_point_formats 可还原
		case 65037:
			// JA3 无法区分真 ECH 与 GREASE ECH，按 GREASE 近似并告警
			e.ECH = &ECHConfig{Mode: "grease"}
			warnings = append(warnings, warnf("ech_assumed_grease",
				"JA3 cannot distinguish real ECH from GREASE ECH; assuming grease"))
		case 43:
			// supported_versions 空负载无法握手；存在该扩展即按 TLS 1.3+1.2 填充
			e.Versions = []string{"0x0304", "0x0303"}
			payloadDefaulted = true
		case 51:
			// key_share 空负载无法握手；取 groups 里前两个密钥交换组
			// （少了会在服务端选 MLKEM 时触发 HRR，uTLS HRR 路径不支持 MLKEM）
			shares := []string{}
			for _, g := range lists[3] {
				if g == 4588 || g == 29 || g == 23 || g == 24 || g == 25 {
					shares = append(shares, fmt.Sprintf("0x%04x", g))
				}
				if len(shares) == 2 {
					break
				}
			}
			if len(shares) == 0 {
				shares = []string{"X25519"}
			}
			e.KeyShares = shares
			payloadDefaulted = true
		case 16:
			// ALPN 空负载无法协商；按浏览器常态填 h2/http1.1
			e.ALPN = []string{"h2", "http/1.1"}
			payloadDefaulted = true
		case 13:
			// sig_algs 空负载会被服务端拒绝；填 Chrome 标准八项
			e.SigAlgs = []string{"0x0403", "0x0804", "0x0401", "0x0503", "0x0805", "0x0501", "0x0806", "0x0601"}
			payloadDefaulted = true
		case 27:
			e.CertCompression = []string{"brotli"}
			payloadDefaulted = true
		case 17513, 17613:
			e.ALPN = []string{"h2"}
			payloadDefaulted = true
		case 65281:
			// renegotiation_info 空负载非法；客户端常态为单字节 0
			e.Data = "00"
			payloadDefaulted = true
		}
		d.Extensions = append(d.Extensions, e)
	}
	if payloadDefaulted {
		warnings = append(warnings, warnf("payload_defaults_applied",
			"JA3 has no extension payloads; supported_versions/key_share/ALPN filled with defaults to make the hello bootable"))
	}
	return &Profile{TLS: &TLSProfile{JA3: ja3, Detail: d}}, warnings, nil
}

func parseDashDecimals(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, "-")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid decimal %q", p)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

func hexStrings(vals []uint16) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, fmt.Sprintf("0x%04x", v))
	}
	return out
}

func uint8s(vals []uint16) []uint8 {
	out := make([]uint8, 0, len(vals))
	for _, v := range vals {
		out = append(out, uint8(v))
	}
	return out
}

// --- JA4R ---

// FromJA4R 解析 JA4 raw 指纹（a_ciphers_extensions_sigalgs 四段，下划线分隔）。
//
// 按 FoxIO JA4 语义，ciphers/extensions 段是排序后的值，原始线上顺序不可
// 还原——detail.ExtensionsSorted 置位并给 warning。a 段的计数用于交叉校验，
// 不一致只警告不报错。
func FromJA4R(ja4r string) (*Profile, []Warning, error) {
	sections := strings.Split(strings.TrimSpace(ja4r), "_")
	if len(sections) != 4 {
		return nil, nil, &ParseError{Field: "ja4r",
			Msg: fmt.Sprintf("want 4 underscore-separated sections, got %d", len(sections))}
	}
	a := sections[0]
	if len(a) != 10 {
		return nil, nil, &ParseError{Field: "ja4r.a",
			Msg: fmt.Sprintf("want 10 chars (e.g. t13d1516h2), got %d", len(a))}
	}
	proto, sniFlag := a[0], a[3]
	if proto != 't' && proto != 'q' && proto != 'd' {
		return nil, nil, &ParseError{Field: "ja4r.a", Msg: fmt.Sprintf("unknown protocol flag %q", proto)}
	}
	if sniFlag != 'd' && sniFlag != 'i' {
		return nil, nil, &ParseError{Field: "ja4r.a", Msg: fmt.Sprintf("unknown SNI flag %q", sniFlag)}
	}
	cipherCount, err1 := strconv.Atoi(a[4:6])
	extCount, err2 := strconv.Atoi(a[6:8])
	if err1 != nil || err2 != nil {
		return nil, nil, &ParseError{Field: "ja4r.a", Msg: "cipher/extension counts must be 2 digits"}
	}

	ciphers, err := parseCSVHex16(sections[1])
	if err != nil {
		return nil, nil, &ParseError{Field: "ja4r.ciphers", Msg: err.Error()}
	}
	exts, err := parseCSVHex16(sections[2])
	if err != nil {
		return nil, nil, &ParseError{Field: "ja4r.extensions", Msg: err.Error()}
	}
	sigAlgs, err := parseCSVHex16(sections[3])
	if err != nil {
		return nil, nil, &ParseError{Field: "ja4r.sig_algs", Msg: err.Error()}
	}

	var warnings []Warning
	warnings = append(warnings,
		warnf("sorted_order", "JA4R ciphers/extensions are sorted; original wire order is unrecoverable"),
		warnf("extension_payloads_lost",
			"JA4R carries only extension type ids (plus sig_algs); key_share/groups/versions payloads are unknown"),
	)
	if cipherCount != len(ciphers) {
		warnings = append(warnings, warnf("count_mismatch",
			"a-section cipher count %d != actual %d", cipherCount, len(ciphers)))
	}
	if extCount != len(exts) {
		warnings = append(warnings, warnf("count_mismatch",
			"a-section extension count %d != actual %d", extCount, len(exts)))
	}

	d := &Detail{
		Ciphers:          hexStrings(ciphers),
		ExtensionsSorted: true,
	}
	alpnCode := a[8:10]
	hasExt := map[uint16]bool{}
	for _, extID := range exts {
		hasExt[extID] = true
		e := Extension{Type: extID}
		switch extID {
		case 0:
			if sniFlag == 'd' {
				e.SNI = "auto"
			}
		case 13:
			e.SigAlgs = hexStrings(sigAlgs) // sig_algs 负载可还原
		case 16:
			e.ALPN = alpnFromCode(alpnCode, &warnings)
		case 43:
			e.Versions = versionsFromCode(a[1:3], &warnings)
		case 65037:
			// ECH：JA4R 只给扩展 type，既没有负载、也分不清真 ECH 与 GREASE ECH
			// ⇒ 与 FromJA3 同策略（按 GREASE 近似 + 告警）。
			//
			// 必须补这一条：编译期对"空 data 且没有 ech 配置"的 65037 直接报错
			// （compile.go: "ech config is required for extension 65037"），
			// 于是**带 ECH 的真实浏览器 JA4R 整条不可用**——Chrome 152+ 的
			// JA4R 全都带 fe0d，等于把最主要的一类入口堵死。
			e.ECH = &ECHConfig{Mode: "grease"}
			warnings = append(warnings, warnf("ech_assumed_grease",
				"JA4R cannot distinguish real ECH from GREASE ECH; assuming grease"))
		}
		d.Extensions = append(d.Extensions, e)
	}
	// JA4R 的扩展列表按规范剔除 SNI/ALPN；按 a 段标志补回（顺序本就不可得，追加末尾）。
	if sniFlag == 'd' && !hasExt[0] {
		d.Extensions = append(d.Extensions, Extension{Type: 0, SNI: "auto"})
	}
	if alpnCode != "00" && !hasExt[16] {
		d.Extensions = append(d.Extensions, Extension{Type: 16, ALPN: alpnFromCode(alpnCode, &warnings)})
	}
	return &Profile{TLS: &TLSProfile{JA4R: ja4r, Detail: d}}, warnings, nil
}

func parseCSVHex16(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid hex %q", p)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

func alpnFromCode(code string, warnings *[]Warning) []string {
	switch code {
	case "00":
		return nil
	case "h1":
		return []string{"http/1.1"}
	case "h2":
		return []string{"h2"}
	case "h3":
		return []string{"h3"}
	default:
		*warnings = append(*warnings, warnf("alpn_guess",
			"ALPN code %q cannot be mapped to a protocol name; using it literally", code))
		return []string{code}
	}
}

func versionsFromCode(code string, warnings *[]Warning) []string {
	*warnings = append(*warnings, warnf("versions_lossy",
		"only the max TLS version (%s) is known from JA4R; full supported_versions list is unrecoverable", code))
	switch code {
	case "13":
		return []string{"0x0304"}
	case "12":
		return []string{"0x0303"}
	case "11":
		return []string{"0x0302"}
	case "10":
		return []string{"0x0301"}
	default:
		return nil
	}
}

// --- ClientHello hex ---

// FromClientHelloHex 解析 Wireshark 抓包的 TLS ClientHello（含 5 字节 record
// 头）为 profile。这是无损路径：扩展按线上顺序原样保留，已知类型解析出语义
// 字段，未知类型透传 data。纯字节解析，不引入新依赖。
func FromClientHelloHex(hexStr string) (*Profile, []Warning, error) {
	raw, err := hex.DecodeString(strings.NewReplacer(" ", "", "0x", "", "0X", "", "\n", "", "\t", "").Replace(hexStr))
	if err != nil {
		return nil, nil, &ParseError{Field: "clienthello_hex", Msg: fmt.Sprintf("invalid hex: %v", err)}
	}
	d, warnings, err := parseClientHello(raw)
	if err != nil {
		return nil, nil, err
	}
	return &Profile{TLS: &TLSProfile{ClientHelloHex: hexStr, Detail: d}}, warnings, nil
}

type chReader struct {
	b   []byte
	pos int
	err error
}

func (r *chReader) take(n int, what string) ([]byte, error) {
	if n < 0 || len(r.b)-r.pos < n {
		return nil, &ParseError{Field: "clienthello_hex",
			Msg: fmt.Sprintf("truncated: want %d bytes for %s at offset %d, have %d", n, what, r.pos, len(r.b)-r.pos)}
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *chReader) u8(what string) (uint8, error) {
	b, err := r.take(1, what)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *chReader) u16(what string) (uint16, error) {
	b, err := r.take(2, what)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (r *chReader) remaining() int { return len(r.b) - r.pos }

func parseClientHello(raw []byte) (*Detail, []Warning, error) {
	r := &chReader{b: raw}

	// TLS record 头（5 字节）：type=22, version, length。
	recType, err := r.u8("record type")
	if err != nil {
		return nil, nil, err
	}
	if recType != 22 {
		return nil, nil, &ParseError{Field: "clienthello_hex",
			Msg: fmt.Sprintf("record type = %d, want 22 (handshake)", recType)}
	}
	if _, err := r.take(4, "record version+length"); err != nil {
		return nil, nil, err
	}

	// Handshake 头（4 字节）：type=1 (client_hello), 3 字节 length。
	hsType, err := r.u8("handshake type")
	if err != nil {
		return nil, nil, err
	}
	if hsType != 1 {
		return nil, nil, &ParseError{Field: "clienthello_hex",
			Msg: fmt.Sprintf("handshake type = %d, want 1 (client_hello)", hsType)}
	}
	if _, err := r.take(3, "handshake length"); err != nil {
		return nil, nil, err
	}

	d := &Detail{}
	legacyVer, err := r.u16("legacy_version")
	if err != nil {
		return nil, nil, err
	}
	d.LegacyVersion = fmt.Sprintf("0x%04x", legacyVer)

	if _, err := r.take(32, "random"); err != nil {
		return nil, nil, err
	}
	sidLen, err := r.u8("session_id length")
	if err != nil {
		return nil, nil, err
	}
	if _, err := r.take(int(sidLen), "session_id"); err != nil {
		return nil, nil, err
	}

	cipherLen, err := r.u16("cipher_suites length")
	if err != nil {
		return nil, nil, err
	}
	if cipherLen%2 != 0 {
		return nil, nil, &ParseError{Field: "clienthello_hex", Msg: "odd cipher_suites length"}
	}
	cb, err := r.take(int(cipherLen), "cipher_suites")
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i+1 < len(cb); i += 2 {
		d.Ciphers = append(d.Ciphers, fmt.Sprintf("0x%02x%02x", cb[i], cb[i+1]))
	}

	compLen, err := r.u8("compression length")
	if err != nil {
		return nil, nil, err
	}
	cb, err = r.take(int(compLen), "compression methods")
	if err != nil {
		return nil, nil, err
	}

	var warnings []Warning
	if len(cb) != 1 || cb[0] != 0 {
		warnings = append(warnings, warnf("compression_lost",
			"non-default compression methods %v are not preserved (detail schema has no field for them)", cb))
	}

	extTotal, err := r.u16("extensions length")
	if err != nil {
		return nil, nil, err
	}
	extBytes, err := r.take(int(extTotal), "extensions")
	if err != nil {
		return nil, nil, err
	}
	er := &chReader{b: extBytes}
	for er.remaining() > 0 {
		extType, err := er.u16("extension type")
		if err != nil {
			return nil, nil, err
		}
		extLen, err := er.u16("extension length")
		if err != nil {
			return nil, nil, err
		}
		data, err := er.take(int(extLen), fmt.Sprintf("extension %d data", extType))
		if err != nil {
			return nil, nil, err
		}
		d.Extensions = append(d.Extensions, parseExtension(extType, data, &warnings))
	}
	return d, warnings, nil
}

// parseExtension 对已知类型解析语义字段，未知/GREASE 类型透传 data（hex）。
func parseExtension(extType uint16, data []byte, warnings *[]Warning) Extension {
	e := Extension{Type: extType}
	r := &chReader{b: data}
	fail := func() Extension {
		// 语义解析失败不报错，退化为透传（宁可留原始字节也不丢数据）。
		*warnings = append(*warnings, warnf("extension_passthrough",
			"extension %d payload failed semantic parse; passing through raw bytes", extType))
		return Extension{Type: extType, Data: hex.EncodeToString(data)}
	}

	switch extType {
	case 0: // server_name
		if _, err := r.u16("sni list len"); err != nil {
			return fail()
		}
		if t, err := r.u8("sni entry type"); err != nil || t != 0 {
			return fail()
		}
		nameLen, err := r.u16("sni name len")
		if err != nil {
			return fail()
		}
		name, err := r.take(int(nameLen), "sni name")
		if err != nil {
			return fail()
		}
		e.SNI = string(name)
	case 10: // supported_groups
		e.Groups = hexStrings(u16List(r, 2))
		if r.err != nil {
			return fail()
		}
	case 11: // ec_point_formats
		pts, err := u8List(r)
		if err != nil {
			return fail()
		}
		e.PointFormats = pts
	case 13, 34, 50: // signature_algorithms / delegated_credentials / sig_algs_cert
		e.SigAlgs = hexStrings(u16List(r, 2))
		if r.err != nil {
			return fail()
		}
	case 16, 17513, 17613: // ALPN / ALPS（新旧 codepoint，同为长度前缀字符串列表）
		protos, err := protoList(r)
		if err != nil {
			return fail()
		}
		e.ALPN = protos
	case 21: // padding：原样保留零字节（hex 回放是无损路径，不套 padding_to 策略）
		e.Data = hex.EncodeToString(data)
	case 27: // compress_certificate
		algos := u16List(r, 1)
		if r.err != nil {
			return fail()
		}
		for _, a := range algos {
			name, ok := certCompressionName(a)
			if !ok {
				return fail()
			}
			e.CertCompression = append(e.CertCompression, name)
		}
	case 28: // record_size_limit：2 字节值，透传 data（编译器认 2 字节 data）
		if len(data) != 2 {
			return fail()
		}
		e.Data = hex.EncodeToString(data)
	case 43: // supported_versions
		versions, err := u16List1(r)
		if err != nil {
			return fail()
		}
		e.Versions = hexStrings(versions)
	case 45: // psk_key_exchange_modes
		modes, err := u8List(r)
		if err != nil {
			return fail()
		}
		e.PSKModes = modes
	case 51: // key_share：保留组序，密钥负载必然重新生成（本来也不可复用）
		if _, err := r.u16("key_share list len"); err != nil {
			return fail()
		}
		for r.remaining() > 0 {
			g, err := r.u16("key_share group")
			if err != nil {
				return fail()
			}
			klen, err := r.u16("key_share data len")
			if err != nil {
				return fail()
			}
			if _, err := r.take(int(klen), "key_share data"); err != nil {
				return fail()
			}
			e.KeyShares = append(e.KeyShares, fmt.Sprintf("0x%04x", g))
		}
	case 65037: // ECH：负载不透明，原样透传
		e.Data = hex.EncodeToString(data)
	default:
		// 未知类型与 GREASE 扩展（type 本身是 0x?a?a）：透传。
		e.Data = hex.EncodeToString(data)
	}
	return e
}

func certCompressionName(id uint16) (string, bool) {
	switch id {
	case 1:
		return "zlib", true
	case 2:
		return "brotli", true
	case 3:
		return "zstd", true
	}
	return "", false
}

// 以下小解析器失败时记 r.err（fail() 会读到），不 panic。

func (r *chReader) setErr(err error) {
	if r.err == nil {
		r.err = err
	}
}

func u16List(r *chReader, lenBytes int) []uint16 {
	var n int
	switch lenBytes {
	case 2:
		v, err := r.u16("list length")
		if err != nil {
			r.setErr(err)
			return nil
		}
		n = int(v)
	case 1:
		v, err := r.u8("list length")
		if err != nil {
			r.setErr(err)
			return nil
		}
		n = int(v)
	}
	b, err := r.take(n, "u16 list")
	if err != nil {
		r.setErr(err)
		return nil
	}
	if n%2 != 0 {
		r.setErr(fmt.Errorf("odd u16 list length %d", n))
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

func u16List1(r *chReader) ([]uint16, error) {
	n, err := r.u8("list length")
	if err != nil {
		return nil, err
	}
	b, err := r.take(int(n), "u16 list")
	if err != nil {
		return nil, err
	}
	if len(b)%2 != 0 {
		return nil, fmt.Errorf("odd u16 list length %d", len(b))
	}
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out, nil
}

func u8List(r *chReader) ([]uint8, error) {
	n, err := r.u8("list length")
	if err != nil {
		return nil, err
	}
	return r.take(int(n), "u8 list")
}

func protoList(r *chReader) ([]string, error) {
	total, err := r.u16("protocol list length")
	if err != nil {
		return nil, err
	}
	b, err := r.take(int(total), "protocol list")
	if err != nil {
		return nil, err
	}
	pr := &chReader{b: b}
	var out []string
	for pr.remaining() > 0 {
		n, err := pr.u8("protocol length")
		if err != nil {
			return nil, err
		}
		p, err := pr.take(int(n), "protocol")
		if err != nil {
			return nil, err
		}
		out = append(out, string(p))
	}
	return out, nil
}
