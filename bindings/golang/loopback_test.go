package geektls

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/geekbyter/geektls/core/profiles"
)

// --- T-G：Go 便捷入口的"本地回环请求 → selfcheck 与期望一致"全链路测试 ---
//
// 三个入口（clienthello_hex / ja3 / ja4r）各建一个会话，对本地 httptest TLS
// 服务端发一次真实请求，验证：
//   - 握手成功（载荷借用/兜底后能真打通）；
//   - hex 入口：selfcheck 自算 JA3 == ImportPcap 对同一 CH 的自算值；
//   - ja3/ja4r 入口：JA3Match / JA4Match 为真（与入口期望一致）；
//   - HTTP 层自检（T-I8）已填充且身份兜底生效（UA 非空、非 Go 默认）。

func hex16Test(s string) (uint16, bool) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if s == "" || s == "grease" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
}

func greaseTest(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

// ja3FromPresetTest 从内置预设的 detail 生成"真实形态"的 JA3 串。
func ja3FromPresetTest(t *testing.T, name string) string {
	t.Helper()
	p, err := profiles.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	d := p.TLS.Detail
	var ciphers, exts, groups, points []string
	for _, c := range d.Ciphers {
		if v, ok := hex16Test(c); ok && !greaseTest(v) {
			ciphers = append(ciphers, fmt.Sprintf("%d", v))
		}
	}
	for _, e := range d.Extensions {
		if greaseTest(e.Type) {
			continue
		}
		if e.Type == 41 {
			continue // pre_shared_key 只在 resumption 时发出；冷启动形态的期望值不含它
		}
		exts = append(exts, fmt.Sprintf("%d", e.Type))
		if e.Type == 10 {
			for _, g := range e.Groups {
				if gv, ok := hex16Test(g); ok && !greaseTest(gv) {
					groups = append(groups, fmt.Sprintf("%d", gv))
				}
			}
		}
		if e.Type == 11 {
			for _, pf := range e.PointFormats {
				points = append(points, fmt.Sprintf("%d", pf))
			}
		}
	}
	return fmt.Sprintf("771,%s,%s,%s,%s",
		strings.Join(ciphers, "-"), strings.Join(exts, "-"),
		strings.Join(groups, "-"), strings.Join(points, "-"))
}

// ja4rFromPresetTest 从内置预设的 detail 生成"真实形态"的 JA4R 串（a 段按 JA4
// 规范：计数十进制两位、剔除 GREASE 与 SNI/ALPN、扩展排序）。
func ja4rFromPresetTest(t *testing.T, name string) string {
	t.Helper()
	p, err := profiles.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	d := p.TLS.Detail
	var ciphers []string
	for _, c := range d.Ciphers {
		if v, ok := hex16Test(c); ok && !greaseTest(v) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", v))
		}
	}
	hasSNI := false
	alpnCode := "00"
	var exts []uint16
	var sigs []string
	for _, e := range d.Extensions {
		if greaseTest(e.Type) {
			continue
		}
		if e.Type == 41 {
			continue // 同 ja3：冷启动形态的期望值不含 pre_shared_key
		}
		switch e.Type {
		case 0:
			hasSNI = true
			continue
		case 16:
			for _, a := range e.ALPN {
				if a == "h2" {
					alpnCode = "h2"
				}
			}
			continue
		case 13:
			for _, s := range e.SigAlgs {
				if v, ok := hex16Test(s); ok && !greaseTest(v) {
					sigs = append(sigs, fmt.Sprintf("%04x", v))
				}
			}
		}
		exts = append(exts, e.Type)
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	sort.Strings(ciphers) // JA4R 的 ciphers 段是排序值；sig_algs 段保持原始序
	extHex := make([]string, 0, len(exts))
	for _, v := range exts {
		extHex = append(extHex, fmt.Sprintf("%04x", v))
	}
	sniFlag := "i"
	if hasSNI {
		sniFlag = "d"
	}
	// a 段计数是"含 SNI/ALPN"的总扩展数（JA4R 的 exts 段则不含——它们由 d/i
	// 标志与 ALPN 码承载）。
	extCount := len(exts)
	if hasSNI {
		extCount++
	}
	if alpnCode != "00" {
		extCount++
	}
	return fmt.Sprintf("t13%s%02d%02d%s_%s_%s_%s",
		sniFlag, len(ciphers), extCount, alpnCode,
		strings.Join(ciphers, ","), strings.Join(extHex, ","), strings.Join(sigs, ","))
}

// buildChromeLikeCHForTest 拼一份"类 Chrome"的 ClientHello record：ciphers 与扩展
// 类型序取自 chrome_154_windows，SNI=localhost，白名单扩展带最小合法载荷。无法
// 安全合成的类型（GREASE / ECH / ALPS 等）跳过——匹配分数仍远高于阈值。
func buildChromeLikeCHForTest(t *testing.T) []byte {
	t.Helper()
	p, err := profiles.Get("chrome_154_windows")
	if err != nil {
		t.Fatal(err)
	}
	extPayload := func(e profiles.Extension) ([]byte, bool) {
		switch e.Type {
		case 0: // SNI：localhost
			host := []byte("localhost")
			entry := append([]byte{0x00, byte(len(host) >> 8), byte(len(host))}, host...)
			out := []byte{byte(len(entry) >> 8), byte(len(entry))}
			return append(out, entry...), true
		case 10: // supported_groups：x25519/secp256r1/secp384r1
			groups := []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18}
			return append([]byte{0x00, byte(len(groups))}, groups...), true
		case 11: // ec_point_formats
			return []byte{0x01, 0x00}, true
		case 13: // signature_algorithms
			algs := []byte{0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03}
			return append([]byte{0x00, byte(len(algs))}, algs...), true
		case 16: // ALPN：h2 / http/1.1
			list := []byte{0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
			return append([]byte{byte(len(list) >> 8), byte(len(list))}, list...), true
		case 23, 35: // EMS / session_ticket：空载荷
			return []byte{}, true
		case 27: // certificate_compression：brotli
			return []byte{0x01, 0x02}, true
		case 43: // supported_versions：TLS 1.3
			return []byte{0x02, 0x03, 0x04}, true
		case 45: // psk_key_exchange_modes
			return []byte{0x01, 0x01}, true
		case 51: // key_share：x25519 + 32 字节占位（密钥由运行时重生成）
			exp := append([]byte{0x00, 0x1d, 0x00, 0x20}, make([]byte, 32)...)
			return append([]byte{0x00, byte(len(exp))}, exp...), true
		case 65281: // renegotiation_info
			return []byte{0x00}, true
		default:
			return nil, false
		}
	}
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0x11}, 32)...) // random（导入后重生成）
	body = append(body, 0x00)                              // session_id len = 0
	var ciph []byte
	for _, c := range p.TLS.Detail.Ciphers {
		if v, ok := hex16Test(c); ok {
			ciph = append(ciph, byte(v>>8), byte(v))
		}
	}
	body = append(body, byte(len(ciph)>>8), byte(len(ciph)))
	body = append(body, ciph...)
	body = append(body, 0x01, 0x00) // compression: null
	var exts []byte
	for _, e := range p.TLS.Detail.Extensions {
		pl, ok := extPayload(e)
		if !ok {
			continue
		}
		exts = append(exts, byte(e.Type>>8), byte(e.Type), byte(len(pl)>>8), byte(len(pl)))
		exts = append(exts, pl...)
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// sessionSingleSegmentForTest 与 sessionForTest 同形，但 ClientHello 作为**单个
// TCP 段**发送（pcapimport 不支持"CH 跨 record"的罕见形态）。
func sessionSingleSegmentForTest(ch []byte, sport int) [][]byte {
	src := [4]byte{192, 168, 1, 10}
	dst := [4]byte{93, 184, 216, 34}
	return [][]byte{
		frameForTest(src, dst, sport, 443, 1000, 0, 0x02, 64240, 64, true, synOptsForTest(), nil),
		frameForTest(dst, src, 443, sport, 5000, 1001, 0x12, 65535, 57, false, nil, nil),
		frameForTest(src, dst, sport, 443, 1001, 5001, 0x10, 64240, 64, false, nil, nil),
		frameForTest(src, dst, sport, 443, 1001, 5001, 0x18, 64240, 64, false, nil, ch),
	}
}

func TestEntrypointsLoopbackSelfCheck(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	opts := &Options{
		InsecureSkipVerify: true,
		Resolve:            map[string]string{"localhost": "127.0.0.1"},
	}

	getOK := func(t *testing.T, s *Session, label string) *Response {
		t.Helper()
		r, err := s.Get(url)
		if err != nil {
			t.Fatalf("%s 回环请求失败: %v", label, err)
		}
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		if string(body) != "ok" {
			t.Errorf("%s 响应体 = %q", label, body)
		}
		return r
	}

	// ① hex 入口：selfcheck 自算 JA3 与 ImportPcap 对同一 CH 的自算值一致。
	ch := buildChromeLikeCHForTest(t)
	res, err := ImportPcapBytes(pcapBytesForTest(sessionSingleSegmentForTest(ch, 51431)...), nil, "cap")
	if err != nil || len(res.Records) == 0 {
		t.Fatalf("ImportPcapBytes: %v records=%d skipped=%+v chLen=%d", err, len(res.Records), res.Skipped, len(ch))
	}
	rec := res.Records[0]
	s1, _, err := NewSessionFromClientHelloHex(rec.ClientHelloHex, opts)
	if err != nil {
		t.Fatalf("hex 入口建会话: %v", err)
	}
	defer s1.Close()
	r1 := getOK(t, s1, "hex")
	if r1.SelfCheck.JA3 != rec.JA3 {
		t.Errorf("hex selfcheck JA3 不一致:\n got  %s\n want %s", r1.SelfCheck.JA3, rec.JA3)
	}
	if r1.SelfCheck.UserAgent == "" || r1.SelfCheck.GoDefaultUA {
		t.Errorf("HTTP 层自检/身份兜底异常: ua=%q headers=%d goDefault=%v",
			r1.SelfCheck.UserAgent, r1.SelfCheck.HeaderCount, r1.SelfCheck.GoDefaultUA)
	}

	// ② ja3 入口：JA3Match 为真（载荷借用后线上形态与入口一致）。
	ja3 := ja3FromPresetTest(t, "chrome_154_windows")
	s2, _, err := NewSessionFromJA3(ja3, opts)
	if err != nil {
		t.Fatalf("ja3 入口建会话: %v", err)
	}
	defer s2.Close()
	r2 := getOK(t, s2, "ja3")
	if r2.SelfCheck.JA3Match == nil || !*r2.SelfCheck.JA3Match {
		t.Errorf("ja3 selfcheck 未匹配:\n got  %s\n want %s", r2.SelfCheck.JA3, ja3)
	}
	if r2.SelfCheck.UserAgent == "" {
		t.Error("ja3 会话的 HTTP 层自检 UA 为空")
	}

	// ③ ja4r 入口：JA4Match 为真。
	ja4r := ja4rFromPresetTest(t, "chrome_154_windows")
	s3, _, err := NewSessionFromJA4R(ja4r, opts)
	if err != nil {
		t.Fatalf("ja4r 入口建会话: %v", err)
	}
	defer s3.Close()
	r3 := getOK(t, s3, "ja4r")
	if r3.SelfCheck.JA4Match == nil || !*r3.SelfCheck.JA4Match {
		t.Errorf("ja4r selfcheck 未匹配:\n got  %s\n want %s\n exts %v\n wire %v",
			r3.SelfCheck.JA4, ja4r, r3.SelfCheck.Extensions, r3.SelfCheck.WireExts)
	}
}
