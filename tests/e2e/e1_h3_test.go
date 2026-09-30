package e2e

// E1 真浏览器 H3/QUIC 基准（Item 1）：
// 真实浏览器 → 本机 UDP 嗅探（RFC 9001 Initial 解密）→ 取出 transport params
// 与内层 ClientHello → 落盘证据记录。
//
// 为什么必须做：`core/h3` 在 `profile.http3 == nil` 时直接退回 quic-go 默认
// transport params（等于在 H3 上暴露"通用 Go 客户端"）；而 Firefox / Safari 的
// transport params 与 Chromium **不同**，不能靠家族继承——只能靠真实浏览器实测。
//
// 工作方式（全本地，无外网）：
//  1. 同一端口上起 TCP/TLS(h2) 服务端（自签证书）与 UDP 嗅探器；
//  2. 用 --origin-to-force-quic-on=localhost:<port> 让浏览器对该源**直接走 QUIC**，
//     无需 Alt-Svc 往返，也无需可信证书链（--ignore-certificate-errors 只影响证书校验）；
//  3. 嗅探器解密浏览器发出的 Initial（密钥由 DCID 按 RFC 9001 推导，与实现无关）；
//  4. 从 CRYPTO 流重组出内层 ClientHello → 解析 transport params + 计算 JA4(QUIC)；
//  5. 证据记录写入 profiles/evidence/browsers/。
//
// 运行（默认跳过，避免 CI 依赖浏览器）：
//
//	GEEKTLS_E1_H3_BROWSER="C:\Program Files\Google\Chrome\Application\chrome.exe" \
//	  go test ./... -run TestE1RealBrowserH3 -v
//
// 可选：GEEKTLS_E1_H3_NAME=chrome_windows_h3 指定证据名。

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gospider007/gtls"

	tlscore "github.com/geekbyter/geektls/core/tls"
)

// tpNames 是已知 QUIC transport parameter 名（RFC 9000 §18.2 / RFC 9221）。
// 未知 id（含 GREASE）按数值记录，不猜名字。
var tpNames = map[uint64]string{
	0x00:   "original_destination_connection_id",
	0x01:   "max_idle_timeout",
	0x02:   "stateless_reset_token",
	0x03:   "max_udp_payload_size",
	0x04:   "initial_max_data",
	0x05:   "initial_max_stream_data_bidi_local",
	0x06:   "initial_max_stream_data_bidi_remote",
	0x07:   "initial_max_stream_data_uni",
	0x08:   "initial_max_streams_bidi",
	0x09:   "initial_max_streams_uni",
	0x0a:   "ack_delay_exponent",
	0x0b:   "max_ack_delay",
	0x0c:   "disable_active_migration",
	0x0d:   "preferred_address",
	0x0e:   "active_connection_id_limit",
	0x0f:   "initial_source_connection_id",
	0x10:   "retry_source_connection_id",
	0x20:   "max_datagram_frame_size",
	0x2ab2: "google_connection_options", // Chrome 私有（gQUIC 遗留选项）
}

type h3TPRecord struct {
	ID     uint64 `json:"id"`
	Name   string `json:"name,omitempty"`
	Value  uint64 `json:"value,omitempty"`
	Hex    string `json:"hex,omitempty"`
	Len    int    `json:"len"`
	Grease bool   `json:"grease,omitempty"`
}

type h3Record struct {
	Kind              string       `json:"kind"`
	Name              string       `json:"name"`
	Browser           string       `json:"browser"`
	BrowserVersion    string       `json:"browser_version,omitempty"`
	CapturedAt        string       `json:"captured_at"`
	ALPN              string       `json:"alpn"`
	InitialDgramLen   int          `json:"initial_datagram_len"`
	TransportParams   []h3TPRecord `json:"transport_params"`
	ClientHelloCrypto string       `json:"clienthello_crypto_hex"`
	// 内层 ClientHello 的形态（QUIC 只允许 TLS1.3 ⇒ 与 TCP 侧形态不同，
	// 这是 clampSpecForQUIC 必须复刻的部分）。
	Ciphers        []uint16 `json:"ciphers"`
	ExtensionTypes []uint16 `json:"extension_types"`
	Curves         []uint16 `json:"curves"`
	KeyShares      []uint16 `json:"key_shares"`
	Versions       []uint16 `json:"versions"`
	SigAlgs        []uint16 `json:"sig_algs"`
	Computed       *struct {
		JA4 string `json:"ja4"`
	} `json:"computed,omitempty"`
}

func TestE1RealBrowserH3(t *testing.T) {
	browser := os.Getenv("GEEKTLS_E1_H3_BROWSER")
	if browser == "" {
		t.Skip("未设置 GEEKTLS_E1_H3_BROWSER —— 该测试需要真实浏览器，默认跳过")
	}
	if _, err := os.Stat(browser); err != nil {
		t.Fatalf("浏览器不存在: %v", err)
	}
	name := os.Getenv("GEEKTLS_E1_H3_NAME")
	if name == "" {
		name = "h3_" + sanitize(browser)
	}

	// 1) TCP/TLS(h2) 服务端（同端口）——浏览器若回落 TCP 也能拿到响应，便于区分"没走 QUIC"。
	// 通配绑定（双栈）：Chrome 可能把 localhost 解析到 ::1，只绑 127.0.0.1 会收不到。
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	tlsCfg := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return gtls.GetCertificate(chi, nil, nil)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv := &http.Server{
		TLSConfig: tlsCfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("e1-h3\n"))
		}),
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	// 2) UDP 嗅探器：与 TCP 同端口（协议不同不冲突），浏览器强制 QUIC 会打到这个端口。
	sniffer, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Skipf("无法占用 UDP %d 做嗅探（可能被其他进程占用）: %v", port, err)
	}
	defer sniffer.Close()

	// 3) 启动真实浏览器，强制该源走 QUIC。
	args := []string{
		"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--ignore-certificate-errors", "--enable-quic",
		"--origin-to-force-quic-on=localhost:" + strconv.Itoa(port),
		"--user-data-dir=" + t.TempDir(),
		"https://localhost:" + strconv.Itoa(port) + "/",
	}
	cmd := exec.Command(browser, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动浏览器失败: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// 4) 嗅探 + 解密 + 重组（复用 quic_sniff.go 的实现）。
	var keys quicInitialKeys
	var keysSet bool
	var reasm cryptoStreamReassembler
	var dgramLens []int
	deadline := time.Now().Add(45 * time.Second)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		_ = sniffer.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := sniffer.ReadFromUDP(buf)
		if err != nil {
			continue // 超时就再等（浏览器启动有延迟）
		}
		dgram := make([]byte, n)
		copy(dgram, buf[:n])
		dgramLens = append(dgramLens, n)
		if len(dgramLens) <= 3 {
			head := dgram
			if len(head) > 12 {
				head = head[:12]
			}
			t.Logf("收到 UDP 报文 #%d：%d 字节，头 %x", len(dgramLens), n, head)
		}

		if !keysSet {
			if len(dgram) < 7 {
				continue
			}
			dcidLen := int(dgram[5])
			if len(dgram) < 6+dcidLen {
				continue
			}
			keys = initialKeys(dgram[6 : 6+dcidLen])
			keysSet = true
		}
		off := 0
		for off < n {
			pkt, err := decryptInitialAt(dgram, off, keys)
			if err != nil {
				t.Logf("decrypt at %d 失败（版本/GREASE 头可能导致）: %v", off, err)
				break
			}
			if pkt == nil || pkt.NextOffset <= off {
				break
			}
			off = pkt.NextOffset
			for _, f := range pkt.CryptoFrames {
				reasm.add(f)
			}
		}
		if _, _, complete := reasm.assembled(); complete {
			break
		}
	}
	cryptoBytes, total, complete := reasm.assembled()
	if len(cryptoBytes) == 0 {
		t.Fatalf("没抓到 QUIC Initial（浏览器可能未启用 QUIC 或端口未命中）")
	}
	t.Logf("Initial datagrams=%v crypto=%d/%d bytes complete=%v", dgramLens, len(cryptoBytes), total, complete)

	chProfile, err := clientHelloFromCrypto(cryptoBytes)
	if err != nil {
		t.Fatalf("解析内层 ClientHello 失败: %v", err)
	}
	inner := chProfile.TLS.Detail

	rec := &h3Record{
		Kind:              "e1_real_browser_h3",
		Name:              name,
		Browser:           browser,
		BrowserVersion:    browserVersionOf(browser),
		CapturedAt:        time.Now().UTC().Format(time.RFC3339),
		ALPN:              "h3",
		InitialDgramLen:   dgramLens[0],
		ClientHelloCrypto: hex.EncodeToString(cryptoBytes),
	}
	rec.Computed = &struct {
		JA4 string `json:"ja4"`
	}{}

	// ALPN 必须是 h3（内层 hello 的形态证据）。
	alpnOK := false
	var rawTP []byte
	for _, e := range inner.Extensions {
		rec.ExtensionTypes = append(rec.ExtensionTypes, e.Type)
		switch e.Type {
		case 16:
			alpnOK = len(e.ALPN) == 1 && e.ALPN[0] == "h3"
		case 57: // quic_transport_parameters
			rawTP, err = hex.DecodeString(e.Data)
			if err != nil {
				t.Fatalf("transport params hex: %v", err)
			}
		case 10:
			for _, g := range e.Groups {
				var x uint32
				if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(g, "0x")), "%x", &x); err == nil {
					rec.Curves = append(rec.Curves, uint16(x))
				}
			}
		case 43:
			for _, v := range e.Versions {
				var x uint32
				if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(v, "0x")), "%x", &x); err == nil {
					rec.Versions = append(rec.Versions, uint16(x))
				}
			}
		case 13:
			for _, s := range e.SigAlgs {
				var x uint32
				if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(s, "0x")), "%x", &x); err == nil {
					rec.SigAlgs = append(rec.SigAlgs, uint16(x))
				}
			}
		case 51:
			for _, k := range e.KeyShares {
				var x uint32
				if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(k, "0x")), "%x", &x); err == nil {
					rec.KeyShares = append(rec.KeyShares, uint16(x))
				}
			}
		}
	}
	for _, c := range inner.Ciphers {
		var x uint32
		if _, err := fmt.Sscanf(strings.ToLower(strings.TrimPrefix(c, "0x")), "%x", &x); err == nil {
			rec.Ciphers = append(rec.Ciphers, uint16(x))
		}
	}
	if !alpnOK {
		t.Errorf("内层 ClientHello 的 ALPN 不是 [h3]")
	}

	// transport params：按**线上顺序**记录（顺序本身是指纹的一部分）。
	if len(rawTP) > 0 {
		ordered, err := parseQUICTransportParamsOrdered(rawTP)
		if err != nil {
			t.Fatalf("解析 transport params: %v", err)
		}
		for _, tp := range ordered {
			r := h3TPRecord{ID: tp.ID, Len: len(tp.Val), Name: tpNames[tp.ID]}
			if tp.ID >= 27 && (tp.ID-27)%31 == 0 {
				r.Grease = true
				r.Name = ""
			} else if v, ok := tpVarint(map[uint64][]byte{tp.ID: tp.Val}, tp.ID); ok && len(tp.Val) <= 8 {
				r.Value = v
			} else {
				r.Hex = hex.EncodeToString(tp.Val)
			}
			rec.TransportParams = append(rec.TransportParams, r)
		}
	} else {
		t.Error("内层 ClientHello 缺 quic_transport_parameters(57)")
	}

	// 我们的 JA4（QUIC 变体）——用同一份已解析 detail 重新编译计算。
	if inner != nil {
		if spec, err := tlscore.CompileDetail(inner); err == nil {
			rec.Computed.JA4 = tlscore.ComputeJA4QUIC(spec)
		}
	}

	// 5) 落盘。
	outDir := filepath.Join("..", "..", "profiles", "evidence", "browsers")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(outDir, name+".json")
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	if rec.InitialDgramLen < 1200 {
		t.Errorf("首个 Initial datagram = %d 字节，QUIC 要求 >= 1200", rec.InitialDgramLen)
	}
	t.Logf("wrote %s", path)
	t.Logf("浏览器 %s；JA4(QUIC) = %s；transport params %d 项",
		rec.BrowserVersion, rec.Computed.JA4, len(rec.TransportParams))
	t.Logf("内层 CH ciphers(%d) = %v", len(rec.Ciphers), rec.Ciphers)
	t.Logf("内层 CH exts(%d)    = %v", len(rec.ExtensionTypes), rec.ExtensionTypes)
	t.Logf("内层 CH curves/key_shares/versions/sigalgs = %v / %v / %v / %v", rec.Curves, rec.KeyShares, rec.Versions, rec.SigAlgs)
	for _, tp := range rec.TransportParams {
		name := tp.Name
		if name == "" {
			name = fmt.Sprintf("id=%#x", tp.ID)
		}
		if tp.Grease {
			name = fmt.Sprintf("GREASE(id=%#x)", tp.ID)
		}
		t.Logf("    %-42s = %d (len=%d)", name, tp.Value, tp.Len)
	}
}

func sanitize(s string) string {
	base := filepath.Base(s)
	base = regexp.MustCompile(`[^a-zA-Z0-9]+`).ReplaceAllString(base, "_")
	base = regexp.MustCompile(`_+$`).ReplaceAllString(base, "")
	base = regexp.MustCompile(`^_+`).ReplaceAllString(base, "")
	if v := browserVersionOf(s); v != "" {
		major := regexp.MustCompile(`^(\d+)`).FindString(v)
		if major != "" {
			return base + "_" + major
		}
	}
	return base
}

// browserVersionOf 从安装目录里的版本号子目录推断浏览器版本（不启动进程去问）。
func browserVersionOf(path string) string {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	var versions []string
	for _, e := range entries {
		if e.IsDir() && re.MatchString(e.Name()) {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		return ""
	}
	sort.Strings(versions)
	return versions[len(versions)-1]
}
