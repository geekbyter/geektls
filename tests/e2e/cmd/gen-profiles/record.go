package main

// E1 记录 → 预设：把 cmd/e1-browser 落盘的真浏览器证据记录转成标本，
// 再走与抓包标本完全相同的生成链路（build），使「真机 → 预设」可一条命令复现。
//
// 与抓包标本的差别：记录里带**真实常规请求头**（UA / UA-CH / accept-language …），
// 因此 identity 直接用真实值（合成值再准也是猜），只在记录缺头时才退回合成。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/geektls/core/profiles"
	"github.com/geektls/tests/e2e/specimens"
)

// e1Record 对应 tests/e2e/cmd/e1-browser 的记录（只取生成预设所需字段）。
type e1Record struct {
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Browser        string `json:"browser"`
	BrowserVersion string `json:"browser_version"`
	ClientHelloHex string `json:"clienthello_hex"`
	HTTP2          *struct {
		Settings       [][2]uint32 `json:"settings"`
		WindowUpdate   uint32      `json:"window_update"`
		RegularHeaders [][2]string `json:"regular_headers"`
	} `json:"http2"`
}

// loadRecord 读取一个 E1 记录并转成标本。
func loadRecord(path string) (specimens.Item, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return specimens.Item{}, err
	}
	var rec e1Record
	if err := json.Unmarshal(b, &rec); err != nil {
		return specimens.Item{}, fmt.Errorf("%s: %w", path, err)
	}
	if rec.Kind != "e1_real_browser" {
		return specimens.Item{}, fmt.Errorf("%s: kind=%q 不是 E1 真浏览器记录", path, rec.Kind)
	}
	if rec.ClientHelloHex == "" {
		return specimens.Item{}, fmt.Errorf("%s: 缺 clienthello_hex", path)
	}

	ua := headerOf(rec, "user-agent")
	family, major := familyAndVersion(ua, rec.Browser)
	if family == "" || major == "" {
		return specimens.Item{}, fmt.Errorf("%s: 无法从 UA 推断浏览器族/版本：%q", path, ua)
	}
	platform := platformOf(rec, ua)

	it := specimens.Item{
		Name:     fmt.Sprintf("%s_%s_%s", family, major, strings.ToLower(platform)),
		Family:   family,
		Version:  major,
		Platform: platform,
		Hex:      rec.ClientHelloHex,
	}
	if rec.HTTP2 != nil {
		it.H2Settings = rec.HTTP2.Settings
		it.H2ConnFlow = rec.HTTP2.WindowUpdate
		it.Headers = rec.HTTP2.RegularHeaders
	}
	return it, nil
}

func headerOf(rec e1Record, name string) string {
	if rec.HTTP2 == nil {
		return ""
	}
	for _, kv := range rec.HTTP2.RegularHeaders {
		if strings.EqualFold(kv[0], name) {
			return kv[1]
		}
	}
	return ""
}

// familyAndVersion 从 UA 推断浏览器族与主版本（可执行文件名作兜底）。
func familyAndVersion(ua, browserPath string) (string, string) {
	fam := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		fam = "edge"
	case strings.Contains(ua, "Firefox/"):
		fam = "firefox"
	case strings.Contains(ua, "Chrome/"):
		fam = "chrome"
	}
	if fam == "" {
		base := strings.ToLower(filepath.Base(browserPath))
		switch {
		case strings.Contains(base, "msedge"):
			fam = "edge"
		case strings.Contains(base, "firefox"):
			fam = "firefox"
		case strings.Contains(base, "chrome"):
			fam = "chrome"
		}
	}
	major := ""
	if m := regexp.MustCompile(`(?:Chrome|Edg|Firefox)/(\d+)`).FindStringSubmatch(ua); m != nil {
		major = m[1]
	}
	return fam, major
}

// platformOf 优先取 UA-CH 的 sec-ch-ua-platform（真值），否则从 UA 粗判。
func platformOf(rec e1Record, ua string) string {
	if p := strings.Trim(headerOf(rec, "sec-ch-ua-platform"), `"`); p != "" {
		return p
	}
	switch {
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		return "macOS"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	}
	return "Unknown"
}

// familyH3 返回该浏览器族的 H3 节。
//
// **只对 Chromium 家族给值**：Firefox / Safari 的 QUIC transport params 与
// Chromium **不同**，不能家族继承；凭记忆编数值等于制造"看起来对、实际是假"的
// 指纹，比留空更糟（留空时 core/h3 用 quic-go 默认值，至少是"明确的通用 Go 形态"，
// 且 profile 证据表里能一眼看到缺口）。待真实浏览器 H3 抓包
// （tests/e2e/e1_h3_test.go）后再补。
//
// 等级：E4（公开 QUIC 参数 + 家族一致性），逐版本待 E1。
func familyH3(family string) *profiles.HTTP3Profile {
	switch family {
	case "chrome", "edge":
		return &profiles.HTTP3Profile{
			Enabled:     true,
			QUICVersion: "0x00000001",
			// **只列 Config 能生效的键**（core/h3 transportParamsToQUICConfig 只认
			// max_idle_timeout / initial_max_data / initial_max_streams_* /
			// initial_max_stream_data_*）。其余键（max_ack_delay / ack_delay_exponent /
			// active_connection_id_limit / max_udp_payload_size /
			// max_datagram_frame_size）在 quic-go 里是硬编码的，写了也不生效——
			// 列出来只会造成"看似可控"的假象，故不列（差距清单见
			// docs/p4-h3-capability.md）。
			// 值来自真机实测（Chrome 149 E1，见 docs/07-capability-gaps.md §6.1）：
			// initial_max_data = 15728640（原 E4 构造值 10485760 偏小）；
			// 三个 stream 窗口真机同为 6291456（quic-go 只取一个值，见 H3 capability 文档）。
			TransportParams: map[string]uint64{
				"max_idle_timeout":                    30000,
				"initial_max_data":                    15728640,
				"initial_max_stream_data_bidi_local":  6291456,
				"initial_max_stream_data_bidi_remote": 6291456,
				"initial_max_stream_data_uni":         6291456,
				"initial_max_streams_bidi":            100,
				"initial_max_streams_uni":             103,
			},
			// QUIC 内层 CH 形态（实测驱动）：剔 status_request/SCT、补 0x0201、
			// 不发任何 TLS 层 GREASE（cipher/扩展/group/key_share/version 五处）。
			InnerHelloDropExtensions: []uint16{5, 18},
			InnerHelloExtraSigAlgs:   []string{"0x0201"},
			InnerHelloDropGrease:     true,
			Settings:                 [][]uint32{{7, 268435456}},
			GreaseFrames:             true,
			PseudoHeaderOrder:        []string{"m", "a", "s", "p"},
			PriorityParam:            984832,
		}
	}
	return nil
}
