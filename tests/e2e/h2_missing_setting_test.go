package e2e

// Q4 / h2.missing_setting_signal：H2 的"缺失项即信号"。
// E1 实测（profiles/evidence/browsers/chrome_windows*.json、edge_windows.json）：
// Chrome/Edge 的 H2 SETTINGS 恰好只有 {1,2,4,6}——**没有 3**（MAX_CONCURRENT_STREAMS）
// 也**没有 5**（MAX_FRAME_SIZE）。这两项是 curl / 部分代理工具会发而真浏览器不发的
// 区分点，光断言"存在的项正确"挡不住"引擎/预设多发一项"的漂移。
//
// 断言分两层：
//  1. 预设数据层：预设的 http2.settings 与 E1 证据逐项相等（相等本身蕴含缺失），
//     再显式负断言 {3,5} 不在其列——锚点是证据文件而不是预设自身（防自我循环论证）；
//  2. 线上层：captureH2Frames 抓到的 SETTINGS 帧里这些 id 确实不存在
//    （真正的线上负断言，防"引擎偷偷补默认项"）。

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/geektls/core/profiles"
)

// chromeH2EvidenceAbsentIDs 是 E1 证据里 Chrome/Edge **不发**、而其它常见实现
// 会发的 SETTINGS id（负断言对象）。
var chromeH2EvidenceAbsentIDs = []uint32{3, 5}

type h2EvidenceFile struct {
	HTTP2 *struct {
		Settings [][]uint32 `json:"settings"`
	} `json:"http2"`
}

func settingsIDs(settings [][]uint32) []uint32 {
	out := make([]uint32, 0, len(settings))
	for _, kv := range settings {
		out = append(out, kv[0])
	}
	return out
}

func TestH2MissingSettingNegativeAssertion(t *testing.T) {
	// 证据文件 → 对应内置预设（按浏览器版本锚定）。
	cases := []struct {
		evidence string
		preset   string
	}{
		{"chrome_windows.json", "chrome_149_windows"},            // Chrome 149 真机 E1
		{"chrome_149_windows_peetws.json", "chrome_149_windows"}, // peet.ws 字段级
		{"chrome_154_windows_peetws.json", "chrome_154_windows"}, // peet.ws 字段级
		{"edge_windows.json", "edge_153_windows"},                // Edge 153 真机 E1
	}
	for _, tc := range cases {
		t.Run(tc.preset+"/"+tc.evidence, func(t *testing.T) {
			raw, err := os.ReadFile("../../profiles/evidence/browsers/" + tc.evidence)
			if err != nil {
				t.Fatal(err)
			}
			var ev h2EvidenceFile
			if err := json.Unmarshal(raw, &ev); err != nil {
				t.Fatal(err)
			}
			if ev.HTTP2 == nil || len(ev.HTTP2.Settings) == 0 {
				t.Fatal("证据文件没有 http2.settings")
			}
			p, err := profiles.Get(tc.preset)
			if err != nil {
				t.Fatal(err)
			}
			if p.HTTP2 == nil {
				t.Fatalf("预设 %s 没有 http2 节", tc.preset)
			}

			// 正断言 + 蕴含的缺失：预设与证据逐项相等（值与顺序）。
			if fmt.Sprint(p.HTTP2.Settings) != fmt.Sprint(ev.HTTP2.Settings) {
				t.Errorf("预设 settings = %v，E1 证据 = %v", p.HTTP2.Settings, ev.HTTP2.Settings)
			}

			// 显式负断言：证据里不存在的 id，预设里也不能有。
			inPreset := map[uint32]bool{}
			for _, kv := range p.HTTP2.Settings {
				inPreset[kv[0]] = true
			}
			for _, id := range chromeH2EvidenceAbsentIDs {
				if inPreset[id] {
					t.Errorf("预设含 SETTINGS id %d——E1 证据里真浏览器**不发**这项（缺失项即信号）", id)
				}
			}

			// 线上层：真抓帧，断言线上 SETTINGS 没有这些 id。
			cap := captureH2Frames(t, p)
			onWire := map[uint32]bool{}
			for _, kv := range cap.Settings {
				onWire[kv[0]] = true
			}
			for _, id := range chromeH2EvidenceAbsentIDs {
				if onWire[id] {
					t.Errorf("线上 SETTINGS 帧含 id %d——真浏览器不发（引擎不得补默认项）", id)
				}
			}
			for _, kv := range ev.HTTP2.Settings {
				if !onWire[kv[0]] {
					t.Errorf("线上 SETTINGS 帧缺 id %d——证据里有", kv[0])
				}
			}
			t.Logf("%s：线上 SETTINGS ids = %v；%v 确认缺失", tc.preset, settingsIDs(p.HTTP2.Settings), chromeH2EvidenceAbsentIDs)
		})
	}
}
