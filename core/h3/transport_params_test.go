package h3

// Q2（2026-09-30）：transport_params_raw 的冲突规则——不许静默忽略。
// 全部在 QUICConfigFromProfile（配置期）报错或映射回 quic.Config。

import (
	"strings"
	"testing"

	"github.com/geektls/core/profiles"
)

func rawProfile(t *testing.T, raw [][]any) *profiles.Profile {
	t.Helper()
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	p.HTTP3 = &profiles.HTTP3Profile{Enabled: true, TransportParamsRaw: raw}
	return p
}

func TestTransportParamsRawConflicts(t *testing.T) {
	// 合法基线：Chrome 149 形态的已知键 + 私有参数 0x11/0x3128（hex 透传）
	t.Run("chrome149全量形态可用", func(t *testing.T) {
		p := rawProfile(t, [][]any{
			{"grease", 7.0},
			{8.0, 100.0}, {1.0, 30000.0}, {6.0, 6291456.0},
			{9.0, 103.0}, {5.0, 6291456.0},
			{17.0, "hex:000000012a3a9aea00000001"}, // 0x11 私有参数
			{7.0, 6291456.0},
			{12584.0, 3922.0}, // 0x3128 私有参数
			{32.0, 65536.0},   // max_datagram_frame_size
			{3.0, 1472.0},     // max_udp_payload_size（Chrome 真值）
			{4.0, 15728640.0},
		})
		if _, err := QUICConfigFromProfile(p); err != nil {
			t.Fatalf("Chrome 149 全量 blob 应当合法: %v", err)
		}
	})

	t.Run("行为映射_0x03与0x20", func(t *testing.T) {
		p := rawProfile(t, [][]any{{3.0, 1472.0}, {32.0, 65536.0}, {1.0, 30000.0}})
		qcfg, err := QUICConfigFromProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		if qcfg.MaxUDPPayloadSize != 1472 {
			t.Errorf("MaxUDPPayloadSize = %d, want 1472（patch #9 行为一致）", qcfg.MaxUDPPayloadSize)
		}
		if qcfg.DatagramFrameSize != 65536 {
			t.Errorf("DatagramFrameSize = %d, want 65536", qcfg.DatagramFrameSize)
		}
	})

	for _, tc := range []struct {
		name string
		raw  [][]any
		want string
	}{
		{"服务端专属_0x00", [][]any{{0.0, "hex:0102"}}, "仅服务端"},
		{"服务端专属_0x02", [][]any{{2.0, "hex:0102"}}, "仅服务端"},
		{"服务端专属_0x0d", [][]any{{13.0, "hex:0102"}}, "仅服务端"},
		{"服务端专属_0x10", [][]any{{16.0, "hex:0102"}}, "仅服务端"},
		{"iscid_0x0f", [][]any{{15.0, "hex:"}}, "initial_source_connection_id"},
		{"重复id", [][]any{{1.0, 100.0}, {1.0, 200.0}}, "重复"},
		{"udp_payload_太小", [][]any{{3.0, 1199.0}}, "越界"},
		{"udp_payload_超出接收缓冲", [][]any{{3.0, 1501.0}}, "越界"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := QUICConfigFromProfile(rawProfile(t, tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want 含 %q", err, tc.want)
			}
		})
	}

	t.Run("map与raw同设报错", func(t *testing.T) {
		p, err := profiles.Get("chrome_133")
		if err != nil {
			t.Fatal(err)
		}
		p.HTTP3 = &profiles.HTTP3Profile{
			Enabled:            true,
			TransportParams:    map[string]uint64{"max_idle_timeout": 30000},
			TransportParamsRaw: [][]any{{1.0, 30000.0}},
		}
		if _, err := QUICConfigFromProfile(p); err == nil || !strings.Contains(err.Error(), "互斥") {
			t.Fatalf("err = %v, want 互斥报错", err)
		}
	})
}
