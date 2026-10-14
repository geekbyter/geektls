package h3

// T2.4：transport params 值可控子集补全——max_udp_payload_size /
// max_datagram_frame_size 经 quic.Config 映射生效（E1：Chrome 149/Windows 实测
// 1472 / 65536，profiles/evidence/browsers/chrome_windows_h3.json）。

import (
	"testing"

	"github.com/geekbyter/geektls/core/profiles"
	quic "github.com/geekbyter/geektls/core/third_party/quic-go-utls"
)

func TestTransportParamsUDPAndDatagram(t *testing.T) {
	p, err := profiles.Get("chrome_149_windows")
	if err != nil {
		t.Fatal(err)
	}
	qcfg, err := QUICConfigFromProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if qcfg.MaxUDPPayloadSize != 1472 {
		t.Errorf("MaxUDPPayloadSize = %d, want 1472（E1 实测）", qcfg.MaxUDPPayloadSize)
	}
	if qcfg.DatagramFrameSize != 65536 {
		t.Errorf("DatagramFrameSize = %d, want 65536（E1 实测）", qcfg.DatagramFrameSize)
	}

	// 越界 max_udp_payload_size（RFC 9000 §18.2 合法域 1200..65527）不静默写坏值：
	// 走 unsupported 清单由调用方记录。
	unsup := transportParamsToQUICConfig(
		map[string]uint64{"max_udp_payload_size": 100}, &quic.Config{})
	if len(unsup) != 1 || unsup[0] != "max_udp_payload_size" {
		t.Errorf("越界应进 unsupported，got %v", unsup)
	}
	empty := &quic.Config{}
	transportParamsToQUICConfig(map[string]uint64{}, empty)
	if empty.MaxUDPPayloadSize != 0 {
		t.Errorf("空 map 不应改配置，got %d", empty.MaxUDPPayloadSize)
	}
}

// L-4（2026-10-14）：不可表达的键（未知键 / 越界值）必须经
// QUICConfigFromProfileWithWarnings 带出给调用方——此前唯一调用点丢弃返回值，
// 指纹会静默回落上游默认且零信号。
func TestQUICConfigFromProfileReportsUnsupportedTP(t *testing.T) {
	base, err := profiles.Get("chrome_150_windows")
	if err != nil {
		t.Fatal(err)
	}
	p := &profiles.Profile{
		Name: "test_unsupported_tp",
		TLS:  base.TLS,
		HTTP3: &profiles.HTTP3Profile{TransportParams: map[string]uint64{
			"initial_max_data":     1048576, // 可表达，正常映射
			"bogus_key":            1,       // 未知键
			"max_udp_payload_size": 99999,   // 越界（RFC 9000 §18.2 上限 65527）
		}},
	}
	_, warns, err := QUICConfigFromProfileWithWarnings(p)
	if err != nil {
		t.Fatal(err)
	}
	has := func(k string) bool {
		for _, w := range warns {
			if w == k {
				return true
			}
		}
		return false
	}
	if !has("bogus_key") || !has("max_udp_payload_size") {
		t.Errorf("unsupported 清单 = %v, want 含 bogus_key 与 max_udp_payload_size", warns)
	}
	if has("initial_max_data") {
		t.Errorf("可表达键不应进 unsupported：%v", warns)
	}
	// 旧签名兼容路径行为不变（错误/配置结果一致）。
	if _, err := QUICConfigFromProfile(p); err != nil {
		t.Fatalf("QUICConfigFromProfile: %v", err)
	}
}
