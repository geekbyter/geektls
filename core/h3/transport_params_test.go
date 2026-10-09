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
