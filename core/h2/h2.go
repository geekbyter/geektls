// Package h2 封装 fhttp/http2：H2 帧层指纹控制（P2）。
//
// 连接建立复用 tlscore 的 uTLS 握手（ALPN 需含 h2），本包只管帧层：
// SETTINGS 值+顺序（含任意/GREASE setting id）、连接级 WINDOW_UPDATE、
// priority 帧序列、伪头顺序。preface 分帧与 Chrome 一致：fhttp 把
// clientPreface+SETTINGS+WINDOW_UPDATE+priorities 缓冲后一次 Flush。
package h2

import (
	"fmt"
	"io"
	"net"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"

	"github.com/geektls/core/profiles"
)

// NewClientConn 在已建立的（TLS）连接上按 http2 profile 建 H2 ClientConn。
// p 为 nil 时给出 Chrome 风格默认值。
func NewClientConn(conn net.Conn, p *profiles.HTTP2Profile) (*http2.ClientConn, error) {
	tr, err := TransportFromProfile(p)
	if err != nil {
		return nil, err
	}
	return tr.NewClientConn(conn)
}

// TransportFromProfile 把 profile.http2 节编译为 fhttp http2.Transport。
func TransportFromProfile(p *profiles.HTTP2Profile) (*http2.Transport, error) {
	tr := &http2.Transport{}
	if p == nil {
		return tr, nil
	}

	if len(p.Settings) > 0 {
		tr.Settings = make(map[http2.SettingID]uint32, len(p.Settings))
		tr.SettingsOrder = make([]http2.SettingID, 0, len(p.Settings))
		for i, kv := range p.Settings {
			if len(kv) != 2 {
				return nil, fmt.Errorf("h2: settings[%d] must be [id, value]", i)
			}
			id := http2.SettingID(kv[0])
			tr.Settings[id] = kv[1]
			tr.SettingsOrder = append(tr.SettingsOrder, id)
		}
	}
	// 连接级 WINDOW_UPDATE 增量（Chrome 15663105 等）
	tr.ConnectionFlow = p.WindowUpdate

	order, err := PseudoHeaderOrder(p.PseudoHeaderOrder)
	if err != nil {
		return nil, err
	}
	tr.PseudoHeaderOrder = order

	// HEADERS 帧内嵌 priority（flags 0x20）。缺省时 fhttp 用 exclusive=true/
	// weight=255（= Chrome 实测形状）；Firefox 实测是 exclusive=false/weight=41，
	// 必须显式覆盖，否则会在 HEADERS 里露出 Chrome 的优先级形态（G11）。
	if hp := p.HeadersPriority; hp != nil {
		tr.HeaderPriority = &http2.PriorityParam{
			StreamDep: hp.StreamDep,
			Exclusive: hp.Exclusive,
			Weight:    hp.Weight,
		}
	}

	// HPACK 编码策略（T-HPACK）：generic/chrome/firefox/safari 四档，
	// 由 vendor fork 的 Transport.HpackStrategy 落地（语义与证据见
	// third_party/fhttp/GEEKTLS_PATCHES.md 与 docs/p2-h2-capability.md）。
	switch p.HpackStrategy {
	case "", http2.HpackStrategyGeneric, http2.HpackStrategyChrome,
		http2.HpackStrategyFirefox, http2.HpackStrategySafari:
		tr.HpackStrategy = p.HpackStrategy
	default:
		return nil, fmt.Errorf("h2: unknown hpack_strategy %q (want chrome/firefox/safari/generic)", p.HpackStrategy)
	}

	for i, pr := range p.Priorities {
		if pr.StreamID%2 == 0 || pr.StreamID == 0 {
			return nil, fmt.Errorf("h2: priorities[%d]: stream_id must be a positive odd client stream id", i)
		}
		tr.Priorities = append(tr.Priorities, http2.Priority{
			StreamID: pr.StreamID,
			PriorityParam: http2.PriorityParam{
				StreamDep: pr.StreamDep,
				Exclusive: pr.Exclusive,
				Weight:    pr.Weight,
			},
		})
	}
	return tr, nil
}

// PseudoHeaderOrder 把短码（m/a/s/p）映射为 fhttp 的伪头名列表。
func PseudoHeaderOrder(codes []string) ([]string, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	m := map[string]string{
		"m": ":method",
		"a": ":authority",
		"s": ":scheme",
		"p": ":path",
	}
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		name, ok := m[c]
		if !ok {
			return nil, fmt.Errorf("h2: unknown pseudo-header code %q (want m/a/s/p)", c)
		}
		out = append(out, name)
	}
	return out, nil
}

// Do 在 H2 连接上发一个请求（P2 最小 API；cookie/重定向/代理在 P3 engine 层）。
// headers 按给定顺序写出；body 为 nil 表示无请求体。
func Do(cc *http2.ClientConn, method, url string, headers [][2]string, body io.Reader) (*fhttp.Response, error) {
	req, err := fhttp.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	order := make([]string, 0, len(headers))
	for _, kv := range headers {
		req.Header.Set(kv[0], kv[1])
		order = append(order, kv[0])
	}
	if len(order) > 0 {
		req.Header[fhttp.HeaderOrderKey] = order
	}
	return cc.RoundTrip(req)
}
