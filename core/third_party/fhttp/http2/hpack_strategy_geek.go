// geektls patch: HPACK 编码策略钩子（geektls T-HPACK，2026-09-28）。
//
// 背景：上游 x/net 系编码器"一切皆可入动表"（含 :path 等伪头），与真实
// 浏览器不同。四档策略（profile.http2.hpack_strategy）：
//
//	generic —— 上游默认（对照档；geektls 旧行为）
//	chrome  —— QUICHE HpackEncoder DefaultPolicy（Chromium 现网 HTTP/2 栈，
//	          源码级证据）：伪头仅 :authority 入动表，其余伪头 no-index；
//	          常规头全部 incremental indexing；Huffman 更短则用；对默认
//	          4096 表的服务端不发 table size update（上游已有该逻辑）。
//	firefox —— 与 chrome 同形（Firefox 59 真实抓包字节级证据：:authority
//	          与常规头 incremental indexing、:path no-index、Huffman 普遍）。
//	          独立命名以便未来真机证据分叉。
//	safari  —— 保守近似（CFNetwork 闭源，无公开字节级证据，待 E1 校验）：
//	          全 literal 不做动表插入。
//
// 证据与降级说明见 geektls docs/p2-h2-capability.md。

package http2

import (
	"github.com/bogdanfinn/fhttp/http2/hpack"
)

// HPACK 策略名（与 geektls profile.http2.hpack_strategy 对齐）。
const (
	HpackStrategyGeneric = "generic"
	HpackStrategyChrome  = "chrome"
	HpackStrategyFirefox = "firefox"
	HpackStrategySafari  = "safari"
)

// applyHpackStrategy 把策略装到编码器上；空串/generic = 上游默认行为。
func applyHpackStrategy(enc *hpack.Encoder, strategy string) {
	switch strategy {
	case "", HpackStrategyGeneric:
		return
	case HpackStrategyChrome, HpackStrategyFirefox:
		enc.SetIndexPolicy(func(name string, pseudo bool) bool {
			return !pseudo || name == ":authority"
		})
	case HpackStrategySafari:
		enc.SetIndexPolicy(func(name string, pseudo bool) bool { return false })
	}
}
