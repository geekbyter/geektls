package engine

// 请求头顺序策略（G9）。
//
// 背景：反爬里确实有一类检测是看**头的先后顺序**（以及是否恰好是某个字典序）。
// 但真浏览器的头序是固定的，随机化是"对抗顺序检测"的手段，不是更真——两者取舍
// 不同，所以做成显式开关，默认保持与 profile 一致的固定序。
//
// 取值（SessionOptions.HeaderOrder）：
//
//	""/"preserve"  默认：按 profile.http1.header_order（H1）/ 调用方传入序（H2/H3）
//	                归位；**与改动前逐字节相同**。
//	"input"        按调用方传入的原始顺序发（不按 profile 重排），Host 仍在最前。
//	                requests 用户在自己的 headers 字典里排好序时用这个。
//	"random"       在 preserve 的结果上打乱（Host 保持最前）。⚠️ 与真浏览器不符，
//	                且破坏可复现性（回归测试里别开）；只用于绕"顺序即信号"的检测。
//
// 作用范围：H1（含流式上传与 WebSocket 握手）、H2、H3 的**普通头**顺序；
// H2/H3 的伪头顺序（`:method` 等）由 profile.http2.pseudo_header_order 决定，不受影响。

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"

	"github.com/geektls/core/profiles"
)

const (
	headerOrderPreserve = "preserve"
	headerOrderInput    = "input"
	headerOrderRandom   = "random"
)

// normalizeHeaderOrder 归一化并校验取值（建会话时就报错，不留到发请求）。
func normalizeHeaderOrder(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return headerOrderPreserve, nil
	case headerOrderPreserve, "fixed":
		return headerOrderPreserve, nil
	case headerOrderInput, "caller", "as-is":
		return headerOrderInput, nil
	case headerOrderRandom, "shuffle":
		return headerOrderRandom, nil
	default:
		return "", fmt.Errorf("engine: header_order 取值 %q 未知（want preserve / input / random）", v)
	}
}

// randomizeHeaderOrder 打乱普通头顺序（Host 保持在最前）。
// 就地改副本，不改调用方的切片；单头/空头直接原样返回。
func randomizeHeaderOrder(headers [][2]string) [][2]string {
	if len(headers) < 3 {
		return headers
	}
	out := append([][2]string(nil), headers...)
	head := 0
	if equalFoldASCII(out[0][0], "host") {
		head = 1
	}
	rand.Shuffle(len(out)-head, func(i, j int) {
		out[head+i], out[head+j] = out[head+j], out[head+i]
	})
	return out
}

// orderH1Headers 是 H1 侧的策略入口：preserve 走原有 profile 排序（默认路径，
// 字节不变）；input 按调用方原序；random 在 profile 序基础上打乱。
func (s *Session) orderH1Headers(p *profiles.Profile, headers [][2]string, u *url.URL) [][2]string {
	caseMode := ""
	if p != nil && p.HTTP1 != nil {
		caseMode = p.HTTP1.HeaderCase
	}
	switch s.hdrOrder {
	case headerOrderInput:
		return inputOrderHeaders(headers, u.Host, caseMode)
	case headerOrderRandom:
		return randomizeHeaderOrder(orderH1Headers(p, headers, u))
	default:
		return orderH1Headers(p, headers, u)
	}
}

// inputOrderHeaders 按调用方传入顺序重建（Host 从 URL 补在最前，其余去掉 Host）。
// caseMode 仍按 profile.http1.header_case 整形（大小写与顺序是两件事）。
func inputOrderHeaders(headers [][2]string, host, caseMode string) [][2]string {
	out := make([][2]string, 0, len(headers)+1)
	out = append(out, [2]string{applyHeaderCase(caseMode, "host"), host})
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "host") {
			continue
		}
		out = append(out, [2]string{applyHeaderCase(caseMode, kv[0]), kv[1]})
	}
	return out
}
