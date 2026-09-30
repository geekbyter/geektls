// Package version 集中维护 core 与 ABI 版本常量，以及**指纹栈溯源**信息，
// 是 gtls_version 的数据源。
package version

import (
	"runtime/debug"
	"strings"
	"sync"
)

const (
	// ABI 是 C ABI 主版本号，只增不改；破坏性变更升号（docs/02-ffi-abi.md §4）。
	ABI = 1
	// Core 是 core 语义版本。
	Core = "0.1.6"
)

// stackModules 是"指纹栈"依赖（顺序即报告顺序）。语义见 UTLSVersion。
var stackModules = []string{
	"github.com/refraction-networking/utls", // TCP 侧 ClientHello spec 引擎
	"github.com/bogdanfinn/utls",            // QUIC 内层 TLS（随 quic-go-utls vendor）
	"github.com/bogdanfinn/fhttp",           // H2 帧层 + HPACK（vendor fork）
	"github.com/bogdanfinn/quic-go-utls",    // QUIC + H3（vendor fork）
}

var (
	stackOnce sync.Once
	stackStr  string
)

// UTLSVersion 报告动态库里**实际链接**的指纹栈版本（uTLS 及其同族 fork），形如：
//
//	refraction-networking/utls v1.8.2; bogdanfinn/utls v1.7.8-barnius;
//	bogdanfinn/fhttp v0.6.9 => ./third_party/fhttp; ...
//
// 数据取自二进制内嵌的 build info（runtime/debug.ReadBuildInfo），因此**跟随
// go.mod 自动更新**，不会像手写常量那样漂移；本地 replace 的 vendor fork 会显示成
// `=> ./third_party/...`，正好说明用的是自持 fork 而非上游原版（出问题时报版本也有的放矢）。
//
// 取不到时为 ""（例如 build info 被裁剪的极端构建）——调用方必须容忍空串：
// gtls_version 的 utls 字段就是这个值，历史版本一直为空，属**只填不改**的语义。
func UTLSVersion() string {
	stackOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		var parts []string
		for _, want := range stackModules {
			for _, m := range info.Deps {
				if m.Path != want {
					continue
				}
				v := strings.TrimPrefix(m.Path, "github.com/") + " " + m.Version
				if m.Replace != nil {
					v += " => " + m.Replace.Path
					// 本地目录 replace 的 Version 是占位符 "(devel)"，带上纯属噪音。
					if rv := m.Replace.Version; rv != "" && rv != "(devel)" {
						v += "@" + rv
					}
				}
				parts = append(parts, v)
				break
			}
		}
		stackStr = strings.Join(parts, "; ")
	})
	return stackStr
}
