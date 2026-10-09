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
	Core = "0.1.9"
)

// stackModules 是"指纹栈"依赖（顺序即报告顺序）。语义见 UTLSVersion。
var stackModules = []string{
	"github.com/refraction-networking/utls",                         // TCP 侧 ClientHello spec 引擎
	"github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn", // QUIC 内层 TLS（随 quic-go-utls vendor）
	"github.com/geekbyter/geektls/core/third_party/fhttp",           // H2 帧层 + HPACK（vendor fork）
	"github.com/geekbyter/geektls/core/third_party/quic-go-utls",    // QUIC + H3（vendor fork）
}

var (
	stackOnce sync.Once
	stackStr  string
)

// UTLSVersion 报告动态库里**实际链接**的指纹栈版本（uTLS 及其同族 fork），形如：
//
//	refraction-networking/utls v1.8.2;
//	geekbyter/geektls/core/third_party/utls-bogdanfinn (in-tree);
//	geekbyter/geektls/core/third_party/fhttp (in-tree); ...
//
// 外部模块（refraction utls）取自二进制内嵌的 build info（runtime/debug.ReadBuildInfo），
// 跟随 go.mod 自动更新；三个 vendor fork 自 2026-09-30 起**内联进 core 模块**
// （core/third_party/*，不再有独立 go.mod / replace），因此不在 build info 的 Deps 里，
// 报告为 `(in-tree)`——版本随 core 一同发布，出问题时报 core 版本即可定位。
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
			found := false
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
				found = true
				break
			}
			if !found && info.Main.Path != "" && strings.HasPrefix(want, info.Main.Path+"/") {
				// 内联 vendor：属于主模块，不在 Deps 里，报告为 (in-tree)。
				parts = append(parts, strings.TrimPrefix(want, "github.com/")+" (in-tree)")
			}
		}
		stackStr = strings.Join(parts, "; ")
	})
	return stackStr
}
