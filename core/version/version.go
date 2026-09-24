// Package version 集中维护 core 与 ABI 版本常量，是 gtls_version 的数据源。
package version

const (
	// ABI 是 C ABI 主版本号，只增不改；破坏性变更升号（docs/02-ffi-abi.md §4）。
	ABI = 1
	// Core 是 core 语义版本。
	Core = "0.1.0"
	// UTLS 记录所集成 uTLS fork 的版本/commit；P0 尚未接入，为空。
	UTLS = ""
)
