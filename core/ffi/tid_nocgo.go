//go:build !cgo

package main

// threadID 的无 cgo 兜底。ffi 只能以 c-shared（必须 cgo）产出，此实现
// 仅让 go vet ./... 等纯 Go 工具链在无 gcc 环境下不报错；last error 退化为全局。
func threadID() uint64 { return 0 }
