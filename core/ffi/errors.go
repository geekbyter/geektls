package main

import (
	"encoding/json"
	"fmt"
	"sync"
)

// lastErrors 按 OS 线程记录最近一次错误的 JSON（gtls_last_error 是线程局部语义）。
var lastErrors sync.Map // map[threadID]string

// threadHandle 记录每个线程最近一次成功解析的 handle。
var threadHandle sync.Map // map[threadID]handleID

// handleErrors 按对象记录最近一次失败：线程局部错误对"把阻塞调用放到别的
// 线程上执行"的绑定（Node/koffi 的 .async）是不可见的——调用在 worker 线程
// setLastError，回调却回主线程查询。gtls_error_of(handle) 补的就是这条路。
var handleErrors sync.Map // map[handleID]string

type abiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func encodeError(code, format string, args ...any) string {
	b, err := json.Marshal(abiError{Code: code, Message: fmt.Sprintf(format, args...)})
	if err != nil {
		b = []byte(`{"code":"internal","message":"failed to marshal error detail"}`)
	}
	return string(b)
}

func setLastError(code, format string, args ...any) {
	b := encodeError(code, format, args...)
	tid := threadID()
	lastErrors.Store(tid, b)
	if h, ok := threadHandle.Load(tid); ok {
		handleErrors.Store(h, b)
	}
}

// setLastErrorFor 是"点名对象"版：错误同时归档到调用方手里的那个 handle。
//
// 为什么需要它：上面那条 handleErrors 写入依赖 threadHandle（本线程最近一次
// lookup 过的 handle）。异步绑定（Node/koffi 的 .async）在 worker 线程上直接对
// 一个 response/upload/ws handle 报错时，该线程从没 lookup 过它 ⇒
// gtls_error_of(handle) 取回 "{}"，调用方只看到"没有原因"。凡是在错误点上手里
// 已经有 handle 的，都应该走这个函数（同一段错误消息两边都有，保持一致）。
//
// 注：handle 关闭不清理这里的条目 —— 关闭后仍要能查到"它为什么失败"（比如
// gtls_request_finish 失败即回收 upload handle，绑定正是在那一刻回头查错的）。
// 代价是每个"失败过"的 handle 留一条小字符串，属可接受的取舍。
func setLastErrorFor(handle uint64, code, format string, args ...any) {
	b := encodeError(code, format, args...)
	lastErrors.Store(threadID(), b)
	if handle != 0 {
		handleErrors.Store(handle, b)
	}
}

func clearLastError() {
	tid := threadID()
	lastErrors.Delete(tid)
	if h, ok := threadHandle.Load(tid); ok {
		handleErrors.Delete(h)
	}
}

func lastErrorJSON() string {
	if v, ok := lastErrors.Load(threadID()); ok {
		return v.(string)
	}
	return "{}"
}

func handleErrorJSON(id uint64) string {
	if v, ok := handleErrors.Load(id); ok {
		return v.(string)
	}
	return "{}"
}
