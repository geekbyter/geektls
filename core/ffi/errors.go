package main

import (
	"encoding/json"
	"fmt"
	"sync"
)

// lastErrors 按 OS 线程记录最近一次错误的 JSON（gtls_last_error 是线程局部语义）。
var lastErrors sync.Map // map[uint64]string

type abiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func setLastError(code, format string, args ...any) {
	b, err := json.Marshal(abiError{Code: code, Message: fmt.Sprintf(format, args...)})
	if err != nil {
		b = []byte(`{"code":"internal","message":"failed to marshal error detail"}`)
	}
	lastErrors.Store(threadID(), string(b))
}

func clearLastError() { lastErrors.Delete(threadID()) }

func lastErrorJSON() string {
	if v, ok := lastErrors.Load(threadID()); ok {
		return v.(string)
	}
	return "{}"
}
