package main

// 错误归因的单测（A-B 两个 handle 交替报错这条最容易踩）。

import (
	"encoding/json"
	"testing"
)

func TestHandleErrorAttribution(t *testing.T) {
	const hA, hB = uint64(1), uint64(2)
	handleErrors.Delete(hA)
	handleErrors.Delete(hB)

	setLastErrorFor(hA, "read_failed", "conn A reset")
	setLastErrorFor(hB, "read_timeout", "conn B idle")

	for _, tc := range []struct {
		h    uint64
		code string
	}{{hA, "read_failed"}, {hB, "read_timeout"}} {
		var e abiError
		if err := json.Unmarshal([]byte(handleErrorJSON(tc.h)), &e); err != nil {
			t.Fatalf("handle %d: unmarshal: %v", tc.h, err)
		}
		if e.Code != tc.code {
			t.Errorf("handle %d code = %q, want %q（按对象取错串了）", tc.h, e.Code, tc.code)
		}
	}

	// 未知 handle 仍是 "{}"：绑定用"空"判定"没有该对象的错误记录"，
	// 不能变成 invalid_handle（那会让 Node 的 errorOf 不再回落线程槽）。
	if got := handleErrorJSON(1 << 40); got != "{}" {
		t.Errorf("未知 handle = %q, want {}", got)
	}
}

func TestSetLastErrorKeepsThreadSlot(t *testing.T) {
	lastErrors.Delete(threadID())
	setLastError("internal", "boom")
	if got := lastErrorJSON(); got == "{}" {
		t.Error("线程槽语义被破坏：gtls_last_error 取不到刚写的错误")
	}
	// handle=0（没对象可归因）也必须写线程槽、且不该 panic
	setLastErrorFor(0, "internal", "zero-handle")
	if got := lastErrorJSON(); got == "{}" {
		t.Error("handle=0 时线程槽没写")
	}
}
