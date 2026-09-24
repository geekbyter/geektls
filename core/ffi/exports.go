package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"unsafe"

	"github.com/geektls/core/engine"
	"github.com/geektls/core/internal/registry"
	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
	"github.com/geektls/core/version"
)

// 跨 ABI 对象注册表；handle 规则见 docs/02-ffi-abi.md §2。
var handles = registry.New()

// inited 仅供 gtls_init 幂等语义留档；P0 无任何需要初始化的全局状态。
var inited bool

// 跨 ABI 对象：client 持有 profile，session 持有 engine.Session，
// response 持有 engine.Response（body 流式）。
type client struct{ profile *profiles.Profile }

type session struct{ eng *engine.Session }

type response struct{ resp *engine.Response }

// --- 公共辅助 ---

// goString 把 ABI 入参转为 Go string；NULL 视为空串。
func goString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

// parseJSONArg 解析 JSON 入参；空串/NULL 按 "{}" 处理。
// 失败时写入 last error 并返回 false。
func parseJSONArg(s *C.char, dst any) bool {
	raw := goString(s)
	if raw == "" {
		raw = "{}"
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		setLastError("invalid_json", "malformed JSON argument: %v", err)
		return false
	}
	return true
}

func anyKey(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// lookup 取 handle 并校验种类；失败时写入 last error。
func lookup[T any](id uint64, kind string) (*T, bool) {
	v, ok := handles.Get(id)
	if !ok {
		setLastError("invalid_handle", "unknown %s handle %d", kind, id)
		return nil, false
	}
	typed, ok := v.(*T)
	if !ok {
		setLastError("invalid_handle", "handle %d is not a %s", id, kind)
		return nil, false
	}
	return typed, true
}

// closeHandle 删除 handle（类型已校验）；重复 close 返回错误而非 panic。
func closeHandle(id uint64) C.int {
	if err := handles.Delete(id); err != nil {
		setLastError("invalid_handle", "%v", err)
		return -1
	}
	return 0
}

// panic 护栏：任何 panic 都不越过 ABI，转成 last error 并返回该类型的失败值。
func guardCString(ret **C.char) {
	if r := recover(); r != nil {
		setLastError("panic", "%v", r)
		*ret = nil
	}
}

func guardInt(ret *C.int) {
	if r := recover(); r != nil {
		setLastError("panic", "%v", r)
		*ret = -1
	}
}

func guardHandle(ret *C.uint64_t) {
	if r := recover(); r != nil {
		setLastError("panic", "%v", r)
		*ret = 0
	}
}

func guardInt64(ret *C.int64_t) {
	if r := recover(); r != nil {
		setLastError("panic", "%v", r)
		*ret = -1
	}
}

// lockThread 把 goroutine 钉在当前 OS 线程上，保证线程局部 last error
// 落在调用方线程上。每个导出的第一段都是：lockThread + defer guard。
func lockThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// --- 生命周期与元信息 ---

//export gtls_version
func gtls_version() (ret *C.char) {
	defer lockThread()()
	defer guardCString(&ret)
	clearLastError()

	b, err := json.Marshal(struct {
		ABI  int    `json:"abi"`
		Core string `json:"core"`
		UTLS string `json:"utls"`
	}{version.ABI, version.Core, version.UTLS})
	if err != nil {
		setLastError("internal", "marshal version: %v", err)
		return nil
	}
	return C.CString(string(b))
}

//export gtls_init
func gtls_init(optionsJSON *C.char) (ret C.int) {
	defer lockThread()()
	defer guardInt(&ret)
	clearLastError()

	var opts map[string]any
	if !parseJSONArg(optionsJSON, &opts) {
		return -1
	}
	inited = true
	return 0
}

//export gtls_last_error
func gtls_last_error() (ret *C.char) {
	defer lockThread()()
	defer guardCString(&ret) // 本函数自身 panic 时无处可记录，仅保证不越过 ABI
	return C.CString(lastErrorJSON())
}

//export gtls_free_string
func gtls_free_string(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// --- Client / Session ---

// buildProfile 从 client config JSON 构造 profile：
// {"impersonate":"chrome_150"} / {"profile":{...}} / {"ja3"|"ja4r"|"clienthello_hex":"..."}
func buildProfile(cfg map[string]any) (*profiles.Profile, error) {
	if name, ok := cfg["impersonate"].(string); ok && name != "" {
		return profiles.Get(name)
	}
	if raw, ok := cfg["profile"]; ok {
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		return profiles.Parse(b)
	}
	if v, ok := cfg["ja3"].(string); ok && v != "" {
		p, _, err := profiles.FromJA3(v)
		return p, err
	}
	if v, ok := cfg["ja4r"].(string); ok && v != "" {
		p, _, err := profiles.FromJA4R(v)
		return p, err
	}
	if v, ok := cfg["clienthello_hex"].(string); ok && v != "" {
		p, _, err := profiles.FromClientHelloHex(v)
		return p, err
	}
	return nil, fmt.Errorf("config must set one of: impersonate, profile, ja3, ja4r, clienthello_hex")
}

//export gtls_client_new
func gtls_client_new(configJSON *C.char) (ret C.uint64_t) {
	defer lockThread()()
	defer guardHandle(&ret)
	clearLastError()

	if configJSON == nil {
		setLastError("invalid_argument", "config_json must not be NULL")
		return 0
	}
	var cfg map[string]any
	if !parseJSONArg(configJSON, &cfg) {
		return 0
	}
	if cfg == nil {
		setLastError("invalid_json", "config_json must be a JSON object")
		return 0
	}
	p, err := buildProfile(cfg)
	if err != nil {
		setLastError("invalid_config", "%v", err)
		return 0
	}
	return C.uint64_t(handles.Register(&client{profile: p}))
}

//export gtls_client_close
func gtls_client_close(clientH C.uint64_t) (ret C.int) {
	defer lockThread()()
	defer guardInt(&ret)
	clearLastError()

	if _, ok := lookup[client](uint64(clientH), "client"); !ok {
		return -1
	}
	return closeHandle(uint64(clientH))
}

//export gtls_session_new
func gtls_session_new(clientH C.uint64_t, sessionOptsJSON *C.char) (ret C.uint64_t) {
	defer lockThread()()
	defer guardHandle(&ret)
	clearLastError()

	c, ok := lookup[client](uint64(clientH), "client")
	if !ok {
		return 0
	}
	var opts engine.SessionOptions
	if !parseJSONArg(sessionOptsJSON, &opts) {
		return 0
	}
	eng, err := engine.NewSession(c.profile, opts)
	if err != nil {
		setLastError("invalid_config", "%v", err)
		return 0
	}
	return C.uint64_t(handles.Register(&session{eng: eng}))
}

//export gtls_session_close
func gtls_session_close(sessionH C.uint64_t) (ret C.int) {
	defer lockThread()()
	defer guardInt(&ret)
	clearLastError()

	if _, ok := lookup[session](uint64(sessionH), "session"); !ok {
		return -1
	}
	return closeHandle(uint64(sessionH))
}

// --- 请求与响应 ---

//export gtls_request
func gtls_request(sessionH C.uint64_t, requestJSON *C.char) (ret C.uint64_t) {
	defer lockThread()()
	defer guardHandle(&ret)
	clearLastError()

	s, ok := lookup[session](uint64(sessionH), "session")
	if !ok {
		return 0
	}
	var req engine.Request
	if !parseJSONArg(requestJSON, &req) {
		return 0
	}
	if req.URL == "" {
		setLastError("invalid_argument", "request_json must set url")
		return 0
	}
	if req.BodyB64 != "" {
		body, err := base64.StdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			setLastError("invalid_argument", "body_b64: %v", err)
			return 0
		}
		req.Body = body
	}

	resp, err := s.eng.Do(&req)
	if err != nil {
		setLastError("request_failed", "%v", err)
		return 0
	}
	return C.uint64_t(handles.Register(&response{resp: resp}))
}

//export gtls_response_info
func gtls_response_info(respH C.uint64_t) (ret *C.char) {
	defer lockThread()()
	defer guardCString(&ret)
	clearLastError()

	r, ok := lookup[response](uint64(respH), "response")
	if !ok {
		return nil
	}
	b, err := json.Marshal(map[string]any{
		"status":        r.resp.Status,
		"headers":       r.resp.Headers,
		"used_protocol": r.resp.UsedProtocol,
		"selfcheck":     r.resp.SelfCheck,
	})
	if err != nil {
		setLastError("internal", "marshal response info: %v", err)
		return nil
	}
	return C.CString(string(b))
}

//export gtls_response_read
func gtls_response_read(respH C.uint64_t, buf *C.char, bufLen C.int64_t) (ret C.int64_t) {
	defer lockThread()()
	defer guardInt64(&ret)
	clearLastError()

	r, ok := lookup[response](uint64(respH), "response")
	if !ok {
		return -1
	}
	if bufLen <= 0 {
		setLastError("invalid_argument", "buf_len must be positive")
		return -1
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	n, err := r.resp.Body.Read(b)
	if n > 0 {
		return C.int64_t(n)
	}
	if err == io.EOF {
		return 0
	}
	if err != nil {
		setLastError("read_failed", "%v", err)
		return -1
	}
	return 0
}

//export gtls_response_close
func gtls_response_close(respH C.uint64_t) (ret C.int) {
	defer lockThread()()
	defer guardInt(&ret)
	clearLastError()

	r, ok := lookup[response](uint64(respH), "response")
	if !ok {
		return -1
	}
	r.resp.Body.Close()
	return closeHandle(uint64(respH))
}

// --- 预设与自校验（P0 stub） ---

//export gtls_list_presets
func gtls_list_presets() (ret *C.char) {
	defer lockThread()()
	defer guardCString(&ret)
	clearLastError()

	b, err := json.Marshal(profiles.List())
	if err != nil {
		setLastError("internal", "marshal preset list: %v", err)
		return nil
	}
	return C.CString(string(b))
}

//export gtls_describe_preset
func gtls_describe_preset(name *C.char) (ret *C.char) {
	defer lockThread()()
	defer guardCString(&ret)
	clearLastError()

	n := goString(name)
	if n == "" {
		setLastError("invalid_argument", "preset name must not be empty")
		return nil
	}
	b, err := profiles.Describe(n)
	if err != nil {
		setLastError("preset_not_found", "%v", err)
		return nil
	}
	return C.CString(string(b))
}

//export gtls_check_profile
func gtls_check_profile(profileJSONOrJA3OrJA4R *C.char) (ret *C.char) {
	defer lockThread()()
	defer guardCString(&ret)
	clearLastError()

	input := goString(profileJSONOrJA3OrJA4R)
	if input == "" {
		setLastError("invalid_argument", "input must not be empty")
		return nil
	}
	result, err := tlscore.CheckProfile(input)
	if err != nil {
		setLastError("invalid_profile", "%v", err)
		return nil
	}
	b, err := json.Marshal(result)
	if err != nil {
		setLastError("internal", "marshal check result: %v", err)
		return nil
	}
	return C.CString(string(b))
}
