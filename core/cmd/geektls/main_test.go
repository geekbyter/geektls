package main

// CLI 冒烟：五个子命令各跑一遍（request 打本地明文服务端，顺带覆盖 G5 明文档）。

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geektls/core/version"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIVersion(t *testing.T) {
	code, out, _ := runCLI(t, "version")
	if code != 0 || !strings.Contains(out, version.Core) {
		t.Fatalf("code=%d out=%q（应含版本 %s）", code, out, version.Core)
	}
}

func TestCLIPresetsJSON(t *testing.T) {
	code, out, _ := runCLI(t, "presets", "--json")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	type row struct{ Name, Grade string }
	var all []row
	if err := json.Unmarshal([]byte(out), &all); err != nil {
		t.Fatalf("presets --json 不是合法 JSON: %v", err)
	}
	if len(all) < 300 {
		t.Fatalf("预设数 %d，太少（内置集应 ≥ 300）", len(all))
	}

	_, out2, _ := runCLI(t, "presets", "--json", "--grade", "self")
	var self []row
	if err := json.Unmarshal([]byte(out2), &self); err != nil {
		t.Fatal(err)
	}
	if len(self) == 0 || len(self) >= len(all) {
		t.Fatalf("--grade self 过滤没生效: %d / %d", len(self), len(all))
	}
	for _, r := range self {
		if r.Grade != "self" {
			t.Fatalf("--grade self 里混进 %+v", r)
		}
	}
}

func TestCLIDescribeAndCheckProfile(t *testing.T) {
	code, out, _ := runCLI(t, "describe", "chrome_133")
	if code != 0 || !json.Valid([]byte(out)) {
		t.Fatalf("describe 输出不是合法 JSON（code=%d）", code)
	}

	code, out, _ = runCLI(t, "check-profile", "chrome_133")
	if code != 0 || !strings.Contains(out, "ja4") || !strings.Contains(out, "ja3_hash") {
		t.Fatalf("check-profile: code=%d out=%q", code, out)
	}

	if code, _, _ := runCLI(t, "check-profile", "ja4:这不是哈希"); code == 0 {
		t.Error("坏入参应当以非 0 退出")
	}
}

func TestCLIRequestPlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "cli-ok")
	}))
	defer srv.Close()

	code, out, errb := runCLI(t, "request", srv.URL+"/x", "--selfcheck")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errb)
	}
	if out != "cli-ok\n" {
		t.Fatalf("stdout = %q（正文应原样输出 + 补换行）", out)
	}
	if !strings.Contains(errb, "selfcheck") {
		t.Errorf("--selfcheck 应写 stderr: %q", errb)
	}
}

func TestCLIRequestFailAndHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Marker", "yes")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "nope")
	}))
	defer srv.Close()

	// 默认：4xx 不改退出码（curl 口径）
	code, _, _ := runCLI(t, "request", srv.URL+"/missing", "-i")
	if code != 0 {
		t.Fatalf("默认 4xx 不该失败: code=%d", code)
	}
	// -i 打印状态行与响应头
	_, out, _ := runCLI(t, "request", srv.URL+"/missing", "-i")
	if !strings.Contains(out, "404") || !strings.Contains(out, "X-Marker: yes") {
		t.Errorf("-i 应打印状态行与响应头: %q", out)
	}
	// --fail：4xx 变退出码 1
	if code, _, _ := runCLI(t, "request", srv.URL+"/missing", "--fail"); code != 1 {
		t.Errorf("--fail 下 4xx 应返回 1，得到 %d", code)
	}
}

func TestCLIUsageErrors(t *testing.T) {
	for _, tc := range [][]string{
		{"request"},
		{"nope"},
		{"request", "http://127.0.0.1:1/", "-H", "novalue"},
		{"describe"},
		{"presets", "--grade"},
	} {
		if code, _, _ := runCLI(t, tc...); code != 2 {
			t.Errorf("%v 应以用法错误码 2 退出，得到 %d", tc, code)
		}
	}
}
