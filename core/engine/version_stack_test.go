package engine

import (
	"strings"
	"testing"

	"github.com/geekbyter/geektls/core/version"
)

// 指纹栈溯源必须真的接上：core/engine 链接了整条栈（tls + h2/fhttp + h3/quic-go-utls），
// 因此 build info 里必然带着这些模块——若为空，gtls_version 的 utls 字段就退化成空串。
func TestUTLSVersionReportsStack(t *testing.T) {
	got := version.UTLSVersion()
	if got == "" {
		t.Fatal("UTLSVersion() 为空：build info 没接上（utls 溯源字段会退化为空串）")
	}
	for _, want := range []string{
		"refraction-networking/utls",
		"geekbyter/geektls/core/third_party/utls-bogdanfinn (in-tree)",
		"geekbyter/geektls/core/third_party/fhttp (in-tree)",
		"geekbyter/geektls/core/third_party/quic-go-utls (in-tree)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("UTLSVersion()=%q 里缺 %s", got, want)
		}
	}
	// 三个 vendor fork 已内联进 core 模块（2026-09-30），必须能看出 in-tree 身份，
	// 否则"自持 fork"这件事无从断言。
	if !strings.Contains(got, "(in-tree)") {
		t.Errorf("UTLSVersion()=%q 未体现 in-tree vendor fork", got)
	}
	if strings.Contains(got, "(devel)") {
		t.Errorf("UTLSVersion()=%q 里混进了本地 replace 的占位版本 (devel)", got)
	}
	t.Logf("指纹栈溯源: %s", got)
}
