package engine

import (
	"strings"
	"testing"

	"github.com/geektls/core/version"
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
		"bogdanfinn/utls",
		"bogdanfinn/fhttp",
		"bogdanfinn/quic-go-utls",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("UTLSVersion()=%q 里缺 %s", got, want)
		}
	}
	// vendor fork 必须能看出来（replace 到本地目录），否则"自持 fork"这件事无从断言。
	if !strings.Contains(got, "=> ./third_party/") {
		t.Errorf("UTLSVersion()=%q 未体现 vendor fork 的 replace（应出现 => ./third_party/...）", got)
	}
	if strings.Contains(got, "(devel)") {
		t.Errorf("UTLSVersion()=%q 里混进了本地 replace 的占位版本 (devel)", got)
	}
	t.Logf("指纹栈溯源: %s", got)
}
