package tlscore

// 预设入库即测试（03 文档 §3）：每个内置预设必须能编译、能自算 JA3/JA4、
// 无意外 warnings。

import (
	"strings"
	"testing"

	"github.com/geektls/core/profiles"
)

func TestPresetsAreValid(t *testing.T) {
	names := profiles.List()
	if len(names) == 0 {
		t.Fatal("no builtin presets registered")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if p.TLS == nil || p.TLS.Detail == nil {
				t.Fatal("preset has no tls.detail")
			}
			spec, err := CompileDetail(p.TLS.Detail)
			if err != nil {
				t.Fatalf("CompileDetail: %v", err)
			}
			ja3, ja4 := ComputeJA3(spec), ComputeJA4(spec)
			if len(JA3Hash(ja3)) != 32 {
				t.Errorf("bad ja3 hash for %q", ja3)
			}
			parts := strings.Split(ja4, "_")
			if len(parts) != 3 || len(parts[0]) != 10 {
				t.Errorf("bad ja4 %q", ja4)
			}
			t.Logf("%s ja3=%s ja4=%s wire~%dB", name, JA3Hash(ja3), ja4, estimateClientHelloLen(spec))
		})
	}
}

func TestDescribeRoundTrip(t *testing.T) {
	for _, name := range profiles.List() {
		data, err := profiles.Describe(name)
		if err != nil {
			t.Fatalf("Describe(%s): %v", name, err)
		}
		// Describe 输出必须能再 Parse（规范化 JSON 自洽）
		if _, err := profiles.Parse(data); err != nil {
			t.Errorf("Describe(%s) output fails Parse: %v", name, err)
		}
	}
	if _, err := profiles.Describe("no_such_preset"); err == nil {
		t.Error("Describe of unknown preset should fail")
	}
	if _, err := profiles.Describe("../evil"); err == nil {
		t.Error("Describe should reject path traversal")
	}
}
