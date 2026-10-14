package profiles

import "testing"

// TestMergePatch：以预设为底的增量覆盖——扩展列表数组整体替换、身份头覆盖、
// 未 patch 字段继承基底、基底不被污染、未知字段报错、空 patch 原样返回。
func TestMergePatch(t *testing.T) {
	base, err := Get("chrome_154_windows")
	if err != nil {
		t.Fatal(err)
	}
	before := len(base.TLS.Detail.Extensions)

	patched, err := MergePatch(base, []byte(`{
	  "tls": {"detail": {"extensions": [{"type": 0, "sni": "auto"}, {"type": 43, "versions": ["0x0304"]}]}},
	  "identity": {"headers": [["user-agent", "X-Patch/1"]]}
	}`))
	if err != nil {
		t.Fatalf("MergePatch: %v", err)
	}
	if n := len(patched.TLS.Detail.Extensions); n != 2 {
		t.Errorf("extensions = %d, want 2（数组整体替换）", n)
	}
	if patched.Identity == nil || len(patched.Identity.Headers) != 1 ||
		patched.Identity.Headers[0][1] != "X-Patch/1" {
		t.Errorf("identity 覆盖未生效: %+v", patched.Identity)
	}
	// 未 patch 的字段从基底继承（对象递归、缺省不丢）。
	if len(patched.TLS.Detail.Ciphers) == 0 {
		t.Error("未 patch 的字段应继承基底")
	}
	// 基底不被污染。
	if len(base.TLS.Detail.Extensions) != before {
		t.Errorf("基底被污染: %d -> %d", before, len(base.TLS.Detail.Extensions))
	}
	// 未知字段报错（走完整解析校验，不静默吞）。
	if _, err := MergePatch(base, []byte(`{"tls": {"nope": 1}}`)); err == nil {
		t.Error("未知字段应报错")
	}
	// 空 patch 原样返回。
	if p2, err := MergePatch(base, nil); err != nil || p2 != base {
		t.Errorf("空 patch 应原样返回: %v", err)
	}
	// 容错：patch 是"JSON 文本的字符串形态"（绑定层二次编码）也能解析。
	if p3, err := MergePatch(base, []byte(`"{\"identity\":{\"headers\":[[\"user-agent\",\"X-S/1\"]]}}"`)); err != nil {
		t.Errorf("字符串形态 patch 容错失败: %v", err)
	} else if p3.Identity == nil || p3.Identity.Headers[0][1] != "X-S/1" {
		t.Errorf("字符串形态 patch 未生效: %+v", p3.Identity)
	}
}
