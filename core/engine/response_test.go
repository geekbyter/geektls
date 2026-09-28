package engine

// Response 便捷读取面的单元测试（与 Python/Node 绑定同一套语义：
// 状态判断、大小写不敏感取头、文本编码探测、JSON、缓存）。
// 不联网：直接构造 Response + 假 body。

import (
	"io"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type fakeBody struct {
	data   []byte
	closed bool
}

func (f *fakeBody) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

func (f *fakeBody) Close() error {
	f.closed = true
	return nil
}

func newResp(status int, headers [][2]string, body []byte) (*Response, *fakeBody) {
	fb := &fakeBody{data: body}
	return &Response{Status: status, Headers: headers, UsedProtocol: "h2", Body: fb}, fb
}

func TestResponseStatusHelpers(t *testing.T) {
	r, _ := newResp(200, nil, nil)
	if r.StatusCode() != 200 || !r.OK() || r.Reason() != "OK" {
		t.Fatalf("200: StatusCode=%d OK=%v Reason=%q", r.StatusCode(), r.OK(), r.Reason())
	}
	r404, _ := newResp(404, nil, nil)
	if r404.OK() || r404.Reason() != "Not Found" {
		t.Fatalf("404: OK=%v Reason=%q", r404.OK(), r404.Reason())
	}
	r599, _ := newResp(599, nil, nil)
	if r599.OK() || r599.Reason() != "Server Error" {
		t.Fatalf("599: OK=%v Reason=%q", r599.OK(), r599.Reason())
	}
}

func TestResponseHeaderCaseInsensitive(t *testing.T) {
	r, _ := newResp(200, [][2]string{
		{"Content-Type", "text/html; charset=gbk"},
		{"Set-Cookie", "a=1"},
		{"Set-Cookie", "b=2"},
	}, nil)
	if got := r.Header("content-type"); got != "text/html; charset=gbk" {
		t.Fatalf("Header 大小写不敏感失败: %q", got)
	}
	if got := r.HeaderValues("set-cookie"); len(got) != 2 {
		t.Fatalf("HeaderValues 应返回两个值，得 %v", got)
	}
	if got := parseCharset(r.Header("content-type")); got != "gbk" {
		t.Fatalf("parseCharset = %q", got)
	}
}

func TestResponseTextEncoding(t *testing.T) {
	// 1) 声明 charset=gbk 的 GBK 字节 → 正确解码
	gbk, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte("中文测试"))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newResp(200, [][2]string{{"Content-Type", "text/html; charset=gbk"}}, gbk)
	if got, err := r.Text(); err != nil || got != "中文测试" {
		t.Fatalf("声明 gbk 解码失败: %q %v", got, err)
	}

	// 2) 未声明 charset 的 GBK 字节 → 走 gb18030 兜底
	r2, _ := newResp(200, nil, gbk)
	if got, err := r2.Text(); err != nil || got != "中文测试" {
		t.Fatalf("未声明 charset 的 gb18030 兜底失败: %q %v", got, err)
	}

	// 3) 合法 utf-8 → 原样
	r3, _ := newResp(200, nil, []byte("héllo 世界"))
	if got, _ := r3.Text(); got != "héllo 世界" {
		t.Fatalf("utf-8 解码失败: %q", got)
	}
}

func TestResponseBytesCacheAndJSON(t *testing.T) {
	payload := []byte(`{"a":1,"中文":"值"}`)
	r, fb := newResp(200, nil, payload)
	b1, err := r.Bytes()
	if err != nil || string(b1) != string(payload) {
		t.Fatalf("Bytes: %q %v", b1, err)
	}
	b2, _ := r.Bytes() // 第二次应命中缓存（body 已消费）
	if string(b2) != string(payload) {
		t.Fatalf("Bytes 缓存失败: %q", b2)
	}
	var v map[string]any
	if err := r.JSON(&v); err != nil {
		t.Fatal(err)
	}
	if v["中文"] != "值" || v["a"].(float64) != 1 {
		t.Fatalf("JSON 解析结果不符: %v", v)
	}
	if err := r.Close(); err != nil || !fb.closed {
		t.Fatalf("Close: err=%v closed=%v", err, fb.closed)
	}
}

func TestResponseJSONWithBOM(t *testing.T) {
	r, _ := newResp(200, nil, append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"ok":true}`)...))
	var v map[string]bool
	if err := r.JSON(&v); err != nil || !v["ok"] {
		t.Fatalf("BOM JSON 解析失败: %v %v", v, err)
	}
	_ = strings.TrimSpace("") // 保留 strings 依赖占位（无实际作用）
}
