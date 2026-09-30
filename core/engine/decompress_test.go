package engine

// T-DECOMP：透明解压单测（矩阵 / 流式跨界 / 空 body / 直通 / 未知编码 / 开关）。

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/geekbyter/geektls/core/profiles"
)

// testCompressPayload 与压缩端点共用正文。
var testCompressPayload = []byte(strings.Repeat("geektls-decompress-check,", 400) + "END")

func gzipIt(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func deflateIt(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func rawFlateIt(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func brIt(b []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func zstdIt(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// registerCompressRoutes 挂到 in-package echo server（engine_test.go）。
func registerCompressRoutes(mux *http.ServeMux) {
	serve := func(enc string, body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", enc)
			w.Header().Set("Content-Type", "text/plain")
			w.Write(body)
		}
	}
	mux.HandleFunc("/gzip", serve("gzip", gzipIt(testCompressPayload)))
	mux.HandleFunc("/deflate", serve("deflate", deflateIt(testCompressPayload)))
	mux.HandleFunc("/deflate-raw", serve("deflate", rawFlateIt(testCompressPayload)))
	mux.HandleFunc("/br", serve("br", brIt(testCompressPayload)))
	mux.HandleFunc("/zstd", serve("zstd", zstdIt(testCompressPayload)))
	mux.HandleFunc("/multi", serve("gzip, br", brIt(gzipIt(testCompressPayload))))
	mux.HandleFunc("/x-enc", serve("xgzip-custom", testCompressPayload))
	mux.HandleFunc("/gzip-empty", serve("gzip", gzipIt(nil)))
}

// TestDecompressMatrix：六种编码路径全解出原文；headers 保留线上原值。
func TestDecompressMatrix(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_133")

	for _, path := range []string{"/gzip", "/deflate", "/deflate-raw", "/br", "/zstd", "/multi"} {
		t.Run(path, func(t *testing.T) {
			resp, err := s.Do(&Request{URL: echo.URL + path})
			if err != nil {
				t.Fatal(err)
			}
			body := readBody(t, resp)
			if body != string(testCompressPayload) {
				t.Errorf("%s 解压后 %d 字节，want %d", path, len(body), len(testCompressPayload))
			}
			if !resp.Decoded {
				t.Errorf("%s decoded 应为 true", path)
			}
			// headers 保留线上原值（Content-Encoding 不删不改）
			if resp.Header("content-encoding") == "" {
				t.Errorf("%s content-encoding 头不应被篡改", path)
			}
			if resp.ContentEncoding == "" {
				t.Errorf("%s info 的 content_encoding 应有值", path)
			}
		})
	}
}

// TestDecompressStreaming：流式小块读（7 字节块跨压缩块边界）。
func TestDecompressStreaming(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_133")

	resp, err := s.Do(&Request{URL: echo.URL + "/gzip"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []byte
	buf := make([]byte, 7) // 刻意不整除，跨压缩块边界
	for {
		n, err := resp.Body.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, testCompressPayload) {
		t.Errorf("流式解压 %d 字节 != %d", len(got), len(testCompressPayload))
	}
}

// TestDecompressEmptyAndPlain：空 gzip body 解为空；无编码 body 直通。
func TestDecompressEmptyAndPlain(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_133")

	resp, err := s.Do(&Request{URL: echo.URL + "/gzip-empty"})
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); len(body) != 0 {
		t.Errorf("空 gzip body 解出 %d 字节", len(body))
	}
	if !resp.Decoded {
		t.Error("gzip-empty decoded 应为 true")
	}

	resp, err = s.Do(&Request{URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if resp.Decoded || resp.ContentEncoding != "" {
		t.Errorf("无编码响应: decoded=%v content_encoding=%q", resp.Decoded, resp.ContentEncoding)
	}
}

// TestDecompressUnknownPassthrough：未知编码原样透传 + warning，不报错。
func TestDecompressUnknownPassthrough(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_133")

	resp, err := s.Do(&Request{URL: echo.URL + "/x-enc"})
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if body != string(testCompressPayload) {
		t.Error("未知编码应原样透传")
	}
	if resp.Decoded {
		t.Error("未知编码 decoded 应为 false")
	}
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], "xgzip-custom") {
		t.Errorf("缺 warning: %v", resp.Warnings)
	}
}

// TestDecompressDisabled：请求级与会话级开关。
func TestDecompressDisabled(t *testing.T) {
	echo := startEchoServer(t)

	// 请求级关闭
	s := testSession(t, "chrome_133")
	off := false
	resp, err := s.Do(&Request{URL: echo.URL + "/gzip", AutoDecompress: &off})
	if err != nil {
		t.Fatal(err)
	}
	raw := readBody(t, resp)
	if resp.Decoded || raw != string(gzipIt(testCompressPayload)) {
		t.Errorf("请求级关闭后应拿到压缩原字节（len=%d decoded=%v）", len(raw), resp.Decoded)
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Error("原字节应以 gzip magic 1f8b 开头")
	}

	// 会话级关闭
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSession(p, SessionOptions{InsecureSkipVerify: true, AutoDecompress: &off})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = s2.Do(&Request{URL: echo.URL + "/br"})
	if err != nil {
		t.Fatal(err)
	}
	raw = readBody(t, resp)
	if resp.Decoded || raw == string(testCompressPayload) {
		t.Error("会话级关闭后不应解压")
	}
}
