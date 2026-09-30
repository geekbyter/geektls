package main

// 压缩端点（T-DECOMP 测试）：/gzip /deflate /deflate-raw /br /zstd
// /multi（gzip+br 双重）/x-enc（未知编码透传）。payload 固定可预期。

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// compressPayload 是所有压缩端点的固定正文（可重复 ⇒ 压缩后足够小）。
var compressPayload = []byte(strings.Repeat("geektls-decompress-check,", 400) + "END")

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func deflateBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func rawFlateBytes(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func brBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func zstdBytes(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func registerCompressEndpoints(mux *http.ServeMux) {
	serve := func(enc string, body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", enc)
			w.Header().Set("Content-Type", "text/plain")
			w.Write(body)
		}
	}
	mux.HandleFunc("/gzip", serve("gzip", gzipBytes(compressPayload)))
	mux.HandleFunc("/deflate", serve("deflate", deflateBytes(compressPayload)))
	// deflate-raw：无 zlib 头的原始 flate（线上大量服务器的实际形态）
	mux.HandleFunc("/deflate-raw", serve("deflate", rawFlateBytes(compressPayload)))
	mux.HandleFunc("/br", serve("br", brBytes(compressPayload)))
	mux.HandleFunc("/zstd", serve("zstd", zstdBytes(compressPayload)))
	// multi：先 gzip 后 br（Content-Encoding 按施加顺序声明）
	mux.HandleFunc("/multi", serve("gzip, br", brBytes(gzipBytes(compressPayload))))
	// x-enc：未知编码，原样透传 + warning
	mux.HandleFunc("/x-enc", serve("xgzip-custom", compressPayload))
}
