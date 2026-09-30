package engine

// 响应透明解压层（对齐 curl_cffi/libcurl/requests 行为）。
//
// 按响应 Content-Encoding 包装 body reader：gzip / deflate（zlib 头 + raw
// flate 容错，curl 同语义）/ br / zstd；多重编码按声明顺序逆序解开
// （Content-Encoding 列表的顺序是"被施加的顺序"，解码从最后一个开始）。
// 全部懒初始化——响应头到达即返回，首个 Read 才动压缩流头；因此
// gtls_response_read 的流式路径读到的就是解压后字节。
// 未知编码原样透传不报错，记 warning。headers 一律保留线上原值
//（Content-Encoding/Content-Length 不篡改，与 requests 一致）。

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decodeStage 是一层解压包装（懒初始化）。
type decodeStage struct {
	inner   *bufio.Reader
	newFn   func(*bufio.Reader) (io.Reader, error)
	rc      io.Reader // 初始化后的实际解码器
	init    bool
	initErr error
}

func (s *decodeStage) Read(p []byte) (int, error) {
	if !s.init {
		s.init = true
		rc, err := s.newFn(s.inner)
		switch {
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			// 空 body 却声明了压缩：按空流处理（容忍非标服务器）
			s.rc = strings.NewReader("")
		case err != nil:
			s.initErr = err
		default:
			s.rc = rc
		}
	}
	if s.initErr != nil {
		return 0, s.initErr
	}
	return s.rc.Read(p)
}

func (s *decodeStage) Close() error {
	if c, ok := s.rc.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// closerFunc 适配 void Close（zstd.Decoder.Close 无返回值）。
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// newDeflateReader：zlib 头嗅探，失败回退 raw flate（curl 的容错语义——
// 线上大量服务器的 "deflate" 实际是无 zlib 头的原始 flate）。
func newDeflateReader(br *bufio.Reader) (io.Reader, error) {
	head, err := br.Peek(2)
	if err != nil {
		return nil, err
	}
	// zlib 头：低半字节 CM=8（deflate），且 (CMF<<8|FLG) 31 整除（FCHECK）
	if head[0]&0x0f == 8 && (int(head[0])<<8|int(head[1]))%31 == 0 {
		return zlib.NewReader(br)
	}
	return flate.NewReader(br), nil
}

func newZstdReader(br *bufio.Reader) (io.Reader, error) {
	zr, err := zstd.NewReader(br)
	if err != nil {
		return nil, err
	}
	return zr.IOReadCloser(), nil
}

// wrapDecompression 按编码链包装 body；返回（包装后的 reader, 是否实际解码,
// warnings）。encodings 为声明顺序（施加顺序），这里逆序包装。
func wrapDecompression(body io.ReadCloser, encodings []string) (io.ReadCloser, bool, []string) {
	var warnings []string
	r := body
	// closers 记录关闭顺序：后包的网络层先关（自顶向下到 body）。
	closers := []io.Closer{body}
	decoded := false
	for i := len(encodings) - 1; i >= 0; i-- {
		enc := strings.ToLower(strings.TrimSpace(encodings[i]))
		if enc == "" || enc == "identity" {
			continue
		}
		st := &decodeStage{inner: bufio.NewReader(r)}
		switch enc {
		case "gzip", "x-gzip":
			st.newFn = func(br *bufio.Reader) (io.Reader, error) { return gzip.NewReader(br) }
		case "deflate":
			st.newFn = newDeflateReader
		case "br":
			st.newFn = func(br *bufio.Reader) (io.Reader, error) { return brotli.NewReader(br), nil }
		case "zstd":
			st.newFn = newZstdReader
		default:
			warnings = append(warnings,
				fmt.Sprintf("unknown content-encoding %q（原样透传）", enc))
			continue
		}
		closers = append([]io.Closer{st}, closers...)
		r = st
		decoded = true
	}
	if !decoded {
		return body, false, warnings
	}
	return &decompressedBody{stage: r, closers: closers}, true, warnings
}

// decompressedBody 是链顶 reader + 有序关闭链。
type decompressedBody struct {
	stage   io.Reader
	closers []io.Closer
}

func (d *decompressedBody) Read(p []byte) (int, error) { return d.stage.Read(p) }

func (d *decompressedBody) Close() error {
	var first error
	for _, c := range d.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// contentEncodings 收集响应头里的全部 Content-Encoding 值（逗号分隔拆分）。
func contentEncodings(headers [][2]string) []string {
	var out []string
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "content-encoding") {
			for _, v := range strings.Split(kv[1], ",") {
				if s := strings.TrimSpace(v); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// applyDecompression 在响应链路上接入透明解压（doSingle 与流式上传的
// Finish 共用）。开关：session 级 opts.auto_decompress（默认 true），
// 请求级 req.auto_decompress 覆盖。headers 保留线上原值。
func (s *Session) applyDecompression(req *Request, resp *Response) {
	if resp.Body == nil {
		return
	}
	ces := contentEncodings(resp.Headers)
	resp.ContentEncoding = strings.Join(ces, ", ")
	if len(ces) == 0 {
		return
	}
	enabled := true
	if s.opts.AutoDecompress != nil {
		enabled = *s.opts.AutoDecompress
	}
	if req.AutoDecompress != nil {
		enabled = *req.AutoDecompress
	}
	if !enabled {
		return
	}
	wrapped, decoded, warnings := wrapDecompression(resp.Body, ces)
	resp.Body = wrapped
	resp.Decoded = decoded
	resp.Warnings = append(resp.Warnings, warnings...)
}
