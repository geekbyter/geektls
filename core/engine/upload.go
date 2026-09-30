package engine

// 流式上传（二期 T2）：请求头先行，body 分块写，Finish 收响应头。
//
// 线上形态：H1 走 Transfer-Encoding: chunked（每次 Write 一个 chunk 帧，
// Finish 发终止 0-chunk——浏览器上传未知长度 body 的编码）；H2 走 DATA 帧
// 流（io.Pipe 喂给 fhttp RoundTrip）。H3 不支持（明确报错）。
// 不跟随重定向（body 不可重放）；连接照常进连接池。

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	h2core "github.com/geektls/core/h2"
)

// Upload 是一次进行中的流式上传。Write 可多次调用；Finish 结束 body 并
// 阻塞到响应头到达。不再使用时必须 Finish（否则连接随会话关闭才释放）。
type Upload struct {
	s   *Session
	u   *url.URL
	req *Request

	// H1：连接与写目标（headers 已在 Begin 时发出）
	h1e *poolEntry

	// H2：io.Pipe 喂 DATA 帧
	pw    *io.PipeWriter
	resCh chan uploadResult

	done atomic.Bool
}

type uploadResult struct {
	resp *Response
	err  error
}

// BeginUpload 开始一次流式上传请求：建连（或复用池内连接）并发出请求行
// 与头部（H1 随即进入 chunked 编码态；H2 的 HEADERS 在首个 DATA 前发出）。
// req.Body/BodyB64 忽略（body 走 Write）。force_http3 报错。
func (s *Session) BeginUpload(req *Request) (*Upload, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("engine: session closed")
	}
	if req.Method == "" {
		req.Method = "POST"
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("engine: bad url: %w", err)
	}
	switch u.Scheme {
	case "https", "http":
	default:
		return nil, fmt.Errorf("engine: unsupported scheme %q (want https/http)", u.Scheme)
	}
	if req.ForceHTTP3 {
		return nil, fmt.Errorf("engine: streaming upload over h3 is not supported")
	}

	headers := s.appendCookieHeader(u, s.applyIdentity(req.Headers))
	key, err := s.poolKey(req, u.Scheme, u.Host)
	if err != nil {
		return nil, err
	}

	// 池内 h2 共享连接优先
	if s.poolOn() {
		if e := s.pool.getH2(key); e != nil {
			if e.cc.CanTakeNewRequest() {
				return s.beginH2Upload(e, req, u, headers), nil
			}
			s.pool.removeH2(key, e)
			e.tc.uconn.Close()
		}
	}

	tc, err := s.connect(req, u)
	if err != nil {
		return nil, err
	}
	if tc.proto == "h2" {
		e, err := s.newH2Entry(key, tc)
		if err != nil {
			tc.uconn.Close()
			return nil, err
		}
		return s.beginH2Upload(e, req, u, headers), nil
	}
	return s.beginH1Upload(&poolEntry{key: key, tc: tc}, req, u, headers)
}

// beginH2Upload：fhttp RoundTrip 吃 PipeReader，goroutine 里等响应头。
func (s *Session) beginH2Upload(e *poolEntry, req *Request, u *url.URL, headers [][2]string) *Upload {
	pr, pw := io.Pipe()
	up := &Upload{s: s, u: u, req: req, pw: pw, resCh: make(chan uploadResult, 1)}
	go func() {
		resp, err := h2core.Do(e.cc, req.Method, req.URL, headers, pr)
		if err != nil {
			// RoundTrip 提前失败：关读端唤醒阻塞中的 Write
			pr.CloseWithError(err)
			up.resCh <- uploadResult{err: fmt.Errorf("engine: h2 upload: %w", err)}
			return
		}
		var rc io.ReadCloser = resp.Body
		if !e.shared {
			rc = &connClosingReader{ReadCloser: resp.Body, onClose: func() { e.tc.uconn.Close() }}
		}
		out := &Response{Status: resp.StatusCode, UsedProtocol: "h2", Body: rc, SelfCheck: e.tc.sc}
		for name, vals := range resp.Header {
			for _, v := range vals {
				out.Headers = append(out.Headers, [2]string{name, v})
			}
		}
		up.resCh <- uploadResult{resp: out}
	}()
	return up
}

// beginH1Upload：立即写出请求行 + 头部并进入 chunked 编码态。
func (s *Session) beginH1Upload(e *poolEntry, req *Request, u *url.URL, headers [][2]string) (*Upload, error) {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	headers = orderH1Headers(s.profile, headers, u)

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)
	// 流式上传长度未知：剥离用户给的 content-length，TE chunked 收尾
	//（浏览器对未知长度上传的线上形态；TE 放最后）。
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "content-length") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", kv[0], kv[1])
	}
	b.WriteString("transfer-encoding: chunked\r\n\r\n")

	if _, err := io.WriteString(e.tc.uconn, b.String()); err != nil {
		e.tc.uconn.Close()
		return nil, fmt.Errorf("engine: h1 upload write headers: %w", err)
	}
	return &Upload{s: s, u: u, req: req, h1e: e}, nil
}

// Write 写一块 body：H1 是一个 chunk 帧（%x\r\n<data>\r\n），H2 喂给 DATA
// 流。空写（len 0）是 no-op——终止帧由 Finish 发。
func (u *Upload) Write(p []byte) (int, error) {
	if u.done.Load() {
		return 0, fmt.Errorf("engine: upload already finished")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if u.pw != nil {
		n, err := u.pw.Write(p)
		if err != nil {
			return n, fmt.Errorf("engine: h2 upload write: %w", err)
		}
		return n, nil
	}
	conn := u.h1e.tc.uconn
	if _, err := fmt.Fprintf(conn, "%x\r\n", len(p)); err != nil {
		return 0, fmt.Errorf("engine: h1 upload chunk head: %w", err)
	}
	if _, err := conn.Write(p); err != nil {
		return 0, fmt.Errorf("engine: h1 upload chunk data: %w", err)
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		return 0, fmt.Errorf("engine: h1 upload chunk tail: %w", err)
	}
	return len(p), nil
}

// Finish 结束 body（H1 发终止 0-chunk；H2 关闭 DATA 流），阻塞到响应头
// 到达并返回 Response（body 读取/连接回收语义与普通请求一致）。
func (u *Upload) Finish() (*Response, error) {
	if !u.done.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("engine: upload already finished")
	}
	if u.pw != nil {
		u.pw.Close()
		r := <-u.resCh
		if r.err != nil {
			return nil, r.err
		}
		r.resp.Body = newTimeoutReader(r.resp.Body, u.s.readTimeout(u.req))
		u.s.applyDecompression(u.req, r.resp)
		u.s.absorbResponseMeta(u.u, r.resp)
		return r.resp, nil
	}

	e := u.h1e
	if _, err := io.WriteString(e.tc.uconn, "0\r\n\r\n"); err != nil {
		e.tc.uconn.Close()
		return nil, fmt.Errorf("engine: h1 upload finish: %w", err)
	}
	if e.br == nil {
		e.br = bufio.NewReader(e.tc.uconn)
	}
	resp, err := http.ReadResponse(e.br, &http.Request{Method: "POST"})
	if err != nil {
		e.tc.uconn.Close()
		return nil, fmt.Errorf("engine: h1 upload read response: %w", err)
	}
	reuse := !resp.Close && u.s.poolOn()
	out := &Response{Status: resp.StatusCode, UsedProtocol: "http/1.1", SelfCheck: e.tc.sc}
	for name, vals := range resp.Header {
		for _, v := range vals {
			out.Headers = append(out.Headers, [2]string{name, v})
		}
	}
	if resp.Body == http.NoBody {
		out.Body = http.NoBody
		if reuse {
			u.s.pool.putH1(e.key, e)
		} else {
			e.tc.uconn.Close()
		}
	} else {
		out.Body = &h1Body{ReadCloser: resp.Body, entry: e, pool: u.s.pool, reuse: reuse}
	}
	u.s.applyDecompression(u.req, out)
	u.s.absorbResponseMeta(u.u, out)
	out.Body = newTimeoutReader(out.Body, u.s.readTimeout(u.req))
	return out, nil
}
