package engine

// H1 请求路径：手写请求行 + 有序 header（大小写按 profile.http1.header_case）
// + body；响应解析用标准库 http.ReadResponse（状态行/头部/chunked 都交给它，
// body 天然流式）。
//
// keep-alive（二期阶段 5）：body 读到 EOF 且服务端未要求关闭（无
// "Connection: close"、非 HTTP/1.0 无 keep-alive）时，连接回空闲池；
// 未读干净即 Close = 连接作废（协议流不可信，与浏览器/Go 一致）。

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/geektls/core/profiles"
)

func (s *Session) doH1(e *poolEntry, req *Request, u *url.URL, headers [][2]string) (*Response, error) {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var w strings.Builder
	fmt.Fprintf(&w, "%s %s HTTP/1.1\r\n", req.Method, path)

	headers = orderH1Headers(s.profile, headers, u)

	hasContentLength := false
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "content-length") {
			hasContentLength = true
		}
	}
	if req.Body != nil && !hasContentLength {
		fmt.Fprintf(&w, "Content-Length: %d\r\n", len(req.Body))
	}
	for _, kv := range headers {
		fmt.Fprintf(&w, "%s: %s\r\n", kv[0], kv[1])
	}
	w.WriteString("\r\n")

	if _, err := io.WriteString(e.tc.uconn, w.String()); err != nil {
		return nil, fmt.Errorf("engine: h1 write headers: %w", err)
	}
	if req.Body != nil {
		if _, err := e.tc.uconn.Write(req.Body); err != nil {
			return nil, fmt.Errorf("engine: h1 write body: %w", err)
		}
	}

	br := e.br
	if br == nil {
		br = bufio.NewReader(e.tc.uconn)
		e.br = br
	}
	stdReq := &http.Request{Method: req.Method}
	resp, err := http.ReadResponse(br, stdReq)
	if err != nil {
		return nil, fmt.Errorf("engine: h1 read response: %w", err)
	}

	// resp.Close 涵盖 "Connection: close" 与 HTTP/1.0 无显式 keep-alive。
	reuse := !resp.Close && s.poolOn()

	out := &Response{
		Status:       resp.StatusCode,
		UsedProtocol: "http/1.1",
		SelfCheck:    e.tc.sc,
	}
	for name, vals := range resp.Header {
		for _, v := range vals {
			out.Headers = append(out.Headers, [2]string{name, v})
		}
	}

	if resp.Body == http.NoBody {
		// HEAD / 204 / CL=0：无 body，连接立即可复用
		out.Body = http.NoBody
		if reuse {
			s.pool.putH1(e.key, e)
		} else {
			e.tc.uconn.Close()
		}
		return out, nil
	}
	out.Body = &h1Body{ReadCloser: resp.Body, entry: e, pool: s.pool, reuse: reuse}
	return out, nil
}

// h1Body 是 H1 响应体的池感知封装：读到 EOF 且可复用 → 连接回池；
// 提前 Close / 读错误 / 不可复用 → 关连接。
type h1Body struct {
	io.ReadCloser
	entry *poolEntry
	pool  *connPool
	reuse bool
	done  atomic.Bool
}

func (b *h1Body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.release(true)
	} else if err != nil {
		b.release(false)
	}
	return n, err
}

func (b *h1Body) Close() error {
	err := b.ReadCloser.Close()
	b.release(false)
	return err
}

// abort 是读超时的取消入口：直接作废连接，不走 stdlib 那份"为复用连接而排空
// 剩余 body"的 Close（chunked 流的排空会一直读到服务端写完）。
func (b *h1Body) abort() error {
	b.release(false)
	return nil
}

func (b *h1Body) release(cleanEOF bool) {
	if !b.done.CompareAndSwap(false, true) {
		return
	}
	if cleanEOF && b.reuse {
		b.pool.putH1(b.entry.key, b.entry)
	} else {
		b.entry.tc.uconn.Close()
	}
}

// orderH1Headers 按 profile.http1.header_order 排序请求头（Host 永远最先，
// 未列出的保持原相对顺序追加在后），再按 header_case 变换大小写：
// "preserve"（默认，原样保留）/"lower"（全小写）/"title"（逐 dash 段首字母大写，
// 如 User-Agent）。Host 头名也随档变化（preserve/lower 档为 "host"，title 档
// 为 "Host"）。
func orderH1Headers(p *profiles.Profile, headers [][2]string, u *url.URL) [][2]string {
	host := u.Host
	caseMode := ""
	if p.HTTP1 != nil {
		caseMode = p.HTTP1.HeaderCase
	}
	out := make([][2]string, 0, len(headers)+1)
	out = append(out, [2]string{applyHeaderCase(caseMode, "host"), host})

	rest := make([][2]string, 0, len(headers))
	for _, kv := range headers {
		if equalFoldASCII(kv[0], "host") {
			continue // 以 URL 为准
		}
		rest = append(rest, kv)
	}

	if p.HTTP1 != nil && len(p.HTTP1.HeaderOrder) > 0 {
		ranked := make(map[string]int, len(p.HTTP1.HeaderOrder))
		for i, name := range p.HTTP1.HeaderOrder {
			ranked[strings.ToLower(name)] = i
		}
		ordered := make([][2]string, 0, len(rest))
		used := make([]bool, len(rest))
		for _, name := range p.HTTP1.HeaderOrder {
			for i, kv := range rest {
				if !used[i] && equalFoldASCII(kv[0], name) {
					ordered = append(ordered, kv)
					used[i] = true
				}
			}
		}
		for i, kv := range rest {
			if !used[i] {
				ordered = append(ordered, kv)
			}
		}
		rest = ordered
	}
	if caseMode == "lower" || caseMode == "title" {
		for i, kv := range rest {
			rest[i] = [2]string{applyHeaderCase(caseMode, kv[0]), kv[1]}
		}
	}
	return append(out, rest...)
}

// applyHeaderCase 应用 header_case 档；未知档与 "preserve" 都是原样。
func applyHeaderCase(mode, name string) string {
	switch mode {
	case "lower":
		return strings.ToLower(name)
	case "title":
		parts := strings.Split(name, "-")
		for i, p := range parts {
			if p == "" {
				continue
			}
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
		return strings.Join(parts, "-")
	}
	return name
}
