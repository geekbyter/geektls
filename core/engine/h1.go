package engine

// H1 请求路径：手写请求行 + 有序 header（保大小写）+ body；
// 响应解析用标准库 http.ReadResponse（状态行/头部/chunked 都交给它，
// body 天然流式）。

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/geektls/core/profiles"
)

func (s *Session) doH1(tc *transportConn, req *Request, u *url.URL, headers [][2]string) (*Response, error) {
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

	if _, err := io.WriteString(tc.uconn, w.String()); err != nil {
		return nil, fmt.Errorf("engine: h1 write headers: %w", err)
	}
	if req.Body != nil {
		if _, err := tc.uconn.Write(req.Body); err != nil {
			return nil, fmt.Errorf("engine: h1 write body: %w", err)
		}
	}

	br := bufio.NewReader(tc.uconn)
	stdReq := &http.Request{Method: req.Method}
	resp, err := http.ReadResponse(br, stdReq)
	if err != nil {
		return nil, fmt.Errorf("engine: h1 read response: %w", err)
	}

	out := &Response{
		Status:       resp.StatusCode,
		UsedProtocol: "http/1.1",
		Body: &connClosingReader{
			ReadCloser: resp.Body,
			onClose:    func() { tc.uconn.Close() },
		},
	}
	for name, vals := range resp.Header {
		for _, v := range vals {
			out.Headers = append(out.Headers, [2]string{name, v})
		}
	}
	return out, nil
}

// orderH1Headers 按 profile.http1.header_order 排序请求头（Host 永远最先，
// 未列出的保持原相对顺序追加在后）。大小写原样保留（header_case 默认
// "preserve"；lower/title 在 P3 后续迭代实现）。
func orderH1Headers(p *profiles.Profile, headers [][2]string, u *url.URL) [][2]string {
	host := u.Host
	out := make([][2]string, 0, len(headers)+1)
	out = append(out, [2]string{"host", host})

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
	return append(out, rest...)
}
