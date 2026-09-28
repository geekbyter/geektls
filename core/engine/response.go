package engine

// Response 的便捷读取面——与 Python/Node 绑定保持同一套语义。
//
// 三个绑定对外提供同样的响应视图：
//
//	状态      Go: Status / StatusCode() / OK() / Reason()
//	          Py: status_code / ok / reason        Node: status / statusCode / ok / reason
//	取头      Go: Header(name) / HeaderValues(name)（均大小写不敏感）
//	          Py: headers["Content-Type"]          Node: header('Content-Type')
//	正文      Go: Bytes() / Text() / JSON(&v)       Py: .content/.text/.json()
//	          Node: await bytes()/await text()/await json()
//	流式      Go: Body（io.ReadCloser）             Py: iter_content()/iter_lines()
//	          Node: body（Readable）/iterContent()
//	编码      Text()/text() 都按 Content-Type charset → utf-8 → gb18030 → latin-1 探测
//
// Go 侧保持 net/http 习惯：Body 仍是 io.ReadCloser；下面的 Bytes/Text/JSON 是"读完并缓存"
// 的便捷方法（读完即消费 Body，与 Python 的 .content 语义一致，只应调用一次）。

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// StatusCode 是 Status 的别名（跨语言命名一致）。
func (r *Response) StatusCode() int { return r.Status }

// OK 与 requests 语义一致：4xx/5xx 之外为 true。
func (r *Response) OK() bool { return r.Status < 400 }

// Reason 由状态码本地映射（RFC 9110 常见短语；引擎不上报服务端原文）。
func (r *Response) Reason() string { return reasonPhrase(r.Status) }

// HeaderValues 返回某响应头的全部取值（大小写不敏感）。
func (r *Response) HeaderValues(name string) []string {
	var out []string
	for _, kv := range r.Headers {
		if equalFoldASCII(kv[0], name) {
			out = append(out, kv[1])
		}
	}
	return out
}

// HeaderContentType 便捷取 Content-Type（含 charset 解析用）。
func (r *Response) contentEncoding() string { return parseCharset(r.Header("content-type")) }

// Bytes 读完整 body 并缓存（Body 随之消费；重复调用返回缓存）。
func (r *Response) Bytes() ([]byte, error) {
	if r.body != nil {
		return r.body, nil
	}
	if r.Body == nil {
		r.body = []byte{}
		return r.body, nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("engine: read response body: %w", err)
	}
	r.body = b
	return r.body, nil
}

// Text 按 Content-Type 声明的 charset 解码；未声明时依次尝试
// utf-8 → gb18030 → latin-1（与 Python/Node 绑定同一套兜底，避免中文乱码）。
func (r *Response) Text() (string, error) {
	b, err := r.Bytes()
	if err != nil {
		return "", err
	}
	if enc := r.contentEncoding(); enc != "" && !isUTF8Name(enc) {
		if dec := charsetDecoder(enc); dec != nil {
			if out, derr := dec(b); derr == nil {
				return out, nil
			}
		}
	}
	if utf8.Valid(b) {
		return string(b), nil
	}
	if out, derr := simplifiedchinese.GB18030.NewDecoder().Bytes(b); derr == nil {
		return string(out), nil
	}
	return string(b), nil // latin-1 兜底：逐字节映射，不报错
}

// JSON 解析 body（先按 Text 的编码规则转成字符串再解析）。
func (r *Response) JSON(v any) error {
	s, err := r.Text()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(strings.TrimPrefix(s, "\ufeff")), v)
}

// Close 关闭底层 body（幂等）。
func (r *Response) Close() error {
	if r.Body == nil {
		return nil
	}
	err := r.Body.Close()
	r.Body = nil
	return err
}

// ---- 内部辅助 ----

func isUTF8Name(enc string) bool {
	n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(enc), "_", "-"))
	return n == "utf-8" || n == "utf8" || n == "us-ascii"
}

// charsetDecoder 按名字返回解码函数；只覆盖常见中文/西欧编码，其余交给 utf-8 探测。
func charsetDecoder(enc string) func([]byte) (string, error) {
	n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(enc), "_", "-"))
	switch n {
	case "gb18030", "gbk", "gb2312", "gb-2312":
		return func(b []byte) (string, error) {
			out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(b)
			return string(out), err
		}
	case "latin-1", "latin1", "iso-8859-1", "iso8859-1":
		return func(b []byte) (string, error) { return string(b), nil }
	}
	return nil
}

// parseCharset 从 Content-Type 里取 charset（无则空串）。
func parseCharset(contentType string) string {
	parts := strings.Split(contentType, ";")
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "charset") {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// reasonPhrase 是状态码 → RFC 9110 短语的本地映射。
func reasonPhrase(code int) string {
	if s, ok := reasonPhrases[code]; ok {
		return s
	}
	switch {
	case code >= 100 && code < 200:
		return "Informational"
	case code >= 200 && code < 300:
		return "Success"
	case code >= 300 && code < 400:
		return "Redirection"
	case code >= 400 && code < 500:
		return "Client Error"
	case code >= 500 && code < 600:
		return "Server Error"
	}
	return ""
}

var reasonPhrases = map[int]string{
	100: "Continue", 101: "Switching Protocols",
	200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
	301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
	307: "Temporary Redirect", 308: "Permanent Redirect",
	400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
	405: "Method Not Allowed", 406: "Not Acceptable", 408: "Request Timeout",
	409: "Conflict", 410: "Gone", 413: "Payload Too Large", 415: "Unsupported Media Type",
	418: "I'm a teapot", 422: "Unprocessable Entity", 429: "Too Many Requests",
	500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
	503: "Service Unavailable", 504: "Gateway Timeout",
}
