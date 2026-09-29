package engine

// 流式上传（二期 T2）验证：H2 DATA 帧流、H1 chunked 线上字节形态、
// 上传连接回池复用。

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// TestUploadH2：echo 链路走 h2，body 分 3 块写，服务端回显拼接结果一致。
func TestUploadH2(t *testing.T) {
	echo := startEchoServer(t)
	s := testSession(t, "chrome_133")

	up, err := s.BeginUpload(&Request{Method: "POST", URL: echo.URL + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []string{"hello", ",", "chunked-world"} {
		if _, err := up.Write([]byte(chunk)); err != nil {
			t.Fatalf("write %q: %v", chunk, err)
		}
	}
	resp, err := up.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if resp.UsedProtocol != "h2" {
		t.Errorf("protocol = %q, want h2", resp.UsedProtocol)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "hello,chunked-world") {
		t.Errorf("echo body = %s, 应含拼接后的流式 body", body)
	}
	if resp.SelfCheck.JA4 == "" {
		t.Error("上传响应也应有 selfcheck")
	}
}

// rawChunkCapture：抓原始请求字节的 TLS 服务端（验证 chunked 线上形态）。
type rawChunkCapture struct {
	URL  string
	ln   net.Listener
	got  chan []byte
	cert tls.Certificate
}

func startRawChunkCapture(t *testing.T) *rawChunkCapture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	rc := &rawChunkCapture{got: make(chan []byte, 1), cert: cert}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rc.ln = ln
	rc.URL = "https://" + ln.Addr().String()
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		defer tc.Close()
		br := bufio.NewReader(tc)
		var raw []byte
		buf := make([]byte, 4096)
		// 读到终止 0-chunk 为止（头部 + chunk 帧全量原文）
		for !bytes.Contains(raw, []byte("\r\n0\r\n\r\n")) {
			n, err := br.Read(buf)
			if n > 0 {
				raw = append(raw, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		rc.got <- raw
		io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()
	return rc
}

// TestUploadH1ChunkedWire：剥 ALPN 走 h1；断言线上字节是合法 chunked：
// TE 头存在、无 content-length、每块是 "%x\r\n<data>\r\n"、终止 0-chunk。
func TestUploadH1ChunkedWire(t *testing.T) {
	rc := startRawChunkCapture(t)
	p := h1Profile(t, "chrome_133")
	s, err := NewSession(p, SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	up, err := s.BeginUpload(&Request{Method: "POST", URL: rc.URL + "/up",
		Headers: [][2]string{{"content-length", "999"}, {"x-test", "1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := up.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Write([]byte(" world!")); err != nil {
		t.Fatal(err)
	}
	resp, err := up.Finish()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Status != 200 {
		t.Errorf("status = %d", resp.Status)
	}

	raw := string(<-rc.got)
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	if !strings.Contains(head, "transfer-encoding: chunked") {
		t.Errorf("缺 transfer-encoding: chunked 头:\n%s", head)
	}
	if strings.Contains(strings.ToLower(head), "content-length") {
		t.Errorf("流式上传不应带 content-length:\n%s", head)
	}
	want := "5\r\nhello\r\n7\r\n world!\r\n0\r\n\r\n"
	if body != want {
		t.Errorf("chunked 线上字节 = %q, want %q", body, want)
	}
}
