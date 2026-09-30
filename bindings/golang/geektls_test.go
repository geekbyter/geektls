package geektls

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/geekbyter/geektls/core/engine"
	"github.com/geekbyter/geektls/core/profiles"
)

func startEcho(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "echo"},
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
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "proto": r.Proto, "body": string(body),
		})
	})
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	}))
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return "https://" + ln.Addr().String()
}

func TestRoundTripper(t *testing.T) {
	base := startEcho(t)
	rt, err := NewRoundTripper("chrome_133", &Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(base + "/echo")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("proto = %s, want HTTP/2", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["method"] != "GET" || got["proto"] != "HTTP/2.0" {
		t.Errorf("echo = %v", got)
	}
	t.Logf("roundtripper echo OK: %s", body)
}

func TestSessionSelfCheck(t *testing.T) {
	base := startEcho(t)
	s, err := NewSession("firefox_120", &Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Do(&engine.Request{Method: "GET", URL: base + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if len(resp.SelfCheck.JA3Hash) != 32 || resp.SelfCheck.JA4 == "" {
		t.Errorf("selfcheck = %+v", resp.SelfCheck)
	}
	t.Logf("go binding ja4=%s", resp.SelfCheck.JA4)
}

// Options → engine.SessionOptions 的字段映射（证书材料在 engine 侧另有测试）。
func TestOptionsMapToEngineSessionOptions(t *testing.T) {
	o := &Options{
		Proxy: "socks5://127.0.0.1:1080", TimeoutMs: 5000, ReadTimeoutMs: 700,
		InsecureSkipVerify: true,
		CABundle:           "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		ClientCert:         "/tmp/client.pem", ClientKey: "/tmp/client.key",
	}
	got := engineOpts(o, false)
	if got.ProxyFromEnv != nil {
		t.Errorf("ProxyFromEnv 未给时应为 nil（=沿用引擎默认）: %+v", got.ProxyFromEnv)
	}
	off := false
	if e := engineOpts(&Options{ProxyFromEnv: &off}, false); e.ProxyFromEnv == nil || *e.ProxyFromEnv {
		t.Errorf("ProxyFromEnv=false 应原样透传: %+v", e.ProxyFromEnv)
	}
	if got.CaBundle != o.CABundle || got.ClientCert != o.ClientCert || got.ClientKey != o.ClientKey {
		t.Errorf("证书材料未透传: %+v", got)
	}
	if got.Proxy != o.Proxy || got.TimeoutMs != o.TimeoutMs || got.ReadTimeoutMs != o.ReadTimeoutMs ||
		!got.InsecureSkipVerify {
		t.Errorf("基础字段未透传: %+v", got)
	}
	if rt := engineOpts(&Options{CABundle: "x"}, true); rt.RedirectMax != -1 || rt.CookieJar == nil || *rt.CookieJar {
		t.Errorf("RoundTripper 模式应关闭引擎侧重定向与 cookie: %+v", rt)
	}

	// A9 地址控制：三项都要原样透传
	nc := &Options{
		Resolve:      map[string]string{"a.example:8443": "192.0.2.1"},
		LocalAddress: "192.0.2.9",
		IPVersion:    "v4",
	}
	e := engineOpts(nc, false)
	if e.Resolve["a.example:8443"] != "192.0.2.1" || e.LocalAddress != nc.LocalAddress || e.IPVersion != nc.IPVersion {
		t.Errorf("地址控制项未透传: %+v", e)
	}
	// 冲突项在建会话时就要失败（不是等到第一次拨号）
	p, err := profiles.Get("chrome_133")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSessionFromProfile(p, &Options{LocalAddress: "eth0"}); err == nil {
		t.Error("网卡名不是 IP 字面量，NewSession 应报错")
	}
}

// startWSEcho 起一个最小 wss echo 服务端（stdlib 没有 WS 服务端，帧层手写）。
// 返回连接串与"握手里的 sec-websocket-extensions 值"（没发则空串）。
// 刻意**不**回声扩展：本用例钉的是"绑定的 DialWS/Compress 是否真的到了线上"，
// 压缩帧层的判据在 core/engine/ws_deflate_test.go（那里有独立写的 stdlib 对端）。
func startWSEcho(t *testing.T) (string, chan string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ws-echo"},
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(conn)

		var wsKey, ext string
		if line, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(line, "GET ") {
			got <- ""
			return
		}
		for {
			h, err := br.ReadString('\n')
			if err != nil {
				got <- ""
				return
			}
			h = strings.TrimRight(h, "\r\n")
			if h == "" {
				break
			}
			name, val, _ := strings.Cut(h, ":")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "sec-websocket-key":
				wsKey = strings.TrimSpace(val)
			case "sec-websocket-extensions":
				ext = strings.TrimSpace(val)
			}
		}
		got <- ext
		accept := base64.StdEncoding.EncodeToString(
			sha1Sum([]byte(wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))
		if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n")); err != nil {
			return
		}
		// 原样回显一条帧（去 mask；服务端帧不回 mask）
		for {
			op, payload, _, err := readWSFrame(br)
			if err != nil {
				return
			}
			if op == WSOpClose {
				return
			}
			if err := writeWSFrame(conn, op, payload); err != nil {
				return
			}
		}
	}()
	return "wss://" + ln.Addr().String() + "/ws", got
}

func sha1Sum(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

// readWSFrame 读客户端帧（RFC 要求必须 masked）。
func readWSFrame(br *bufio.Reader) (op int, payload []byte, fin bool, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	op = int(hdr[0] & 0x0f)
	if hdr[1]&0x80 == 0 {
		return op, nil, fin, errors.New("客户端帧没 mask")
	}
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var e [2]byte
		if _, err = io.ReadFull(br, e[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err = io.ReadFull(br, e[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(e[:])
	}
	var mask [4]byte
	if _, err = io.ReadFull(br, mask[:]); err != nil {
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(br, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return
}

func writeWSFrame(w io.Writer, op int, payload []byte) error {
	hdr := []byte{0x80 | byte(op)}
	n := len(payload)
	switch {
	case n <= 125:
		hdr = append(hdr, byte(n))
	case n <= 0xffff:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127)
		var e [8]byte
		binary.BigEndian.PutUint64(e[:], uint64(n))
		hdr = append(hdr, e[:]...)
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// TestSessionDialWS：Go 绑定也要有 wss（Python/Node 早就有）。钉三件事：
// DialWS 走的是本会话的指纹链路（自签证书要靠 InsecureSkipVerify 才连得上）、
// Compress=true 让 offer 头真的上线、Send/Recv/Close 拉模型可用。
func TestSessionDialWS(t *testing.T) {
	url, gotExt := startWSEcho(t)
	s, err := NewSession("chrome_133", &Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ws, err := s.DialWS(&WSRequest{URL: url, Compress: true})
	if err != nil {
		t.Fatalf("DialWS: %v", err)
	}
	if ext := <-gotExt; ext != "permessage-deflate" {
		t.Errorf("Compress=true 却没把 offer 发出去: %q", ext)
	}
	if err := ws.Send(WSOpText, []byte("go-binding-ws")); err != nil {
		t.Fatal(err)
	}
	op, data, err := ws.Recv(5000)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if op != WSOpText || string(data) != "go-binding-ws" {
		t.Errorf("echo 不符: op=%d %q", op, data)
	}
	if err := ws.Close(1000); err != nil {
		t.Errorf("Close: %v", err)
	}

	// compress=false（默认）：这个头不发——默认形态不变
	url2, gotExt2 := startWSEcho(t)
	ws2, err := s.DialWS(&WSRequest{URL: url2})
	if err != nil {
		t.Fatalf("DialWS(无 compress): %v", err)
	}
	if ext := <-gotExt2; ext != "" {
		t.Errorf("默认不该发 extensions: %q", ext)
	}
	ws2.Close(0)
}
