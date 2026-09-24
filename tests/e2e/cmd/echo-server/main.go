// echo-server：P3 测试用的本地 HTTPS 回环服务（h2 + http/1.1 双协议）。
// 启动后向 stdout 打印一行 "READY <base-url>" 供父进程读取。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/quic-go-utls/http3"
	utlsb "github.com/bogdanfinn/utls"
	"golang.org/x/net/http2"
)

func selfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "geektls-echo"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	cert, err := selfSignedCert()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "path": r.URL.Path, "host": r.Host,
			"body": string(body), "proto": r.Proto,
			"ua": r.Header.Get("User-Agent"),
		})
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/echo", 302)
	})
	mux.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/"})
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/check-cookie", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil {
			http.Error(w, "no cookie", 400)
			return
		}
		fmt.Fprint(w, c.Value)
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		chunk := make([]byte, 16384)
		for i := 0; i < 64; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	})

	// H3 侧：fhttp mux（quic-go-utls http3.Server 吃 fhttp.Handler），同逻辑。
	fmux := fhttp.NewServeMux()
	fmux.HandleFunc("/echo", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method, "path": r.URL.Path, "host": r.Host,
			"body": string(body), "proto": r.Proto,
			"ua": r.Header.Get("User-Agent"),
		})
	})
	fmux.HandleFunc("/stream", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		chunk := make([]byte, 16384)
		for i := 0; i < 64; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})

	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	// H3 over QUIC：同端口 UDP；TCP 响应带 Alt-Svc 广告（驱动 Alt-Svc 学习路径）。
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	h3srv := &http3.Server{
		Handler: fmux,
		TLSConfig: http3.ConfigureTLSConfig(&utlsb.Config{
			Certificates: []utlsb.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
			NextProtos:   []string{"h3"},
		}),
	}
	go h3srv.Serve(udp)

	// Alt-Svc 广告挂在 mux 外层
	altSvc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"`, port))
		mux.ServeHTTP(w, r)
	})
	srv.Handler = altSvc

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	fmt.Printf("READY https://127.0.0.1:%d\n", port)
	os.Stdout.Sync()
	if err := srv.Serve(tls.NewListener(ln, tlsCfg)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
