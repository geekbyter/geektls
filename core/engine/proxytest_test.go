package engine

// A8 代理形态测试的假服务端。它们既是隧道，也是"代理侧到底看到了什么"的
// 证据采集器——那正是 socks4 / socks4a / socks5 / socks5h 四档之间唯一的
// 可区分证据（发出去的字节形状不同，而不是"能不能连通"）。

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// socksHello 是一次 SOCKS 握手的解析结果。
type socksHello struct {
	vn     byte // 4 = SOCKS4/4A，5 = SOCKS5
	cd     byte // 命令（1 = CONNECT）
	atyp   byte // 仅 SOCKS5：1=IPv4 3=域名 4=IPv6
	port   uint16
	ip     string
	host   string
	userid string
}

type testSOCKSProxy struct {
	addr string

	mu     sync.Mutex
	hellos []socksHello
	notes  []string // 代理侧提前断开的原因（测试失败时打印，避免只看一个 EOF）
}

func (p *testSOCKSProxy) failf(format string, args ...any) {
	p.mu.Lock()
	p.notes = append(p.notes, fmt.Sprintf(format, args...))
	p.mu.Unlock()
}

func (p *testSOCKSProxy) logNotes(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, n := range p.notes {
		t.Logf("proxy: %s", n)
	}
}

func startSOCKSProxy(t *testing.T) *testSOCKSProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &testSOCKSProxy{addr: ln.Addr().String()}
	go p.serve(ln)
	t.Cleanup(func() { ln.Close() })
	return p
}

// lastHello 取最近一次握手记录；一次都没有则直接 fail。
func (p *testSOCKSProxy) lastHello(t *testing.T) socksHello {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.hellos) == 0 {
		t.Fatal("代理没有收到任何握手")
	}
	return p.hellos[len(p.hellos)-1]
}

func (p *testSOCKSProxy) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *testSOCKSProxy) record(h socksHello) {
	p.mu.Lock()
	p.hellos = append(p.hellos, h)
	p.mu.Unlock()
}

func (p *testSOCKSProxy) handle(c net.Conn) {
	br := bufio.NewReader(c)
	var h socksHello

	vn, err := br.ReadByte()
	if err != nil {
		c.Close()
		return
	}
	h.vn = vn

	var target string
	switch vn {
	case 4:
		if h.cd, err = br.ReadByte(); err != nil {
			c.Close()
			return
		}
		var hdr [6]byte
		if _, err = io.ReadFull(br, hdr[:]); err != nil {
			c.Close()
			return
		}
		h.port = binary.BigEndian.Uint16(hdr[:2])
		h.ip = net.IPv4(hdr[2], hdr[3], hdr[4], hdr[5]).String()
		if h.userid, err = br.ReadString(0); err != nil {
			c.Close()
			return
		}
		h.userid = strings.TrimSuffix(h.userid, "\x00")
		if h.ip == "0.0.0.1" { // SOCKS4A 约定：DSTIP=0.0.0.x ⇒ 域名跟在 USERID 之后
			dom, err := br.ReadString(0)
			if err != nil {
				c.Close()
				return
			}
			h.host = strings.TrimSuffix(dom, "\x00")
		}
		host := h.host
		if host == "" {
			host = h.ip
		}
		target = net.JoinHostPort(host, strconv.Itoa(int(h.port)))
		reply := make([]byte, 8)
		reply[1] = 90 // requested network operation = successful
		binary.BigEndian.PutUint16(reply[2:4], h.port)
		if h.host == "" {
			copy(reply[4:8], net.ParseIP(h.ip).To4())
		}
		if _, err := c.Write(reply); err != nil {
			c.Close()
			return
		}

	case 5:
		nm, err := br.ReadByte()
		if err != nil {
			p.failf("s5 greeting nm: %v", err)
			c.Close()
			return
		}
		if _, err = io.ReadFull(br, make([]byte, nm)); err != nil {
			p.failf("s5 methods: %v", err)
			c.Close()
			return
		}
		if _, err := c.Write([]byte{5, 0}); err != nil { // 选"免认证"
			p.failf("s5 auth reply: %v", err)
			c.Close()
			return
		}
		var hdr [4]byte
		if _, err = io.ReadFull(br, hdr[:]); err != nil {
			p.failf("s5 req hdr: %v", err)
			c.Close()
			return
		}
		// 请求头：VER CD RESERVED ATYP
		h.cd, h.atyp = hdr[1], hdr[3]
		var portRaw [2]byte
		switch hdr[3] {
		case 1, 4:
			n := 4
			if hdr[3] == 4 {
				n = 16
			}
			ip := make([]byte, n)
			if _, err = io.ReadFull(br, ip); err != nil {
				p.failf("s5 addr: %v", err)
				c.Close()
				return
			}
			if _, err = io.ReadFull(br, portRaw[:]); err != nil {
				p.failf("s5 port: %v", err)
				c.Close()
				return
			}
			h.ip = net.IP(ip).String()
			target = net.JoinHostPort(h.ip, strconv.Itoa(int(binary.BigEndian.Uint16(portRaw[:]))))
		case 3:
			l, err := br.ReadByte()
			if err != nil {
				p.failf("s5 domlen: %v", err)
				c.Close()
				return
			}
			dom := make([]byte, l)
			if _, err = io.ReadFull(br, dom); err != nil {
				p.failf("s5 dom: %v", err)
				c.Close()
				return
			}
			if _, err = io.ReadFull(br, portRaw[:]); err != nil {
				p.failf("s5 domport: %v", err)
				c.Close()
				return
			}
			h.host = string(dom)
			target = net.JoinHostPort(h.host, strconv.Itoa(int(binary.BigEndian.Uint16(portRaw[:]))))
		default:
			p.failf("s5 atyp %d 不支持", hdr[3])
			c.Close()
			return
		}
		h.port = binary.BigEndian.Uint16(portRaw[:])
		if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			p.failf("s5 reply: %v", err)
			c.Close()
			return
		}

	default:
		p.failf("VN %d 不是 socks", vn)
		c.Close()
		return
	}

	p.record(h)

	up, err := net.Dial("tcp", target)
	if err != nil {
		p.failf("dial %s: %v", target, err)
		c.Close()
		return
	}
	go func() { io.Copy(up, br); up.Close() }()
	io.Copy(c, up)
	c.Close()
}

// connectProxy 是 HTTP CONNECT 隧道服务端，同时记录它对到的目标与
// Proxy-Authorization 头（CONNECT 那一档的既有行为此前零覆盖）。
type connectProxy struct {
	addr string

	mu    sync.Mutex
	hosts []string
	auths []string
}

func startConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &connectProxy{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *connectProxy) recorded() ([]string, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hosts...), append([]string(nil), p.auths...)
}

func (p *connectProxy) handle(c net.Conn) {
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		c.Close()
		return
	}
	p.mu.Lock()
	p.hosts = append(p.hosts, req.Host)
	p.auths = append(p.auths, req.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()

	if req.Method != http.MethodConnect {
		fmt.Fprint(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		c.Close()
		return
	}
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		c.Close()
		return
	}
	fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { io.Copy(up, c); up.Close() }()
	io.Copy(c, up)
	c.Close()
}
