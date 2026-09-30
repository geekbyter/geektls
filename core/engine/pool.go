package engine

// per-origin 连接池（二期阶段 5）。
//
// 池键 = scheme + "://" + host:port + "|proxy=" + 生效代理 URL。
// profile 在同一 Session 内恒定（池挂在 Session 上），指纹/代理不同的两个
// Session 各自持池，天然不串；同 Session 内 proxy 覆盖（请求级 proxy 字段）
// 会落到不同的键上，亦不串。
//
// H2：同键一条共享连接多路复用（fhttp ClientConn 自身并发安全，
// CanTakeNewRequest 判活）；并发建连撞车时后到的连接作孤儿处理（服务完
// 当前请求即关），保"Chrome 同 origin 一条 h2 连接"的形态。
// H1：keep-alive 空闲队列，每键上限 maxIdleH1PerKey，空闲超时
// h1IdleTimeout；复用失败（服务端静默关连接）换新连接重试一次——
// 请求体在内存中可重放，静默死连接上的写落在 TCP 缓冲、对端未处理，
// 重试不产生重复投递（与 curl/浏览器同策略）。
//
// 复用连接不发新 ClientHello：SelfCheck 在握手时算好随连接走
// （transportConn.sc），复用时原样报告。

import (
	"bufio"
	"net"
	"sync"
	"time"

	"github.com/geekbyter/geektls/core/third_party/fhttp/http2"
)

const (
	maxIdleH1PerKey = 8
	h1IdleTimeout   = 90 * time.Second
)

// poolEntry 是池内一条连接的完整状态。
type poolEntry struct {
	key string
	tc  *transportConn

	// H2
	cc     *http2.ClientConn
	shared bool // true = 正作为池内共享 h2 连接；false = 孤儿（body 关时连连接一起关）

	// H1
	br        *bufio.Reader // 与连接绑定的读缓冲（缓冲字节属于这条流，必须随连接走）
	idleSince time.Time
}

type connPool struct {
	mu     sync.Mutex
	closed bool
	h2     map[string]*poolEntry
	h1Idle map[string][]*poolEntry
}

func newConnPool() *connPool {
	return &connPool{
		h2:     make(map[string]*poolEntry),
		h1Idle: make(map[string][]*poolEntry),
	}
}

// poolKey 计算池键：scheme+host:port+生效代理。代理解析与拨号侧同一个函数
// （proxySpecFor），否则 NO_PROXY / 环境变量派生的代理会让池键与实际连接不一致。
// 缺端口时按 scheme 缺省计（https 443 / http 80，G5）。scheme 必须进键：
// 明文 H1 与 https H1 是两条完全不同的路径，绝不能互相复用。
func (s *Session) poolKey(req *Request, scheme, hostport string) (string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, defaultPort(scheme)
	}
	proxy, err := s.proxySpecFor(req, scheme, host, port)
	if err != nil {
		return "", err
	}
	return scheme + "://" + hostport + "|proxy=" + proxy, nil
}

// --- H2 ---

// getH2 取键下的共享 h2 连接；调用方负责 CanTakeNewRequest 判活，
// 死连接用 removeH2 移除。
func (p *connPool) getH2(key string) *poolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.h2[key]
}

// putH2 登记新建 h2 连接为键下共享连接；已有共享连接时返回 false
// （并发撞车：本连接作孤儿，服务完当前请求即关）。
func (p *connPool) putH2(key string, e *poolEntry) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	if _, exists := p.h2[key]; exists {
		return false
	}
	p.h2[key] = e
	e.shared = true
	return true
}

// removeH2 摘除键下共享连接（仅当还是同一条）。
func (p *connPool) removeH2(key string, e *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h2[key] == e {
		delete(p.h2, key)
		e.shared = false
	}
}

// --- H1 ---

// popH1 取一条空闲 h1 连接；过期的顺手关掉。
func (p *connPool) popH1(key string) *poolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	q := p.h1Idle[key]
	for len(q) > 0 {
		e := q[len(q)-1]
		q = q[:len(q)-1]
		if time.Since(e.idleSince) > h1IdleTimeout {
			e.tc.uconn.Close()
			continue
		}
		p.h1Idle[key] = q
		return e
	}
	p.h1Idle[key] = q
	return nil
}

// putH1 把读干净的 h1 连接放回空闲队列；池满/已关则直接关连接。
func (p *connPool) putH1(key string, e *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		e.tc.uconn.Close()
		return
	}
	q := p.h1Idle[key]
	if len(q) >= maxIdleH1PerKey {
		e.tc.uconn.Close()
		return
	}
	e.idleSince = time.Now()
	p.h1Idle[key] = append(q, e)
}

// drain 排空整个池（Session.Close）：h1 空闲连接与 h2 共享连接全部关闭。
// 仍在进行的 h2 流会随连接关闭而中断——Close 的语义即"会话结束"，
// 调用方应在请求完成后关闭会话（与 net/http 的 Transport.Close 一致）。
func (p *connPool) drain() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for k, e := range p.h2 {
		e.shared = false
		e.tc.uconn.Close()
		delete(p.h2, k)
	}
	for k, q := range p.h1Idle {
		for _, e := range q {
			e.tc.uconn.Close()
		}
		delete(p.h1Idle, k)
	}
}
