package engine

// A6：响应 body 的读取超时。
//
// TimeoutMs 只覆盖"dial + TLS + 响应头"，body 逐块读取此前没有任何 deadline：
// 慢速/挂死的服务端能让 gtls_response_read 永久阻塞，把 FFI 调用线程吃掉
// （Node 的 koffi worker、Python 的 asyncio to_thread 线程池都按线程计数）。
//
// 实现选"每次 Read 起一个 goroutine，超时则关闭底层"，而不是给连接挂
// SetReadDeadline：h2 的 body 由连接级 reader 协程喂数据，阻塞点在流缓冲的
// 条件变量上，conn 级 deadline 既解不开这个阻塞，又会把整条共享连接打挂
// （池化后会误伤同连接上的其他流）。而"关闭底层"是三协议共同的取消入口：
// h1 = conn.Close、h2 = 流 reset、h3 = CancelRead。
//
// 超时后本次读取已消耗的字节不可恢复（与 requests / curl 的 read timeout 同
// 语义：连接就此作废，不做"续读"）。被放弃的 goroutine 只写它自己的缓冲，
// 不碰调用方传进来的 buf —— 否则 FFI 那边早就返回的 C 缓冲区会被事后写入。

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// ErrReadTimeout 是一次 body 读取超过 read_timeout_ms 时报的错误
// （FFI 侧映射为 last_error.code = "read_timeout"）。
var ErrReadTimeout = errors.New("engine: read timeout")

// abortableBody 是"立即作废这次读取"的入口。不能拿 Close 当取消用：部分
// body 的 Close 会为了把连接放回池里而先排空剩余字节（stdlib 的 HTTP/1.1
// chunked body 就是），慢服务端能把超时本身挂住几十秒。
type abortableBody interface {
	io.Reader
	abort() error
}

type timeoutReader struct {
	rc       io.ReadCloser
	cancel   func() error // 作废读取（可能是 Close，也可能是 abort）
	d        time.Duration
	mu       sync.Mutex
	timedOut bool
	closed   bool
}

// newTimeoutReader 给 body 挂读取超时；d<=0 时原样返回（零开销，默认路径不变）。
// 必须在解压层之前包住原始 body，才能认出协议层的 abort。
func newTimeoutReader(rc io.ReadCloser, d time.Duration) io.ReadCloser {
	if d <= 0 || rc == nil || rc == http.NoBody {
		return rc
	}
	cancel := rc.Close
	if ab, ok := rc.(abortableBody); ok {
		cancel = ab.abort
	}
	return &timeoutReader{rc: rc, cancel: cancel, d: d}
}

func (r *timeoutReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.timedOut {
		r.mu.Unlock()
		return 0, ErrReadTimeout
	}
	if r.closed {
		r.mu.Unlock()
		return 0, http.ErrBodyReadAfterClose
	}
	r.mu.Unlock()

	type result struct {
		n   int
		err error
	}
	buf := make([]byte, len(p))
	ch := make(chan result, 1)
	go func() {
		n, err := r.rc.Read(buf)
		ch <- result{n, err}
	}()

	select {
	case v := <-ch:
		copy(p, buf[:v.n])
		return v.n, v.err
	case <-time.After(r.d):
		r.mu.Lock()
		r.timedOut = true
		r.mu.Unlock()
		// 作废底层把 goroutine 放出来（它之后只写 buf，不影响调用方）。
		_ = r.cancel()
		return 0, ErrReadTimeout
	}
}

// Close 幂等：超时路径已经关过一次，调用方再 defer Close() 不应重复关底层。
func (r *timeoutReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.timedOut {
		return nil // 底层在超时那一刻已经关掉了
	}
	return r.rc.Close()
}
