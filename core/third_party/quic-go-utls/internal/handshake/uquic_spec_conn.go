package handshake

// geektls patch（见 third_party/GEEKTLS_PATCHES.md）：
// uquicSpecConn 适配 *tls.UQUICConn 到 quicTLSConn，并把 quic-go 传入的
// transport params（已 marshal 的裸字节）填进 spec 里的
// QUICTransportParametersExtension——UQUICConn.SetTransportParameters 在
// preset 模式下不会进 ClientHello（bogdanfinn/utls u_quic.go 的已知行为），
// 必须落到扩展上。
//
// StoreSession 为 no-op：QUIC 会话缓存依赖 uTLS 未导出的 cache key 逻辑，
// 0-RTT/会话复用随 geektls P7-T2 再做（UQUICConn 默认也不发
// QUICStoreSession 事件，此路径实际不会被调到）。

import (
	"fmt"

	tls "github.com/bogdanfinn/utls"
)

type uquicSpecConn struct {
	*tls.UQUICConn
	spec *tls.ClientHelloSpec
}

func (c *uquicSpecConn) StoreSession(*tls.SessionState) error { return nil }

func (c *uquicSpecConn) SetTransportParameters(params []byte) {
	for _, ext := range c.spec.Extensions {
		if qtp, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			qtp.TransportParameters = rawToTransportParameters(params)
			return
		}
	}
	// spec 里没有 QUICTransportParametersExtension 占位时无处可填；
	// geektls 的 h3.QUICConfigFromProfile 总会放占位，静默不填是上游直用场景的合理默认。
}

// rawToTransportParameters 把已 marshal 的 transport params 字节解析为
// FakeQUICTransportParameter 列表（透传，不改字节）。
func rawToTransportParameters(raw []byte) tls.TransportParameters {
	var out tls.TransportParameters
	r := &tpVarintReader{b: raw}
	for r.pos < len(raw) {
		id, err := r.read()
		if err != nil {
			break
		}
		n, err := r.read()
		if err != nil {
			break
		}
		if len(r.b)-r.pos < int(n) {
			break
		}
		val := make([]byte, n)
		copy(val, r.b[r.pos:r.pos+int(n)])
		r.pos += int(n)
		out = append(out, &tls.FakeQUICTransportParameter{Id: id, Val: val})
	}
	return out
}

type tpVarintReader struct {
	b   []byte
	pos int
}

func (r *tpVarintReader) read() (uint64, error) {
	if r.pos >= len(r.b) {
		return 0, fmt.Errorf("eof")
	}
	n := 1 << (r.b[r.pos] >> 6)
	if len(r.b)-r.pos < n {
		return 0, fmt.Errorf("truncated")
	}
	v := uint64(r.b[r.pos] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(r.b[r.pos+i])
	}
	r.pos += n
	return v, nil
}
