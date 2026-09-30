package handshake

// geektls patch（见 third_party/GEEKTLS_PATCHES.md）：
// uquicSpecConn 适配 *tls.UQUICConn 到 quicTLSConn，并把 quic-go 传入的
// transport params（已 marshal 的裸字节）填进 spec 里的
// QUICTransportParametersExtension——UQUICConn.SetTransportParameters 在
// preset 模式下不会进 ClientHello（bogdanfinn/utls u_quic.go 的已知行为），
// 必须落到扩展上。
//
// StoreSession 委托给 utls fork 补上的 UQUICConn.StoreSession（0-RTT 链路，
// 见 third_party/utls-bogdanfinn/GEEKTLS_PATCHES.md）。

import (
	"fmt"

	tls "github.com/bogdanfinn/utls"
)

type uquicSpecConn struct {
	*tls.UQUICConn
	spec *tls.ClientHelloSpec
	// tpOverride 为 geektls patch #7：非空时原样写入扩展（顺序/非标/GREASE 全可控），
	// 取代对 quic-go 自身 marshal 字节的解析填充。
	tpOverride tls.TransportParameters
}

// geektls vendor fork：StoreSession 委托（0-RTT 链路）——适配器不再 no-op，
// 直接转发给 utls fork 补上的 UQUICConn.StoreSession（票据 Extra 里带对端
// transport params，QUICResumeSession 恢复用）。
func (c *uquicSpecConn) StoreSession(s *tls.SessionState) error {
	return c.UQUICConn.StoreSession(s)
}

func (c *uquicSpecConn) SetTransportParameters(params []byte) {
	for _, ext := range c.spec.Extensions {
		if qtp, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			if len(c.tpOverride) > 0 {
				qtp.TransportParameters = c.tpOverride
			} else {
				qtp.TransportParameters = rawToTransportParameters(params)
			}
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
