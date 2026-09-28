package h3

// transport_params_raw（T4-1，blob 直通）：把 profile 的有序裸参数编译为
// tls.TransportParameters，经 quic.Config.TransportParamsOverride（vendor
// patch #7）原样写入 ClientHello 的 quic_transport_parameters 扩展——
// 顺序、非标参数、GREASE 参数全可控。
//
// 实现取「整块有序直通」而非逐项 setter：只有整块直通才能保住参数顺序与
// 非标 id，逐项设置做不到顺序语义。

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	quic "github.com/bogdanfinn/quic-go-utls"
	utlsb "github.com/bogdanfinn/utls"
)

// buildTransportParamsRaw 编译 profile.http3.transport_params_raw：
// 每项 [id, value]；id 为 float64（JSON 数值）或 "grease"；
// value 为 float64（按 varint 编码）或 "hex:..."（原始字节）。
func buildTransportParamsRaw(entries [][]any) (utlsb.TransportParameters, error) {
	tps := make(utlsb.TransportParameters, 0, len(entries))
	for i, kv := range entries {
		if len(kv) != 2 {
			return nil, fmt.Errorf("h3: transport_params_raw[%d] must be [id, value]", i)
		}
		switch id := kv[0].(type) {
		case float64:
			val, err := rawTPValueBytes(kv[1])
			if err != nil {
				return nil, fmt.Errorf("h3: transport_params_raw[%d]: %w", i, err)
			}
			tps = append(tps, &utlsb.FakeQUICTransportParameter{Id: uint64(id), Val: val})
		case string:
			if id != "grease" {
				return nil, fmt.Errorf("h3: transport_params_raw[%d]: id must be a number or \"grease\"", i)
			}
			n, ok := kv[1].(float64)
			if !ok || n < 0 {
				return nil, fmt.Errorf("h3: transport_params_raw[%d]: grease value must be a body length number", i)
			}
			tps = append(tps, &utlsb.GREASETransportParameter{Length: uint16(n)})
		default:
			return nil, fmt.Errorf("h3: transport_params_raw[%d]: id must be a number or \"grease\"", i)
		}
	}
	return tps, nil
}

func rawTPValueBytes(v any) ([]byte, error) {
	switch val := v.(type) {
	case float64:
		if val < 0 {
			return nil, fmt.Errorf("varint value must be >= 0")
		}
		return appendVarint(nil, uint64(val)), nil
	case string:
		if !strings.HasPrefix(val, "hex:") {
			return nil, fmt.Errorf("string value must have \"hex:\" prefix")
		}
		return hex.DecodeString(val[len("hex:"):])
	default:
		return nil, fmt.Errorf("value must be a number or \"hex:\" string")
	}
}

// appendVarint RFC 9000 §16 varint 编码。
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// readVarintValue 读取一个完整值（应当恰好消费完）。
func readVarintValue(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) != n {
		return 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, true
}

// applyKnownRawTP 行为一致性：从有序裸参数中提取已知流控键值到 quic.Config，
// 使内部流控状态与 wire 声明一致（wire 值与实际行为脱节会被对端触发流控错误）。
// 未覆盖的键（max_udp_payload_size/ack_delay 等）quic-go 内部有默认值，忽略。
func applyKnownRawTP(tps utlsb.TransportParameters, cfg *quic.Config) {
	for _, tp := range tps {
		fake, ok := tp.(*utlsb.FakeQUICTransportParameter)
		if !ok {
			continue
		}
		v, ok := readVarintValue(fake.Val)
		if !ok {
			continue // 非 varint 值（hex 形式）不参与行为映射
		}
		switch fake.Id {
		case 0x1: // max_idle_timeout（ms）
			cfg.MaxIdleTimeout = time.Duration(v) * time.Millisecond
		case 0x4: // initial_max_data
			cfg.InitialConnectionReceiveWindow = v
		case 0x5, 0x6, 0x7: // 三个 stream 窗口（同 map 形态的粒度损失，取先出现者）
			if cfg.InitialStreamReceiveWindow == 0 {
				cfg.InitialStreamReceiveWindow = v
			}
		case 0x8: // initial_max_streams_bidi
			cfg.MaxIncomingStreams = int64(v)
		case 0x9: // initial_max_streams_uni
			cfg.MaxIncomingUniStreams = int64(v)
		}
	}
}
