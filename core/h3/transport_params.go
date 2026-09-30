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

// applyKnownRawTP 行为一致性 + 冲突校验（Q2）：从有序裸参数中提取已知键值到
// quic.Config，使内部流控/接收行为与 wire 声明一致（wire 值与实际行为脱节会被
// 对端触发流控错误或静默丢包）。冲突规则（违反即报错，不静默忽略）：
//
//   - 服务端专属参数（0x00/0x02/0x0d/0x10）出现在客户端 blob ⇒ 错
//   - initial_source_connection_id(0x0f)：必须与逐连接随机 SCID 一致，profile
//     无法钉死 ⇒ 错（Chrome 发空值，前提是 SCID 长度 0；fork 默认 SCID 长 4）
//   - max_udp_payload_size(0x03)：必须 1200..1500（上限 = fork 接收缓冲
//     protocol.MaxIncomingPacketSize；vendor patch #9 把接收缓冲从 1452 提到
//     1500，Chrome 的 1472 因此可用），并映射为 Config.MaxUDPPayloadSize
//     （行为侧供 MTU 发现/非 blob 路径使用）
//   - max_datagram_frame_size(0x20)：映射为 Config.DatagramFrameSize（vendor
//     patch #9：接收 DATAGRAM 帧上限同步放宽，否则声明 65536 却在 >16383 时
//     断连 = 声明与行为脱节）
//   - 同一 id 出现两次（GREASE 除外）⇒ 错（RFC 9000 §7.4：重复参数即
//     TRANSPORT_PARAMETER_ERROR）
//   - max_ack_delay(0x0b)/ack_delay_exponent(0x0a)：纯声明项——描述的是**我们
//     自己**的 ACK 行为，quic-go 发包侧硬编码 MaxAckDelayInclGranularity，
//     声明什么不影响线上正确性（只影响对端 RTT 估计），故不映射、不报错
func applyKnownRawTP(tps utlsb.TransportParameters, cfg *quic.Config) error {
	seen := map[uint64]bool{}
	for _, tp := range tps {
		fake, ok := tp.(*utlsb.FakeQUICTransportParameter)
		if !ok {
			continue // GREASE 参数：id 逐连接随机，不参与校验
		}
		if seen[fake.Id] {
			return fmt.Errorf("h3: transport_params_raw 中参数 %#x 重复（RFC 9000 §7.4 禁止）", fake.Id)
		}
		seen[fake.Id] = true
		if why, bad := forbiddenClientRawTP[fake.Id]; bad {
			return fmt.Errorf("h3: transport_params_raw 不允许包含 %#x：%s", fake.Id, why)
		}
		v, ok := readVarintValue(fake.Val)
		if !ok {
			continue // 非 varint 值（hex 形式）不参与行为映射
		}
		switch fake.Id {
		case 0x1: // max_idle_timeout（ms）
			cfg.MaxIdleTimeout = time.Duration(v) * time.Millisecond
		case 0x3: // max_udp_payload_size
			if v < 1200 || v > 1500 {
				return fmt.Errorf("h3: max_udp_payload_size %d 越界（want 1200..1500；上限=fork 接收缓冲 MaxIncomingPacketSize）", v)
			}
			cfg.MaxUDPPayloadSize = uint16(v)
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
		case 0x20: // max_datagram_frame_size
			cfg.DatagramFrameSize = v
		}
	}
	return nil
}

// forbiddenClientRawTP 是客户端 blob 中禁止出现的 transport parameter id 及原因。
var forbiddenClientRawTP = map[uint64]string{
	0x00: "original_destination_connection_id 仅服务端发送",
	0x02: "stateless_reset_token 仅服务端发送",
	0x0d: "preferred_address 仅服务端发送",
	0x10: "retry_source_connection_id 仅服务端发送",
	0x0f: "initial_source_connection_id 必须与逐连接随机 SCID 一致，profile 钉不死" +
		"（Chrome 发的是空值，前提是 SCID 长度 0；fork 默认 SCID 长 4，SCID 长度控制未接线）",
}
