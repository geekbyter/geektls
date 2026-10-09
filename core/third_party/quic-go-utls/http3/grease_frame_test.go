package http3

// T2.3：GREASE 帧（控制流上、SETTINGS 之后）的生成侧形态钉住。
// 背景：matrix h3.quic_grease_frames 此前 evidence=unverified（E2 真机对拍待
// H3 层采集——现存 E1 链路只采 QUIC 握手层，未含 H3 控制流）；本测试把生成侧
// 钉到 local：帧类型符合 RFC 9114 §7.2.8 的 GREASE 形态（0x1f * N + 0x21）、
// 空载荷、序列化恰好两个 varint。
// 待 E2 采样后可进一步对拍"Chrome 的 N 是每连接随机还是固定"（当前实现固定
// N=1000000000，保持不动——无依据不臆改）。

import (
	"testing"

	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/quicvarint"
)

func TestGreaseFrameFormat(t *testing.T) {
	buf := appendGreaseFrame(nil)

	ft, n, err := quicvarint.Parse(buf)
	if err != nil || n <= 0 {
		t.Fatalf("GREASE 帧类型 varint 解析失败: %v (err=%v)", buf, err)
	}
	// RFC 9114 §7.2.8：GREASE 帧类型 = 0x1f * N + 0x21。
	if ft <= 0x21 || (ft-0x21)%0x1f != 0 {
		t.Errorf("帧类型 %d 不符合 0x1f*N+0x21 形态", ft)
	}

	length, m, err := quicvarint.Parse(buf[n:])
	if err != nil || m <= 0 {
		t.Fatalf("GREASE 帧长度 varint 解析失败: %v", err)
	}
	if length != 0 {
		t.Errorf("帧长度 = %d, want 0（当前实现为空载荷）", length)
	}
	if n+m != len(buf) {
		t.Errorf("序列化多出字节: 共 %d，帧头消费 %d", len(buf), n+m)
	}

	// 当前实现固定 N=1000000000 ⇒ 31000000033；若未来改为逐连接随机，
	// 同步更新 matrix 的 H3-3 结论与 docs。
	if want := uint64(0x1f*1000000000 + 0x21); ft != want {
		t.Errorf("帧类型 = %d, want %d（固定 N 口径；改随机需同步文档）", ft, want)
	}
}
