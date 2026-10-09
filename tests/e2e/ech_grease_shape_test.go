package e2e

// T5.1 线上字节断言：GREASE ECH（65037）的形状必须**在最终线上字节上**成立，
// 而不只是编译产物字段——这条链是"我们的候选集/线长集 → utls 的每连接随机挑
// + 线长 +16 → marshal 出的字节"。
//
// 判据（2026-10-08 Firefox 157 四样本裁定）：
//   - firefox_157_windows 预设：aead ∈ {1,3} 与 payload_len ∈ {240,400} 两维
//     独立随机（真实 Firefox 也如此），kdf=1、enc_len=32 恒定；
//   - 对照 chrome 族：aead 恒 1、payload_len ∈ {144,176,208,240}。
//
// 手法：本地 TCP listener 只读 ClientHello 原始字节（不做握手，连接让它断，
// 客户端错误一律忽略——我们只要"发出的字节"）。

import (
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/geekbyter/geektls/core/profiles"
	tlscore "github.com/geekbyter/geektls/core/tls"
)

// chCapture 起一个只收 ClientHello 原始字节的本地 listener。
type chCapture struct {
	ln  net.Listener
	ch  chan []byte
	cfg *utls.Config
}

func startCHCapture(t *testing.T) *chCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &chCapture{
		ln:  ln,
		ch:  make(chan []byte, 64),
		cfg: &utls.Config{ServerName: "example.com", InsecureSkipVerify: true},
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(cn net.Conn) {
				defer cn.Close()
				_ = cn.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 8192)
				n, _ := cn.Read(buf)
				if n > 0 {
					out := make([]byte, n)
					copy(out, buf[:n])
					c.ch <- out
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

// sendCapture 打一发（忽略握手错误），返回服务端读到的原始字节。
func (c *chCapture) sendCapture(t *testing.T, spec *utls.ClientHelloSpec) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", c.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer conn.Close()
		_, _ = tlscore.Handshake(conn, c.cfg, spec) // 服务端不做握手，必错，忽略
	}()
	select {
	case b := <-c.ch:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("5s 内未捕获到 ClientHello")
		return nil
	}
}

// parseECHOnWire 从原始 ClientHello 字节提取 65037 的关键字段并做结构校验。
func parseECHOnWire(t *testing.T, b []byte) (aead uint16, payloadLen int) {
	t.Helper()
	if len(b) < 5+4+2+32 {
		t.Fatalf("字节过短（%d）不是 ClientHello", len(b))
	}
	p := 5 + 4 + 2 + 32 // record header + handshake header + legacy_version + random
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		t.Fatal("截断：cipher_suites")
	}
	csLen := int(b[p])<<8 | int(b[p+1])
	p += 2 + csLen
	if p+1 > len(b) {
		t.Fatal("截断：compression")
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		t.Fatal("无扩展段")
	}
	extLen := int(b[p])<<8 | int(b[p+1])
	p += 2
	end := p + extLen
	for p+4 <= end {
		et := uint16(b[p])<<8 | uint16(b[p+1])
		el := int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if et == 65037 {
			if el < 8+32+2 {
				t.Fatalf("65037 载荷过短：%d", el)
			}
			d := b[p : p+el]
			if d[0] != 0x00 {
				t.Errorf("outer type = %#x, want 0x00", d[0])
			}
			kdf := uint16(d[1])<<8 | uint16(d[2])
			if kdf != 0x0001 {
				t.Errorf("kdf = %#x, want 0x0001（两族恒定）", kdf)
			}
			aead = uint16(d[3])<<8 | uint16(d[4])
			encLen := int(d[6])<<8 | int(d[7])
			if encLen != 32 {
				t.Errorf("enc_len = %d, want 32", encLen)
			}
			payloadLen = int(d[8+encLen])<<8 | int(d[9+encLen])
			if total := 8 + encLen + 2 + payloadLen; total != el {
				t.Errorf("内部长度自洽失败：总 %d != ext 长 %d", total, el)
			}
			return aead, payloadLen
		}
		p += el
	}
	t.Fatal("ClientHello 里未找到 65037")
	return
}

func compilePreset(t *testing.T, name string) *utls.ClientHelloSpec {
	t.Helper()
	p, err := profiles.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := tlscore.CompileDetail(p.TLS.Detail)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestECHGreaseOnWireFirefox157 钉住 firefox_157 预设的线上形状：
// aead∈{1,3}、payload_len∈{240,400}，两维都应在多次连接里出现（真实 Firefox
// 的每连接随机行为，2026-10-08 四样本 2:2 同构）。
func TestECHGreaseOnWireFirefox157(t *testing.T) {
	c := startCHCapture(t)
	seenAead := map[uint16]int{}
	seenLen := map[int]int{}

	const rounds = 32 // 32 次里单值恒定的概率 2^-31 ≈ 0
	for i := 0; i < rounds; i++ {
		spec := compilePreset(t, "firefox_157_windows")
		aead, plen := parseECHOnWire(t, c.sendCapture(t, spec))
		if aead != 0x0001 && aead != 0x0003 {
			t.Fatalf("第 %d 次：aead = %#x，不在 {1,3}", i+1, aead)
		}
		if plen != 240 && plen != 400 {
			t.Fatalf("第 %d 次：payload_len = %d，不在 {240,400}", i+1, plen)
		}
		seenAead[aead]++
		seenLen[plen]++
	}
	if seenAead[0x0001] == 0 || seenAead[0x0003] == 0 {
		t.Errorf("%d 连接里 aead 未见两值（%v）——每连接随机未生效", rounds, seenAead)
	}
	if seenLen[240] == 0 || seenLen[400] == 0 {
		t.Errorf("%d 连接里 payload_len 未见两值（%v）——线长随机未生效", rounds, seenLen)
	}
	t.Logf("firefox_157 线上形状采样 %d 次：aead=%v payload_len=%v", rounds, seenAead, seenLen)
}

// TestECHGreaseOnWireChromeControl 对照组：Chrome 族恒定 aead=1、线长在
// {144,176,208,240}（BoringSSL 口径）——防止"形状分族"误伤 Chrome 路径。
func TestECHGreaseOnWireChromeControl(t *testing.T) {
	c := startCHCapture(t)
	seenLen := map[int]int{}
	const rounds = 16
	for i := 0; i < rounds; i++ {
		spec := compilePreset(t, "chrome_154_windows")
		aead, plen := parseECHOnWire(t, c.sendCapture(t, spec))
		if aead != 0x0001 {
			t.Fatalf("Chrome 的 aead 应恒为 1，got %#x", aead)
		}
		switch plen {
		case 144, 176, 208, 240:
			seenLen[plen]++
		default:
			t.Fatalf("Chrome 的 payload_len = %d，不在 {144,176,208,240}", plen)
		}
	}
	if len(seenLen) < 2 {
		t.Errorf("Chrome 的线长应随机化（BoringSSL 四档），只见到 %v", seenLen)
	}
	t.Logf("chrome_154 线上形状采样 %d 次：payload_len=%v", rounds, seenLen)
}
