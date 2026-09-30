//go:build linux

package tcp

// raw socket 档（P6-T2，仅 Linux，需 CAP_NET_RAW/root）。
//
// 最终形态：**定制 SYN 探测模式**（不发完整连接）。
// 工程理由（诚实声明）：raw socket 全量接管一条 TCP 连接需要用户态协议栈
// 级别的投入——内核不认识这条流，SYN-ACK 到达后内核会先抢发 RST（需 iptables
// 旁路规则），还要自管序列号/重传/拥塞控制，这是 gVisor 级的工程量，超出
// 本期范围。本文件交付的是字节级可控的 SYN 构造 + SYN-ACK 采集（探测/验证
// 用途），完整接管在 docs/tcp-platform-matrix.md 标为"本期不做"。

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/geekbyter/geektls/core/profiles"
)

// SYNProbeResult 的定义在 dialer.go（跨平台共享）。

// tcpOption 是 TCP 选项（kind+data）。
type tcpOption struct {
	kind uint8
	data []byte // 不含 kind/length 字节
}

// optionsFor 把 profile 的 options_order 编译为 TCP 选项字节序。
// 已知 kind：mss(2)/sack(4 空)/ts(8)/nop(1)/ws(3)。未知名报错。
func optionsFor(cfg *profiles.TCPProfile) ([]byte, error) {
	var out []byte
	for _, name := range cfg.OptionsOrder {
		switch name {
		case "mss":
			mss := cfg.MSS
			if mss == 0 {
				mss = 1460
			}
			out = append(out, 2, 4, byte(mss>>8), byte(mss))
		case "sack":
			out = append(out, 4, 2)
		case "ts":
			out = append(out, 8, 10)
			out = append(out, make([]byte, 8)...) // TSval/TSecr 探测包填 0
		case "nop":
			out = append(out, 1)
		case "ws":
			out = append(out, 3, 3, byte(cfg.WindowScale))
		default:
			return nil, fmt.Errorf("tcp raw: unknown option %q", name)
		}
	}
	// 4 字节对齐补 EOL
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out, nil
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP net.IP, tcp []byte) uint16 {
	pseudo := append(append([]byte{}, srcIP.To4()...), dstIP.To4()...)
	pseudo = append(pseudo, 0, unix.IPPROTO_TCP, byte(len(tcp)>>8), byte(len(tcp)))
	var sum uint32
	for _, seg := range [][]byte{pseudo, tcp} {
		for i := 0; i+1 < len(seg); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(seg[i:]))
		}
		if len(seg)%2 == 1 {
			sum += uint32(seg[len(seg)-1]) << 8
		}
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildSYN 构造 IP+TCP SYN 包（IP_HDRINCL 模式：含 IP 头）。
func buildSYN(srcIP, dstIP net.IP, srcPort uint16, cfg *profiles.TCPProfile) ([]byte, error) {
	opts, err := optionsFor(cfg)
	if err != nil {
		return nil, err
	}
	window := cfg.WindowSize
	if window == 0 {
		window = 65535
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 64
	}

	dataOffset := 5 + len(opts)/4
	tcp := make([]byte, 20+len(opts))
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	// seq=0（探测模式无所谓）
	tcp[12] = byte(dataOffset) << 4
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:], uint16(window))
	copy(tcp[20:], opts)
	binary.BigEndian.PutUint16(tcp[16:], tcpChecksum(srcIP, dstIP, tcp))

	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[1] = 0 // TOS
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[8] = uint8(ttl)
	ip[9] = unix.IPPROTO_TCP
	copy(ip[12:], srcIP.To4())
	copy(ip[16:], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))

	return append(ip, tcp...), nil
}

// ProbeSYN 发定制 SYN 并等 SYN-ACK（超时返回 GotSynAck=false）。
// 需 root/CAP_NET_RAW。这是探测模式，不建立完整连接。
func ProbeSYN(dstIP net.IP, cfg *profiles.TCPProfile, timeout time.Duration) (*SYNProbeResult, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("tcp raw: socket (need root/CAP_NET_RAW): %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return nil, fmt.Errorf("tcp raw: IP_HDRINCL: %w", err)
	}

	// 源地址：走一次 UDP 拨号拿到出口 IP（不发包）
	probe, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: dstIP, Port: 443})
	if err != nil {
		return nil, err
	}
	srcIP := probe.LocalAddr().(*net.UDPAddr).IP
	probe.Close()

	pkt, err := buildSYN(srcIP, dstIP, 40000, cfg)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	if err := unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Addr: [4]byte{dstIP.To4()[0], dstIP.To4()[1], dstIP.To4()[2], dstIP.To4()[3]}}); err != nil {
		return nil, fmt.Errorf("tcp raw: sendto: %w", err)
	}
	res := &SYNProbeResult{SentBytes: len(pkt)}

	// 等 SYN-ACK：raw TCP socket 会收到给我们的 TCP 段
	deadline := start.Add(timeout)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		unix.SetNonblock(fd, true)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if n < 40 {
			continue
		}
		// IP 头长 + TCP 头：检查 SYN+ACK 且源是目标
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+20 || !net.IP(buf[12:ihl]).Equal(dstIP) {
			continue
		}
		flags := buf[ihl+13]
		if flags&0x12 == 0x12 { // SYN+ACK
			res.GotSynAck = true
			res.PeerWindow = binary.BigEndian.Uint16(buf[ihl+14:])
			res.RTT = time.Since(start)
			return res, nil
		}
	}
	return res, nil
}
