//go:build linux

package tcp

// netstack 档（T2）：gVisor 用户态 TCP 栈，SYN 全字段可控（TTL/DF/MSS/
// window/wscale/SACK 取舍），交 net.Conn 给 tlscore.Handshake——指纹链路
// 其余部分零改动。
//
// 拓扑（实测迭代收敛，见 docs/tcp-platform-matrix.md）：
//   **TUN 设备**（/dev/net/tun，IFF_TUN|IFF_NO_PI，gtls0，内核侧
//   10.99.0.1/24、netstack 侧 10.99.0.2/24）。netstack 写出的包进内核 RX
//   → 内核本地投递到 nginx；内核应答经 tun0 路由回 netstack。
//   **RST 抑制问题在 TUN 拓扑下天然不存在**（内核从不收到目的为
//   netstack 地址的包）——任务书的 AF_PACKET+iptables 方案实测在 WSL2
//   的 lo 上不成立（注入帧不进内核 L3，tcpdump 取证），降级为备选记录。
//   AF_PACKET 路径只在目标不在回环时才考虑（本实现当前仅支持 TUN/回环族
//   拓扑：nginx 监听 0.0.0.0，netstack 打内核侧 tun 地址）。
//
// gVisor 能力边界（如实）：SYN 选项顺序固定为 Linux 族（mss,sok,ts,nop,ws，
// connect.go makeSynOptions 硬编码）——options_order 的任意排列不可得；
// TS 恒开、SACK 可关；IP ID 与 TSVal 由栈内时钟/计数器生成，不可控。
//
// 需要 root/CAP_NET_ADMIN（/dev/net/tun + ip 命令）。

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/geektls/core/profiles"
)

const nsNICID = tcpip.NICID(1)

// TUN 拓扑的固定地址（内核侧 / netstack 侧）。
var (
	nsKernelIP   = net.ParseIP("10.99.0.1")
	nsNetstackIP = net.ParseIP("10.99.0.2")
)

// netstackInstance 是共享的 netstack 实例（全局单例 + 引用计数）。
type netstackInstance struct {
	stack *stack.Stack
	fd    int // TUN fd（关闭即自动销毁非持久 tun 设备）
}

var (
	nsMu     sync.Mutex
	nsInst   *netstackInstance
	nsRefCnt int
)

// nsAcquire 获取（必要时创建）共享 netstack 实例。TUN 拓扑只服务
// "目标是内核侧 tun 地址"的连接（dstIP 须为 nsKernelIP）。
func nsAcquire(dstIP net.IP, cfg *profiles.TCPProfile) (*netstackInstance, error) {
	nsMu.Lock()
	defer nsMu.Unlock()
	if nsInst != nil {
		nsRefCnt++
		return nsInst, nil
	}
	inst, err := nsCreate(cfg)
	if err != nil {
		return nil, err
	}
	nsInst = inst
	nsRefCnt = 1
	return inst, nil
}

// nsRelease 释放引用；归零时销毁栈与 TUN 设备（fd 关闭即回收，无残留）。
func nsRelease() {
	nsMu.Lock()
	defer nsMu.Unlock()
	nsRefCnt--
	if nsRefCnt > 0 || nsInst == nil {
		return
	}
	inst := nsInst
	nsInst = nil
	inst.stack.Close()
	unix.Close(inst.fd)
}

// CloseNetstack 供 engine Session.Close 调用（实例随连接计数回收，此处空操作）。
func CloseNetstack() {}

// nsCreate 建 TUN + netstack。
func nsCreate(cfg *profiles.TCPProfile) (*netstackInstance, error) {
	fd, err := openTun("gtls0")
	if err != nil {
		return nil, fmt.Errorf("tcp netstack: open TUN（需 root/CAP_NET_ADMIN）: %w", err)
	}
	// 内核侧地址（非持久设备：fd 关闭后配置随设备消失，无残留）
	if out, err := exec.Command("ip", "addr", "add", "10.99.0.1/24", "dev", "gtls0").CombinedOutput(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tcp netstack: ip addr add: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", "gtls0", "up").CombinedOutput(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tcp netstack: ip link up: %v: %s", err, out)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            1500,
		EthernetHeader: false, // TUN 是纯 L3，无以太头
		Address:        "",
	})
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tcp netstack: fdbased: %w", err)
	}

	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	// SACK 取舍（TS/WS 在 gVisor 恒开；顺序固定 Linux 族——如实记录）
	sack := true
	st.SetTransportProtocolOption(tcp.ProtocolNumber, (*tcpip.TCPSACKEnabled)(&sack))

	// wscale 控制：FindWndScale(maxBuf) ⇒ maxBuf = 65535<<ws 精确命中目标档
	if cfg.WindowScale > 0 {
		maxBuf := 65535 << uint(cfg.WindowScale)
		st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
			Min: maxBuf, Default: maxBuf, Max: maxBuf,
		})
	}

	if err := st.CreateNIC(nsNICID, linkEP); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tcp netstack: CreateNIC: %v", err)
	}
	if err := st.AddProtocolAddress(nsNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(nsNetstackIP.To4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tcp netstack: AddProtocolAddress: %v", err)
	}
	// 默认路由走本 NIC；TUN 点对点无 ARP/邻居解析
	st.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nsNICID,
	}})

	return &netstackInstance{stack: st, fd: fd}, nil
}

// openTun 打开非持久 TUN 设备（fd 关闭即消失）。
func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	// IFF_TUN=0x0001, IFF_NO_PI=0x1000（ifr_flags 紧跟接口名）
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = 0x0001 | 0x1000
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(0x400454ca /* TUNSETIFF */), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return -1, errno
	}
	return fd, nil
}

// netstackConn 包装 gonet.TCPConn + 释放钩子。
type netstackConn struct {
	*gonet.TCPConn
	once sync.Once
}

func (c *netstackConn) Close() error {
	err := c.TCPConn.Close()
	c.once.Do(nsRelease)
	return err
}

// DialNetstack 经 netstack 档拨 TCP（仅 Linux root，TUN 拓扑）。
// TUN 拓扑下目标必须是内核侧 tun 地址（当前 10.99.0.1）。
func DialNetstack(addr string, cfg *profiles.TCPProfile) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tcp netstack: bad addr %q: %w", addr, err)
	}
	dstIP := net.ParseIP(host)
	if dstIP == nil || dstIP.To4() == nil {
		return nil, fmt.Errorf("tcp netstack: 仅支持 IPv4 字面量目标（%q）", host)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("tcp netstack: bad port: %w", err)
	}

	inst, err := nsAcquire(dstIP, cfg)
	if err != nil {
		return nil, err
	}

	var wq waiter.Queue
	ep, tErr := inst.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tErr != nil {
		nsRelease()
		return nil, fmt.Errorf("tcp netstack: NewEndpoint: %s", tErr)
	}

	// SYN 字段控制点（全部在 Connect 前落到 endpoint）
	if cfg.MSS > 0 {
		if err := ep.SetSockOptInt(tcpip.MaxSegOption, cfg.MSS); err != nil {
			ep.Close()
			nsRelease()
			return nil, fmt.Errorf("tcp netstack: MaxSegOption: %v", err)
		}
	}
	if cfg.TTL > 0 {
		ep.SetSockOptInt(tcpip.IPv4TTLOption, cfg.TTL)
	}
	if cfg.DF {
		ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDo))
	}
	if cfg.WindowSize > 0 {
		// SYN window = min(rcvbuf>>1, 65535, InitialCwnd(10)*MSS*2) 再按
		// wscale 向下对齐（rcvAdvWndScale=1 ⇒ gVisor 公告缓冲的一半，
		// endpoint.go wndFromSpace 实测）——调用方须选满足该公式的值
		//（docs/tcp-platform-matrix.md 有公式表）。
		ep.SocketOptions().SetReceiveBufferSize(int64(cfg.WindowSize)*2, false)
	}

	if err := ep.Bind(tcpip.FullAddress{NIC: nsNICID, Addr: tcpip.AddrFromSlice(nsNetstackIP.To4()), Port: 0}); err != nil {
		ep.Close()
		nsRelease()
		return nil, fmt.Errorf("tcp netstack: Bind: %v", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	cErr := ep.Connect(tcpip.FullAddress{NIC: nsNICID, Addr: tcpip.AddrFromSlice(dstIP.To4()), Port: uint16(port)})
	if _, ok := cErr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-notifyCh:
		case <-time.After(10 * time.Second):
			ep.Close()
			nsRelease()
			return nil, fmt.Errorf("tcp netstack: connect timeout")
		}
		cErr = ep.LastError()
	}
	if cErr != nil {
		ep.Close()
		nsRelease()
		return nil, fmt.Errorf("tcp netstack: connect: %s", cErr)
	}
	return &netstackConn{TCPConn: gonet.NewTCPConn(&wq, ep)}, nil
}
