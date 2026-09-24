# TCP 指纹平台矩阵（P6-T4）

> 承 docs/01-fingerprint-dimensions.md §4 的"两档"设计，逐字段落地现状。
> 结论先行：**setsockopt 档三平台可用（Windows 缺 MSS）；raw socket 档本期
> 只做 Linux 探测模式，完整连接接管不做**（理由见下）。

## 字段 × 平台矩阵

| 字段 | Windows | Linux | macOS | 档位 |
|---|---|---|---|---|
| `ttl` | ✅ setsockopt（IP_TTL，实测读回一致） | ✅ setsockopt | ✅ setsockopt | setsockopt |
| `mss` | ❌ **不支持**（TCP_MAXSEG 实测 WSAENOPROTOOPT；跳过 + `tcp_mss_unsupported` warning） | ✅ setsockopt（读回为协商值，可能被 MTU 钳制） | ✅ setsockopt | setsockopt |
| `window_size` | ❌ | ⚠️ 仅探测模式（`ProbeSYN`，需 root） | ❌ 本期不做 | raw |
| `window_scale` | ❌ | ⚠️ 仅探测模式 | ❌ 本期不做 | raw |
| `options_order`（mss/sack/ts/nop/ws 顺序） | ❌ | ⚠️ 仅探测模式 | ❌ 本期不做 | raw |

## raw socket 档的最终形态与理由（P6-T2 结论）

**形态：定制 SYN 探测模式**（`core/tcp/raw_linux.go`：IP_HDRINCL 构造
IP+TCP 头——自定义 TTL/window/WS/options 顺序——发送并采集 SYN-ACK）。

**为什么不做完整连接接管**：raw socket 发出的 SYN 与内核 TCP 栈是两条
平行世界——SYN-ACK 到达时内核会因"不认识的连接"**抢发 RST**（需要
iptables 旁路规则压制），后续序列号/重传/拥塞控制都要在用户态自管，
这是 gVisor 级工程量。把它做成本期需求 = 用一个子系统换一个指纹维度，
投入产出不成立。探测模式保留了字节级构造与验证能力，供 nginx 采集端
（P1-T8 环境）做 JA4TCP 维度销项。

## 边界声明（如实）

- **代理/NAT 下 TCP 指纹对目标站不可见**：经 HTTP CONNECT 时指纹暴露给
  代理而非目标（engine 把选项落在到代理的连接上，这是正确语义）；
  NAT 会改写 TTL/window_scale 的观测值。
- **H3/QUIC 流量没有 TCP 指纹**（UDP）。
- Windows 无 raw socket 档属设计边界（00 文档 §8 已声明），不算失败。
- TTL/MSS 必须在 connect 前设置才影响 SYN——本实现挂在
  `net.Dialer.Control` 钩子上，事后补设无效。
- 本机（Windows）验证到"setsockopt 成功 + getsockopt 读回一致"；线上
  pcap 验证与 JA4TCP 销项随 nginx 采集端环境（P1-T8 同源阻塞）。

## 预设取值口径

`tcp` 节建模的是**宿主 OS 协议栈**而非浏览器自身（TTL 是 OS 属性）：
chrome_* = Windows 典型（TTL 128, MSS 1460）；safari_* = macOS/iOS 典型
（TTL 64）；firefox_* = Linux/macOS 典型（TTL 64）。跨平台预设的正确
形态是"chrome_133_windows / chrome_133_mac"分变体，随预设体系 v2
（目录式管理）落地，见 03 文档 §3。
