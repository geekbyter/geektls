# TCP 指纹平台矩阵（P6-T4，2026-09-29 重写：两档三平台终态；2026-09-30 补 BSD 档 + 平台文件互斥表）

> 承 docs/01-fingerprint-dimensions.md §4 的两档设计。结论先行：
> **setsockopt 档三平台可用（Windows 缺 MSS）；netstack 档（gVisor 用户态栈）
> 在 Linux root 全量落地并通过 P6-T3 验收（nginx 采集端 ja4tcp 五分量逐项
> MATCH）**；raw_linux.go 的探测模式保留为调试工具。

## 字段 × 平台 × 档位终态表

| 字段 | Windows | Linux | macOS | 档位/实现 |
|---|---|---|---|---|
| `ttl` | ✅ setsockopt（读回一致） | ✅ setsockopt（双栈：IP_TTL + IPV6_UNICAST_HOPS 同设） | ✅ setsockopt | setsockopt |
| `mss` | ❌ 不支持（WSAENOPROTOOPT，跳过+warning） | ✅ setsockopt / netstack 均可 | ✅ setsockopt | setsockopt |
| `window_size` | ❌ | ✅ **两档**：setsockopt 夹击法（SO_RCVBUF=win×4 + TCP_WINDOW_CLAMP=win，尽力逼近，超 rmem_max 告警）/ netstack 精确（SYN window 公式见下） | ❌ | setsockopt ≈ / netstack = |
| `df` | ⚠️ best-effort（IP_DONTFRAGMENT=14，ENOPROTOOPT 不中止） | ✅（IP_MTU_DISCOVER=DO；netstack 档走 PMTUDiscoveryDo） | ⚠️ best-effort（IP_DONTFRAG=28） | setsockopt / netstack |
| `window_scale` | ❌ | ✅ netstack 精确（FindWndScale 反解：TCPReceiveBufferSizeRange.Max=65535<<ws） | ❌ | netstack |
| `options_order` | ❌ | ⚠️ **仅取舍，任意排列不可得**（gVisor `makeSynOptions` 硬编码 Linux 族序 `mss,sok,ts,nop,ws`；SACK 可关） | ❌ | netstack（受限） |
| IP ID / TSval | ❌ | ⚠️ netstack 栈内计数器/时钟生成，不可控 | ❌ | — |

## netstack 档（Linux root，`mode:"netstack"`）

**架构**：gVisor netstack 实例挂 **TUN 设备**（/dev/net/tun，IFF_TUN|IFF_NO_PI，
非持久——fd 关闭即消失无残留）；内核侧 10.99.0.1/24、netstack 侧 10.99.0.2/24；
netstack 写出的包进内核 RX → 本地投递到监听 0.0.0.0 的服务端；应答经 tun0
路由回 netstack。产出的 `net.Conn` 直接交 `tlscore.Handshake`。

**RST 抑制：TUN 拓扑下天然不需要**。任务书原方案（AF_PACKET + iptables 丢
OUTPUT 链 RST）实测在 WSL2 的 lo 上不成立：AF_PACKET 注入帧到不了内核 L3
（tcpdump 取证：帧在 tap 可见、内核 TCP 无 SYN-RECV；iptables/accept_local/
协议号/假以太头四个嫌疑逐一排除）。iptables 装规则路径曾实现后移除——TUN
拓扑里内核从不收到目的为 netstack 地址的包，无 RST 可压。

**SYN window 公式**（gVisor endpoint.go initialReceiveWindow，实测对齐）：
```
SYN.window = min(rcvbuf>>1, 65535, 10×MSS×2)  再按 wscale 向下对齐
```
（rcvAdvWndScale=1 ⇒ 公告缓冲的一半；rcvbuf 由 `window_size`×2 设置。）
调用方须选满足公式的值；P6-T3 验收用 mss=1460/window=29184/wscale=8。

**边界**：仅 IPv4 字面量目标；与代理不兼容（结构化报错）；TS 恒开、SACK
可关；IP ID/TSval 不可控；非 Linux 报 linux-only 结构化错误。

**实例复用与回收**：全局单例 + 引用计数（每连接 acquire/close 释放），归零
时 stack.Close + 关 TUN fd；engine Session.Close 不额外持有。

## setsockopt 档（默认，按平台分文件）

**平台文件互斥表**（每个 GOOS 必须有且只有一份实现，`core/tcp/sockopt_*.go`）：

| GOOS | 文件 | 构建约束 | 覆盖项 |
|---|---|---|---|
| linux | `sockopt_linux.go` | `linux` | TTL / MSS / DF / window（夹击法）+ rmem_max 预警 |
| darwin | `sockopt_darwin.go` | `darwin` | TTL / MSS / DF（`IP_DONTFRAG`=28，osx 私有常量） |
| windows | `sockopt_windows.go` | `windows` | TTL（MSS 实测 `WSAENOPROTOOPT` ⇒ 跳过 + warning） |
| 其它 Unix | `sockopt_unix.go` | `!linux && !darwin && !windows` | TTL / MSS（DF 各家取值不一致 ⇒ warning） |

⚠️ **这份互斥表是被一次事故逼出来的**（2026-09-30）：darwin 从原来的
`sockopt_unix.go`（约束 `!windows`）里拆出来时，**老文件没同步收窄约束**——
mac 上两份同时参与编译、`applySockopts`/`readBackSockopts`/`platformWarnings`
三重声明冲突，云编译 macOS runner 直接红；本地与 linux runner 全绿是因为
`linux`/`windows` 各自独占一份、掩盖了重叠。修法两步：① 补回"其余 Unix"档（约束
`!linux && !darwin && !windows`），② CI 加**跨平台编译守门**（每个 GOOS 编一遍
纯 Go 包，见 `.github/workflows/ci.yml` 的 "cross-OS compile gate"）。
验证口径：`GOOS=<os> go list -f '{{join .GoFiles " "}}' ./tcp/ | grep sockopt`
应当**只列出上表对应的一行**。

- TTL/MSS 必须在 connect 前设置（`net.Dialer.Control` 钩子），事后补设无效。
- window 夹击法借鉴 httpcloak（MIT）；超内核 rmem_max 时告警
  `tcp_window_clamped`（钳制不中止）。
- DF 在 linux/darwin best-effort，windows 不支持，BSD 一档如实告警
  `tcp_df_unsupported`；双栈 TTL 同设，单边失败无害。
- 读回验证（WSL/Linux，`core/tcp/sockopt_linux_test.go`）：clamp=65535 设定
  读回 65535、DF 读回 IP_MTU_DISCOVER=2、IPv6 hops 读回 42。

## 边界声明（如实，承前版）

- **代理/NAT 下 TCP 指纹对目标站不可见**：经 HTTP CONNECT 时指纹暴露给代理
  （engine 把选项落在到代理的连接上，这是正确语义）；netstack 档与代理互斥。
- **H3/QUIC 流量没有 TCP 指纹**（UDP）。
- Windows 无 netstack 档属设计边界（00 文档 §8 已声明），不算失败。

## 预设取值口径

`tcp` 节建模的是**宿主 OS 协议栈**而非浏览器自身（TTL 是 OS 属性）：
chrome_* = Windows 典型（TTL 128, MSS 1460）；safari_* = macOS/iOS 典型
（TTL 64）；firefox_* = Linux/macOS 典型（TTL 64）。跨平台预设的正确
形态是"chrome_133_windows / chrome_133_mac"分变体，随预设体系 v2
（目录式管理）落地，见 03 文档 §3。
