# 11 - TLS 以下的指纹伪造：分层、可行性与参考实现（2026-09-29）

> 回答的问题：除了 ClientHello 逐字段伪造（geektls 现有能力），**更底层**还能伪什么——
> TCP 三次/四次握手的报文级伪造、IP/ICMP 面——能不能做、怎么做才不自曝、有哪些参考仓库。
> 结论先行：**"更底层"的正确形态不是"裸发报文替换"，而是"自有用户态栈"**——netstack 档
> （gVisor）已经在走这条路；下一程是把最后几个字段（IP ID / TSval / 选项顺序）吃满。

## 1. TLS 以下的可控层

| 层 | 被检测的东西 | 谁在看 | 可控手段（由易到难） |
|---|---|---|---|
| L4 TCP | SYN 选项（MSS/wscale/SACK/TS/**选项顺序**）、window、DF、ISN、重传/RTO、延迟 ACK | p0f、**JA4T/JA4TS**、Cloudflare/Akamai 的 TCP 面 | ① setsockopt（现 setsockopt 档：TTL/MSS/window/DF）② **用户态 TCP 栈**（全字段）③ eBPF/tc 出口改写 SYN 选项（透明）④ AF_PACKET/DPDK 裸发 |
| L3 IP | TTL、**IP ID 生成模式**、DF、ToS、分片行为、IPv6 扩展头顺序/组合 | p0f、nmap OS 探测、部分 WAF | 用户态栈 / 裸发；IPv6 扩展头只能自造 |
| 分段 | 检测器只看首段时的可见性 | 一切 DPI / 采集器 | ClientHello **拆段/乱序/插小段**（"打采集器"而非"打指纹"） |
| ICMP | 错误报文语义（frag-needed 是否带 DF、引用 payload 长度）、速率 | nmap/p0f 的 OS 探测输入 | **不是承载通道**：ICMP 无端口无流，承载 HTTP 只能走隧道（见 §4） |

## 2. "报文级直接伪造 ClientHello"的三个真问题

**字节层面当然能伪造**——你发什么就是什么。难点全在会话一致性：

1. **内核会拆台**：raw socket 发了 SYN，内核收到对端 SYN-ACK 会回 RST。要么压内核
   （`iptables --tcp-flags RST RST -j DROP`，masscan/zmap 的标准做法），要么**不用内核栈**。
2. **SYN 可以伪，握手后的"行为"伪不了**：ACK 节奏、RTO 退避、窗口动态、延迟 ACK、
   TSval 递增由**实际跑的栈**决定。SYN 像 Windows、重传像 Linux 的连接，比老实使用
   Linux 栈**更容易被抓** ⇒ **半伪造比不伪造更危险**。
3. **正确姿势是"整栈自有"**：用户态 TCP/IP 栈产出全部字节，`net.Conn` 直接交给 uTLS
   （netstack 档正是这个架构：指纹链路零改动，SYN→关连接同一套逻辑，一致性天然成立）。

**裸发（AF_PACKET/DPDK/SR-IOV）真正需要的场景**只有：扫描器压内核 RST、要求 IP ID/TTL/
ICMP 错误语义逐位对齐（抗 p0f）、隐蔽通道/抗审查、以及检测器研究。对"让目标接受我"，
**用户态栈是性价比拐点**。

## 3. 与真栈/隧道的本质区别（选型）

| 路线 | 真实度 | 可控性 | 备注 |
|---|---|---|---|
| 真栈（Cronet/naiveproxy/真浏览器） | 行为级全真 | 极低 | naiveproxy = Chromium 网络栈装进代理，是真栈路线标杆 |
| 隧道 + 真栈出口（icmptunnel/sing-box 类） | 看出口 | 中 | **换检测面**：目标看到的指纹由出口栈产生；ICMP 只当管道 |
| 协议层伪造（geektls） | 高（靠证据收敛） | **最高** | 单二进制、高并发、可回归 |
| 用户态栈 + 协议层伪造（netstack 档） | 高（TLS 面 + TCP 面同源自洽） | **最高** | **本项目的位置**：TLS 面与 TCP 面一起控 |

## 4. 参考实现与资料（按类别；标注确定度）

**用户态 TCP 栈**（最相关）
- gVisor `netstack`（Go）——已接入（netstack 档）；`tcp-platform-matrix.md` 记录了 SYN window 公式。
- smoltcp（Rust）、lwIP（C）——同类，抗审查/嵌入式广泛使用。
- naiveproxy——"真栈装进代理"的标杆。

**报文构造与裸发**
- scapy（Python）、gopacket/pnet（Go/Rust）、hping3（任意 flags/options/TTL）。
- masscan / zmap（raw SYN + RST 抑制的标准做法）、nmap（`--ttl/-f/-S/--data-length`）、
  fragroute（分片/TTL 手法）。

**检测侧（对拍的另一半；本项目两头都有）**
- p0f（SYN 签名格式事实标准）、FoxIO **JA4T/JA4TS/JA4L**（TCP 项；nginx 采集端已在算 ja4tcp）。

**抗 DPI / 包级操纵（"打采集器"的手法库）**
- GoodbyeDPI（Windows）、zapret/nfqws（Linux）、ByeDPI、Geneva（马里兰大学，包操纵策略框架）——
  核心手法就是 ClientHello 分段 / TTL / 伪造 RST，全部是 TLS 以下的操作。

**隧道**
- ptunnel / icmptunnel（ICMP 隐蔽通道）、sing-box / Xray（uTLS 指纹 + 传输层参数）。

**确定度声明**：eBPF/tc 改写 SYN 选项、IP ID/TSval 精确控制——技术可行**确信**，但
**没有可点名的成熟通用仓库**，社区多为自研 tc-bpf/nft 片段或自 patch netstack
（与本项目 patch gVisor 同路）。

## 5. 落地顺序（建议）

1. **吃满 netstack 档字段面**：把 `tcp-platform-matrix.md` 标 ⚠️ 的 TSval / IP ID / SACK 开关 /
   选项顺序逐个确认 gVisor 能否暴露、哪些要 patch（比新造一层划算）。
2. **setsockopt 档加 eBPF/tc 出口改写**（可选）：无 root 建不了 TUN 的环境也能改 JA4T 面，
   应用层零改动；验收用现成 nginx L2 + ja4tcp 对拍。
3. **ClientHello 分段控制**：一条 CH 拆成可配置段序列——同时是对自己采集端重组逻辑的回归测试。
4. **不要碰 ICMP 承载**：对"目标接受我"零收益，只对隐蔽通道有意义，不是本项目定位。

## 6. 一致性红线（任何做法的验收底线）

- SYN 伪造的每一条都必须能在**同一连接**的后续行为里自证一致（窗口动态/TSval/RTO）；
- 采集端对照必须**双端**做：本地 fp/nginx 采集端 + 真实线上 oracle；
- 任何新字段先在 `tcp-platform-matrix.md` 登记"可控/半可控/不可控"再实现。
