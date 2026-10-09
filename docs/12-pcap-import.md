# 12 - pcap 抓包 → 装载：设计与实测（2026-09-29）

> 回答的问题：浏览器能访问、代码（含指纹伪造库）过不去时，能不能**一边用浏览器一边抓包
> （Wireshark/tshark 存 pcap），然后把 pcap 里的 TLS/TCP 指纹解析出来装载到 geektls**？
> 结论先行：**可行，且是本项目证据链的天然一环**——但必须分清 pcap 里**哪些层是明文可见**
>（TLS 握手 ✅、TCP/IP ✅、QUIC Initial ✅），**哪些层根本不在 pcap 里**（H2/H1 应用层
> ——在 TLS 隧道内，需要 SSLKEYLOGFILE 解密或走 nginx 采集端）。
> 本文含一次端到端实测记录（§5）。

## 1. 这个想法补的是哪个空位

`profiles/evidence/README.md` 明文登记：生成器产出的 E1 标本**"无 `tcp` 节：TCP 层需 pcap，
标本不含"**；`http2.pseudo_header_order` 也是"标本内不可得，暂记 E4"。
⇒ **pcap 导入不是重复造轮子，而是补上 E1 链路自己声明缺的两块**：TCP/IP 层 + 独立第三方视角。

## 2. 分层可见性矩阵（关键认知）

| 层 | pcap 明文可见？ | 说明 |
|---|---|---|
| TCP SYN 选项（MSS/wscale/SACK/TS/顺序）、window、TTL、IP ID、DF | ✅ | 全部在线上明文；抓到什么就是什么 |
| TLS ClientHello（ciphers/扩展序与负载/groups/sig_algs/ALPN/ECH 外层/padding） | ✅ | 握手是明文；tshark/自研解析均可 |
| QUIC Initial（transport params/版本/ICID） | ✅ | Initial 包的密钥由 DCID 派生，tshark 可直接解 |
| TLS ServerHello（JA4S 侧） | ✅ | 同为明文握手 |
| **H2 SETTINGS/WINDOW_UPDATE/伪头序/头序、H1 头序** | **❌ 密文** | 在 TLS 隧道内。两条路：① 浏览器带 `SSLKEYLOGFILE` 抓包后解密；② 用 nginx 采集端（服务器侧明文，本项目已有） |
| PSK binder / 会话票据 / 0-RTT | ❌ 且**不可装载** | 会话绑定，换目标必失效 ⇒ 导入器必须识别并拒绝复用形态 |

## 3. 装载入口（已存在，零开发）

- **`clienthello_hex`**：`FromClientHelloHex` 直接吃 ClientHello **record 原始字节**的 hex
  （`16 03 01 ...` 开头，无损路径：扩展按线上顺序保留、未知扩展透传）——
  pcap/采集端给出的就是这段字节。
- **`check_profile`**：2026-09-29 起支持**裸 hex** 串（此前只认
  `{"clienthello_hex":...}` 包装 JSON，README 口径与实现脱节已修）；
  守门测试 `core/tls/check_hex_test.go`。
- **`tcp` 节**：preset schema 已有（`ttl/mss/window/df/mode/window_scale/...`），
  netstack/setsockopt 两档都能吃。

## 4. 必须处理的五个坑（导入器的核心工作就是这些）

1. **会话复用形态必须拒绝**：浏览器二次访问的 CH 是 **resumption**（带 PSK binder、
   可能有 0-RTT），装载后打别的目标必失败。导入器要识别
   （有 pre_shared_key 且带 binder ⇒ 拒绝或剥离到 fresh 形态），**只采首访 fresh 连接**。
2. **随机化归一**：client_random/session_id/key_share 公钥/ECH 外层/GREASE 值全是
   逐连接随机的 ⇒ 不能原样装载（会把"这一次"冻进预设）。规则：结构装载、随机项由
   引擎按浏览器语义重生成（GREASE 逐连接重随机、key_share 现算——与 gen-profiles 同一套）。
3. **GREASE 双表示**：既保留 `grease_random` 占位（线上重随机），也保留原始值作证据。
4. **分段与重组**：CH 常跨多个 TCP 段；解析前必须按流重组（tshark 自带；
   自研解析要按 seq 重组，PoC 里已实现最小版）。
5. **ALPN 缺省位的实现差异**：FoxIO 规范无 ALPN 填 `00`（geektls 遵循），而
   tls.peet.ws 的实现对缺省 ALPN 直接省略该段 ⇒ 对拍时先归一再比（实测 §5）。

## 5. 端到端实测（2026-09-29，WSL，无 root）

无 root 抓不了 eth0 ⇒ 用"**搭线 tap**"等价替代：本地代理 `client → tap → tls.peet.ws:443`
只转发字节，在明文阶段截到与线上 pcap 逐字节一致的 ClientHello record，并**合成标准 pcap**
（Ethernet/IPv4/TCP + record 载荷）。随后走完整链路：

```
tap 截获 ClientHello record：1553 字节（record 头 5 + 握手 1544）
pcap 重组出 client 流 1553 字节 → 提取 record → hex
check_profile(裸 hex) ✅
  ja3_hash = 284deaeae14ea5ddc96c5d7e59855422
  ja4      = t13d301200_1d37bd780c83_ecd0401ec68b
  warning  = psk_placeholder_added（TLS1.3 无 41 ⇒ 补空占位，首访指纹不变）
装载 clienthello_hex=… 重放 https://tls.peet.ws/api/all
  selfcheck.ja4 = t13d301200_1d37bd780c83_ecd0401ec68b
原始请求服务器看到的 ja4 = t13d3012_1d37bd780c83_ecd0401ec68b
规范化 ALPN 缺省位后三方一致 ✅（采集端 / 离线自检 / 装载重放；ja3_hash 亦同）
```

**这证明了什么**：pcap（或任何抓包面）里的 ClientHello 字节 → `check_profile`/`clienthello_hex`
装载 → 引擎重放，**指纹逐位复现**（JA4 规范化后一致、ja3_hash 一致）。
"tap 合成 pcap"与真实 Wireshark 抓包在 CH 字节上等价；真实 pcap 里还会有 IP/TCP 头
（那正是要导入的 tcp 节 ✓）。

## 6. 落地实现（`import-pcap`，2026-10-08 落地）

```bash
geektls import-pcap --pcap a.pcapng [--stream N|--all] [--tcp-only]
                    [--ua "<UA 串>"] [--name 记录名] -o out.e1.json
```

**实现口径修正（相对本节初版设计）**：初版计划"驱动 tshark、不自研 TLS 汇编"。
落地改为**纯 Go 最小解析**——① tshark 不是随处可用（本机/CI 都要额外装），而这里
需要的只是"字节级搬运"：按 seq 重组 TCP 流、定位 `16 03 0x` record、取完整握手
消息——**不是**初版反对的那种字段级 TLS 汇编；② 换来离线可用、本机可测、CI 零额外
依赖。字段级深解（keylog 解密补 H2 面）仍按 §7-2 留作后续支线。

- **容器**：pcap classic 与 pcapng（Wireshark 默认）；链路层 Ethernet（含 VLAN 单/多层）、
  Linux cooked v1/v2（tcpdump -i any）、raw IP；IPv4/IPv6；其余链路类型明确报错。
- **`--ua`**：pcap 明文里看不到 HTTP 头（在 TLS 隧道内），UA 由调用方补；
  **给了 UA 的记录可直接进 `gen-profiles`**（kind=e1p_pcap，生成器 2026-10-08 起接受）。
  没给 UA 只作记录用（`check-profile` / `--clienthello-hex` 装载自检可用，不进预设链）。
- **输出**：与 E1 记录同 schema；`kind=e1p_pcap`、`grade=E1p`、
  `source=pcap:<file>#<stream>`；`tcp` 节（ttl/mss/window_size/window_scale/
  options_order/df）与 profile.tcp 的观测字段对齐（options_order 的名字与
  `core/tcp/raw_linux.go` 的 optionsFor 一致：mss/sack/ts/nop/ws）。
- **拒绝项**（照 §4）：resumption（CH 带非空 PSK(41)）、缺 SYN、抓包缺口（宁缺毋滥）、
  CH 跨 record（罕见形态明确报错）。
- **自验（2026-10-08，本机）**：真实 Chrome 149 CH（1751B）切 3 段**乱序** →
  `import-pcap` → `clienthello_hex` **逐字节一致**、tcp 节完整、自算
  JA4=`t13d1516h2_8daaf6152771_d8a2da3f94cd` → `gen-profiles` 直吃 →
  生成物 `chrome_149_windows.json` 的 **tls 节与 builtin 逐字段一致**
  （差 http2 节——pcap 明文看不到，如实为边界）。
- **测试**：`core/cmd/geektls/importpcap_test.go`（合成帧/双容器/乱序重组/四类拒绝/
  `--ua`/`--all`/`--tcp-only`，全离线、不依赖真实 pcap）。
- **CI 预设守门（可选后接）**：E1p 记录要进 `ci.yml` 的 `-record` 逗号清单才参与
  逐字节门禁（生成器只自动吃内嵌 hex 标本；该 job 只在 Linux runner 上跑）。

## 7. 待办

| # | 事项 | 判据 |
|---|---|---|
| 1 | ✅ `import-pcap` MVP（2026-10-08 落地：纯 Go 最小解析，见 §6） | 合成真 CH 的真实闭环已测（§6 自验：CH 逐字节 + tls 节逐字段）；**真机 pcap 的现场闭环待一次采样**（Wireshark 存一份 → 同样的两条命令） |
| 2 | keylog 解密支线（H2 SETTINGS/WU/伪头序） | 与 nginx 采集端对同一会话的 H2 面对拍一致（补 `pseudo_header_order` 的 E4 空位） |
| 3 | QUIC Initial 支线 | tshark 解 Initial → transport params 装载 → 与 e1_h3 记录对拍 |
| 4 | 与"浏览器过、代码不过"的诊断流程挂钩 | 文档化排查顺序：先 pcap diff（TCP/TLS）→ keylog diff（H2）→ 再 IP/行为面 |
