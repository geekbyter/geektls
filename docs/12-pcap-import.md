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

## 6. 落地设计（`import-pcap`，待排期）

```
geektls import-pcap --pcap a.pcapng [--keylog sslkeys.log] [--stream N|--all]
                    [--tcp-only] -o out.e1.json
```

- 解析：优先驱动 **tshark**（`-Y tls.handshake.type==1 -T json`；有 keylog 时
  `-o tls.keylog_file:<f>` 解密 H2）——**不自研 TLS 汇编**，汇编是 tshark 的强项；
  TCP 选项/TTL 从 SYN 包取（`tcp.flags.syn==1 && tcp.ack==0`）。
- 输出：**与 E1 记录同 schema**（`evidence/browsers/*.json` 同款）⇒ 直接进
  `gen-profiles`（preset 内 `grade`/`source` 由记录字段决定）；但"CI 预设守门"要生效
  还需两步：把记录路径加进 `ci.yml` 的 `-record` 逗号清单（生成器只自动吃内嵌 hex 标本，
  E1/pcap 记录是显式列表），且该 job 只在 Linux runner 上跑。
  `grade` 记 **E1p（pcap 线上抓包）**，`source=pcap:<file>#<stream>#<ts>`。
- 校验：装载 → 重放 → 与原 pcap 对拍（JA4/JA4R/扩展序/SETTINGS）——
  本文件 §5 就是这个闭环的命令行版。
- 拒绝项：resumption/0-RTT 流、跨连接混抓、缺 SYN 的流（tcp 节无法导出）。

## 7. 待办

| # | 事项 | 判据 |
|---|---|---|
| 1 | `import-pcap` MVP（仅 TLS+TCP，tshark 驱动） | 一份真实浏览器 pcap → E1 记录 → gen-profiles → 预设装载重放与原 pcap 逐字段一致 |
| 2 | keylog 解密支线（H2 SETTINGS/WU/伪头序） | 与 nginx 采集端对同一会话的 H2 面对拍一致（补 `pseudo_header_order` 的 E4 空位） |
| 3 | QUIC Initial 支线 | tshark 解 Initial → transport params 装载 → 与 e1_h3 记录对拍 |
| 4 | 与"浏览器过、代码不过"的诊断流程挂钩 | 文档化排查顺序：先 pcap diff（TCP/TLS）→ keylog diff（H2）→ 再 IP/行为面 |
