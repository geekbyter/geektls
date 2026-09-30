# 01 - 指纹全维度清单

本文档是 geektls 的**可控性契约**：列出每一层每一个影响指纹的维度，标注可控性等级、**当前实现状态**与**验证等级**。实现与测试都以此清单为 checklist。维度来源：33 个开源仓库调研（尤其 impersonator 的 QUIC 拆解、requests-go 的扩展清单、noble-tls 的 76 预设覆盖面、specter 的 H2 帧证据）+ 本仓库 nginx 采集端的 39 个采集变量反向定义。

可控性等级（**目标**列）：**A**=API 直接可控；**B**=可控但需特权/平台限制；**C**=行为级（通过时序/逻辑模拟）；**—**=不控制（放行 OS/库默认）。

**当前状态**列（2026-09-24 基线，对应 `docs/capability-matrix.yml`）：**✅ 已实现**；**⚠️ 部分/降级**；**❌ 未实现**；**—** 不控制。
**验证等级**列：`E1` 真浏览器 pcap / `E2` 外部 oracle 回读 MATCH / `E3` 权威转写 / `E4` 知识构造 / `本地` 回环或嗅探 / `未验证`。

> 2026-09-24 修订说明：本表此前只标「目标等级」，导致「目标 A」被误读为「现状可控」。现增列三列与实现对齐；差异项以「阻塞项」说明，与 `06-task-list.md` 的降级标注一致。冻结项见 `docs/CONTRACT-FREEZE.md`。

## 1. TLS ClientHello 层

| # | 维度 | 目标 | 现状 | 验证 | 阻塞/说明 |
|---|---|---|---|---|---|
| 1 | legacy_version | A | ✅ | E2 | 0x0303/0x0301 |
| 2 | cipher suites 列表与顺序 | A | ✅ | E2 | JA3 第二段 |
| 3 | 扩展集合与**线上顺序** | A | ✅ | E2 | Chrome per-connection permutation 可开关（`extension_permutation`） |
| 4 | GREASE 值与**位置**（ciphers/ extensions/ curves 各自） | A | ✅ | E2 | RFC 8701 `0x?a?a`；nginx 端 `$http_ssl_ja3_grease_*` 可逐项核对 |
| 5 | supported_versions | A | ✅ | E2 | 决定 JA4 的 `t13`/`t12` 段 |
| 6 | signature_algorithms (+ cert 侧 50 号) | A | ✅ | E2 | |
| 7 | supported_groups / ec_point_formats | A | ✅ | E2 | |
| 8 | ALPN 协议列表与顺序 | A | ✅ | E2 | h2/h3/http1.1 |
| 9 | SNI 有无/值 | A | ✅ | E2 | 决定 JA4 的 `d`/`i` 标志 |
| 10 | key_share 组（含后量子 X25519MLKEM768） | A | ✅ | E2 | noble-tls/curl_cffi 已覆盖 |
| 11 | psk_key_exchange_modes | A | ✅ | E2 | |
| 12 | 证书压缩算法（brotli/zstd） | A | ✅ | E2 | requests-go 清单 |
| 13 | ALPS（application_settings） | A | ✅ | E2 | Chrome 特有 |
| 14 | record_size_limit / delegated_credentials | A | ✅ | E2 | requests-go 清单 |
| 15 | padding 扩展长度策略 | A | ✅ | E2 | 决定 ClientHello 总长落点 |
| 16 | ECH（含 GREASE ECH） | A | ✅ | E2（cloudflare-ech.com 实测） | P7 实现 |
| 17 | session resumption / 0-RTT 首飞 | C | ⚠️ 声明侧可控、协议侧不做 | E2（本地 std 服务端实测） | 1-RTT PSK resumption 有（`session_resumption` 开关）；`early_data`(42) 能在预设里声明并改变 JA3 扩展段与 JA4 计数（`core/tls/early_data_test.go`），但"只带 42 不带 PSK"必被标准服务端拒 ⇒ 不当开关用；A10 结案见矩阵 `tls.session_resumption_0rtt` |
| 18 | **整体 hex 回放** | A | ✅ | E2 | 输入 Wireshark ClientHello hex 原样发出（tlsmask/requests-go 已验证此形态） |

**输入格式三选一**（详见 03 文档）：JA3 fullstring、JA4R 串、完整 JSON / hex。注意 JA3 不可逆（丢失扩展顺序与 GREASE 位置），JA4R 与 JSON 可逆，hex 无损——profile 体系内部一律以 JSON 为规范形式，JA3/JA4R 仅作兼容入口。

**自算回读**：core 内置 JA3/JA4 **计算**器（仅这两个，BSD 许可范围内），构造完 ClientHello 后自算并与用户期望值比对，不等发包就报错。

> **身份一致性（T2-1，2026-09-24 已交付）**：`identity` 节把 UA/UA-CH/默认头绑定进 profile，engine 统一注入（用户头优先），fp oracle 硬断言常规头全等。
> **待补（见方案 T-2/T-3）**：无 profile 生成器（手写转录）；identity 取值与
> `chrome_150_windows` / `firefox_135_windows` 两个预设仍是 E4 构造，待 E1 真浏览器基准升级。
> （原列的 `safari_18` 已在 2026-09-30 处理：那条无实测来源的形态被删除，旧名 `safari_18`
> 现为别名 → 实测导航形态 `safari_18_macos`。）

## 2. HTTP/2 层（Akamai 指纹四段）

| # | 维度 | 目标 | 现状 | 验证 | 阻塞/说明 |
|---|---|---|---|---|---|
| 1 | SETTINGS 各 id:value **及发送顺序**（含 GREASE settings 如 0x0a0a） | A | ✅ | E2 | 指纹第 1 段；注意"缺失项"也是信号（Chrome 必有 HEADER_TABLE_SIZE）——**缺失项断言待阶段 3**（H2-2） |
| 2 | WINDOW_UPDATE 初始增量（如 Chrome 15663105） | A | ✅ **三态** | E2 | 第 2 段；省略=补 15663105 / `0`=**不发该帧** / `N`=发 N（A11，2026-09-29）。不发时读路径退回协议默认窗口，长响应不卡死 |
| 3 | PRIORITY 帧序列（stream:exclusive:dep:weight） | A | ✅ | E2 | 第 3 段；按资源类型的优先级表（httpcloak 维度）待阶段 3（H2-3） |
| 4 | 伪头顺序（m,s,a,p 等） | A | ✅ | E2 | 第 4 段 |
| 5 | HPACK 编码细节（索引表使用、编码顺序） | A | ✅ **四档** | E2 | **T-HPACK 已落地（2026-09-28）**：vendor fork `core/third_party/fhttp` 加编码器钩子（`hpack.Encoder.SetIndexPolicy` + `SetHuffmanMode` ← `Transport.HpackStrategy` ← `profile.http2.hpack_strategy`）；chrome=QUICHE 源码级、firefox=抓包字节级、safari=保守近似（待 E1）、generic=上游默认对照。线上 HPACK block 逐字节断言 `tests/e2e/h2_hpack_strategy_test.go`，证据与限制见 `docs/p2-h2-capability.md` |
| 6 | connection preface 时序（SETTINGS 与首 HEADERS 的分帧） | A | ✅ | E2 | 单段 Flush 与 Chrome 一致（oracle `sent_frames` 实测）；硬断言化随阶段 1 |
| 7 | 首个请求的 stream id | A | ✅ | E2 | **四段之外**的可观测形态（A11）：`http2.first_stream_id`，省略=1，须为奇数；第三方对 Firefox 135/145 记 3 ⇒ 已入 E3 预设 |

## 3. HTTP/3 + QUIC 层

维度清单主要来自 zhkl0228/impersonator 的文档（该方向最细）+ 本仓库 `ngf-nginx-http3-fingerprint.patch` 的采集端定义：

| # | 维度 | 目标 | 现状 | 验证 | 阻塞/说明 |
|---|---|---|---|---|---|
| 1 | QUIC version（含 version_information 参数） | A | ✅ | 本地（RFC 9001 嗅探） | nginx 端 `$quic_fingerprint_version` |
| 2 | QUIC transport params 12+ 项及顺序 | A | ✅（T4-1 blob 直通，`transport_params_raw`，2026-09-24） | 本地嗅探（顺序+值硬断言） | 顺序/非标/GREASE 位置全控（vendor patch #7）；已知流控键值自动映射回 `quic.Config` 保证行为一致 |
| 3 | 非标 transport params（google_connection_options 等） | A | ✅（同 T4-1，任意 id + hex 值） | 本地嗅探（硬断言） | `TestQUICTransportParamsRaw` 实证 |
| 4 | Initial datagram 布局：分片、PADDING 位置、乱序 | A | ✅（patch #8，2026-09-30：`initial_layout` 的 padding/disable_scramble/crypto_fragments/coalesce_min_size） | 本地嗅探（字节级硬断言 + 真服务端中继） | 此前判"packer 无钩子、结案不投入"——vendor fork 后钩子自建；`tests/e2e/quic_layout_test.go` 实证 |
| 5 | QUIC GREASE 帧 | A | ✅（`SendGreaseFrames`） | 未验证 | 实现已接线，E2 验证待阶段 4（H3-3） |
| 6 | H3 SETTINGS 帧各 id:value 及顺序 | A | ✅（`AdditionalSettings`+`Order`） | E4（预设值），本地嗅探 | `$http3_fingerprint_settings`；4 预设 H3 为空（H3-2） |
| 7 | H3 伪头顺序 | A | ✅（`PseudoHeaderOrder`） | E4 | `$http3_fingerprint_pseudo_headers`；强于 lexiforest（其 nghttp3.patch 无此项） |
| 8 | 0-RTT / 会话恢复 | C | ❌ 协议侧不做（A10 结案；2026-09-30 fork 内重新取证：缺环在 bogdanfinn/utls——`newUQUICConn` 不复制 `EnableSessionEvents`（u_quic.go:31 vs quic.go:191），UQUICConn 无 `StoreSession` 方法 ⇒ 无 QUICStoreSession/QUICResumeSession 事件，票据 Extra 里的 transport params 存不进、恢复不出；补齐 = vendor 第三个 fork） | — | 指纹侧的 early_data(42) 声明已可控，见 TLS 维度表 17 与 `core/tls/early_data_test.go` |
| 9 | H2/H3 protocol racing（Chrome 300ms 偏好 H2） | C | ✅（`raceH3H2`+`h2_race_ms`） | 本地实测 | |
| 10 | Alt-Svc 升级缓存行为 | C | ✅（会话级缓存） | pytest 实测 | |

QUIC 层之下仍是 TLS ClientHello（走 quic-go 的 uTLS 集成，vendor fork patch 已解决内层注入并字节级实证），第 1 节全部维度对 H3 同样生效。

## 4. TCP/IP 层（JA4TCP 对应）

| # | 维度 | 目标 | 现状 | 验证 | 阻塞/说明 |
|---|---|---|---|---|---|
| 1 | TTL | B | ✅ 三平台 | getsockopt 读回 | `IP_TTL` setsockopt |
| 2 | MSS | B | ⚠️ Linux/macOS | getsockopt 读回 | `TCP_MAXSEG`；**Windows 不支持**（WSAENOPROTOOPT，跳过+warning），上游限制 |
| 3 | 初始 window size | B | ⚠️ 仅 Linux 探测模式 | 未验证 | `ProbeSYN`（IP_HDRINCL，需 root）；**探测不影响真实连接**——真实连接的 JA4TCP 与 profile 不一致，阶段 5 降级承诺（T5-1） |
| 4 | window_scale / options 内容与顺序（MSS,SACK,TS,NOP,WS） | B | ⚠️ 仅 Linux 探测模式 | 未验证 | 同 #3 |
| 5 | IP 层标志（DF 等） | B | ❌ | — | 不做 |

如实声明：**raw socket 档只在 Linux 完整支持且需 root**；无 root 时只承诺 TTL/MSS。对端经代理/NAT 时 TCP 指纹本来就不可见，文档写清边界。JA4TCP 指纹商用受 FoxIO License 约束（见 00 文档第 7 节）。

## 5. HTTP/1.1 与应用行为层

| # | 维度 | 目标 | 现状 | 验证 | 阻塞/说明 |
|---|---|---|---|---|---|
| 1 | header 顺序与大小写 | A | ✅ | E2 | wreq-js 专门处理（HTTP/1 WAF 看大小写） |
| 2 | HTTP 方法/版本字符串 | A | ✅ | E2 | |
| 3 | 重定向/cookie/连接复用行为 | C | ⚠️ 重定向+cookie 有；**连接复用未实现** | 本地 | 每请求新连接（P7 未完成）；连接池做成**可选开关（默认关）**（E-1，阶段 5） |
| 4 | 请求时序特征 | C | ❌ 仅 delay 钩子 | — | 不做精确时钟模拟 |

## 6. 与采集端的字段映射（测试用）

本清单每一项都标注了对应的 nginx 采集变量（`$http_clienthello_*` / `$http2_fingerprint_*` / `$http3_fingerprint_*` / `$quic_fingerprint_*` / `$http_ssl_ja4tcp_*`）——e2e 测试就是"设定值 → nginx 采集值"的逐项 diff，映射表在 `05-testing.md` 落地为机器可读的断言配置，状态快照见 `docs/capability-matrix.yml`。
