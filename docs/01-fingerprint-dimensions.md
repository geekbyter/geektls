# 01 - 指纹全维度清单

本文档是 geektls 的**可控性契约**：列出每一层每一个影响指纹的维度，标注可控性等级与 ground truth 来源。实现与测试都以此清单为 checklist。维度来源：33 个开源仓库调研（尤其 impersonator 的 QUIC 拆解、requests-go 的扩展清单、noble-tls 的 76 预设覆盖面、specter 的 H2 帧证据）+ 本仓库 nginx 采集端的 39 个采集变量反向定义。

可控性等级：**A**=API 直接可控；**B**=可控但需特权/平台限制；**C**=行为级（通过时序/逻辑模拟）；**—**=不控制（放行 OS/库默认）。

## 1. TLS ClientHello 层

| # | 维度 | 等级 | 说明 / ground truth |
|---|---|---|---|
| 1 | legacy_version | A | 0x0303/0x0301 |
| 2 | cipher suites 列表与顺序 | A | JA3 第二段 |
| 3 | 扩展集合与**线上顺序** | A | Chrome per-connection permutation 须可开关 |
| 4 | GREASE 值与**位置**（ciphers/ extensions/ curves 各自） | A | RFC 8701 `0x?a?a`；nginx 端 `$http_ssl_ja3_grease_*` 可逐项核对 |
| 5 | supported_versions | A | 决定 JA4 的 `t13`/`t12` 段 |
| 6 | signature_algorithms (+ cert 侧 50 号) | A | |
| 7 | supported_groups / ec_point_formats | A | |
| 8 | ALPN 协议列表与顺序 | A | h2/h3/http1.1 |
| 9 | SNI 有无/值 | A | 决定 JA4 的 `d`/`i` 标志 |
| 10 | key_share 组（含后量子 X25519MLKEM768） | A | noble-tls/curl_cffi 已覆盖 |
| 11 | psk_key_exchange_modes | A | |
| 12 | 证书压缩算法（brotli/zstd） | A | requests-go 清单 |
| 13 | ALPS（application_settings） | A | Chrome 特有 |
| 14 | record_size_limit / delegated_credentials | A | requests-go 清单 |
| 15 | padding 扩展长度策略 | A | 决定 ClientHello 总长落点 |
| 16 | ECH（含 GREASE ECH） | A | P7 实现；impersonator/noble-tls 先行 |
| 17 | session resumption / 0-RTT 首飞 | C | 会话复用行为本身即指纹 |
| 18 | **整体 hex 回放** | A | 输入 Wireshark ClientHello hex 原样发出（tlsmask/requests-go 已验证此形态） |

**输入格式三选一**（详见 03 文档）：JA3 fullstring、JA4R 串、完整 JSON / hex。注意 JA3 不可逆（丢失扩展顺序与 GREASE 位置），JA4R 与 JSON 可逆，hex 无损——profile 体系内部一律以 JSON 为规范形式，JA3/JA4R 仅作兼容入口。

**自算回读**：core 内置 JA3/JA4 **计算**器（仅这两个，BSD 许可范围内），构造完 ClientHello 后自算并与用户期望值比对，不等发包就报错。

## 2. HTTP/2 层（Akamai 指纹四段）

| # | 维度 | 等级 | 说明 |
|---|---|---|---|
| 1 | SETTINGS 各 id:value **及发送顺序**（含 GREASE settings 如 0x0a0a） | A | 指纹第 1 段；注意"缺失项"也是信号（Chrome 必有 HEADER_TABLE_SIZE） |
| 2 | WINDOW_UPDATE 初始增量（如 Chrome 15663105） | A | 第 2 段 |
| 3 | PRIORITY 帧序列（stream:exclusive:dep:weight） | A | 第 3 段；含按资源类型的优先级表（httpcloak 维度） |
| 4 | 伪头顺序（m,s,a,p 等） | A | 第 4 段 |
| 5 | HPACK 编码细节（索引表使用、编码顺序） | A | httpcloak/specter 打磨的维度 |
| 6 | connection preface 时序（SETTINGS 与首 HEADERS 的分帧） | A | specter 指出 h2 crate 丢这个，fork 必须保留 |

## 3. HTTP/3 + QUIC 层

维度清单主要来自 zhkl0228/impersonator 的文档（该方向最细）+ 本仓库 `ngf-nginx-http3-fingerprint.patch` 的采集端定义：

| # | 维度 | 等级 | 说明 |
|---|---|---|---|
| 1 | QUIC version（含 version_information 参数） | A | nginx 端 `$quic_fingerprint_version` |
| 2 | QUIC transport params 12+ 项及顺序（max_idle_timeout、max_udp_payload_size、initial_max_*、ack_delay_exponent、active_connection_id_limit…） | A | `$quic_fingerprint_transport_params` 逐项核对 |
| 3 | 非标 transport params（google_connection_options 等） | A | impersonator 清单 |
| 4 | Initial datagram 布局：分片、PADDING 位置、乱序 | A | 反爬关注维度，多数库忽略 |
| 5 | QUIC GREASE 帧 | A | noble-tls 已支持 |
| 6 | H3 SETTINGS 帧各 id:value 及顺序 | A | `$http3_fingerprint_settings` |
| 7 | H3 伪头顺序 | A | `$http3_fingerprint_pseudo_headers` |
| 8 | 0-RTT / 会话恢复 | C | |
| 9 | H2/H3 protocol racing（Chrome 300ms 偏好 H2） | C | noble-tls 有此行为模拟 |
| 10 | Alt-Svc 升级缓存行为 | C | specter 提到 |

QUIC 层之下仍是 TLS ClientHello（走 quic-go 的 uTLS 集成），第 1 节全部维度对 H3 同样生效。

## 4. TCP/IP 层（JA4TCP 对应）

| # | 维度 | 等级 | 说明 |
|---|---|---|---|
| 1 | TTL | B | `IP_TTL` setsockopt，三平台均可 |
| 2 | MSS | B | `TCP_MAXSEG`；Windows 受限 |
| 3 | 初始 window size | B | raw socket 构造 SYN 才可精确，需 root |
| 4 | window_scale / options 内容与顺序（MSS,SACK,TS,NOP,WS） | B | 同上 |
| 5 | IP 层标志（DF 等） | B | 同上 |

如实声明：**raw socket 档只在 Linux 完整支持且需 root**；无 root 时只承诺 TTL/MSS。对端经代理/NAT 时 TCP 指纹本来就不可见，文档写清边界。JA4TCP 指纹商用受 FoxIO License 约束（见 00 文档第 7 节）。

## 5. HTTP/1.1 与应用行为层

| # | 维度 | 等级 | 说明 |
|---|---|---|---|
| 1 | header 顺序与大小写 | A | wreq-js 专门处理（HTTP/1 WAF 看大小写） |
| 2 | HTTP 方法/版本字符串 | A | |
| 3 | 重定向/cookie/连接复用行为 | C | engine 层实现 |
| 4 | 请求时序特征 | C | 不做精确时钟模拟，只提供可调 delay 钩子 |

## 6. 与采集端的字段映射（测试用）

本清单每一项都标注了对应的 nginx 采集变量（`$http_clienthello_*` / `$http2_fingerprint_*` / `$http3_fingerprint_*` / `$quic_fingerprint_*` / `$http_ssl_ja4tcp_*`）——e2e 测试就是"设定值 → nginx 采集值"的逐项 diff，映射表在 `05-testing.md` 落地为机器可读的断言配置。
