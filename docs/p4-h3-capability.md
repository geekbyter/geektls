# P4 能力摸底：bogdanfinn/quic-go-utls v1.0.10-utls（QUIC/H3）支持矩阵

> 依据：module cache 源码通读 + **线上字节级实证**（tests/e2e/quic_sniff_test.go：
> RFC 9001 Initial 解密嗅探器，直接解出客户端发出的 transport params）。
> fork 版本对齐 bogdanfinn/tls-client master go.mod。

## H3 层（quic-go-utls/http3）——全控

| 维度（01 文档 §3） | 结论 | 入口 |
|---|---|---|
| H3 SETTINGS id:value + 顺序 | 原生 | `http3.Transport.AdditionalSettings` + `AdditionalSettingsOrder` |
| H3 伪头序 | 原生 | `PseudoHeaderOrder`（复用 h2 包的 m/a/s/p 映射） |
| GREASE 帧 | 原生 | `SendGreaseFrames`（控制流随机 GREASE 帧） |
| H3 DATAGRAM | 原生 | `EnableDatagrams`（Chrome 开） |
| PRIORITY 参数 | 原生 | `PriorityParam`（Chrome 984832） |

## QUIC transport params ——值可控子集（经 quic.Config）

| 参数 | 可控性 | 说明 |
|---|---|---|
| max_idle_timeout | ✅ | `Config.MaxIdleTimeout`（嗅探实证 30000 上线） |
| initial_max_data | ✅ | `Config.InitialConnectionReceiveWindow` |
| initial_max_stream_data_bidi_local/remote/uni | ⚠️ 部分 | 三者**共用一个值**（`InitialStreamReceiveWindow`）；三者不一致时取 bidi_local 优先。Chrome 真值 remote=2097152 ≠ local=6291456，粒度损失 |
| initial_max_streams_bidi / uni | ✅ | `Config.MaxIncomingStreams` / `MaxIncomingUniStreams` |
| max_udp_payload_size | ❌ | 硬编码 `protocol.MaxPacketBufferSize`（1452；Chrome 1472） |
| max_ack_delay / ack_delay_exponent | ❌ | 无 config 入口；与默认值相同则不发送（恰好与 Chrome 一致） |
| active_connection_id_limit | ❌ | 硬编码 `protocol.MaxActiveConnectionIDs`（4，恰与 Chrome 一致） |
| disable_active_migration | ❌ | 客户端恒不发送（Chrome 也不发） |
| 非标参数（google_connection_options 等） | ❌ | 无注入点 |
| **参数顺序** | ❌ | `internal/wire.Marshal` 固定顺序写死 |
| GREASE transport param | ⚠️ | quic-go 总是发且**恒在首位**；Chrome 位置随机——指纹差异点 |

## QUIC 内层 TLS ClientHello ——✅ 已解决（vendor fork patch）

~~不可控~~ → **已可控**：vendor fork（`core/third_party/quic-go-utls`，replace
落地，改动登记 `GEEKTLS_PATCHES.md`）让 `quic.Config.ClientHelloSpec != nil` 时
握手走 `UQUICClient`+`ApplyPreset`。core/h3 把 tlscore.CompileDetail 的产物经
`SpecToBogdan` 类型转换后注入——**tls.detail 现在对 TCP-TLS 与 QUIC-TLS 同时生效**。

嗅探实证（tests/e2e/quic_sniff_test.go，RFC 9001 Initial 解密）：
chrome_133 预设 QUIC 内层 hello JA4 = `q13d1516h3_8daaf6152771_a45c8c51e9ac`，
与 TCP 侧仅差 q/t 协议标志；扩展线上顺序逐位一致；GREASE 存在。

QUIC 化钳制规则（`clampSpecForQUIC`）：
- supported_versions 过滤为 GREASE+0x0304，版本上下限收紧 1.3（QUIC 强制）
- ALPN / ALPS 重写为 h3（真实 Chrome QUIC hello 形态）
- **ECH GREASE（65037）已补齐（P7-T1）**——注意一个互操作边界：bogdanfinn 的
  QUIC 服务端不处理 ECH 扩展会静默失败（其 server 端从没被 ECH-in-QUIC
  测过）；真实 H3 端点（BoringSSL 系）按规范忽略 GREASE ECH。本仓库 H3
  互操作测试用剥 ECH 的 profile 变体（pytest/node/core 均如此标注）。
：bogdanfinn/utls 的 ECH 负载生成在
  QUIC 下静默失败（依赖 TCP record 层），改按 BoringSSL 线上格式在
  `clampSpecForQUIC` 直接合成等效 payload——嗅探实测 QUIC hello JA4
  `q13d1517h3_8daaf6152771_697a4d344d1e`，与 TCP 侧仅差 q/t 标志。

QUIC 会话缓存（StoreSession）在 spec 模式下为 no-op——0-RTT/复用随 P7-T2。

## Initial datagram 布局（T4）——不可控（嗅探实证）

嗅探实测 quic-go 客户端首发：2 个 1280B datagram、每 datagram 单 Initial 包
（pn 0/1）、ClientHello 被分片进两个 CRYPTO 帧跨包重组。

| 维度 | 结论 |
|---|---|
| 分片策略 | ❌ quic-go 内部 packet packer 决定，无钩子 |
| PADDING 位置/大小 | ❌ 同上（实测每 datagram pad 到 1280） |
| coalesce（Initial+Handshake 合并） | ❌ 由对端时序驱动，无配置入口 |

**结论**：Initial 布局控制需要 fork quic-go 的 packet packer / crypto stream
层（比 crypto_setup 深得多），工作量与风险不成比例——P4 标"不可控"，
真实 Chrome 的 Initial 布局差异点记入此文档，待 nginx 采集端（P1-T8 环境
就绪）量化后再评估是否值得 deep fork。

## 行为层（T5）

| 维度 | 结论 |
|---|---|
| H2/H3 racing | ✅ engine.raceH3H2：H3 先跑，h2_race_ms 未决则并发 H2，先到先得（本地实测 H3 赢/死端口正确回落） |
| Alt-Svc 升级缓存 | ✅ 会话级 map（学习 `h3=` 广告；pytest 实测首访 h2 → 次访 h3） |
| 0-RTT | ⚠️ 未接线：quic-go 客户端 0-RTT 依赖 DialEarly+会话票据缓存，engine 尚无连接/票据复用（P3 每请求一连接）；随 P7-T2 会话复用一起做 |

## 验收证据

- `tests/e2e/quic_sniff_test.go`：Initial 解密嗅探，13 个 transport params
  全部与 profile 一致；GREASE 参数存在；datagram ≥1200；内层 hello ALPN=h3。
- `core/h3` / `core/engine` H3 用例（强制/竞速/回落）全绿；pytest 新增
  `test_h3_forced` / `test_h3_alt_svc_upgrade` 全绿。
