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
**2026-09-24 起，QUIC 内层 hello 不再是"TCP 形态换个标志"**——按真机实测裁剪为
TLS1.3 形态（见下文「QUIC 内层 ClientHello 形态」）。当前 JA4(QUIC) =
`q13d0311h3_55b375c5d22e_653d80c3fe9d`，与真 Chrome 149 (Windows) 的 **E1 实测值逐字符相同**。

QUIC 化钳制规则（`clampSpecForQUIC`，2026-09-24 起含 TLS1.3 专属裁剪）：
- ciphers 只保留 TLS1.3 套件（`0x1301/0x1302/0x1303`）；QUIC 强制 1.3，TLS1.2 套件不得出现
- 扩展剔 `11/23/35/65281`（TLS1.2 语义，对所有浏览器成立）+ profile 指定的额外项
  （`http3.inner_hello_drop_extensions`，Chrome 实测 `[5,18]`）
- GREASE 处理：`http3.inner_hello_drop_grease` 为真时，cipher / 扩展 / group / key_share /
  version 五处**全不发** GREASE（Chrome 实测如此）；否则保留占位（其它浏览器族）
- sig_algs 追加 `http3.inner_hello_extra_sig_algs`（Chrome 实测 `0x0201`，追加在末尾）
- supported_versions 收紧为 0x0304（+ GREASE，视上一项而定）
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

## Initial datagram 布局（T4）——尺寸可控，布局仍不可控（2026-09-30 修订）

嗅探实测 quic-go 客户端首发：2×默认尺寸的 datagram、每 datagram 单 Initial 包
（pn 0/1）、ClientHello 被分片进两个 CRYPTO 帧跨包重组。

| 维度 | 结论 |
|---|---|
| 分片策略 | ❌ quic-go 内部 packet packer 决定，无钩子（`crypto_stream.go` 有内置的 clienthello scrambling，规则固定） |
| PADDING 位置/大小 | ⚠️ **尺寸可控（部分关闭）**：`http3.initial_packet_size`（1200–1452）经上游 `quic.Config.InitialPacketSize` 决定首 datagram 被 pad 到多少；实测 1350 → `[1350 1350]`、1200 → `[1200 1200]`、不设 → `[1280 1280]`（默认路径逐字节不变）。**PADDING 在包内的位置**仍由 packer 决定 |
| coalesce（Initial+Handshake 合并） | ❌ 由对端时序驱动，无配置入口（阈值 `MinCoalescedPacketSize` 是常量） |

**结论**：能兑现的那半边（首包尺寸 / 填充量）已经落地，且不碰 fork——
用的是上游字段；剩下 coalesce 阈值与 CRYPTO 分片表要动 packer 层
（比 crypto_setup 深得多），归入 **SC-3（quic-go-utls 内化）** 一起做：
内化时这些函数就变成自有代码，届时按 profile 暴露分片/合并策略才有意义。
真实 Chrome 的 Initial 布局差异点仍待 nginx 采集端（P1-T8 环境就绪）量化。

## 行为层（T5）

| 维度 | 结论 |
|---|---|
| H2/H3 racing | ✅ engine.raceH3H2：H3 先跑，h2_race_ms 未决则并发 H2，先到先得（本地实测 H3 赢/死端口正确回落） |
| Alt-Svc 升级缓存 | ✅ 会话级 map（学习 `h3=` 广告；pytest 实测首访 h2 → 次访 h3） |
| 0-RTT | ❌ **结案不做**（A10，2026-09-30）：quic-go 客户端 0-RTT 依赖 `DialEarly` + 会话票据缓存，而 spec 模式下 `StoreSession` 是 no-op、无可补导出面（docs/06 P7-T2 已取证），首飞 Initial 布局又不可控（上文结案项）；指纹侧的 `early_data`(42) 声明已可控，见 `core/tls/early_data_test.go` |

## QUIC 内层 ClientHello 形态（E1 实测，2026-09-24）

采集：`tests/e2e/e1_h3_test.go`（真实浏览器 `--origin-to-force-quic-on` 强制走 QUIC →
本地 UDP 嗅探 RFC 9001 Initial），记录 `profiles/evidence/browsers/chrome_windows_h3.json`
（Chrome 149.0.7827.54 / Windows）。

| 项 | 真机实测 | 说明 |
|---|---|---|
| ciphers | `0x1301 / 0x1302 / 0x1303` | 纯 TLS1.3，**无 GREASE cipher** |
| 扩展 | 11 项 `{0,10,13,16,27,43,45,51,57,65037,17613}` | = TCP 的 16 项剔 `5/11/18/23/35/65281` + 增 `57` |
| supported_groups / key_shares | `{4588,29,23,24}` / `{4588,29}` | 均**无 GREASE** |
| supported_versions | `{772}` | 无 GREASE |
| signature_algorithms | TCP 的 8 项 + `0x0201` | QUIC 特有（rsa_pkcs1_sha1），追加在末尾 |
| 扩展顺序 | **逐连接随机** | 沿用既有洗牌，无需另设顺序 |
| JA4(QUIC) | `q13d0311h3_55b375c5d22e_653d80c3fe9d` | 我方现已**逐字符一致** |

裁剪分工：`11/23/35/65281`（TLS1.2 语义）由 `clampSpecForQUIC` 硬编码，对所有浏览器成立；
`5(status_request)` 与 `18(SCT)` 在 TLS1.3 里仍有意义，Chrome 在 QUIC 上不发属**实现选择**，
因此由 profile 的 `http3.inner_hello_drop_extensions` 提供（不为 Firefox/Safari 臆造）。

## transport params 可控边界（实测对照）

| 参数 | 真机 (Chrome 149) | 我方 wire | 可控性 |
|---|---|---|---|
| max_idle_timeout | 30000 | 30000 | ✅ `transport_params` |
| initial_max_data | **15728640** | 15728640 | ✅ `transport_params`（2026-09-24 按实测修正） |
| initial_max_stream_data_* ×3 | 6291456 | 6291456 | ✅ 但三者共用 quic-go 的**一个**窗口值（粒度损失） |
| initial_max_streams_bidi / uni | 100 / 103 | 100 / 103 | ✅ `transport_params` |
| max_datagram_frame_size | 65536 | 16383 | ❌ quic-go 硬编码（仅 `EnableDatagrams` 决定存在与否） |
| max_udp_payload_size | 1472 | 1452 | ❌ quic-go 硬编码 |
| max_ack_delay | 不发 | 26 | ❌ quic-go 硬编码 |
| 私有参数 `0x11` / `0x3128` | 有 | 无 | ❌ 需 `transport_params_raw` blob；blob 为整块替换、连接级参数不可钉死 ⇒ 待 fork 决策 |

> `transport_params` 里只有 6 个键会被 `transportParamsToQUICConfig` 采纳
> （max_idle_timeout / initial_max_data / initial_max_streams_* / initial_max_stream_data_*）；
> 其余键**静默忽略**——预设已不再列这些无效键，避免"看似可控"的假象。

## 验收证据

- `tests/e2e/quic_sniff_test.go`：Initial 解密嗅探；transport params 与 profile 一致；
  GREASE 参数存在；datagram ≥1200；内层 hello ALPN=h3；**内层 JA4(QUIC) 与真机 E1 值
  逐字符相同**（期望值取真机值，不再自算自比）。
- `tests/e2e/e1_h3_test.go`：真实浏览器 H3 采集（需 `GEEKTLS_E1_H3_BROWSER`，默认跳过）。
- `core/h3` / `core/engine` H3 用例（强制/竞速/回落）全绿；pytest 新增
  `test_h3_forced` / `test_h3_alt_svc_upgrade` 全绿。
