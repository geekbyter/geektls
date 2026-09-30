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
| max_udp_payload_size | ❌→✅ | map 路径硬编码 1452；**blob 路径 1200..1500 可控**（patch #9 接收缓冲已提到 1500，Chrome 1472 可对齐） |
| max_ack_delay / ack_delay_exponent | ❌→✅ | map 路径与默认值相同则不发送；**blob 路径随意**（纯声明项） |
| active_connection_id_limit | ❌→✅ | map 路径硬编码 4（恰与 Chrome 一致）；**blob 路径随意** |
| disable_active_migration | ❌→✅ | map 路径客户端恒不发送（Chrome 也不发）；blob 可显式声明（行为侧注意：本库不做连接迁移，声明无害） |
| 非标参数（google_connection_options 等） | ❌→✅ | **blob 直通**（patch #7），私有参数 0x11/0x3128 已对真机 |
| **参数顺序** | ❌→✅ | **blob 直通**（顺序即线上顺序） |
| GREASE transport param | ⚠️→✅ | map 路径恒在首位；**blob 路径位置任意**（Chrome 位置随机 ⇒ 用 blob 对齐） |

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

QUIC 会话缓存（StoreSession）在 spec 模式下为 no-op——0-RTT 的精确缺环分析见下文
「行为层（T5）」的 0-RTT 行（缺环在 bogdanfinn/utls 的 `newUQUICConn`，非本 fork）。

## Initial datagram 布局（T4）——✅ 已全控（vendor patch #8，2026-09-30）

嗅探实测上游 quic-go 客户端首发：2×默认尺寸的 datagram、每 datagram 单 Initial 包
（pn 0/1）、ClientHello 被内置 scrambling 在 SNI/ECH 中点切片后乱序补发、
PADDING 写在 CRYPTO **之前**（与 Chrome/quiche 相反）。这些现已全部可控：

| 维度 | 结论 | 入口（profile.http3） |
|---|---|---|
| 首 datagram 尺寸 / PADDING 量 | ✅ | `initial_packet_size`（1200–1452，上游 `Config.InitialPacketSize`，无需 patch；0 = 默认 1280） |
| PADDING 在包内位置 | ✅ | `initial_layout.padding: "end"` = PADDING 在包尾（Chrome 形态）；缺省 = 上游（PADDING 在前） |
| CRYPTO 分片表 | ✅ | `initial_layout.crypto_fragments: [300,250,...]`——按表切 CRYPTO 帧（含关闭 scrambling；表内分片保序，跳过上游的反固化洗牌） |
| clienthello scrambling 开关 | ✅ | `initial_layout.disable_scramble`（SNI/ECH 中点切割的逐连接开关；Chrome 形态 = 关） |
| coalesce 阈值 | ✅ | `initial_layout.coalesce_min_size`（0 = 默认 128；-1 = 禁用合并；>0 = 自定义）。注意语义：空 datagram 永远可装，"禁用"不会死锁握手 |

Chrome 149 真机形态（`chrome_windows_h3.json`：首 datagram 1230B、CH 1784B 单片
按包空间填充、PADDING 在尾）= `padding:"end"` + `disable_scramble:true` +
`initial_packet_size` 按 MTU 设。嗅探器断言（`tests/e2e/quic_layout_test.go`）：
默认路径 PADDING 在前 + scramble 空洞（回归守门）；Chrome 形态 CRYPTO 严格连续
+ PADDING 在尾（796B 实测）；分片表 [300 250 400] 逐片上线；coalesce 阈值经真服务端
+ UDP 中继实证（默认第二飞 [initial handshake 1rtt] 合并，-1 拆成 [initial]+[handshake]）。

**不设 `initial_layout` 的默认路径与上游逐字节不变**（nil 即不触碰 packer/crypto stream）。

已知残余差异（登记，未做）：① **SCID 长度**——Chrome 首飞 SCID 长 0（evidence 里
`initial_source_connection_id` len=0），fork 默认 4 字节，ConnectionIDGenerator
未从 http3.Transport 接出；② **填充目标粒度**——`initial_packet_size` 是每个含
Initial 的 datagram 都补齐到该值，Chrome/quiche 是"至少 1200、内容超出则按自然
尺寸"（真机首包 1230B 即自然尺寸）；要逐字节复刻 1230 需把
`initialPaddingLen` 的语义从"补到固定值"改成"补到下限"，增量小、暂未做。

## 行为层（T5）

| 维度 | 结论 |
|---|---|
| H2/H3 racing | ✅ engine.raceH3H2：H3 先跑，h2_race_ms 未决则并发 H2，先到先得（本地实测 H3 赢/死端口正确回落） |
| Alt-Svc 升级缓存 | ✅ 会话级 map（学习 `h3=` 广告；pytest 实测首访 h2 → 次访 h3） |
| 0-RTT | ❌ **结案不做**（A10，2026-09-30；本轮在 fork 里重新取证，缺环定位到具体行）：quic-go 的 0-RTT 链路 = `DialEarly` + TLS 会话票据（票据 Extra 里存对端 transport params，握手时经 `QUICResumeSession` 事件恢复，见 `crypto_setup.go:248` 的双条件门）。**缺环在 bogdanfinn/utls 而非 quic-go-utls**：① `newUQUICConn`（utls `u_quic.go:31`）建 `quicState` 时**没有复制** `QUICConfig.EnableSessionEvents`（对照 `newQUICConn` 在 `quic.go:191` 有复制）⇒ UQUICConn 永不发 `QUICStoreSession`/`QUICResumeSession` 事件——存侧退化成自动写 `ClientSessionCache`（票据里**没有** QUIC transport params 的 Extra），取侧 `zeroRTTParameters` 永远为 nil ⇒ 双条件门恒假；② `UQUICConn` 根本没有 `StoreSession` 方法（`QUICConn.StoreSession` 在 `quic.go:322`，结构不同不通用），我们 fork 里的适配器只能 no-op。补齐路径 = vendor 第三个 fork（bogdanfinn/utls）：`newUQUICConn` 透传 `EnableSessionEvents` + 给 `UQUICConn` 加 `StoreSession`（镜像 quic.go:322）+ 验证 ApplyPreset 下 PSK binder 注入在 QUIC 模式工作——改动面在整个 TCP-TLS 栈上，本轮不动。0-RTT 打通后 `http3.Transport` 本就 `DialEarly`（http3/transport.go:408），链路自然接上。指纹侧的 `early_data`(42) 声明已可控，见 `core/tls/early_data_test.go` |

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

## transport params 可控边界（实测对照，2026-09-30 第二轮修订）

| 参数 | 真机 (Chrome 149) | 我方 wire | 可控性 |
|---|---|---|---|
| max_idle_timeout | 30000 | 30000 | ✅ `transport_params` |
| initial_max_data | **15728640** | 15728640 | ✅ `transport_params`（2026-09-24 按实测修正） |
| initial_max_stream_data_* ×3 | 6291456 | 6291456 | ✅ 但三者共用 quic-go 的**一个**窗口值（粒度损失） |
| initial_max_streams_bidi / uni | 100 / 103 | 100 / 103 | ✅ `transport_params` |
| max_datagram_frame_size | 65536 | 65536 | ✅ **已解**（2026-09-30，patch #9）：blob 声明 + `Config.DatagramFrameSize` 同步放宽接收上限（原先硬编码 16383，声明大于行为会断连） |
| max_udp_payload_size | 1472 | 1472 | ✅ **已解**（2026-09-30，patch #9）：接收缓冲从 1452 提到 1500（`MaxIncomingPacketSize`，与发送/默认宣告值解耦），blob 可安全声明 1200..1500；越界配置期报错 |
| max_ack_delay / ack_delay_exponent | 不发 | map 路径 26（硬编码）/ blob 路径随意 | ✅ 用 blob 对齐（纯声明项，描述自身 ACK 行为，无行为冲突） |
| active_connection_id_limit | 不发 | map 路径 4（硬编码）/ blob 路径随意 | ✅ 用 blob 对齐（行为侧 connIDManager 容忍对端少给 CID） |
| 私有参数 `0x11` / `0x3128` | 有 | 有 | ✅ blob 直通（opaque，无行为冲突） |
| initial_source_connection_id | 空值 | ❌ | **配置期报错**：取值必须与逐连接随机 SCID 一致，profile 钉不死；Chrome 发空值的前提是 SCID 长 0，而 fork 默认 SCID 长 4（SCID 长度控制未接线——独立的指纹差异点，见下） |
| 服务端专属参数（0x00/0x02/0x0d/0x10） | — | — | **配置期报错**（客户端发送即协议违规） |
| 重复 id / `transport_params`+`transport_params_raw` 同时设置 | — | — | **配置期报错**（不许静默忽略） |

> GREASE transport parameter：quic-go 默认恒发且恒在**首位**；blob 直通可放任意位置
> （Chrome 位置随机 ⇒ 用 blob 时才对得上真机）。

> 已知残余差异（本轮登记，未做）：**SCID 长度**——Chrome 首飞 SCID 长 0
> （evidence 里 `initial_source_connection_id` len=0），fork 默认 4 字节；
> 需要把 ConnectionIDGenerator 经 http3.Transport 接出来才有得控。

## 验收证据

- `tests/e2e/quic_sniff_test.go`：Initial 解密嗅探；transport params 与 profile 一致；
  GREASE 参数存在；datagram ≥1200；内层 hello ALPN=h3；**内层 JA4(QUIC) 与真机 E1 值
  逐字符相同**（期望值取真机值，不再自算自比）。
- `tests/e2e/quic_layout_test.go`（2026-09-30，patch #8/#9 验收）：默认路径回归
  （PADDING 在前 + scramble 空洞）/ Chrome 形态（CRYPTO 连续 + PADDING 在尾）/
  分片表逐片上线 / 非法值配置期报错 / coalesce 阈值真服务端 + UDP 中继实证。
- `tests/e2e/e1_h3_test.go`：真实浏览器 H3 采集（需 `GEEKTLS_E1_H3_BROWSER`，默认跳过）。
- `core/h3` / `core/engine` H3 用例（强制/竞速/回落）全绿；pytest 新增
  `test_h3_forced` / `test_h3_alt_svc_upgrade` 全绿。
