# 07 - 对标与能力缺口分析

> 2026-09-24。目的：回答两个问题——
> 1. 与实测能通过采集端的同类库（httpcloak / curl_cffi / requests-go）相比，我们在哪、缺什么；
> 2. 在 TLS 领域还有哪些值得补齐的能力，才能满足「常规 TLS 指纹均可通过」的目标。
>
> 数据来源：本项目 `docs/capability-matrix.yml`（自有能力实测）+ 对三个库的能力面调研
> + 公开资料检视（公开文章多为基础科普，信号有限，本表以自有实测为准）。

## 1. 与三个同类库的结构性对比

| 维度 | httpcloak | curl_cffi | requests-go | **geektls（本项目）** |
|---|---|---|---|---|
| 底层协议栈 | Go：uTLS + fhttp + uquic/quic-go | **BoringSSL 真栈**（libcurl 补丁链） | Go：自研 chttp | Go：uTLS + fhttp + 自家 fork 的 quic-go |
| TLS 可控粒度 | **预设级** | 预设级 + `ja3=`/`akamai=`/`extra_fp=` 少量字段 | 预设级 + 部分逐字段（扩展清单） | **逐字段 + 整体 hex 回放** |
| H2 | SETTINGS / 伪头序 | 预设级 Akamai | SETTINGS 序 / 伪头 / priority | **有序 SETTINGS / WINDOW_UPDATE / PRIORITY / 伪头序 + HPACK 索引策略四档（T-HPACK，2026-09-28）** |
| H3 / QUIC | 有（uquic） | 预设级（v0.15+ 支持 H3 指纹） | ✗ | **H3 帧全控 + transport params 有序可控（T4-1）** |
| TCP / JA4TCP | 未声明 | ✗（栈层拿不到） | ✗ | TTL 三平台 + MSS（Linux/macOS）；window/WS 仅探测 |
| 身份一致性（UA/UA-CH） | 有 | 部分 | 有 | **identity 节（T2-1，三路径统一注入）** |
| 预设保真来源 | 抓包 | **真栈（构造性为真）** | 抓包 | **真实抓包自动生成（T2-2，本日起）** |
| 多语言 | Go | Python / C / Node(impers) | Python / Go | Python / Node / Go（C ABI 单一内核） |

### 结论

- **可控性：我们最强。** 三个库本质是「选一个预设」，我们是「逐字段构造 + hex 回放 + 有序帧参数」。
  唯一逐字段程度接近的是 requests-go（扩展清单/JA3/JA4），但它无 H3、无有序 transport params。
- **保真度：今天起追平。** 此前我们的差距不在引擎而在**预设是手写转录**；`cmd/gen-profiles`
  上线后，预设直接由真实抓包生成（10 个新预设：Chrome 137–152 / Edge 141 / Firefox 140-144 / Safari 18-26），
  与「抓包族」两个库同源。
- **结构性落后仅一项：真栈（BoringSSL）。** curl_cffi 的优势是「用浏览器自己的 TLS 栈，构造性为真」。
  我们不采用（方案 D2/D3），原因：TCP 层与整体 hex 回放只有自有栈能给，且需维护四层补丁链。
  对**常规 bypass** 而言这不是必需项——检测侧看的是握手字节与帧序列，而不是「谁生成的字节」。
- **预设族差异**：curl_cffi 覆盖浏览器版本最广（借真栈）；我们靠生成器可快速补齐任意版本，
  只要有抓包或标本来源。

## 2. TLS 领域能力缺口清单（按 bypass 价值排序）

| # | 能力 | 现状 | 影响 | 成本 | 建议 |
|---|---|---|---|---|---|
| G1 | **TLS 1.2 回退指纹** | ✅ **实测无缺口（2026-09-24 结案）**：服务端强制降级时 CH 逐字段不变；仅"客户端自身上限=1.2"的被裁剪形态未覆盖 | 原「高」**已证伪**：ClientHello 在得知服务端版本偏好之前就已发出，服务端降级不改变 CH → 我们与真 Chrome 的 JA3/JA4 同步不变（`tests/e2e/tls12_fallback_test.go` 17 预设实测证实） | 低（若确需伪装 1.2-only 老客户端，需要的是"一整套 era 预设"，属版本覆盖而非回退问题） | **结案**；"1.2-era 老浏览器预设"另列为按需项 |
| G2a | **会话复用（TLS1.3 PSK）** | ✅ **已实现并实测（2026-09-24 结案）**：引擎默认开启（`engine.go`）、每次拨号重新编译 spec、复用失败**丢票回退**全新握手 | 原「与 Chrome 在复用场景下分叉」**已消除**：真机实测 `resumed=true`（tls.peet.ws）与本地 std 服务端 `resumed=true`；`resumed` 由 `DidResume` 硬断言 | — | **结案**：`core/tls/resumption_test.go`（DidResume）+ `core/engine/resumption_test.go`（回退） |
| G2b | **0-RTT / early data** | ⚠️ **TCP 侧不可做（依赖栈硬限制，已取证）**：uTLS/Go 客户端不支持 early_data——上游注释写明 "0-RTT is not supported"（`handshake_server_tls13.go:1015`），且客户端早数据代码只出现在 `c.quic != nil` 分支；**H3/QUIC 侧原判"可做"现改判"不做"**：前提是 QUIC 会话缓存，而 spec 模式下 `StoreSession` 是 no-op 且无可补导出面（docs/06 P7-T2 取证），且 0-RTT 首飞的 Initial datagram 布局本身已结案为不可控（G6） | 中：真 Chrome 的 0-RTT 主要发生在 QUIC；TCP 侧无法对齐属依赖栈限制，**不是我们漏做** | — | **A10 结案（2026-09-30）**：协议侧不做；**指纹侧已可控**——预设 `{"type": 42}` 经透传上线，JA3 扩展段多一枚 42、JA4 扩展计数 +1（`core/tls/early_data_test.go` 实测，含"只带 42 不带 PSK 必被标准服务端拒"的边界证明） |
| G3 | **TLS record 层行为** | ⚠️ 部分：CH 长度由 padding 扩展控制（已有，可做）；**record 分片/大小序列在 crypto/tls 内部，无钩子** | 低-中：少数检测看 record 分片与首飞 record 数 | 高（需 fork crypto/tls，与 G2b/TCP 同一障碍） | 维持现状；不为它 fork |
| G4 | **session ticket 生命周期行为** | ⚠️ 复用链路已实测可用（G2a）；票据年龄字段由依赖栈按 RFC 8446 处理（**其取值我们未单独验证**）；"复用次数/换票节奏"**无实测依据，故不建模** | 低：需要长时观察才成特征；无依据地编一个"换票节奏"反而更假 | — | 维持现状：有实测证据再建模 |
| G5 | HPACK 索引细节 | ✅ **已落地（T-HPACK，2026-09-28）**：原评估"无钩子"是当时的实态——现由 vendor fork `core/third_party/fhttp` 提供钩子（`SetIndexPolicy`/`SetHuffmanMode`），`profile.http2.hpack_strategy` 四档 | 低（首连接无动态表历史这条仍成立，所以 safari 档只能是保守近似） | 已付（fork fhttp 的维护成本，见 LICENSES.md 风险项） | **结案**：`tests/e2e/h2_hpack_strategy_test.go` 逐字节断言；`docs/p2-h2-capability.md` 记证据与四档语义 |
| G6 | QUIC Initial datagram 布局 | ⚠️ **部分关闭（2026-09-30）**：首 datagram 尺寸 / PADDING 量已可控（`http3.initial_packet_size`，1200–1452，上游 `Config.InitialPacketSize`，无需 fork patch；嗅探实测 1350→[1350 1350]、1200→[1200 1200]、不设→[1280 1280]）；**coalesce 阈值与 CRYPTO 分片表仍不可控**（要动 `packet_packer.go` / `crypto_stream.go` = SC-3） | 低-中 | 高（packer 层，且要按 perspective 分支） | 保留后半：SC-3 时随内化一起做 |
| G7 | TCP 完整档（window/WS/options 真实生效） | ⚠️ 仅 Linux 探测模式 | 中（JA4TCP 场景） | 高（gVisor 级） | 维持降级承诺（T5-1） |
| G8 | 证书压缩 / ALPS / ECH / 后量子 key_share | ✅ 已有 | — | — | 保持 |
| G9 | H3/H2 racing + Alt-Svc | ✅ 已有 | — | — | 保持 |
| G10 | JARM | — 不适用 | 服务端**主动**扫描技术，客户端侧无对应面 | — | 记录说明即可 |
| G12 | **GREASE 值逐连接重随机化** | ✅ **已收口（2026-09-24）**：`sig_algs` 改为编译期取值；扩展 `type` 新增 `grease_random` 开关，13 个预设共 26 处全部迁移 | 影响已消除（原为"GREASE 值跨连接恒定"这一深层特征） | 已完成（compile + schema + 生成器 + 数据迁移） | **结案**；`TestGreaseAllRFC8701Values`（字面值原样透传 = P1-T3 能力）保持不动 |

## 3. 目标可达性判断

「常规 TLS 指纹均可通过」的构成拆解：

| 要求 | 我们是否满足 |
|---|---|
| JA3 / JA4 / JA4R 与主流浏览器一致 | ✅（真实抓包生成预设 + 自算回读） |
| HTTP/2 Akamai 四段一致 | ✅ |
| 身份头与 TLS 指纹自洽（UA/UA-CH） | ✅（T2-1） |
| HTTP/3 + QUIC 指纹一致 | ⚠️ 机制齐备（含有序 transport params），预设证据待 E2 |
| TLS1.2 回退场景一致（服务端降级） | ✅ **实测一致**（G1 结案，`tests/e2e/tls12_fallback_test.go`） |
| 1.2-only 客户端形态（客户端自身上限） | ⚠️ **已由第三方集覆盖（E3 级，非我们实测）**：chrome_43/80/101…、firefox_105/126、safari_7…26、curl_7.x…8.x、ie 等（见 §5.7）；我们自测的预设仍无 1.2-only 形态 |
| 会话复用场景一致（TLS1.3 PSK） | ✅ **实测一致**（G2a 结案：`resumed=true` 真机 + 本地互证） |
| 0-RTT early data 首飞 | ⚠️ **协议侧不做、声明侧可控**（G2b/A10 结案：预设里 42 能上线并改变 JA3/JA4，但真早数据无钩子） |
| TCP 层一致 | ⚠️ 仅 TTL/MSS |

**判断**：TLS1.2 回退（G1）与 TLS1.3 会话复用（G2a）均经实测结案，不构成缺口；
剩余为 0-RTT（G2b，**A10 已结案为"协议侧不做"**）、record 层（G3）、ticket 生命周期（G4）。
优先级排序 **G2b ≈ G3/G4 > 其余**；G12 已按第二轮实测修正（扩展 type 非缺口，真缺口只在 sig_algs）；
"1.2-era 老客户端预设"按需另议。

## 5. 真实抓包 ground truth 对照（2026-09-24）

样本：**Chrome 149 / Edge 149（Windows）** 与某同类库，同样对 `tls.peet.ws` 的完整响应。
逐字段 diff 结论：

| 维度 | Chrome 149 实测 | 同类库 | 本项目（修正后） |
|---|---|---|---|
| ciphers / curves / points / supported_versions / sig_algs | 基准 | 完全一致 | 一致 |
| TLS 扩展集合（剔 GREASE） | 17 项（**含 41 pre_shared_key**） | 16 项（无 41） | 16 项（无 41） |
| 扩展顺序 | 每连接随机洗牌 | 另一种洗牌 | 洗牌（`extension_permutation`） |
| ALPS 码点 | 17613（Chrome ≥132；≤131 为 17513） | 17613 | 版本对应 |
| ECH(65037) 负载结构 | `outer|kdf|aead|config_id|enc_len=32|enc(32)|len|payload`，总长 42+N | 同结构 | **已修正**（原缺 32B enc 段） |
| sec-ch-ua | `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"` | 同格式（Edge 品牌位） | **已修正**（原顺序反 + 旧 GREASE 品牌） |
| 导航头集合与顺序 | `sec-ch-ua*` → `upgrade-insecure-requests` → `user-agent` → `accept` → `sec-fetch-{site,mode,user,dest}` → `accept-encoding` → `accept-language` → `priority: u=0, i` | 同（多一个 `cache-control: max-age=0`） | **已补齐** |
| HTTP/2 akamai 四段 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | 完全相同 | 一致（ground truth 回归钉住） |
| HEADERS 帧 flags | `EndStream,EndHeaders,Priority(0x20)`，priority excl=1 dep=0 w=256 | 相同 | ✅ 已按实测钉住（G11 收口；Chromium 的 fhttp 默认值恰为实测形状，Firefox 已显式改为 excl=0/w=42） |
| TCP SYN | win 65535 / ws 8 / `mss,nop,ws,nop,nop,sok` / 无 TS / DF | 完全相同 | ⚠️ 仅 TTL/MSS 可生效（G7） |

### 5.1 关键判读

1. **JA4 的 `1516` vs `1517` 差异来自 41（pre_shared_key），属场景差异不是缺陷**：
   实测 Chrome 是复访（带会话票据），同类库是首访。两者都是真实 Chrome 的合法状态，
   对应我们的「首访不带 PSK」与「有票据时复用」（G4）。
2. **同类库的 TLS 层几乎完美**——除 PSK 场景项外与真 Chrome 逐字节同构。这印证：
   我们补齐上述两项（ECH 结构、身份头）后，TLS/HTTP2 面已与其持平。
3. **最值得警惕的是身份头**：UA-CH 的品牌顺序与 GREASE 品牌随 Chrome 版本演进，
   写错就是「TLS 完全一致但 HTTP 头一眼假」。现已改为抓包实证格式并加回归测试钉住。

### 5.2 第三方实现交叉校验（2026-09-28）

拿到一份 curl_cffi 的"**号称 Safari**" impersonation 抓包（同一域名 `tls.peet.ws`）。
**它不是 Safari**，判据三条：`user_agent` / `sec-ch-ua` 是 **`Edg/149`**；JA4 的 cipher 段
`8daaf6152771` 与 Chrome/Edge 同源；HTTP/2 四段与 HEADERS priority（`excl=1/w=256/dep=0`）
都是 BoringSSL/Chrome 形状——它**不是 Safari**（Safari 的 priority 形状当时未知；2026-09-28 已用真机实测补齐，见 §5.4），故这份抓包补不了 Safari 的缺口。

但它有一个真实价值——**第三方互证**：

| 维度 | 我们 `chrome_149_windows` / `edge_141_macos` | curl_cffi 该 profile |
|---|---|---|
| JA4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | **逐字符相同** |
| cipher 序 / 扩展集合 | Chrome 序（4865-4866-4867-49195-…）16 扩展 | 相同集合（顺序为其自身洗牌） |
| Akamai 四段 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | 完全相同 |
| HEADERS priority | `excl=1 / w=256 / dep=0`（flags `0x20`） | 完全相同 |
| ECH GREASE 结构 | `outer=0,kdf=1,aead=1,enc_len=32…` | 同结构（`aead=1`） |
| ALPS 码点 | 17613 | 17613 |
| 双 GREASE 扩展 + 位置 | 首 + 尾，值逐连接变化 | 相同 |

⇒ 一个与我们无关的实现独立复现了同一枚指纹，Chrome/Edge 面由此从"单一来源（我们自己的抓包）"
变成**双来源**；该 JA4 已钉进回归（`TestPresetJA4Pinned`）。

**顺带的口径提醒**：外部"Safari 伪装库"的实际产物可能是 Edge/Chrome 形状——真要伪装 Safari
不能照抄这类 profile。（当时 `safari_*` 预设仍属未实测；2026-09-28 起 17.3.1 / 18.6 已有真机实测，见 §5.4。）
4. **G11 已收口（2026-09-24）**：Chrome 149 用 HEADERS **内嵌** priority 而非独立
   PRIORITY 帧（akamai 第 3 段为 `0` 正是这个原因）。实测分族取值：Chrome/Edge
   `excl=1/dep=0/w=256`、Firefox `excl=0/dep=0/w=42`。fhttp 的**默认值恰是 Chrome 形状**，
   故 Chromium 预设无需显式声明——由 `tests/e2e/fp_oracle_test.go` 的断言钉住，
   防止 fork 默认值无声漂移；Firefox 由新增的 `profile.http2.headers_priority` 显式覆盖。
   （2026-09-28 补：手写预设 chrome_131/133/150 的 http2 节已显式补齐
   `headers_priority{excl=1,w=255}`——与默认值同值，纯数据补齐，引擎行为不变。）
   剩余面：**Safari** —— 2026-09-28 已由真机实测收口（17.3.1 / 18.6 均 `exclusive=false`，见 §5.4）。

### 5.2 本轮据实测修复

- `core/h3/h3.go`：ECH GREASE 合成负载补齐 32 字节 enc 段（结构 42+payload）。
- `tests/e2e/cmd/gen-profiles`：Chromium 身份头按实测重写（品牌顺序 / GREASE 品牌 /
  导航头顺序），10 个生成预设重新产出。
- 手写预设 `chrome_131/133/150`：同步修正 sec-ch-ua 并补齐导航头。
- 新增回归：`core/h3/ech_test.go`（ECH 结构）、`tests/e2e/groundtruth_test.go`
  （Chromium 身份头顺序与格式、TLS 扩展集合、H2 akamai 三段）。

## 4. 本轮已落地（对照本清单的变化）

- 预设来源从「手写转录」改为「真实抓包生成」→ 保真度追平抓包族同类库。
- H3 transport params 顺序/非标/GREASE 位置可控（T4-1）。
- 身份一致性 identity 节（T2-1）。
- 语料回归基线本地冻结（10 个真实标本，独立解析器对拍）。
- **G1 结案（2026-09-24）**：新增 `tests/e2e/tls12_fallback_test.go`——同一 profile 分别对
  「支持 1.3 采集端」与「MinVersion=MaxVersion=TLS1.2 采集端」各发一次，逐字段比对
  ciphers / 扩展集合 / groups / points / versions / sig_algs / ALPN 及 H2 SETTINGS / WINDOW_UPDATE，
  17 个预设全绿 → 服务端强制降级下 CH 与 1.3 场景完全一致。这是回归钉，不是一次性实验。
- **G12 口径修正（2026-09-24 第二轮实测，推翻部分先前判断）**：
  - **扩展 `type` 的 GREASE 不是缺口**：复用同一份 spec 连发两次，线上 GREASE 扩展值为
    `[35466 47802] → [19018 10794]` —— uTLS 每次 `ApplyPreset` 重取 `greaseSeed` 并把新值
    **回写进 spec**（这也是 spec 不可复用的原因之一）。先前"uTLS 对扩展 type 原样透传"
    是**由测试推断**而来，推断有误。原「G12 登记」中"13 预设 × 2 处"的说法据此作废。
  - **真正的缺口只有 `sig_algs`**：uTLS 不替换 `signature_algorithms` 里的 GREASE 占位
    （实测恒为 `0x0a0a`），故改由 `core/tls` 在编译期取随机值（`grease_rerandomize_test.go` 钉住）。
  - `Grease.Extensions` 注入 `Value=0` 会被写成扩展 type 0（= SNI）——这是**真隐患**，已修。
  - 已实现的 `grease_random` 开关（13 预设 26 处）**保留**：它覆盖的是 QUIC 路径
    （`bogdanfinn/quic-go-utls` 是另一套 TLS 栈，是否同样重取未测），但其必要性**未经实测证明**，
    若确认 QUIC 侧也重取，可简化掉。
  - **刻意保留**字面 GREASE 值原样透传能力（`TestGreaseAllRFC8701Values` 不动），随机化走 opt-in。
- **口径澄清（实测）**：`tls_version_record` 恒为 771，**不可作版本判据**；判据是 `tls_version_negotiated`
  与 JA4 前缀（`t13`/`t12`）。服务端降级时 H2/Akamai 四段不受影响。

- **spec 跨连接复用不安全（2026-09-24 真机探针发现）**：uTLS 的 `ApplyPreset` 会把状态**回写**
  传入的 `ClientHelloSpec`（实测回写点：SNI `0 → 主机名`、key_share `19 → 1267` 字节、
  GREASE 值改写），上游注释亦明文要求"每次用不同的 spec、避免共享状态"。复用同一份 spec 的
  第二次握手会以 `tls: internal error` 失败，且 SNI 会残留上一台主机名（跨主机身份泄漏）。
  - **engine 本就是安全的**：`core/engine/dial.go` 每次拨号重新 `CompileDetail`；
  - 库边界已补：`Handshake` 文档写明契约，并在签名吻合时把该失败转成可行动提示；
  - 回归钉：`core/tls/spec_reuse_test.go`（本地确定性复现 + 回写机制断言）。
- **崩溃路径修复：预设缺 `pre_shared_key` 占位 + 复用缓存命中 ⇒ uTLS panic**
  （`u_session_controller.go:128` `initPskExt failed ...`）。引擎**默认开启**会话复用，而按 E1
  首访抓包生成的 9 个预设（chrome_141/142/143/149/152、edge_141/153、safari_18_macos/26_macos）
  都没有该占位 ⇒ 那曾是一条真实的**进程崩溃**路径（e2e 没抓到是因为它们多用 chrome_133，
  恰好有占位）。修复：
  - 生成器新增 `normalizePskPlaceholder`（族无关：缺则**末尾**追加空占位，并清掉标本里转录的
    真实票据负载——`chrome_137_macos` 原先就带着 232 hex 的真实票据），12 个生成预设与
    8 个手写预设口径统一；
  - 守门测试 `TestPresetCarriesPskPlaceholder`（**双向**：声明 TLS 1.3 的预设必须有 41 且位于**末尾**；
    不声明 1.3 的老客户端预设**必须没有** 41——硬加会让 ClientHello 结构非法）；
  - `Handshake` 另加 panic→error 兜底（uTLS 对"异常会话状态"同样会空指针 panic，见下）。
- **会话复用实测可用（G2a 结案）**：真机 `tls.peet.ws` 与本地 Go std 服务端均实测 `resumed=true`
  （`DidResume` 硬断言）。**旧文"std 服务端不接受 uTLS binder（bad record MAC）"是误诊**——
  当时那份测试两次握手复用了同一 spec，根因就是上面的 spec 回写。缓存键实测为 SNI
  （共享一个缓存不会串台）。引擎策略补齐：复用失败**丢票回退**全新握手（浏览器同款行为），
  由 `core/engine/resumption_test.go` 注入坏票据做确定性验证。
- **方法论教训（两个把实测读歪的坑，已固化进探针注释）**：
  1. spec 复用会让"第二次握手失败"看起来像服务端/协议问题（本次差点据此得出"复用不可用"）；
  2. TLS1.3 票据是**握手之后**才发的——握手完立刻关连接，票据不入缓存，`resumed` 恒 false。

### 5.3 macOS Chrome 154 真机实测（2026-09-28）

又拿到一份 macOS 抓包——**同样不是 Safari，是 Chrome 154 for macOS**。判据：`user_agent` /
`sec-ch-ua` 是 `Chrome/154` + `platform="macOS"`。

> **更正（2026-09-28，同日）**：本节初稿还把"发 GREASE"当作判据（"Safari 从不发 GREASE"）——
> **那是错的**。真 Safari 抓包（见 §5.4）显示 Safari 照样发 GREASE（cipher / versions / groups /
> key_share 五处 + 两个 GREASE 扩展）。判断浏览器族**只能靠 UA/UA-CH/JA4 派生特征**，
> 不能靠 GREASE。好在两处结论（curl_cffi 是 Edge 形状、这份是 Chrome）依据的都不止 GREASE，
> 结论不变，**依据作废**。

这份样本的三项可用信息：

1. **152 → 154 的 TLS 面无漂移（互证）**：JA4 = `t13d1517h2_8daaf6152771_cb7bf5808d99`，与我们
   `chrome_152_macos` **逐字符相同**（cipher 序、扩展集合、sig_algs 皆同）。已新增
   `chrome_154_macos` 预设（逐字段转录：含新扩展 51764 的字面负载、ECH 用 `mode=grease`），
   并把两者一起钉进 `TestPresetJA4Pinned`。
2. **`sec-ch-ua` 的品牌顺序与 GREASE 品牌在版本间会变**（三个实测样本三种形态）：

   | 样本 | sec-ch-ua |
   |---|---|
   | Chrome 149 / Windows | `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"` |
   | Edge 153 / Windows | `"Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"` |
   | Chrome 154 / macOS | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` |

   ⇒ 三样本三种顺序，**无法区分"每版本固定"与"每会话随机"**（需同一版本连抓两次才能定）。
   因此回归测试已放宽为"三项齐全 + 版本自洽"，**不再要求自家品牌在首位**（原先那条属过度固化）；
   预设各自保留其抓包实测的那一份顺序。
3. **首次见到 macOS 侧 TCP SYN 形态**（`mss=1400 / win=42340 / ws=9 / TS on / opts=mss,sok,ts,nop,ws`）：
   但源 IP 是机房地址、与该用户其它抓包一致地疑似经中转 ⇒ **不据此改预设**（`tcp` 节仍留空，G7 维持）。

另记一个**未定论**的观察：扩展 51764 的负载是「`<u16 总长>` + 若干 `<u8 长><内容>` 子项」，
152 与 154 两份的**子项集合完全相同、顺序不同**（154 那份恰为升序）。这可能是
①Chrome 每连接洗牌该列表，或 ②我们早先转录 152 时被工具链重排（Go map 迭代顺序）。
两种解释都能自洽 ⇒ **不实现洗牌、也不改 152 的数据**；同一版本连抓两次即可判定。

**H3 声明**：154 的 `http3` 节**借自 `chrome_152_macos`**（同平台、TLS 面无漂移已证），
QUIC transport params **未实测**；这是为满足 `TestBuiltinChromiumH3Coverage`（缺节会露出
通用 Go 客户端，比"未验证"更糟）而做的显式取舍，待有 mac H3 采样时用 `e1_h3_test.go` 补测。

### 5.4 真 Safari 实测（2026-09-28）——G11 收口

拿到两份**真 Safari**（macOS）：**17.3.1** 与 **18.6**，均为对 `tls.peet.ws` 的导航请求。
配合已实测的 Chrome / Firefox，三族 TLS 面横向对照：

| 维度 | Chrome 149/154 | Firefox 156 | **Safari 17.3.1** | **Safari 18.6** |
|---|---|---|---|---|
| cipher 数（含 GREASE） | 16 | 15 | **21**（含 3DES 三条 + 更多 CBC） | 同 17.3.1 |
| 扩展数（剔 GREASE） | 16 / 17 | 17 | **14** | 14 |
| `padding (21)` | — | — | ✅ **390 字节** | ✅ **394 字节** |
| `application_settings (17613)` | ✅ | — | ❌ | ❌ |
| ECH GREASE (65037) | ✅ | ✅ | ❌ | ❌ |
| `session_ticket (35)` | ✅ | ✅（首访） | ❌ | ❌ |
| `compress_certificate` | brotli | zlib+brotli+zstd | **仅 zlib** | 仅 zlib |
| `supported_versions` | 1.3, 1.2 | 1.3, 1.2 | 1.3, 1.2 + **1.1, 1.0** | 同 17.3.1 |
| sig_algs | 8 项 | 11 项 | 11 项（**含 ecdsa_sha1**、`0x0805` 重复） | 10 项（**去掉 ecdsa_sha1**） |
| key_share | MLKEM768+25519 | MLKEM768+25519+P256 | **仅 X25519** | 仅 X25519 |
| GREASE | 有 | 无 | **有**（五处 + 2 扩展） | 有 |
| 扩展顺序洗牌 | 是 | 否 | **否**（两版顺序逐项一致） | 否 |
| JA4 | `t13d1516/1517…` | `t13d1517…` | `t13d2014h2_a09f3c656075_14788d8d241b` | `t13d2014h2_a09f3c656075_e42f34c56612` |

**G11 收口（HEADERS 帧内嵌 priority）** —— 三族各不相同，已全部实测到位：

| 族 | exclusive | weight（peet 报数 = 线上值 + 1） |
|---|---|---|
| Chrome / Edge | **true** | 256（线上 255） |
| Firefox 156 | false | 42（线上 41） |
| **Safari 17.3.1** | **false** | 255（线上 254） |
| **Safari 18.6** | **false** | 256（线上 255） |

⇒ `exclusive` 是族级硬区别（Chrome 独有 true）；weight 在 Safari 两版间还差 1（**原因未知，如实记录**）。
两版 Safari 的值已写进预设，并由 `tests/e2e/fp_oracle_test.go` 的 G11 断言钉住 ——
**G11 的 Safari 剩余面至此关闭**。

**HTTP/2 面（Safari 两版之间的差异）**：

| | 17.3.1 | 18.6 |
|---|---|---|
| SETTINGS | `2:0; 4:4194304; 3:100` | `2:0; 3:100; 4:2097152; 9:1`（**NO_RFC7540_PRIORITIES**） |
| WINDOW_UPDATE | 10485760 | 10420225 |
| 伪头顺序（Akamai 第 4 段） | **m,s,p,a** | **m,s,a,p** |
| 导航头顺序 | accept → sec-fetch-site → accept-encoding → sec-fetch-mode → UA → accept-language → sec-fetch-dest（**无 priority**） | sec-fetch-dest → UA → accept → sec-fetch-site → sec-fetch-mode → accept-language → **priority** → accept-encoding |
| UA-CH | 无（Safari 不发 UA-CH） | 无 |

**预设更新**（两条路径，注意命名空间——生成预设不能被手改，否则 CI 生成器守门会红）：

- **新增两个全量实测预设**：`safari_17_3_macos`（含 `ecdsa_sha1`、padding 390B、priority
  `excl=false/w=254`）与 `safari_18_6_macos`（padding 394B、priority `excl=false/w=255`、H2 含 `9:1`）。
  二者 JA4 钉进 `TestPresetJA4Pinned`，padding 由 `TestPresetSafariPadding` 钉住。
  —— 这两份抓包是**字段级**记录（无原始 ClientHello hex），只能作为手写预设入库：
  生成器的标本必须是**原始 hex**（见 `gen-profiles/record.go`），所以它们进不了生成链。
- **生成器侧**（`gen-profiles`）：补上 Safari 的 `headers_priority`（`exclusive=false/w=255`）与
  **导航身份头**（新增 `safariIdentity`：<18 用 17.3.1 的顺序且**无** `priority`；≥18 用 18.6 的顺序
  且**含** `priority`）。原先 Safari 走的是"精简集 + `accept: */*`"的非导航形态，源码注释也写着
  "仍无抓包依据，待 E1"。
- 生成预设 `safari_18_macos` 的 **TLS 来自带原始 hex 的标本**，其 JA4 与**实测 18.6 完全相同**
  （`t13d2014h2_a09f3c656075_e42f34c56612`）⇒ 是该形态的独立复现（差异只在不进 JA4 的量上：
  wire 874B vs 实测 1264B）。
- 另两个**无实测来源**的历史预设 `safari_18` / `safari_26_macos` 差距明显：JA4 为 `t13d2013…`
  （13 扩展，比真机少 1 个）且 wire ≈2.9KB（真机 ≈1.26KB）⇒ 一并钉进回归，**登记为待校验**
  （未擅自改数据）。⇒ 需要"导航形态的 Safari"时，请用 `safari_17_3_macos` / `safari_18_6_macos`。

**顺带落定的两件事**：

1. **这几份抓包的 TCP SYN 是"中转"的，不是浏览器的**：同一出口 IP 下 Chrome 140 与 Safari 18.6
   的 SYN 完全一致（`mss=1400/win=7300/ws=10/ECN`），另一出口下 Chrome 154 与 Safari 17.3.1 也一致
   （`mss=1400/win=42340/ws=9`）——两个不同浏览器同参数 ⇒ 该 SYN 属中转节点。
   **结论：不能据此改 TCP 层（G7），`tcp` 节一律不动。**
2. **UA-CH 顺序出现第 4 种形态**：Chrome 140 / macOS = `"Chromium";v="140", "Not=A?Brand";v="24",
   "Google Chrome";v="140"`。加上 149 / 153 / 154 三种，**四样本四种顺序 + 四种 GREASE 品牌名**
   ⇒ 强烈指向"每会话/每安装随机"（UA-CH 规范本就允许客户端打乱品牌顺序并随机 GREASE 品牌），
   但**仍未直接观测到"同一版本两次不一致"** ⇒ 暂不实现随机化（免得比真实更随机），
   只把断言放宽为"三项齐全 + 版本自洽"（见 `tests/e2e/groundtruth_test.go`）。

### 5.5 iOS 17.2 实测（2026-09-28）——「iOS 三兄弟共用 WebKit 形态」

同一台 iPhone / iOS 17.2 / 同一网络下的三份抓包：**Safari、Chrome（CriOS 148）、Edge（EdgiOS 148）**。

| 维度 | iOS Safari 17.2 | iOS Chrome 148 | iOS Edge 148 |
|---|---|---|---|
| JA3 哈希 / JA4 | `773906b0…` / `t13d2014h2_a09f3c656075_14788d8d241b` | **同** | **同** |
| ciphers / 扩展 / sig_algs / padding | 21 / 14 / 含 `ecdsa_sha1` / 390B | **同** | **同** |
| H2 四段 / 伪头顺序 | `2:0;4:2097152;3:100\|10485760\|0\|m,s,p,a` | **同** | **同** |
| HEADERS priority | excl=0，报告 255（线上 254） | **同** | **同** |
| 导航头顺序 | accept → sec-fetch-site → accept-encoding → sec-fetch-mode → UA → accept-language → sec-fetch-dest | **同** | **同** |
| UA | `Version/17.2 … Safari/604.1` | `CriOS/148.0.7778.166` | `EdgiOS/148.0.3967.97 Version/17.0` |

⇒ **iOS 上第三方浏览器必须使用 WebKit**，于是 TLS 栈与 H2 帧层也归 WebKit：三者 TLS/H2 面
**逐字符相同**，**唯一差异是 UA**。两条直接推论：

1. **拿桌面 Chrome 的形状去充当 iOS Chrome 属一眼假**（cipher 序 / 扩展集 / padding / H2 全不对）；
2. iOS 三兄弟可**共用同一份 detail**，只在身份层分叉 —— 预设即按此落：
   `safari_17_2_ios` / `chrome_148_ios` / `edge_148_ios`，
   由 `TestIOSBrowsersShareWebKitShape` 钉住「共用形态 + UA 各异」。

**与 macOS Safari 的关系**：iOS 17.2 与 macOS 17.3.1 的 JA3/JA4 **完全相同** ⇒ WebKit 的 TLS
形态**跨平台一致**（本例只差 H2 的 setting 4：iOS 2097152 vs macOS 4194304）。
**HEADERS priority**：iOS 17.2 与 macOS 17.3.1 同为线上 254，macOS 18.6 为 255 ⇒
更像「随 Safari 版本变化」，比之前的孤例更可信。

**TCP（首个可信的真机移动端 SYN）**：`mss=1380 / win=65535 / ws=6 / **无时间戳** / ip_id=0 / DF /
选项区补 NOP 至 40 字节（mss,nop,wscale,nop×13,sackOK,eol）` —— `ip_id=0` 与「不发 TCP 时间戳」
都是 Apple 设备典型特征，与前面几份「中转节点 SYN」形态完全不同。预设 `tcp` 节取
`ttl=64`（Apple 默认；抓到的 48 是 16 跳后的值）与 `mss=1380`（实测）。

### 5.6 Android 14 实测（2026-09-28）——平台维度补齐，并否掉 UA-CH 随机化

同一台 Android 14 手机的三份抓包：Chrome 154、Edge 153（EdgA）、Firefox 156。

| 维度 | Android Chrome 154 | Android Edge 153 | Android Firefox 156 |
|---|---|---|---|
| JA3 哈希 | `c17d8337…` | `353b27fd…` | `9d42e90b…` |
| JA4 | `t13d1517h2_…_cb7bf5808d99` | `t13d1516h2_…_806a8c22fdea` | `t13d1517h2_…_3cbfd9057e0d` |
| 与**桌面同版本**的 JA4 | **= `chrome_154_macos`** | **= `edge_153_windows`** | **= `firefox_156_windows`** |
| H2 四段 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | 同左 | `1:4096;2:0;4:32768;5:16384\|12517377\|0\|m,p,a,s` ← **与桌面不同** |
| HEADERS priority | excl=1 / 256 | 同左 | excl=0 / 42 |
| 导航头顺序 | **UA-CH 三件套在 `accept` 之后**（桌面版排最前） | 同左 | 与桌面 Firefox 相同（**少 `sec-fetch-user`**） |
| UA | `(Linux; Android 10; K) …Chrome/154…Mobile` ← **UA 缩减** | `…EdgA/153.0.0.0` | `(Android 14; Mobile; rv:156.0) …Firefox/156.0` |
| sec-ch-ua | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` | `"Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | 无 UA-CH |
| 扩展 51764 | ✅（负载与 macOS 154 **逐字节相同**） | ❌ | ❌ |

三条结论：

1. **Chromium 与 Firefox 的 TLS 面跨平台一致**（JA4 逐字符相同）⇒ 同一份 TLS detail 可在平台间复用；
2. **但 Firefox 的 H2 SETTINGS 随平台变化**（Windows `1:65536;4:131072` vs Android `1:4096;4:32768`）
   ⇒ H2 必须**按平台各留一份**（Chromium 无此问题）；
3. **`sec-ch-ua` 是「按版本固定」，不是「每会话随机」** —— Edge 153 的 Windows 与 Android 两份抓包
   **逐字符相同**，Chrome 154 的 macOS 与 Android 同样。⇒ 否掉先前"四样本四形态 ⇒ 可能每会话随机"的猜测，
   **不做 UA-CH 洗牌**（做了反而可能比真实更随机）。`docs/08` 的 S1 前半据此结案；
   后半（扩展 51764 子项顺序：152 乱序 vs 154/Android 升序）仍需「同版本连抓两次」判定。

**UA 缩减提醒**：Chrome 在 Android 10+ 把 UA 冻结为 `Android 10; K`（不暴露真实版本/机型）；
把它"修正"成 `Android 14; Pixel…` 反而是一眼假的破绽。Firefox 不做同等缩减（如实报 `Android 14`）。

**TCP**：该机 SYN（`ttl=53 / mss=1320 / ws=9 / TS`）与用户桌面抓包**同一形态**，且源 IP 即用户出口
⇒ 仍是**中转节点**产物，不据此改 `tcp` 节。

**预设**：新增 `chrome_154_android` / `edge_153_android` / `firefox_156_android`；
三条跨平台结论与"UA-CH 按版本固定""UA 缩减形态"由 `TestCrossPlatformSameVersionShape` 钉住。

### 5.7 第三方指纹集导入（2026-09-28）——覆盖面从 4 族扩到 29 族

用户提供 `tls_config-0.0.2`（Python 包，339 条硬编码配置）。**它不是我们的实测**，但有两个
明确价值：① **覆盖面**（我们没有的版本/平台/客户端）；② **交叉校验**（拿它的数据反过来查我们）。

#### 管线（可复现，全部入库）

| 步骤 | 产物 |
|---|---|
| 导出 | `tests/e2e/cmd/import-tlsconfig/dump.py` → `profiles/evidence/thirdparty/tls_config-0.0.2.json`（快照入库） |
| 转换 | `tests/e2e/cmd/import-tlsconfig/main.go`（Go，纯转换；`-dry` 可预览） |
| 落盘 | `core/profiles/builtin/<name>.json`，带 `grade: "E3"` + `source: "tls_config-0.0.2/<常量名>"` |
| 守门 | `core/profiles/provenance_test.go`（E3 必须标来源、自测不得有 source）；**所有 E1 级断言（oracle / GT / TLS1.2 回退）一律跳过 E3** |

**结果**：`自测 29 + 第三方 E3 319 = 348 个预设`，族分布
`opera 86 / chrome 55 / curl 41 / safari 31 / firefox 19 / charles 15 / edge 10 / wechat 8 /
okhttp 6 / reqable 5 / ie 4 / powershell 4 / heytap 4 / mqq 4 / miui 3 / huawei 3 / quarkpc 3 /
vivo 3 / gold 2 / uc 2 / …`——**顺带把 G1 的"1.2-era 老客户端形态"这一剩余面覆盖了**
（chrome_43/80/101…、firefox_105/126、safari_7…26、curl_7.x…8.x、ie 等）。

#### 交叉校验（第三方 vs 我们的实测）

| 条目 | 结论 |
|---|---|
| `chrome_131_windows` / `chrome_141_macos` / `edge_141_macos` / `safari_17_3_macos` | **cipher 序 / 扩展集合 / H2（含流控与 HEADERS priority）全部一致 ✓** |
| `chrome_133_windows` | **cipher 序不同**：第三方为 `AES256, AES128, CHACHA…`，我们是 Chrome 标准序（`AES128, AES256, CHACHA…`，与 149/154 实测一致）⇒ 疑其该条有误 |
| `firefox_135_windows` | **第三方多 `18(SCT)` 与 `27(compress_certificate)`** —— 而我们实测的 Firefox 156 **有**这两个 ⇒ 说明**我们的 `firefox_135`（早期手写）缺扩展**，需要重测 |

⇒ 这就是第三方数据的正确用法：**当镜子照自己**。上面两条差异已登记为待办（docs/08 S8/S9），
**没有**据第三方去改我们自己的预设（那等于用猜测覆盖实测）。

#### 第三方没给、由我们补的部分（逐条登记，不做静默假设）

- `padding(21)`：第三方只说"有"，长度用我们实测值（Safari 390 / Chromium 策略 `padding_to=512`）；
- `ECH(65037)`：用 `ech.mode=grease`（第三方无负载）；
- `http3` 节：Chromium 系**借用**我们已入库的实测参数（第三方集不含 QUIC 数据）；
- 身份头：**只有 chrome/edge/firefox/safari 用我们的实测模板**（版本号取自第三方）；其余 25 族
  **只给 UA**（它们的请求头我们没有实测，绝不编）；
- `sec-ch-ua`：按我们实测的两个形态二选一（≤149 / ≥150），**逐条登记为推断**；
- `pre_shared_key(41)`：**只在第三方声明 TLS 1.3 时**才追加占位——老客户端（Safari 9）本不发它，
  硬加会让 ClientHello 结构非法（实测：Go 服务端报 `error decoding message`）；
- `force_http1`：忠于第三方标记（老客户端只提供 `http/1.1`，不发 ALPS）。

#### 转换期发现的两处 schema/引擎限制（A11 已解除，2026-09-29）

1. ~~**无法表达"不发连接级 WINDOW_UPDATE"**~~ ⇒ `http2.window_update` 改为**三态**
   （省略 = 补 15663105 / `0` = 不发该帧 / `N` = 发 N），`core/h2` + vendor fork
   全链路生效，线上形态由 `tests/e2e/h2_capture_test.go` 的三态用例钉住；
2. ~~**无法表达"首个请求用 stream_id=3"**~~ ⇒ 新增 `http2.first_stream_id`
   （奇数校验），fork 的 `Transport.InitialStreamID` 落地，同一测试的
   `first_stream_id=3` 用例钉住线上首个 HEADERS 的流号。

**重新执行导入管线后的实际变化（`diff -r` 全量对拍，只有两处）**：预设总数
**363 → 364**——新增 `safari_9_1_3_macos`（E3，不再被跳过）；`firefox_145_windows`
多一个 `first_stream_id: 3`（照抄第三方 `headers_id`）。其余 322 个 E3 文件逐字节
不变，非 E3 预设一律保留原样（同名走对拍）。

Safari 9.1.3 那条**没有**按"flow=0 ⇒ 不发"入库：第三方给的是 `null`（不是 0），
而 null 既可能是"不发"也可能是"未采集"。我们没有该版本的 H2 实测，所以按**未指定**
处理（线上补 15663105）并在导入器报告里逐条登记——来源的空白不读成一种线上行为。
`docs/08` 的 S 项：拿到 Safari 9 真机抓包后才能判定这一档到底该写 0 还是 15663105。

#### 证据分级与晋升路径（2026-09-28 起）

外部导入只是**覆盖面对齐**，绝不当成实测。预设因此有了显式等级（`Profile.grade`）：

| grade | 含义 | 参与 E1 级断言 |
|---|---|---|
| 留空 | 本项目自测（E1 真机抓包 / E1r 字段级实测 / E2 本机可复现） | ✅ |
| `E2i` / `E2i-u` | **谱系内插**（实测锚点 + 逐字段稳定性规则；`-u` = 区间内有字段变化且边界未知） | ❌ |
| `E3` | 外部指纹集导入（只补覆盖，不做保真承诺） | ❌ |

守门：`core/profiles/provenance_test.go`；4 个 E1 测试按 `grade != ""` 一律跳过
（fp oracle / Chromium GT / Firefox GT / TLS1.2 回退）。

**谱系生成**（`gen-profiles -lineage`，机制与对比见 `docs/09`）：用我们自己的实测锚点
（chrome 137/141/142/143/152、edge 141、firefox 140/144、safari 18/26）做**逐字段跨版本
稳定性判定**，内插窗口内的缺失版本，窗口外一律不外推。本次结果：内插 14 个
（chrome 138–140 全稳 = `E2i`；144–151 有 3 个未定界字段 = `E2i-u`；firefox 141–143 全稳 = `E2i`），
**按设计拒绝** Safari 19–25（密码套件在 18→26 之间变过 ⇒ 内插等于凭空造栈）。
副产品是一份**浏览器指纹演化日志**（全部来自我们自己的实测）：Chrome 143→152 出现 `51764`
与 ML-DSA 签名算法（`0x0904/0905/0906`）；Safari 18→26 丢 1.1/1.0、加 `0x11ec`(X25519MLKEM768)、
padding 消失。

## 6. E1 真浏览器基准（2026-09-24）——打破同源自证

工具：`tests/e2e/cmd/e1-browser`（本地无头真实浏览器 → 本地 fp 采集端 → 逐字段对照内置预设；
记录含原始 ClientHello hex，落盘 `profiles/evidence/browsers/`）。

| 真浏览器 | 对照预设 | 结论 |
|---|---|---|
| Chrome 149.0.7827.54 (Windows) | `chrome_150` | ✅ **逐字段完全一致**：ciphers / 扩展集合 / curves / points / versions / sig_algs / ALPN / H2 SETTINGS / WINDOW_UPDATE |
| Edge 153.0.4234.48 (Windows) | `edge_141_macos` | ⚠️ `sig_algs` 差异：真 Edge 多 `0x0904/0x0905/0x0906`（rsa_pss_pss_*，Chromium ≥150 新增） |

**判读**：
1. `chrome_150` 从 E4（知识构造）升级为**有 E1 真机逐字段背书**（真机 149 与本预设同形）。
2. 本机两浏览器 `sig_algs` 均**不含** GREASE，而 `chrome_152_macos` 真标本含 `0xEAEA`
   ——疑为版本差异（Chromium 是否在 ≥150 的某个版本引入 sig_algs GREASE），待 152 真机复核；
   不论结论如何，我们的编译期随机化都避免了"恒定 GREASE 值"这一更差的形态。
3. 同一浏览器两次抓包扩展顺序不同、JA4 相同 → 再次印证逐连接洗牌与 JA4 的排序语义。
4. **仍未解决**：H3/QUIC 的 E1（需真实浏览器 H3 抓包；Firefox/Safari 的 transport params
   不能由 Chromium 家族继承），见 `profiles/evidence/README.md` 待补证据。

### 6.1 H3 E1 采集与由此发现的缺口（2026-09-24）

采集链路：`tests/e2e/e1_h3_test.go` —— 真实浏览器 → `--origin-to-force-quic-on` 强制走 QUIC
→ 本地 UDP 嗅探（复用 `quic_sniff.go` 的 RFC 9001 Initial 解密）→ 内层 ClientHello +
transport params。记录：`profiles/evidence/browsers/chrome_windows_h3.json`
（Chrome 149.0.7827.54 / Windows，JA4(QUIC) = `q13d0311h3_55b375c5d22e_653d80c3fe9d`）。

**实测的真 Chrome QUIC 内层 ClientHello**（注意与 TCP 侧形态**不同**）：

| 项 | 真 Chrome QUIC | 我们当前 QUIC（`clampSpecForQUIC` 产物） |
|---|---|---|
| ciphers | **3**：`0x1301/0x1302/0x1303`（纯 TLS1.3，**无 GREASE**） | 15（照搬 TCP 侧的 TLS1.2 套件 + GREASE） |
| 扩展 | **11**：TCP 的 16 项 **剔 6 项 TLS1.2 专属**（`5/11/18/23/35/65281`）+ **增 `57`** | 16 项（未剔未增减） |
| curves | `4588/29/23/24`（无 GREASE group） | 带 GREASE group |
| versions | `772`（无 GREASE version） | GREASE + 772 |
| sig_algs | TCP 的 8 项 **+ `0x0201`**(rsa_pkcs1_sha1) | TCP 的 8 项，无 `0x0201` |
| JA4(QUIC) | `q13d0311h3_…` | `q13d1516h3_8daaf6152771_…` |

⇒ **缺口 H3-6：已修复（2026-09-24）**。修法：`http3` 新增 `inner_hello_drop_extensions /
inner_hello_extra_sig_algs / inner_hello_drop_grease`（Chromium 预设填实测值 `[5,18]` / `["0x0201"]` / `true`；
协议层最小剔除 `11/23/35/65281` 在 `core/h3` 硬编码，对所有浏览器成立），ciphers 收紧为 TLS1.3 三项。
**结果：我方 QUIC 内层 JA4 = `q13d0311h3_55b375c5d22e_653d80c3fe9d`，与真 Chrome 149 的 E1 实测值
逐字符相同**；回归钉在 `quic_sniff_test.go`，期望值**直接取真机值**（不再自己算自己比）。
另测得 **QUIC 内层扩展顺序逐连接随机**（两次抓包完全不同）⇒ 无需另设顺序，沿用既有洗牌即可。

**transport params 实测差异（H3-7）**：真机 `initial_max_data=15728640`（原 E4 构造值 10485760）
——**已按实测修正**；同时从预设里删掉 `ack_delay_exponent / max_ack_delay / active_connection_id_limit`
三个**无效键**（`transportParamsToQUICConfig` 不支持它们，写了不生效——属"看似可控的假象"）。
**仍未对齐（需 raw blob 路线，本轮不动）**：真机多发 `max_datagram_frame_size=65536`（我方 quic-go 硬编码 16383）、
`max_udp_payload_size=1472`（我方 1452）与两个私有参数（`0x11` / `0x3128`）；真机**不发** `max_ack_delay`（我方 26）。
这些值在 quic-go 里硬编码，只能靠 T4-1 的 `transport_params_raw` blob 直通；但 blob 是**整块替换**，
而 `initial_source_connection_id` 等**连接级参数不可钉死** ⇒ 需要一次 fork 级设计决策
（blob 是否合并连接级参数），故不在本轮硬做。
另：`0x11 / 0x3128 / 0x0f(len=0)` 的解析形态仍待复核——我方 wire 同样出现 `0x0f(len=0)`，
说明是**解析器层面的一致现象**，不影响两方对照结论。

### 6.2 UA-CH 的 GREASE 品牌不是常量（实测修正）

| 真浏览器 | 实测 `sec-ch-ua` |
|---|---|
| Chrome 149 (Windows) | `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"` |
| Edge 153 (Windows) | `"Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"` |

⇒ GREASE 品牌的**名称、版本、位置**都随浏览器/版本变化，此前把它当固定格式属过度固化；
`groundtruth_test.go` 已改为"钉结构（自家品牌第一 + 含 Chromium + 含 GREASE 品牌）+ UA 与
UA-CH 版本自洽"。这也反证：**identity 用 E1 真实抓包头**（`gen-profiles -record`）比合成头可靠。

### 6.3 Firefox 156（Windows）实测对照（2026-09-24）

来源：真 **Firefox 156 / Windows** 对 tls.peet.ws 的字段级实测（无原始字节 ⇒ 记 **E1r/E2**，
与 Chrome/Edge 的原始字节级 E1 区分）。据此外增预设 `firefox_156_windows`（预设数 19 → **20**）。

与既有 `firefox_144_macos`（真实抓包）逐项对照：

| 项 | 144_macos（抓包） | 156（实测） | 判读 |
|---|---|---|---|
| ciphers | 17（含 `0xc00a/0xc009` CBC） | 15 | macOS/Windows 平台策略差异，非缺陷 |
| 扩展集合 | 有 41、**无 35** | 有 35、无 41 | ✅ 讲得通：**复访**用 PSK(41) 顶替 session_ticket(35)，**首访**发 35 |
| groups | 7（含 ffdhe2048/3072） | 5（含 **P-521**，无 ffdhe） | 版本/平台差异；**P-521 是 Firefox 稳定标志**（Chromium 只到 P-384） |
| sig_algs / DC / RSL / cert_compression | 一致 | 同 | ✅ |
| key_shares | MLKEM768 / X25519 / P-256 | 同 | ✅ |
| H2 | `[1:65536,2:0,4:131072,5:16384]\|12517377\|m,p,a,s` | **完全相同** | ✅ |
| identity 头 | **仅 4 个**（`accept: */*`） | **11 个导航集**（含 `te: trailers`） | ❌→✅ **本轮修复** |

**本轮据实测修复**：

1. **Firefox 导航身份头**：生成器的 Firefox identity 原先只有 4 头且 `accept: */*`（典型"一眼假"），
   现按实测补全 11 头导航集（`user-agent → accept → accept-language → accept-encoding →
   upgrade-insecure-requests → sec-fetch-{dest,mode,site,user} → priority → te: trailers`），
   并明确 **Firefox 无 UA-CH 头**（Chromium 才有）；4 个既有 Firefox 预设全部同步。
2. **首访形态建模**：生成器新增 `normalizeFirefoxResumption`——确保首访的 `session_ticket(35)` 存在
   （实测位置：紧跟 `ec_point_formats(11)`），并清掉标本里那条**真实票据负载**
   （compile 只用 41 作占位、忽略 data，原样保留 hex 属"看似钉死票据"的假象）。
3. 新增回归 `tests/e2e/firefox_groundtruth_test.go`：所有 `firefox_*` 预设钉**版本无关不变量**
   （导航头顺序、伪头 `m,p,a,s`、WU 12517377）；`firefox_156_windows` 按实测**严格全等**。
   另修 `groundtruth_test.go` 的 UA-CH 过度固化（见 §6.2）。

**本轮新登记的缺口**：

- **G13｜ECH GREASE 载荷形状分族**：Chrome 的 GREASE ECH 为
  `outer=0,kdf=1,aead=1,config_id,enc(32),payload`（总长 42+N，N∈{144,176,208,240}）；
  Firefox 实测 `aead=3`（**两次独立抓包一致 ⇒ 非随机，是该实现的选择**），且总长更长
  （长度分布需更多样本才能定，暂不建模）。TCP 路径现用 `utls.BoringGREASEECH()`
  （Chrome 形状）⇒ Firefox 预设的 65037 形状不符。另注：生成预设里 65037 若为**字面 payload**
  （如 `firefox_144_macos` / `chrome_152_macos`）则跨连接恒定，与 G12 同族；**2026-09-28 已由生成器
  `normalizeECHGrease` 全部归一为 `ech.mode=grease`（10 个生成预设 + 守门 `TestPresetECHIsNotFrozenLiteral`）**。
- **G11 已收口**：HEADERS 帧内嵌 priority 分族取值——Chrome/Edge `excl=1/dep=0/w=256`、
  Firefox `excl=0/dep=0/w=42`。实现：schema 增 `http2.headers_priority`，`core/h2` 接到 fhttp 的
  `Transport.HeaderPriority`；Chromium 用 fork 默认值（恰为实测形状）+ oracle 断言钉住，
  Firefox 显式赋值。**Safari 已于 2026-09-28 用真机收口**（17.3.1 线上 254 / 18.6 线上 255，均
  `exclusive=false`，见 §5.4）；其余 3 个无实测来源的 Safari 预设按族特征补了 `exclusive=false`。

**无痕窗口二次实测（同日）**：Firefox 156 无痕下扩展为 **15 项**——**同时缺 35 / 45 / 41**
（无痕关闭会话恢复：既无 session_ticket 也无 psk_modes/PSK），另多 `sec-gpc: 1`
（用户偏好，非浏览器固定行为，**不建模**）。三次实测把 Firefox 的会话状态形态讲全了：

| 场景 | 扩展数 | 35 session_ticket | 45 psk_modes | 41 pre_shared_key |
|---|---|---|---|---|
| 普通窗口首访 | 17 | ✅ | ✅ | — |
| 普通窗口复访（`firefox_144_macos` 标本） | 17 | — | ✅ | ✅ |
| 无痕窗口 | 15 | — | — | — |

我们建模的是**普通窗口首访** ⇒ 预设必须含 35 + 45（生成器的 `normalizeFirefoxResumption`
负责保证），41 保留空占位（无票据时线上省略）。无痕下 HEADERS priority 同为
`excl=0/w=42`，与普通窗口一致 ⇒ 该实测值可信（两次独立抓包互证）。
