# geektls 硬化与 H3 补齐方案（2026-09-24）

本方案基于 2026-09-24 全量审查（代码 + 14 篇文档 + 外部库调研），核心结论：
**utls 核心不变，先补验证闭环，再攻 H3/QUIC，全部改动「只加不减」。**

## 0. 已拍板的决策

| # | 决策 | 依据 |
|---|---|---|
| D1 | 目录名保持 `geektls`，不改名 | 避免全链路路径改动 |
| D2 | **核心继续保持 Go/uTLS** | TCP 层与 hex 回放只有自有栈能给（curl-impersonate 与真浏览器转发都拿不到 TCP）；已交付资产全部绑定 utls |
| D3 | 不引入 BoringSSL 后端产品实现，仅在验证侧使用 | 需 curl+BoringSSL+ngtcp2+nghttp3 四层补丁链（约 540KB 补丁），成本远高于收益 |
| D4 | `cyTlsXhr` 仅作参考，**不集成、不运行** | 来源不明的 Windows 预编译产物；只取「真浏览器作基准」的思路（自建 Playwright/CDP 基准替代） |
| D5 | H3 Initial datagram 布局**结案为「行业共性未解决」** | `lexiforest/curl-impersonate` 的 `ngtcp2.patch` 也不提供该钩子（结论待 `curl.patch` 复查确认，见 T4-6） |
| D6 | HPACK、QUIC transport params 等阶段 2/3 的 fork 决策，先 spike 后定 | 避免为改而改 |

## 1. 审查结论摘要

### 1.1 三层资产

| 层 | 判定 | 证据 |
|---|---|---|
| TLS ClientHello | ✅ 已交付，天花板高 | uTLS 逐字段 + hex 回放；ECH 实测通过；JA3/JA4/JA4R 自算独立实现 |
| HTTP/2（Akamai 四段） | ✅ 已交付 | 7 预设 tls.peet.ws E2 MATCH；HPACK 索引不可控 |
| HTTP/3 + QUIC | ⚠️ 半成品且零验证 | 内层 ClientHello ✅（vendor patch）；H3 层 ✅；transport params 顺序/非标 ❌；**7 预设 H3 证据全为 E4/TODO** |
| TCP / JA4TCP | ❌ 未交付 | 仅 TTL（三平台）+ MSS（Linux/macOS）；raw 仅 Linux 探测模式 |

### 1.2 方法论级风险

所有 E2 MATCH 均为**同源自证**：profile 转写自 uTLS/tls-client → 自算 → 发 tls.peet.ws 回读 → 比对。
只能证明「发出的 == 想发的」，不能证明「== 真浏览器」。**E1（真浏览器基准）是硬缺口。**

### 1.3 验证体系缺口

`external_oracle_test.go` / `h2_oracle_test.go` / `ech_external_test.go` 是 `//go:build external`、
只打印不硬断言、不可达即 skip —— 等于没有回归防线。`P1-T8`/`P6-T3` 因 WSL2（Hyper-V 未启用）阻塞，
根因是缺 Linux CI runner。

## 2. 缺口清单

### 2.1 值得补

| ID | 缺口 | 层 | 优先级 |
|---|---|---|---|
| V-1 | E1 真浏览器基准缺失（同源自证） | 验证 | P0 |
| V-2 | 本地双端对拍闭环未建（P1-T8 阻塞） | 验证 | P0 |
| V-3 | oracle 测试只打印不断言 + 依赖外网 + 不可达 skip | 验证 | P0 |
| V-4 | Linux CI runner 缺失（所有「待 Linux」总根因） | 验证 | P0 |
| V-5 | 第二 oracle 未接入（gospider007/fp、fingerproxy） | 验证 | P1 |
| H3-1 | transport params 顺序 + 非标参数（已有移植解方：blob 直通） | H3 | P1 |
| H3-2 | 4 个预设 H3 profile 为空（firefox_120/135、safari_16/18） | H3 | P1 |
| H3-3 | H3 证据全为 E4/TODO（H3 零验证） | H3 | P1 |
| H3-4 | GREASE transport param 恒首位 | H3 | P2 |
| H3-5 | QUIC 会话缓存 no-op（0-RTT 前提） | H3 | P2 |
| T-1 | profile 与 UA/UA-CH/默认头未绑定（身份一致性） | TLS | P1 |
| T-2 | 无 profile 生成器（手写转录） | TLS | P1 |
| T-3 | 3 个预设仍是 E4（chrome_150/firefox_135/safari_18） | TLS | P1 |
| H2-1 | HPACK 索引不可控（fhttp 无钩子） | H2 | P2 |
| H2-2 | 「缺失项也是信号」未可断言 | H2 | P2 |
| H2-3 | PRIORITY 按资源类型序列 | H2 | P3 |
| E-1 | 连接池/复用缺失（性能目标未达） | 引擎 | P2（必须可选开关，默认关） |
| E-2 | Session 非并发安全、无并发参数 | 引擎 | P2 |
| E-3 | 0-RTT / early data 未接线 | 引擎 | P3 |
| D-1 | 平台硬编码 10 处（.dll/.exe 写死） | 交付 | P2 |
| D-2 | 无交叉编译、无 wheel/npm 打包目标 | 交付 | P2 |
| D-3 | 22MB geektls.dll 入库 | 交付 | P2 |
| D-4 | bindings 两条 FFI 声明手写重复 | 交付 | P2 |
| D-5 | Go 版本漂移（go.mod 1.26 vs CI 1.24，本机 1.27） | 交付 | P2 |
| D-6 | koffi .async 死锁靠 setImmediate 规避 | 交付 | P2 |
| D-7 | 许可证复核（quic-go-utls 标 MIT vs 上游 BSD-3；JA4+ 商用边界） | 交付 | P2 |
| D-8 | CI 未推送 GitHub（P0-T7） | 交付 | P2 |

### 2.2 明确不补

| 项 | 处置 | 依据 |
|---|---|---|
| H3 Initial datagram 布局 | 结案「行业共性未解决」 | ngtcp2 也无钩子 |
| Windows MSS | 跳过 + warning | 上游不支持（WSAENOPROTOOPT） |
| TCP 完整 raw 接管（gVisor 级） | 否决 | P6-T2 已论证 |
| BoringSSL 后端产品实现 | 不做，仅留接口 | D2/D3 |
| HTTP↔Stream 桥接（nginx 侧） | 不动 | 项目既定边界 |

## 3. 分阶段计划

### 阶段 0｜契约对齐（0.5 周，零代码风险）

- T0-1 `01-fingerprint-dimensions.md` 增「当前状态/验证等级/阻塞项」列 ✅（本方案落笔即执行）
- T0-2 生成 `docs/capability-matrix.yml`（CI 断言 + nginx 变量映射共用）
- T0-3 `docs/CONTRACT-FREEZE.md` 冻结清单
- T0-4 README / evidence 表述校准
- T0-5 修正 `00-architecture.md` 过时论据（原仓 vs lexiforest fork；curl-impersonate 已支持 H3）

**验收**：契约表每项都能指到「实现函数 + 验证等级」；无「标 A 却无实现」行。

### 阶段 1｜验证闭环（2 周，零代码风险，最高优先）

- T1-1 起本地 nginx 采集端（Linux，同仓 d:/work/tls）
- T1-2 oracle 改「本地/硬断言/必跑」，外网降为附加（V-3）
- T1-3 E1 真浏览器基准：Playwright/CDP 自建 + lexiforest curl-impersonate 双 ground truth（V-1）
- T1-4 接入第二 oracle：gospider007/fp + fingerproxy（V-5）
- T1-5 ClientHello hex 语料库 fixture
- T1-6 Linux CI runner（V-4，解 P1-T8/P6-T3 阻塞）

**验收**：7 预设 × (TLS+H2) 逐字段零差异、离线可跑。

### 阶段 2｜TLS 身份一致性 + profile 基建（1.5 周）

- T2-1 profile ↔ UA/UA-CH/默认头绑定（T-1）
- T2-2 profile 生成器：从 pcap/真浏览器导出（T-2）
- T2-3 evidence 看板自动生成
- T2-4 3 个 E4 预设升 E1（T-3）

### 阶段 3｜H2 收口（1 周，先 spike 后决策）

- T3-1 spike：fhttp HPACK 钩子成本（限定 core/h2 一层）（H2-1）
- T3-2 「缺失项也是信号」+ preface 分帧可断言化（H2-2）
- T3-3 PRIORITY 资源类型序列（H2-3）

### 阶段 4｜H3/QUIC 补齐（2~3 周，主战场，已降本）

- T4-1 **transport params blob 直通**：profile 存有序键值/原始字节 → `quic-go-utls` 加第 7 处 patch 原样编码。
  移植的是 `lexiforest/curl-impersonate` `ngtcp2_conn_set_local_transport_params_raw()` 的**设计**（blob 直通，非逐项 setter），不是 C 代码（H3-1）
- T4-2 GREASE transport param 位置修正（H3-4）
- T4-3 补齐 4 个预设 H3 profile（H3-2）
- T4-4 H3 三方验证：自研 RFC 9001 嗅探 + ja4plus-go pcap + nginx `$quic_fingerprint_*`（H3-3）
- T4-5 QUIC 会话缓存接线（H3-5）
- T4-6 Initial 布局结案标注（D5；复查 447KB `curl.patch` 是否有可借鉴构造逻辑后正式定稿）

**验收**：每预设 H3 从 E4/TODO 升 E2；transport params 逐项 + **顺序**可断言。

### 阶段 5｜TCP 定稿 + 引擎（1 周）

- T5-1 TCP 降级承诺：只承诺 TTL/MSS；schema 中 `window_size/window_scale/options_order` 标 advisory
- T5-2 连接池可选开关（默认关，不改变 wire 特征）（E-1）
- T5-3 并发安全/并发参数（E-2）

### 阶段 6｜交付硬化（1.5 周）

- T6-1 清平台硬编码 + 交叉编译 + wheel/npm 目标 + 移出入库 dll（D-1/D-2/D-3）
- T6-2 FFI 声明生成化；Go 版本对齐（1.26/1.24/1.27 统一到一条线）（D-4/D-5）；koffi async 稳健化（D-6）
- T6-3 许可证复核（D-7）
- T6-4 CI 推送并全绿（D-8）
- T6-5 `00-architecture.md` 论据修订归档（随 T0-5 已先行）

**验收**：三平台 × 三语言 CI 全绿，且阶段 1 硬断言仍全绿。

**关键路径**：T1-6（Linux CI）是阶段 3/4/5 验收的前置；阶段 2/3/4 可部分并行。

## 3.1 进度记录

**2026-09-24（阶段 0 + T1-4 完成）**

- 阶段 0 全部交付：`01` 契约文档加「现状/验证/阻塞」列；`docs/capability-matrix.yml`；
  `docs/CONTRACT-FREEZE.md`（10 项冻结）；`00-architecture.md` 过时论据修正；README/evidence 表述校准。
- **T1-4 完成**：`tests/e2e/fp_oracle_test.go`——gospider007/fp 作独立解析器，**本地硬断言、默认必跑、
  不依赖外网**，7 预设全绿。断言面：cipher 序 / 扩展（Chrome 洗牌 profile 比集合）/ curves / points /
  versions / sig_algs / ALPN / SNI / H2 SETTINGS 序 / WINDOW_UPDATE。
  - 发现 1：**SNI 机制实际是通的**——`sni:"auto"` → spec 空 SNI → uTLS `ApplyPreset` 从
    `config.ServerName` 自动填充（`u_parrots.go` 重排段）；fp 的 `TlsSpec.ServerName()` 恒空是其
    gaukas 补丁所为（"don't copy SNI"），非我方缺陷。测试已改为自行解析原始扩展字节。
  - 发现 2：**T-1 缺口实锤**——H2 常规头含 `user-agent: Go-http-client/2.0`（fhttp 默认），
    任何 profile 下都暴露 Go 栈身份；已登记为测试观测项，阶段 2 T2-1 修复后升级为断言。
  - 发现 3：Chrome 洗牌 profile 的"扩展顺序"在 CompileDetail 与 engine 各自独立洗牌——两次随机序不同属
    设计行为，断言按集合比对。
  - fp 不覆盖伪头顺序（`OrderHeaders` 只含常规头），该维度留给 T1-1 nginx 侧。
  - fingerproxy 降级为可选（fp 已提供字段级断言，fingerproxy 仅字符串级 X-JA3/X-JA4/X-HTTP2）。
- 环境记录：本机 Go 1.27.0；引入 fp 后 `tests/e2e/go.mod` go 指令升至 1.27（core 仍 1.26，CI 1.24）——
  版本线不一致并入 T6-2 处理；本机无 gcc，c-shared 构建暂不可用（不影响纯 Go 开发）。

**2026-09-24（T2-1 完成）**

- **T2-1 完成**：profile↔UA/UA-CH/默认头绑定。
  - schema：`Profile.Identity *IdentityProfile`（`headers [][2]string` 有序缺省头），
    校验：非空名、禁伪头（`profiles/profile.go`）。
  - engine：`doSingle` 统一注入（`applyIdentity`，用户同名头优先，H1/H2/H3 三路径共用）；
    无 identity 节时行为不变（冻结面安全）。
  - presets：7 个预设填充 identity（Chrome 带 UA-CH 三件套 + zstd accept-encoding；Firefox 无 UA-CH；
    Safari macOS UA）。
  - 验证：fp oracle 的 T-1 观测项**升级为硬断言**——常规头有序全等 identity 且不得含
    `Go-http-client`；7 预设全绿；core + e2e 全量回归零破坏。
  - 遗留：accept/accept-language/UA-CH 的精确取值仍是知识构造（E4 级），待 E1 真浏览器基准校准；
    `accept-encoding` 显式下发后 HTTP 栈不再自动解压（已写入 03 文档语义）。

**2026-09-24（B/T3-1 spike 结论 + C/T1-5 完成）**

- **B / T3-1（HPACK spike）结论：暂不实现**。证据与理由：
  - fhttp 的 HPACK 编码决策在 `hpack/encode.go`（`WriteField`/`shouldIndex`/`appendHpackString`），
    无任何策略钩子；要做需 fork fhttp 并新增 Transport→Framer→Encoder 的逐字段策略通路（约 100–200 行 + 长期 fork 维护）。
  - 价值低：① HPACK 编码细节不在 Akamai 四段内，主流检测不看；② 我们「每请求新连接」模型下
    首 HEADERS 无动态表历史，Go 与 Chrome 的编码高度收敛（静态表索引 + 增量索引 + huffman-if-shorter）；
    ③ 真实差异在同连接多请求的动态表演化——但连接复用（E-1）未做，该信号当前不存在。
  - **触发条件**（写入决策）：仅当 E-1（连接池）落地后重开；届时需 Chrome 动态表演化数据（E1）作期望。
- **C / T1-5（语料库）完成**：`tests/e2e/corpus_test.go`——以 `gospider007/ja3` 内置真实浏览器
  ClientHello 标本（10 个，覆盖 Chrome 137–152 / Edge 141 / Firefox 140-144 / Safari 18-26）为 ground truth，
  走「hex 解析 → 编译 → fp 独立解析器重放对拍」，**10/10 全绿**。
  - **发现并修复真 bug**：hex 回放路径下，标本里的**字面 GREASE key_share 组**（如 0x6a6a）经
    `groupToken` 原样传给 uTLS，uTLS 只对 `GREASE_PLACEHOLDER`(0x0a0a) 生成哑 share，字面 GREASE 组
    拿不到哑数据 → key_share 列表残缺 → Go std 服务端 HRR（栈帧实证 `doHelloRetryRequest(0x11ec)`）
    或 decode 失败。修复：编译 `KeyShareExtension` 时对任何 GREASE 组值都补哑数据
    （`compile.go` case 51）。P1-T3「字面 GREASE 值原样透传」语义未受影响（`TestGreaseAllRFC8701Values` 全绿）。
  - PSK(41) 处理：标本带真实票据时回放按 OmitEmptyPsk 省略（fresh 连接语义，不可复用他人票据），
    断言两侧对齐。
- **T1-2 状态**：本地硬断言体系已由 T1-4（fp oracle）+ T1-5（corpus）覆盖；外网 oracle 保持
  `external` tag 作为附加，不再是回归依赖。

**2026-09-24（A/T4-1 完成）**

- **T4-1 完成**：QUIC transport params blob 直通（方案原定主战场之一，已按 spike 结论降本实施）。
  - **fork patch #7**（`quic-go-utls`，6 处）：`Config.TransportParamsOverride tls.TransportParameters`；
    适配器 `uquicSpecConn` 非空时原样写入扩展——**未触碰 `internal/wire`**（复用既有
    `SetTransportParameters` 接缝，与 spike 预期一致）。已登记进 `GEEKTLS_PATCHES.md`。
  - core：`profiles.HTTP3Profile.TransportParamsRaw [][]any`（`[id, value]`，数值→varint，
    `"hex:..."`→原始字节，`"grease"`→随机 GREASE 参数）+ `core/h3/transport_params.go`
    （编译 + `applyKnownRawTP` 把已知流控键 1/4/5/6/7/8/9 映射回 `quic.Config`，
    **wire 声明与实际流控行为保持一致**）。
  - 验证：`tests/e2e/quic_sniff_test.go` 抽出 `sniffInnerClientHello` 公共嗅探器，新增
    `TestQUICTransportParamsRaw`——wire 上参数顺序 `[8, 0x1234, 1, 4, 5, 6, 7, 9]` 与 profile
    完全一致、非标参数 `0x1234=deadbeef` 透传、**GREASE 参数位置可控**（H3-4 一并解决，
    默认 quic-go 恒首位）、Config 行为映射正确；既有 `TestQUICInitialSniff`（map 路径）回归全绿。
  - 边界：`max_udp_payload_size`/`ack_delay_exponent` 等键值可上 wire（任意 id），但其
    **行为**侧 quic-go 无对应 Config 项——这些键值是"声明级"控制，行为按 quic-go 默认。

**2026-09-24（环境 + 预设基建 + 对标分析）**

- **Linux 验证打通**：`scripts/wsl-test.sh`（首次自动装用户态 Go 到 `~/.local`）；
  WSL Ubuntu 26.04 上 **core + e2e 全量通过**。顺带修掉两处跨平台假设：
  `crosslang_test.go` 的 `echo-server.exe`/`geektls.dll` 硬编码改为平台感知、
  `python`/`node` 缺失时 skip 而非失败（原 D-1 部分项）。
- **T2-2 完成（profile 生成器）**：`tests/e2e/cmd/gen-profiles` 从真实抓包标本直接产出预设，
  替代手写转录。生成语义：GREASE 归一占位符、SNI→`auto`、Chrome/Edge 洗牌开关、
  `[]uint8` 字段渲染为数组、族内 UA/UA-CH 合成。**产出 10 个新预设**
  （chrome_137/141/142/143/152、edge_141、firefox_140/144、safari_18/26，均 macOS），
  预设总数 7 → **17**，全部通过 fp oracle（TLS/H2/身份硬断言）与 loopback 真实握手。
- **T1-5 收尾**：语料数据本地冻结（`tests/e2e/specimens/data.go`，由 `cmd/extract-specimens` 生成），
  回归不再以上游包作为数据源（仅保留其作独立解析器）；升级上游不会改变我们的基线。
- **去水印**：自有代码里的外部项目引用已清理（`h3/transport_params.go`、`profiles/profile.go`）；
  依赖 import 路径与 `third_party/` 的上游授权声明按法律要求保留（见下方说明）。
**2026-09-24（真实抓包 ground truth 校正）**

拿到 Chrome 149 / Edge 149 对 `tls.peet.ws` 的完整实测（与某同类库同场景），逐字段 diff 后
修掉两处自有缺陷并钉住回归（详见 `docs/07-capability-gaps.md` §5）：

- **ECH GREASE 结构修正**（`core/h3/h3.go`）：原合成负载缺 32 字节 enc 段（`enc_len` 写成 0），
  与真实浏览器可区分；现按实测结构 42+payload 生成。回归：`core/h3/ech_test.go`。
- **Chromium 身份头按实测重写**：UA-CH 品牌顺序（自家品牌在前，不是 Chromium 在前）与
  GREASE 品牌（`"Not)A;Brand";v="24"`，非 `"Not/A)Brand";v="99"`）此前都是错的；
  并补齐导航头集合与顺序（`upgrade-insecure-requests`/`sec-fetch-*`/`priority`）。
  同类的 10 个生成预设重新产出，手写 `chrome_131/133/150` 同步修正。
- **新增实测回归**：`tests/e2e/groundtruth_test.go`（身份头顺序与 UA-CH 格式、TLS 扩展集合、
  H2 akamai 三段）。ALPS 码点做版本感知（≤131 → 17513，≥132 → 17613）。
- 判读：JA4 `1516` vs `1517` 的差异来自 **41（pre_shared_key）**，属会话复用场景差异而非缺陷；
  同类库 TLS 层除该项外与真 Chrome 逐字节同构——补齐上述两项后我们在 TLS/H2 面已与其持平。
- 新登记 **G11：HEADERS 帧 flags/priority 字段**（Chrome 149 用 HEADERS 内嵌 priority，
  akamai 第 3 段为 `0` 的原因）。

- **对标与缺口分析**：新增 `docs/07-capability-gaps.md`——与 httpcloak / curl_cffi / requests-go
  的结构性对比（可控性我们最强、保真度经生成器追平、唯一结构性落后是"真栈"），
  以及 TLS 领域缺口清单（**G1 TLS1.2 回退指纹为最大剩余缺口**，其次 G2 0-RTT、G3 record 层、
  G4 ticket 生命周期；G5 HPACK/G6 QUIC Initial 维持暂缓/结案）。

## 4. 冻结清单（详见 `docs/CONTRACT-FREEZE.md`）

已 MATCH 的 TLS/H2 构造链路、自算 JA3/JA4、15 个 ABI 导出、7 个预设取值、
engine「每请求新连接」默认行为、quic-go-utls 6 处 patch 锚点 —— **只增不改**。

## 5. 可行性判定（2026-09-24）

| 能力 | 判定 |
|---|---|
| 逐字节控制 ClientHello / hex 回放 | ✅ 能 |
| JA3 / JA4 / JA4R（自声明值） | ✅ 能 |
| 与真浏览器一致 | ⚠️ 待 E1（阶段 1） |
| HTTP/2 Akamai 四段 | ✅ 能 |
| HTTP/2 HPACK 深检 | ❌ 不能（除非 fork fhttp，T3-1 spike） |
| H3 SETTINGS 序 / 伪头 / GREASE 帧 | ✅ 能（强于 lexiforest） |
| H3 transport params 顺序/非标 | ✅ 可达（T4-1，成本中等） |
| H3 Initial 布局 | ❌ 不能（行业共性） |
| TCP / JA4TCP | ❌ 不能承诺（仅 TTL/MSS） |
| 三语言交付 | ✅ 能 |

**整体完成度约 70%**；剩余 30% 集中在验证闭环（阶段 1）与 H3 补齐（阶段 4）。

## 6. 移植评估记录（T3-6 spike 结论）

`lexiforest/curl-impersonate`（MIT，v2.0.0，基于 curl 8.21.0）：

- `ngtcp2.patch`（21KB）：`ngtcp2_conn_set_local_transport_params_raw()` 接受**整块序列化 blob** 原样输出
  → transport params 顺序/非标可控（blob 级）；不涉及 Initial 布局
- `nghttp3.patch`（13KB）：`nghttp3_conn_submit_settings()` 按数组顺序发 SETTINGS → SETTINGS 序可控；
  无 GREASE 帧、无伪头序
- **可移植的是「设计」不是「代码」**；geektls 落点为 `core/h3/h3.go` + `quic-go-utls` 第 7 处 patch
- `curl.patch`（447KB）是否有 Initial 布局构造逻辑：**待复查**（T4-6）
