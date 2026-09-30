# 08 待补采样与后期扩充计划（plan）

> 维护起点：2026-09-28。用途：把「需要真机 / 更多设备 / 更多样本才能推进」的项集中登记，
> 免得散落在各处被遗忘；并把「采集 → 落预设 → 钉回归 → 登记矩阵」固化成流程。
> 本轮已落地项见 `07-capability-gaps.md` §4；族横向对照见 §5.2～§5.5。

## A. 需要真机采样（拿到数据即可闭环）

| 编号 | 要什么数据 | 为什么需要 | 拿到后怎么用 | 优先级 |
|---|---|---|---|---|
| **S1** | **同一台机器、同一浏览器版本、连抓两次**（任意平台） | ① `sec-ch-ua` 品牌顺序与 GREASE 品牌：**已结案=按版本固定**（Edge 153 的 Windows/Android 与 Chrome 154 的 macOS/Android 两份抓包逐字符相同，见 07 §5.6）⇒ **不做洗牌**。② **仍待判定**：扩展 51764 的负载子项顺序（mac 152 那份乱序、mac 154 与 Android 154 两份升序且逐字节相同） | 针对 ②：若为每连接随机 ⇒ 新增「通用扩展负载重排」能力（仿 `extension_permutation`）；若为固定 ⇒ 以升序为规范形并钉死 | 中（前半已结案） |
| **S2** | **H3 / QUIC 抓包：Firefox、Safari**（另：iOS/Android 的 Chromium） | QUIC transport params 属**族内独立**，不能靠 Chromium 继承；`http3` 缺节会让 H3 侧露出「通用 Go 客户端」（比未验证更糟，见 `TestBuiltinChromiumH3Coverage`）。**现状**：`chrome_154_macos` / `chrome_148_ios` / `edge_148_ios` 的 `http3` 节是**借用**桌面 Chromium 参数并已标注未实测 | `set GEEKTLS_E1_H3_BROWSER=<浏览器路径>` + `go test -run TestE1RealBrowserH3`（链路已就绪，`tests/e2e/e1_h3_test.go`）；随后按实测补预设 `http3` 节 | **高** |
| **S3** | **Android Chrome / 其他 Android 浏览器** | Chromium 内核，但 **H2 四段、身份头、平台串与桌面不同**；用桌面 Chrome 伪装 Android 是常见破绽 | 按 §C 流程落预设（已约定：Android 与 iOS 都会按族/平台各留一份） | **高**（已在准备） |
| **S4** | ~~**Chrome 154 / Windows**（任一非 macOS 平台）~~ **已结案 2026-09-28** | 「152→154 TLS 面无漂移」原先只在 macOS 侧验证过 | 真机字段级抓包 → 新增 `chrome_154_windows`，与 mac/Android 版 JA4 逐字符相同；详见 `profiles/evidence/README.md` | ✅ |
| **S5** | **Safari 19+ / 26 的 TLS+H2** | `safari_26_macos` 无实测来源、与真机差距明显（13 扩展、wire≈2.9KB vs 真机≈1.26KB）；且 Safari 版本间确有差异（17.3.1 vs 18.6 的 sig_algs / H2 / priority） | 更新 `safari_*` 预设 + 钉回归 | 中 |
| **S6** | **真机 TCP SYN（不经中转/代理）** | 已证明前几份抓包的 SYN 是**中转节点**产物（两个不同浏览器、同出口、参数完全一致）；而 iOS 真机 SYN（`ip_id=0`、无时间戳、选项区补至 40 字节）形态完全不同 | 更新 `tcp` 节；同时核对 G7 的 setsockopt 能力边界（Windows 不支持 MSS 等） | 中 |
| **S7** | **Firefox / Safari 的 ECH 真实形态**（有 ECH 部署的域名） | 现只有 Chrome 的真 ECH 通道与各家 GREASE 形状 | 用 `ech.mode=real` + `ech_external_test.go` 扩展 | 低 |
| **S8** | **Firefox 135 的真机采样**（任意平台） | 第三方集显示它 **有 `18(SCT)` + `27(compress_certificate)`**，而我们的 `firefox_135`（早期手写）没有；我们实测的 Firefox 156 两者都有 ⇒ 疑我们这条不准 | 采一份 → 按 §C 流程更新 `firefox_135*` 并钉回归；在此之前该预设应视作"待校验" | 中 |
| **S9** | **Chrome 133 的真机采样** | 第三方集与我们的 `chrome_133` **cipher 序不同**（其 AES256 在前，我们为 Chrome 标准序）。我们的序与 149/154 实测一致，但也可能是我们这条早期预设抄错 | 同上 | 中 |
| **S10** | **Chrome 147 与 150 的锚点**（任一平台） | 谱系显示 143→152 之间 `sig_algs`（加 ML-DSA `0x0904/0905/0906` + GREASE）与扩展集合（加 `51764`）变过，**边界未知** ⇒ 现为 `E2i-u`（3/21 字段未定界） | 采两个锚点 ⇒ 边界收敛，`chrome_144..151` 可升为 `E2i` | 中 |
| **S11** | **Safari 19 / 20 / 22 / 24 的锚点**（任一 macOS） | Safari 18→26 之间 ciphers/扩展集合/versions/groups/key_shares 全变过 ⇒ 谱系**拒绝内插** 19–25（10 个版本缺口） | 采 2–3 个锚点即可把 19–25 切成可信区间 | 中 |
| **S12** | **E3 预设 Accept-Encoding 与版本矛盾的真机判定** | 2026-09-29 T-DECOMP 连锁检查：33 条 E3 预设（chrome_61~122 / edge_92~122 各平台，全部 E3 导入）广告 `gzip, deflate, br, zstd`，但 **zstd 是 Chrome 123（2024-03）才加入** Accept-Encoding 的 ⇒ 这些预设的身份头反映的是采集工具（tls_config 当时的客户端）而非该版本真机。同理需核实 Firefox 126+ 的 zstd 广告起点（我们的 firefox_120/135 为 gzip,deflate,br，135 是否应带 zstd 待真机） | 真机各采一份 ⇒ 按 §C 流程修 E3 预设；**当前不修**（E3 数据保持与来源数据集一致，改动需 E1 依据）。引擎侧不受影响：四种编码解压已全部实现 | 中 |

## E. 从上游/网络补齐缺失族（2026-09-28 盘点，待开工）

**盘点方法**：抓上游 `bogdanfinn/tls-client@master` 的 `profiles/` 全部源码（快照入库
`profiles/evidence/thirdparty/tls-client-master-profiles-*.go`：47 个 `ClientProfile` 定义 +
83 条注册），与 builtin 的 362 条做族/条目差集。

| 缺口 | 上游条目 | 说明 |
|---|---|---|
| **整族缺失** | brave(2)、cloudscraper(1)、confirmed(android/ios, 2)、mesh(android/ios ×3, 6)、mms(ios, 4)、nike(2)、zalando(2) | 共 19 条。`cloudscraper` 是 Python 生态的"正常端"；`mesh`/`mms`/`nike`/`zalando` 是 App 端指纹（非浏览器） |
| 同族新版本 | chrome 若干、firefox 若干、**okhttp4_android_10/11/12/13**(4) | 我们 chrome/firefox 的覆盖率已经不低（部分新版本以 `_windows`/`_macos` 后缀落在别的名字上，需按指纹而非名字去重）；okhttp 目前只有 3.x（6 条） |
| **不需要** | 上游 `*_PSK` 变体（`chrome_133_PSK`/`chrome_152_PSK`…） | 我们的 PSK 建模是"空占位 + 无票据时线上省略"（`TestPresetCarriesPskPlaceholder`），不需要单独的 PSK 预设 |

**开工前要先解决的**（第 2 条已于 2026-09-30 修掉，其余仍未动——刻意不做是为了不与在改的代码冲突）：

1. 导入器 `tests/e2e/cmd/import-tlsconfig` 只吃 `tls_config`（Python 包）导出的 JSON
   快照，**不吃上游 Go 源码**。⇒ 要么拿到新版 `tls_config` 包（用户侧提供），
   要么给导入器加一个 Go 源码解析入口（改代码 + 改 `dump.py` 对应流程）。
   **2026-09-30 复核：光有解析器还不够——手上的上游源码是残缺的。**
   `profiles/evidence/thirdparty/` 只 dump 了 `profiles.go`(6.6 KB) 与
   `internal/browser_profiles.go`(91 KB)；`Mesh*/Nike*/Zalando*/Confirmed*` 在
   `profiles.go` 的映射表里**只是引用**，定义在不 dump 的文件里；
   `Mms*`/`Cloudscraper` 两份 dump 里**一次都没出现**。真要整族补齐，第一步是
   把上游 `profiles/` 目录整个抓下来入库，而不是先写 AST 解析。
2. ~~`import-tlsconfig` 把 `source` 写死为 `"tls_config-0.0.2/" + c.Const`~~
   **已修（2026-09-30，A13-a）**：`convert` 改收 `source` 参数，CLI 加 `-source`
   （默认前缀与被替换掉的写死字面量逐字符相同 ⇒ 再次导入产生的 `source` 不变；
   本次没有重写任何预设文件，`-source ""` 直接报错而非静默回落）。
   配套把"说谎"变成可测：`core/profiles/provenance_test.go::TestE3SourceTraceable`
   要求每条 E3 的 `<数据集>` 在 `profiles/evidence/thirdparty/` 有同名快照，且
   `<常量名>` 必须是该快照里某条的 `_const`（320/320 通过；另带 6 条合成负例，
   证明这道门不是恒真断言）。
3. 新族 / 新平台 token 需要在导入器的映射表里补：`chromiumLike`、`measuredIdentity`、
   `platformTokens`、`defaultPlatform`、`sigAlgHex`、`h2SettingID`、`groupHex`。
4. 新增预设后要补的回归与登记：`core/tls/presets_test.go` 的 JA4 钉
   （`chrome_154_windows` = `t13d1517h2_8daaf6152771_cb7bf5808d99`）、跨平台 pair
   （mac/windows/android）、`docs/capability-matrix.yml` 计数 362→363 与 recent_changes。

**不需要等上游的另一条路**（本次已走通）：真机 / 公开 peet.ws 抓包 → 逐字段手写预设
（`docs/08 §C-2`）⇒ 能进 E1/E1r 等级，而不是只能标 E3。代价是需要样本。

**本次顺带发现的待修项（已修，2026-09-29）**：`chrome_149_windows` / `edge_153_windows` 的 UA
带无头令牌（`HeadlessChrome/149.0.0.0`，来自采集链路 `--headless=new` 写进
`profiles/evidence/browsers/*.json` 的记录）。
修法已落地：源头 `cmd/e1-browser` 的 `sanitizeHeaders` 抹掉令牌，预设重新生成，
`core/profiles/builtin_identity_test.go` 三条身份门禁（无 headless 令牌 / UA 平台与
`sec-ch-ua-platform` 一致 / UA 主版本与 `sec-ch-ua` 一致）全预扫描过、0 违反。
生成器产物**禁止手改**（会被 CI 逐字节守门判红；注：那条守门目前只在
`runner.os == 'Linux'` 的 job 上跑，见 `ci.yml` 的 `presets must equal generator output (Linux)`）。

## B. 受依赖栈限制，暂不做（记录理由，避免重复评估）

| 编号 | 项 | 结论 | 依据 |
|---|---|---|---|
| L1 | 0-RTT（early_data）协议侧 | **不可做/不做**（≠「未接线」，A10 结案） | TCP：uTLS/Go 客户端无 early_data——上游注释 `0-RTT is not supported`，早数据代码仅在 `c.quic != nil` 分支。H3：原判"可做（quic-go `allow0RTT`/`DialEarly`）"改判**不做**——前提是 QUIC 会话缓存，而 spec 模式下 `StoreSession` 是 no-op 且无可补导出面（docs/06 P7-T2），首飞 Initial 布局又已结案为不可控（L3）。**声明侧可控**：预设 `{"type": 42}` 经透传上线并改变 JA3/JA4，边界实证在 `core/tls/early_data_test.go`（只带 42 不带 PSK ⇒ 标准服务端拒） |
| L2 | TLS record 分片 / 大小序列 | **不可做** | 在 `crypto/tls` 内部、无钩子；可做的只有 CH 长度（padding 扩展，已有） |
| L3 | QUIC Initial datagram 布局 | 维持结案（G6） | 行业共性：quic-go packer 无钩子 |
| L4 | 生成预设的手工修改 | **禁止** | 会被 `gen-profiles` 守门判为不一致；要改就走生成器（改标本/规则）或另起预设名 |

## C. 采到数据后的固定动作（流程）

1. **判定族与版本**：只依据 UA / UA-CH / JA4 派生特征。
   ⚠️ **不要用 GREASE 判族**——Safari 同样发 GREASE（2026-09-28 更正，见 07 §5.3）。
2. **转录预设**：字段级抓包 ⇒ **手写预设**；生成器只吃**原始 ClientHello hex** 标本
   （字段级抓包进不了生成链，见 `gen-profiles/record.go`）。
3. **对拍**：`go test ./core/tls/... -run TestPresetsAreValid -v`，比对 `ja3_hash` 与 `JA4`
   与抓包值——**逐字符相同**才算转录成功。
4. **钉回归**：`core/tls/presets_test.go` 加 JA4 钉 + 该次观察到的族/平台特征断言
   （同族共用形态、padding 长度、priority 分族值等）。
5. **登记文档**：`07-capability-gaps.md` 加一节（族横向对照）+ `capability-matrix.yml`
   加 `evidence_baselines` 基准与验证记录。
6. **跑守门**：`go run ./tests/e2e/cmd/gen-profiles -out <tmp>` 后与 `core/profiles/builtin`
   diff 必须 **0 差异**。

## D. 已完成（归档指针）

- **2026-09-28 追加**：Chrome 154 / Windows 真机字段级抓包 → 新增 `chrome_154_windows`
  预设（跨平台 JA4 一致，S4 结案）；Chrome 149 / Windows 真机抓包 → 独立复现既有
  `chrome_149_windows` 的 JA4/Akamai/UA-CH，并发现其 UA 带 `HeadlessChrome`（见 §E 待修项）；
  记录落 `profiles/evidence/browsers/chrome_15*_windows_peetws.json`。
- Chrome/Edge（Windows）E1 字节级记录、Chrome 149 的 H3 E1 记录；
- Firefox 156（普通 + 无痕）与 macOS Chrome 140/152/154；
- **真 Safari**：macOS 17.3.1 / 18.6、iOS 17.2（Safari + Chrome + Edge）；
- curl_cffi「号称 Safari」profile（第三方互证，实为 Edge 形状）；
- 会话复用真机互操作（tls.peet.ws `resumed=true`）与本地 std 服务端互证。
