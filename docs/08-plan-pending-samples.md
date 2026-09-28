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
| **S4** | **Chrome 154 / Windows**（任一非 macOS 平台） | 「152→154 TLS 面无漂移」目前只在 macOS 侧验证过 | 加一条 JA4 钉，确认跨平台 | 中 |
| **S5** | **Safari 19+ / 26 的 TLS+H2** | `safari_26_macos` 无实测来源、与真机差距明显（13 扩展、wire≈2.9KB vs 真机≈1.26KB）；且 Safari 版本间确有差异（17.3.1 vs 18.6 的 sig_algs / H2 / priority） | 更新 `safari_*` 预设 + 钉回归 | 中 |
| **S6** | **真机 TCP SYN（不经中转/代理）** | 已证明前几份抓包的 SYN 是**中转节点**产物（两个不同浏览器、同出口、参数完全一致）；而 iOS 真机 SYN（`ip_id=0`、无时间戳、选项区补至 40 字节）形态完全不同 | 更新 `tcp` 节；同时核对 G7 的 setsockopt 能力边界（Windows 不支持 MSS 等） | 中 |
| **S7** | **Firefox / Safari 的 ECH 真实形态**（有 ECH 部署的域名） | 现只有 Chrome 的真 ECH 通道与各家 GREASE 形状 | 用 `ech.mode=real` + `ech_external_test.go` 扩展 | 低 |
| **S8** | **Firefox 135 的真机采样**（任意平台） | 第三方集显示它 **有 `18(SCT)` + `27(compress_certificate)`**，而我们的 `firefox_135`（早期手写）没有；我们实测的 Firefox 156 两者都有 ⇒ 疑我们这条不准 | 采一份 → 按 §C 流程更新 `firefox_135*` 并钉回归；在此之前该预设应视作"待校验" | 中 |
| **S9** | **Chrome 133 的真机采样** | 第三方集与我们的 `chrome_133` **cipher 序不同**（其 AES256 在前，我们为 Chrome 标准序）。我们的序与 149/154 实测一致，但也可能是我们这条早期预设抄错 | 同上 | 中 |
| **S10** | **Chrome 147 与 150 的锚点**（任一平台） | 谱系显示 143→152 之间 `sig_algs`（加 ML-DSA `0x0904/0905/0906` + GREASE）与扩展集合（加 `51764`）变过，**边界未知** ⇒ 现为 `E2i-u`（3/21 字段未定界） | 采两个锚点 ⇒ 边界收敛，`chrome_144..151` 可升为 `E2i` | 中 |
| **S11** | **Safari 19 / 20 / 22 / 24 的锚点**（任一 macOS） | Safari 18→26 之间 ciphers/扩展集合/versions/groups/key_shares 全变过 ⇒ 谱系**拒绝内插** 19–25（10 个版本缺口） | 采 2–3 个锚点即可把 19–25 切成可信区间 | 中 |

## B. 受依赖栈限制，暂不做（记录理由，避免重复评估）

| 编号 | 项 | 结论 | 依据 |
|---|---|---|---|
| L1 | TCP 侧 0-RTT（early_data） | **不可做**（≠「未接线」） | uTLS/Go 客户端无 early_data：上游注释 `0-RTT is not supported`，早数据代码仅在 `c.quic != nil` 分支；H3 侧可做（quic-go `allow0RTT`/`DialEarly`） |
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

- Chrome/Edge（Windows）E1 字节级记录、Chrome 149 的 H3 E1 记录；
- Firefox 156（普通 + 无痕）与 macOS Chrome 140/152/154；
- **真 Safari**：macOS 17.3.1 / 18.6、iOS 17.2（Safari + Chrome + Edge）；
- curl_cffi「号称 Safari」profile（第三方互证，实为 Edge 形状）；
- 会话复用真机互操作（tls.peet.ws `resumed=true`）与本地 std 服务端互证。
