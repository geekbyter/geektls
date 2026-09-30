# 能力对齐评估与追赶计划（2026-09-29）

> 输入：用户指定的 31 个同类仓库（逐仓拉 README 原文核对）+ 本项目现有能力/测试证据。
> 结论面向决策：**哪些已对齐、哪些还差、值不值得做、按什么顺序做、什么算做完了**。
> 相关文档：[README 对比表](../../README.md#与同类项目对比) ·
> [docs/10-ecosystem-comparison.md](../10-ecosystem-comparison.md)（功能矩阵）·
> [2026-09-29-self-contained-roadmap.md](2026-09-29-self-contained-roadmap.md)（自主化 SC-1~4）

## 0. 一句话结论

**指纹能力面已经对等或领先；差距集中在三处**——①**发布面**（Node/Go 未发布、平台不全）、
②**形态面**（明文 `http://`、CLI、cookie 手感）、③**结构性两条**（QUIC Initial 布局 = SC-3、
真栈行为级 = 不可追平只能收敛）。没有任何一条差距会阻止当前发布。

## 1. 一致性记分卡

判定口径：**独有** = 上表无人做到；**对等** = 与最好者同档；**落后** = 有明确对标且未做到。

| 维度 | geektls | 对标最好者 | 判定 |
|---|---|---|---|
| TLS 逐字段 + 多入参（profile/JA3/JA4/JA4R/hex） | ✅ 六入口 + 自洽归一 | 均无 hex 或无私有 | **独有** |
| H2 帧层（SETTINGS 序/伪头序/priority/`window_update` 三态/首流号） | ✅ Akamai 四段 MATCH + 原始帧断言 | specter（+帧时序记录） | 对等；"不发连接级 WINDOW_UPDATE"与"首请求流号"两档同行文档未见 |
| H2 HPACK 编码策略 | ✅ 四档（250/364 预设带值） | 无 | **独有** |
| H3/QUIC（内层 ClientHello 同 profile） | ✅ + TP blob 直通 | impersonator / specter | 对等（Initial 布局落后，见 G3） |
| 四层 TCP | ✅ TTL/MSS/DF/window/wscale（setsockopt 三平台 + netstack Linux root，P6-T3 ja4tcp 全 MATCH） | httpcloak（仅声明 TTL/MSS/Window） | **领先** |
| WebSocket | ✅ RFC 6455（握手走指纹链路） | CycleTLS/curl_cffi/specter/wreq-js/cyCronet | 对等 |
| Python async | ✅ 线程池实现（如实标注） | cyCronet/curl_cffi（原生异步） | 对等（形态差） |
| 响应自动解压 | ✅ 四编码 + 多重链 | 全行业标配 | 对等 |
| 代理 | ✅ HTTP CONNECT + SOCKS5(+h) 带鉴权 | CycleTLS/cyCronet/tls-client | 对等 |
| 预设规模与证据 | ✅ 364 条 29 族 + `grade`/`source` 分级 | noble-tls 76 条（无分级） | **大幅领先** |
| 响应内自校验 | ✅ selfcheck + `check_profile` 五入参 | 无人（specter 仅 pcap 材料） | **独有** |
| 多语言同引擎 | Python ✅ / Node ⚠️ / Go ⚠️ | tls-client（Go+绑定） | **落后（发布面，见 G1）** |
| 明文 `http://` / `ws://` | ✅ 已支持（H1；无 TLS ⇒ selfcheck 零值） | requests/curl_cffi/cyCronet 均支持 | **已对齐（G5，2026-09-30）** |
| CLI / MCP | ✅ CLI（`geektls` 五子命令） | fetchr（CLI + MCP server） | CLI 已对齐（G6，2026-09-30）；MCP 仍不做（G10） |
| 真栈行为级 | ⚠️ 逐维度对齐逼近 | curl_cffi（libcurl+BoringSSL）、cyCronet（Cronet 真栈） | 结构性落后（见 G8） |

## 2. 差距清单（含关闭判据）

| ID | 差距 | 现状证据 | 影响 | 成本 | 优先级 | 关闭判据 |
|---|---|---|---|---|---|---|
| **G1** | Node 包未发 npm、Go module 未发布 | README 安装段标"⚠️ 尚未发布"；`bindings/golang/go.mod` 仍带本地 `replace` | "三语言同引擎"只兑现 Python 一条 | 低（账号 + 发布流程；Go 需先推 core 仓、去 replace、打 `core/v0.1.5` 与 `bindings/golang/v0.1.5`） | **P0** | `npm i geektls` / `go get github.com/geektls/golang` 在干净环境可用且有冒烟记录 |
| **G11** | 发布卫生：0.1.4 的 `manylinux_2_34` 待 yank；macOS 运行期未验证 | release plan §8.6/§8.7 | pip 可能优先选兼容面更小的 2_34；macOS 只有静态断言 | 极低 | **P0** | PyPI 网页 yank 完成；Intel + Apple Silicon 各跑一次 `version()` + 真实请求 |
| **G3** | QUIC Initial 布局不可控（分片/乱序/PADDING/coalesce） | 功能矩阵"H3 ✅（机制）…Initial 布局仍不可控"；impersonator 已按浏览器拟真 | 深层 QUIC 检测面风险；当前最大 missing 项 | 高（=SC-3，quic-go-utls 内化后 packet packer 不再是禁区） | **P1** | `quic_sniff`（RFC 9001 解密断言）+ `e1_h3` + H3 矩阵全绿，且 Initial 布局按 profile 可控 |
| **G5** | 明文 `http://` / `ws://` 不支持 | `core/engine/roundtrip.go:27`、`upload.go:58`、`ws.go:67` 直接报错 | 混合 http/https 抓取要另配 client；drop-in 迁移硬伤 | 中（H1 手写栈可复用 + 代理 absolute-form；h2c 需评估） | **P1** | ✅ **2026-09-30 落地**：`http://` / `ws://` 走 TCP-only（不握手、SelfCheck 零值、协议恒 h1、池键含 scheme）；拨号决策抽成 `planDial` 供两条路径共用；代理环境变量按 scheme 取（https→HTTPS_PROXY / http→HTTP_PROXY）；`force_http3` + 明文明确报错。测试：`core/engine/plaintext_test.go`（7 条）+ `tests/e2e/python/test_requests_parity.py`。**与判据的出入**：HTTP 代理走 CONNECT 隧道，未做 absolute-form `GET http://…`（登记在 README 已知边界）；h2c 不做 |
| **G6** | 无 CLI | 仓库无命令行入口 | 试用门槛高、曝光少（对标 fetchr 的 CLI 形态） | 低（1–2 天） | **P1** | ✅ **2026-09-30 落地**：`core/cmd/geektls`（`make cli`）——`version` / `presets`（`--json/--grade/--name`）/ `describe` / `check-profile`（预设名/JA3/JA4/JA4R/hex）/ `request`（全量拨号选项 + `-i` + `--selfcheck` 打 stderr + `--fail`）；退出码 0/1/2；冒烟在 `core/cmd/geektls/main_test.go`（含明文请求）。`fingerprint <url>` 未单独做：`request --selfcheck` 已覆盖同一需求 |
| **G4** | Safari 侧证据薄 | HPACK safari 档为全 literal 保守近似（待 E1）；Safari H3 未实测 | 自称支持 Safari 但无真机证据 | 中（需 macOS/iOS 真机，走 E1 采集链路） | P1 | safari 档有 E1 记录 + 生成器刷新 + 断言；Safari H3 至少一份 H3 记录 |
| **G2** | wheel 平台面：无 musllinux / Windows ARM64 | release plan §8"暂不处理" | Alpine 容器、ARM Windows 装不上（无 sdist 退路） | 中（CI 加 `musllinux_1_2` 容器 ×2；win-arm64 runner 评估） | P2 | 两类 wheel 在 CI 产出并跑通冒烟；否则在 README 明确"不支持" |
| **G7** | cookie 只支持会话级 bool | `bindings/python/geektls/__init__.py` 明确报错；要带 Cookie 只能塞 header | 迁移手感差（requests 用户预期 dict/Jar） | 低（绑定层：dict → Cookie 头；暴露只读 `session.cookies`） | P2 | ✅ **2026-09-30 落地（超出判据）**：`Cookies`（MutableMapping：get/set/update/clear/get_dict/copy）+ `Session.cookies` / `Response.cookies` / 请求级 `cookies=`；优先级 显式头 > 请求级 > 会话 jar；引擎侧 `appendCookieHeader` 改为**按名合并**（同名以显式头为准）——原先是"有 Cookie 头就整段让位"，会把重定向中间跳设的 cookie 静默丢掉。测试：`test_requests_parity.py` 3 条 |
| **G9** | 依赖 fork 维护成本 | `fhttp`/`quic-go-utls` 为 vendor fork（`version()["utls"]` 可见 `=> ./third_party/*`） | 上游安全修复要人工重打 patch | 高（=SC-2/SC-3 内化后消除） | P1 | LICENSES.md 改为"自有代码 + 原语依赖"两层结构 |
| **G10** | 浏览器自动化 / MCP 生态 | 无 | 生态位缺失（非指纹核心） | 高（跨界） | **不做**（见 §4） | — |
| **G8** | 真栈行为级差异 | 结构性：真栈用原生实现 | 无法证伪的深层行为可能不同 | 不可追平 | **不追**（E1 持续收敛 + 如实标注） | 文档已如实登记即可 |

## 3. 追赶顺序（建议排期）

**阶段 0 · 发布收口（0–3 天，P0）**
1. 0.1.5 打 tag 走 Actions（版本四处已是 0.1.5，守门步已就位）；
2. PyPI 网页 yank 0.1.4 的 `manylinux_2_34_x86_64`；
3. 发 npm（`bindings/nodejs`，打包前拷 `LICENSE`/`LICENSES.md`，见 package.json comment）与
   Go module（推 core 仓 → 去 `replace` → `core/v0.1.5` + `bindings/golang/v0.1.5`）；
4. 借一台 Intel Mac + 一台 Apple Silicon Mac 跑运行期验证（G11）。

**阶段 1 · 形态补齐（第 1 周，低成本的三个 P1）——✅ 2026-09-30 全部落地**
5. ~~G6 CLI~~ ✅ `core/cmd/geektls`（五子命令 + 冒烟；`make cli`）；
6. ~~G7 cookie dict / 只读 Jar~~ ✅ `Cookies` + `Session.cookies` / `Response.cookies` / 请求级 `cookies=`
   （另加同族请求语义：timeout 元组 / auth / 请求级 allow_redirects·max_redirects·proxies / data 表单修正）；
7. ~~G5 明文 `http://`~~ ✅ `http://` 走自有 H1、`ws://` 可用（代理走 CONNECT 隧道，**未做** absolute-form；
   h2c 不做），e2e 已加明文用例。
   附带：`http3.initial_packet_size` 落地 ⇒ **G3（QUIC Initial）的尺寸/PADDING 半边关闭**，
   剩余 coalesce/分片表随 SC-3。

**阶段 2 · 平台与证据（第 2 周，可与阶段 3 并行）**
8. G2 musllinux_1_2 ×2 + win ARM64 评估；
9. G4 Safari E1 真机采样（HPACK safari 档 + H3）。

**阶段 3~6 · 自主化（第 3–9 周，= roadmap SC-1~SC-4）**
10. **SC-1** uTLS 内化裁枝（2–3 周）：`core/internal/gtls/`，重写 marshaling 层，合并 bogdanfinn 增量消灭双 uTLS；
11. **SC-2** fhttp 裁枝内化（1 周）：HPACK 钩子从 patch 转正式 API；
12. **SC-3** quic-go-utls 内化（2 周）⇒ **关闭 G3**（Initial 布局可控）+ **G9**；
13. **SC-4** 收尾（3 天）：依赖收敛、LICENSES.md 两层结构、README 对比表刷新，然后发 0.2.0（三语言齐发）。

**门禁（每阶段必过）**：ABI 签名只增不改 · 364 预设指纹输出逐比特不变 · 全量回归 +
L2 nginx 终审 + 外部 oracle 周检。

## 4. 明确不做（省得反复讨论）

| 项 | 为什么不做 |
|---|---|
| 浏览器自动化集成（对标 hrequests） | 跨界到 Playwright/浏览器管理，与指纹核心无关；有需求可以另起项目 |
| MCP server（对标 fetchr） | 同上，属产品形态而非能力；CLI（G6）已覆盖"快速试用"需求 |
| 自写密码学 / 通用压缩原语 | 不增加指纹价值、只增加事故面（roadmap §0 已声明边界） |
| 追平"真栈行为级"（G8） | 结构性差异，只能靠 E1 采集持续收敛 + 文档如实 |
| RFC 8441（WebSocket over H2） | Chrome 实际仍以 H1 Upgrade 为主；capability-matrix 已登记，等真有目标站点用再补 |

## 5. 对外表述规则（防止自吹/被挑）

- **可以宣称"一致/对等"** 的维度必须同时满足：① 有 E1/E2 证据或可复现测试；② README 对比表
  能指出对标库；③ 该维度在 `docs/capability-matrix.yml` 里有状态条目。
- 表述分三档且必须写清：**独有**（HPACK 策略、证据分级、响应内自校验、TCP 粒度）、
  **对等**（TLS/H2/H3/WS/解压/代理/预设规模）、**落后**（发布面、明文 http、CLI、Initial 布局、真栈）。
- 任何"首个/唯一"的说法先在对比表里自查一遍——本计划的差距清单就是自查清单。
