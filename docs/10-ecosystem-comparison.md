# 10 - 生态对比与差距分析（2026-09-29 复核）

> 输入：用户指定的 31 个同类仓库，逐仓拉取 README 原文核对能力声明 + 一周开发实测。
> 与 README 的对比表互为表里（README 面向用户，本文档面向决策）。
>
> **复核订正（2026-09-29）**：
> ① `akamai/uls` 是 Akamai 的日志流 SIEM 工具（Unified Log Streamer），**不是指纹库**——此前表格
> 误列为"Akamai 内部 TLS/HTTP 伪装实现"，已剔除；
> ② `cyCronet` **存在**：地址是 [2833844911/cyCronet](https://github.com/2833844911/cyCronet)
> （Python + Chromium Cronet 真栈）。此前按名字猜 slug（`cycronet/cycronet`）查不到就断言
> "仓库不存在"是错的——**查不到 ≠ 不存在**，已把对比列补回。
> 另：`bogdanfinn/tls-client` 的 README 本次拉取失败（raw/镜像均 404），其能力按既有文档与
> 本项目 E3 导入记录描述，标"未核实"。
> 未进下表但已复核的仓库：`sardanioss/httpcloak`（Rust 栈 + Python/JS/C#，声明 TCP TTL/MSS/Window）、
> `daijro/hrequests`（BrowserForge 头生成 + 浏览器自动化）、`thesatellite-ai/fetchr`（CLI + MCP）——
> 均已纳入 README 对比表。

## 1. 功能维度对照（勾选 = 对等或超出）

| 能力 | geektls | CycleTLS | curl_cffi | tls-client | noble-tls | wreq-js | specter | impersonator | cyCronet |
|---|---|---|---|---|---|---|---|---|---|
| TLS 逐字段/JA3/JA4R/hex 回放 | ✅ 全 | ✅ 无 hex | 预设+ja3 | ✅ 无 hex（未核实） | ✅ | ✅ | ✅ | ✅ | ❌（真栈，仅选配置） |
| H2 帧层（SETTINGS 序/伪头序/priority/WINDOW_UPDATE 三态/首流号） | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅+时序 | ✅ | ✅（真栈） |
| **H2 HPACK 编码策略** | ✅ 四档 | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌（真栈内置） |
| H3/QUIC | ✅ 内层 CH 同 profile | ✅ | ✅ 新版起 | ✅（未核实） | ✅ | ❌ | ✅ | ✅ | —（README 未见） |
| QUIC Initial 布局 | ❌（SC-3 解锁） | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** | —（真栈自动，不可配） |
| TCP 指纹 | ✅ TTL/MSS/DF/window/wscale（setsockopt 三平台 + netstack Linux root） | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| WebSocket | ✅ RFC 6455（握手走指纹链路） | ✅ | ✅ | 未核实 | ❌ | ✅ 会话复用 | ✅ | ❌ | ✅（TLS 指纹一致） |
| Python async | ✅（线程池实现，如实标注） | ✅ | ✅ | 经绑定 | ✅ | — | ✅ | — | ✅（原生异步 API） |
| 自动解压 | ✅ 四编码 + 多重链 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅（Cronet 内置） |
| 预设规模 | **364（29 族）** | 无内置 | ~20 | ~30 | 76 | Chrome 149 / Firefox 151 | Chrome 142–148 + FF 133–151/ESR | 5 族 | `chrome_144` + `tls_profiles.json` 可自定义 |
| 证据分级/自校验 | ✅ 独有 | ❌ | ❌ | ❌ | ❌ | 部分（声明 live capture 验证） | 部分（pcap 材料） | ❌ | ❌ |
| 三语言同一引擎 | ✅ | JS+Go | Python | Go+绑定 | Python | Node | Rust+绑定 | Java | Python（单语言） |

## 2. geektls 的优势（保持）

1. **可控粒度最深**：逐字段 + hex 回放 + HPACK 策略 + QUIC 内层 CH + transport params blob 直通——逐字段自由度只有 requests-go 接近，其余全面落后。
2. **可验证性独有**：证据分级 + selfcheck 响应内回读 + nginx L2 终审 + 外部 oracle 周检——没有第二家把"伪造是否正确"做成可断言的工程闭环。
3. **三语言同一 C ABI 引擎**：跨语言 JA4 逐字符全等有测试钉住；三语言都有 requests 风格模块级快捷 API。
4. **预设覆盖面**：364 条 29 族（含国产浏览器/App/抓包工具/国产 App 内嵌 WebView），同行最多 76 条。
5. **四层 TCP 指纹**：setsockopt 档三平台 + netstack 档（window/wscale 精确控制，P6-T3 nginx 采集端 ja4tcp 五分量 MATCH）；同类均无。

## 3. 客观劣势（如实）

1. **生态与信任**：curl_cffi 6.5k star / 社区补丁节奏 / 教程数量，这里是零起点。
2. **Initial 布局**：impersonator 唯一做到（Chrome 乱序分片 + PING/PADDING、Firefox 从 SNI 中间切断对调、Safari 999 字节停），这里不可控——**SC-3（quic-go-utls 内化）解锁**。
3. **Safari 系证据**：HPACK safari 档保守近似、H3 未实测——需真机。
4. **真栈派的上限**：curl_cffi（libcurl + BoringSSL）与 `cyCronet`（Chromium Cronet 真栈）用原生网络栈，行为级细节（如 TLS 握手重试模式）天然全真；这里靠逐维度对齐逼近，理论上存在未发现的行为差异——靠 E1 真机采集持续收敛。
5. **发布面**：npm/Go module 未发布。

## 4. 已关闭的缺口与自主化进度

本轮已关闭（对照上表）：

- WebSocket（RFC 6455，握手走指纹链路 + 帧层自实现）与 Python asyncio——从"缺失"补到"对等"；
  另补响应透明解压（gzip/deflate/br/zstd + 多重链）与三语言 requests 风格模块级快捷 API。
- TCP 指纹从"部分（TTL/MSS）"升级为"setsockopt 三平台 + netstack 档"（P6-T3 结案）。

自主化路线（`docs/plans/2026-09-29-self-contained-roadmap.md`）：边界声明与依赖清单已完成，
`gvisor.dev/gvisor` 已引入；**SC-1（uTLS 内化改写）/ SC-2（fhttp 裁枝内化）/ SC-3（quic-go-utls
内化，顺带解锁 Initial 布局）均未开始**。不变量：ABI 签名只增不改、364 预设指纹输出逐比特不变、
每阶段全量回归 + L2 nginx 终审。

差距的完整清单、关闭判据与追赶排期见
[`docs/plans/2026-09-29-parity-and-improvement-plan.md`](plans/2026-09-29-parity-and-improvement-plan.md)：
发布面（G1/G11）→ 形态面（G5/G6/G7）→ 平台与证据（G2/G4）→ 自主化（SC-1~4，关闭 G3/G9）。
