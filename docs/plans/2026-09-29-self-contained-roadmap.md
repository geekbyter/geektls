# 自主化路线图：从"借力生态"到"完全自有"（2026-09-29）

> 目标（用户拍板）：geektls 最终**完全脱离对第三方指纹栈的借鉴引用，自行实现**。
> 本文档定义"自行实现"的边界、阶段划分与验收门禁。
>
> **当前进度（2026-09-29）**：边界声明与依赖清单已完成；`gvisor.dev/gvisor` 已引入（netstack 档，
> P6-T3 结案）；`core/internal/` 目前只有 `registry` ⇒ **SC-1 / SC-2 / SC-3 均未开始**。
> 本轮新增的 WebSocket / 响应解压 / asyncio / 模块级快捷 API 属能力补齐（见 CHANGELOG Unreleased），
> 不改变自主化阶段划分。ABI 导出现在共 **23 个**（15 基础 + 3 流式上传 + 4 WebSocket +
1 按对象取错 `gtls_error_of`）。

## 0. 边界声明（先讲清楚什么不算"借鉴"）

**自行实现的范围 = 所有影响指纹的代码路径**：
ClientHello 序列化与握手编排、扩展编解码、H2 帧层与 HPACK 策略、QUIC transport params 与包布局、TCP 选项。

**明确不自写的部分**（安全反模式，行业共识）：
密码学原语与协议状态机底座——AEAD/曲线/密钥交换（`cloudflare/circl`、`crypto/tls` 的密码学内核）、HPKE、通用压缩（brotli/zstd）。
理由：自写密码学不增加任何指纹价值，只增加安全事故面；curl-impersonate 用 BoringSSL、noble-tls 用 uTLS，密码学底座全部来自成熟实现。

## 1. 当前依赖清单（自主化对象）

| 依赖 | 角色 | 现状 | 自主化终态 |
|---|---|---|---|
| `refraction-networking/utls` | TLS ClientHello spec 引擎（TCP 侧） | go.mod 直接依赖 | **内化改写**（SC-1） |
| `bogdanfinn/utls` | QUIC 内层 TLS | 随 quic-go-utls vendor | 内化改写（SC-1 同批） |
| `bogdanfinn/fhttp` | H2 帧层 + HPACK | vendor fork（patch #0~#3） | 裁枝内化（SC-2） |
| `bogdanfinn/quic-go-utls` | QUIC + H3 | vendor fork（patch #1~#7） | 裁枝内化（SC-3） |
| `golang.org/x/net` | cookiejar/proxy/publicsuffix | 工具面 | 保留（不影响指纹） |
| `cloudflare/circl`、`andybalholm/brotli`、`klauspost/compress` | 密码学/压缩原语 | 传递/直接依赖 | 保留（见 §0） |

## 2. 阶段划分

### SC-1 TLS 栈自有化（核心，预计 2–3 周）
1. `refraction-networking/utls` 整体内化到 `core/internal/gtls/`（自有包名，脱离上游 import path）；
2. **裁枝**：删除服务端代码、未用 parrot 预设、PSK/0-RTT 等我们已自行接管的路径之外的死代码（预计裁掉 60%+）；
3. **改写指纹关键路径**：`ClientHelloSpec` → 线上字节的 marshaling 层用我们自己的代码重写（我们已有完整能力：entries.go 的解析器、compile.go 的编译器、round-trip 测试族——marshaler 是最后一块借来的）；
4. bogdanfinn/utls 的差异增量（QUIC 钩子）合并进同一份内化代码，**消灭双 uTLS 并存**；
5. 门禁：L2 终审 35/35 + fp_oracle + groundtruth 全套不变绿不过夜。

### SC-2 H2 栈裁枝内化（预计 1 周）
1. `third_party/fhttp` 移入 `core/internal/gh2/`，删服务端代码与 HTTP/1 兼容层（我们的 H1 是自己手写的，fhttp 的 h1 是死重）；
2. HPACK 钩子从 patch 形态转正为原生 API；
3. 门禁：h2_capture + hpack_strategy + Akamai 四段 oracle 不变。

### SC-3 QUIC 栈裁枝内化（预计 2 周）
1. `third_party/quic-go-utls` 移入 `core/internal/gquic/`，裁服务端、QLOG、非必要路径探测；
2. patch 锚点转正式 API；
3. **顺势解锁 Initial 布局控制**（自有后 packet packer 不再是禁区）：分片/PADDING/coalesce 按 profile 可控——这是当前能力矩阵里最大的 `missing` 项，自有化后从"不可控"直接变"可控"；
4. 门禁：quic_sniff（RFC 9001 解密断言）+ e1_h3 + H3 矩阵不变。

### SC-4 收尾与声明（预计 3 天）
1. `go.mod` 外部依赖收敛到：x/net（工具面）+ circl/brotli/compress（原语）；
2. LICENSES.md 重写为"自有代码 + 原语依赖"两层结构；
3. README 对比章节更新"自主化"列；
4. capability-matrix.yml 增补 `independence` 维度。

## 3. 不变量（任何阶段不许破坏）

- CONTRACT-FREEZE 的 18 个 ABI 导出签名不变；
- 364 预设的指纹输出逐比特不变（fp_oracle / corpus / groundtruth 三道门）；
- 每阶段结束跑全量回归 + L2 nginx 终审；
- 裁枝删除的代码如需找回，来源是 git 历史与上游 tag——内化前先把上游当前版本 commit 记录进 LICENSES.md。

## 4. 风险

| 风险 | 缓解 |
|---|---|
| 内化后失去上游安全修复通道 | 订阅上游安全公告；指纹关键路径已自有，上游修复合入按 GEEKTLS_PATCHES 重打流程 |
| TLS marshaler 自写引入线上字节漂移 | round-trip 测试族 + L2 + tls.peet.ws 三层既有裁决，漂移无处可藏 |
| QUIC 裁枝误伤拥塞控制等正确性代码 | 只裁服务端/工具面；H3 矩阵 + 流式大文件测试兜底 |
