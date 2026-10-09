# CONTRACT-FREEZE — 已验证面冻结契约（2026-09-24）

为防止「为了改而改」削弱已交付能力，下列资产**只允许新增、禁止行为变更**。
任何涉及它们的改动，PR 必须附带本文件对应条目的解除理由，且必须通过阶段 1 建立的
本地硬断言回归（7 预设 × TLS/H2 逐字段零差异）。

## 冻结清单

| # | 资产 | 范围 | 已验证状态 |
|---|---|---|---|
| 1 | `core/tls/compile.go` | detail→ClientHello 构造链路、`Detail` schema 已用字段 | 7 预设 E2 MATCH |
| 2 | `core/tls/fingerprint.go` | `ComputeJA3/JA3Hash/ComputeJA4/ComputeJA4QUIC/HashJA4R` 及 `effectiveExtensions` 语义 | 跨语言三方全等断言 |
| 3 | `core/ffi` | 15 个导出签名（`gtls_version/init/last_error/free_string/client_new/client_close/session_new/session_close/request/response_info/response_read/response_close/list_presets/describe_preset/check_profile`）**+ 2026-09-28 追加 3 个**（`gtls_request_begin/request_write/request_finish`，流式上传）**+ 2026-09-29 追加 4 个**（`gtls_ws_connect/gtls_ws_send/gtls_ws_recv/gtls_ws_close`，WebSocket）**+ 追加 1 个**（`gtls_error_of(handle)`，按对象取最近错误——给把阻塞调用放 worker 线程的绑定用；属"可缺省"追加项：绑定查不到它时必须退化到 `gtls_last_error`，不得在加载阶段拒绝工作）**+ 2026-10-09 追加 1 个**（`gtls_import_pcap(input_json)`，pcap/pcapng → E1p 指纹记录——与 CLI `import-pcap` 同一解析核 `core/pcapimport`；path 优先、data_b64 兜底）＝共 24 个 | ABI=1 只增不改 |
| 4 | `core/h2/h2.go` | `Settings/SettingsOrder/ConnectionFlow/Priorities/PseudoHeaderOrder` 注入路径 | 7 预设 Akamai 四段 E2 MATCH |
| 5 | `core/engine` 默认行为 | ~~「每请求一条新连接」为默认~~ **已于 2026-09-28 二期阶段 5 解除**（见下） | 现状即真实性特征 |
| 6 | `core/profiles/builtin/*.json` | chrome_131/133/150、firefox_120/135、safari_16/18 已 MATCH 取值 | tls.peet.ws E2 MATCH |
| 7 | `third_party/quic-go-utls` | 6 处既有 patch 锚点（interface.go/config.go/crypto_setup.go/uquic_spec_conn.go/connection.go/fuzz） | 内层 ClientHello 字节级实证 |
| 8 | `core/profiles/entries.go` | `FromJA3/FromJA4R` 解析语义 | 离线自检 4 类入参 |
| 9 | `core/tls/check.go` | `CheckProfile` 返回结构 `CheckResult{JA3,JA3Hash,JA4,WireLen,Warnings}` | pytest/node:test/go test 断言 |
| 10 | `core/tcp` 已验证子集 | TTL 三平台、MSS Linux/macOS 的 setsockopt 行为 | getsockopt 读回一致 |

## 允许动作

- **新增**字段/变量/钩子/预设/profile（只增不改）
- **新增**测试、断言、验证链路（包括把「只打印」测试升级为「硬断言」）
- **新增** `quic-go-utls` 第 7 处 patch（transport params blob 直通），但不得改既有 6 处语义
- **修复**与「当前状态」不符的文档表述（不改代码行为）

## 需要解除理由的动作

- 修改冻结表内任何已有函数签名、返回结构、默认值、解析语义
- 删除或重命名任何已导出符号
- 改变 engine 默认连接行为（如默认开启连接复用）
- 改动已 MATCH 预设的取值（除非有 E1 真浏览器证据支撑修正）

## 冻结项解除记录

### 2026-09-28 — #5「每请求一条新连接」默认行为解除（二期阶段 5）

**解除理由**（评审口径两问）：

1. 性质：**修改冻结面**（engine 默认连接行为）。
2. 为什么：真浏览器本来就复用连接（同 origin 一条 H2 连接多路复用、H1
   keep-alive、QUIC 连接复用）——「每请求一条新连接」只是 P3 的工程简化，
   不是真实性特征；相反，对同一 origin 连续请求每次都重新握手反而是
   **可检测的异常形态**（真 Chrome 不这么做）。连接池是二期任务书阶段 5 的
   明确目标。

**新默认行为**（docs/03-profile-format.md §2 同步记录）：

- per-origin 连接池默认开启；`profile.behavior.connection_pool=false` 完整恢复旧行为
  （每请求新连接），旧行为由此开关冻结保护。
- 池键 = scheme+host:port+生效代理 URL；池挂在 Session 上（profile 同 Session 恒定）。
- 复用连接不发新 ClientHello；selfcheck 语义不变（报告本连接握手时的指纹）。
- 保真回归：握手计数测试（H2 单连接 / H1 keep-alive / 关池逐请求新连接）、
  100×100 并发 `-race`、指纹零差异回归（7 预设 TLS/H2 逐字段断言）全绿。

## 评审口径

改动者需在 PR 描述中回答两个问题：

1. 这个改动属于「新增」还是「修改冻结面」？
2. 若是修改冻结面，为什么 E1 证据或明确缺陷要求这样做？
