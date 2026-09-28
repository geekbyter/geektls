# CONTRACT-FREEZE — 已验证面冻结契约（2026-09-24）

为防止「为了改而改」削弱已交付能力，下列资产**只允许新增、禁止行为变更**。
任何涉及它们的改动，PR 必须附带本文件对应条目的解除理由，且必须通过阶段 1 建立的
本地硬断言回归（7 预设 × TLS/H2 逐字段零差异）。

## 冻结清单

| # | 资产 | 范围 | 已验证状态 |
|---|---|---|---|
| 1 | `core/tls/compile.go` | detail→ClientHello 构造链路、`Detail` schema 已用字段 | 7 预设 E2 MATCH |
| 2 | `core/tls/fingerprint.go` | `ComputeJA3/JA3Hash/ComputeJA4/ComputeJA4QUIC/HashJA4R` 及 `effectiveExtensions` 语义 | 跨语言三方全等断言 |
| 3 | `core/ffi` | 15 个导出签名（`gtls_version/init/last_error/free_string/client_new/client_close/session_new/session_close/request/response_info/response_read/response_close/list_presets/describe_preset/check_profile`） | ABI=1 只增不改 |
| 4 | `core/h2/h2.go` | `Settings/SettingsOrder/ConnectionFlow/Priorities/PseudoHeaderOrder` 注入路径 | 7 预设 Akamai 四段 E2 MATCH |
| 5 | `core/engine` 默认行为 | 「每请求一条新连接」为默认；连接池只能是**可选开关且默认关** | 现状即真实性特征 |
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

## 评审口径

改动者需在 PR 描述中回答两个问题：

1. 这个改动属于「新增」还是「修改冻结面」？
2. 若是修改冻结面，为什么 E1 证据或明确缺陷要求这样做？
