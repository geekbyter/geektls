# 版本策略（P7-T5）

## 版本号

- **core/bindings 统一语义化版本**：`0.1.0`（一期收工）。
- 三处单一事实源：
  - core：`core/version/version.go`（`Core = "0.1.0"`，`gtls_version()` 输出）
  - Python：`bindings/python/pyproject.toml`（`version`）
  - Node：`bindings/nodejs/package.json`（`version`）
  - 发布时三处必须同步；升级流程见 docs/maintenance.md。

## ABI 号与包版本的对应规则

- **ABI 只增不改**（docs/02-ffi-abi.md §4）：新增函数追加到函数表尾部；
  不删不改签名。破坏性变更升 `abi` 号，旧函数保留一个周期。
- 当前 `abi = 1`，与包版本 `0.1.0` 无锁定关系——abi 升位只在 ABI 破坏时发生。
- **绑定启动核对 abi**：三语言绑定的 `version()` 已断言 `abi == EXPECTED_ABI`
  （不匹配报清晰错误——这是 noble-tls 用户最常见的坑，动态库与包错配）。
- **core 版本核对**：绑定在 `version()` 里同时回读 `core` 字段；建议上层应用
  在升级动态库后断言绑定声明的 `MIN_CORE`（当前不强制，0.1.x 阶段 ABI 内
  兼容；1.0 起把 core 版本也纳入硬校验）。

## 动态库与绑定包版本锁

- Python wheel / npm tgz 均把动态库打进包内（`package-data` / `files`）——
  包内库与包版本天然锁死；运行时加载顺序（env → 包内 → 仓库 build → 系统）
  保证"显式指定优先于包内"，便于开发者替换动态库调试。
- 禁止混用"包 A 的绑定 + 包 B 的动态库"：abi 校验在启动时拦截。

## 各渠道发布物

| 渠道 | 形态 | 状态 |
|---|---|---|
| PyPI | **平台标签 wheel**（`py3-none-<plat>`，含该平台的动态库） | 本地构建+安装验证通过；上传方案与 CI 见 `docs/plans/2026-09-28-pypi-release-plan.md` |

**wheel 标签必须按平台区分（`py3-none-any` 是错误的）**：包内带原生动态库，
标成 `any` 会让其他平台装完在加载库时失败。因为绑定是 ctypes（不依赖 CPython ABI），
每个平台只需**一个**轮子，而不是每个 Python 版本一个：

| 平台 | 标签 |
|---|---|
| Linux x86_64 | `manylinux_2_28_x86_64` |
| Linux aarch64 | `manylinux_2_28_aarch64` |
| macOS arm64 | `macosx_11_0_arm64` |
| macOS x86_64 | `macosx_10_15_x86_64` |
| Windows x64 | `win_amd64` |

**不发 sdist**：从源码构建需要 Go 工具链 + C 编译器（失败率高），因此只发布 wheel；
不支持的平台由绑定在加载库时给出明确报错。
| npm | tgz（geektls-0.1.0.tgz，含动态库） | 本地构建+安装验证通过；上传待账号 |
| Go module | `github.com/geektls/golang` | 发布前需移除 go.mod 里的本地 replace（见下） |

## Go module 发布步骤（届时执行，本次不做）

1. 把 `github.com/geektls/*` 推到远端（core 仓库根即 `github.com/geektls/core`）。
2. `bindings/golang/go.mod`：删 `replace github.com/geektls/core => ../../core`，
   改为 `require github.com/geektls/core v0.1.0`；删 quic-go-utls 的本地
   replace（改为 pin 上游版本 + 把 third_party patch 以 fork 仓形式发布为
   `github.com/geektls/quic-go-utls`，或保留 vendor 目录随 core 仓分发——
   vendor 目录已在 core 仓内，Go module 会随仓拉取，无需额外动作）。
3. 打 tag：`core/v0.1.0` 与 `bindings/golang/v0.1.0`（Go 多仓模块要求
   子目录独立 tag）。
