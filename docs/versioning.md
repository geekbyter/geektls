# 版本策略（P7-T5）

## 版本号

- **core/bindings 统一语义化版本**：`0.1.5`（当前）。
- **四处**单一事实源（发布时四处必须同步；升级流程见 docs/maintenance.md）：
  - core：`core/version/version.go`（`Core = "0.1.5"`，`gtls_version()` 输出）
  - Python：`bindings/python/pyproject.toml`（`version`）
  - Node：`bindings/nodejs/package.json`（`version`）
  - Python 包内：`bindings/python/geektls/__init__.py`（`__version__`）
    ⇒ 第 4 处：0.1.4 及之前的清单只写了三处，**漏了它**（PyPI 元数据是 0.1.4、
    `import geektls; geektls.__version__` 也是 0.1.4，靠人手同步，没有守门）。
    现由 `tests/e2e/python/test_engine.py::test_version_sources_agree` 钉住：
    绑定的 `__version__` 必须等于动态库 `gtls_version()["core"]`，漏改其中一处就红。

## ABI 号与包版本的对应规则

- **ABI 只增不改**（docs/02-ffi-abi.md §4）：新增函数追加到函数表尾部；
  不删不改签名。破坏性变更升 `abi` 号，旧函数保留一个周期。
- 当前 `abi = 1`，与包版本 `0.1.5` 无锁定关系——abi 升位只在 ABI 破坏时发生。
- **绑定启动核对 abi**：三语言绑定的 `version()` 已断言 `abi == EXPECTED_ABI`
  （不匹配报清晰错误——这是 noble-tls 用户最常见的坑，动态库与包错配）。
- **core 版本核对**：绑定在 `version()` 里同时回读 `core` 字段；建议上层应用
  在升级动态库后断言绑定声明的 `MIN_CORE`（当前不强制，0.1.x 阶段 ABI 内
  兼容；1.0 起把 core 版本也纳入硬校验）。

## Go 版本线（2026-09-28 统一）

- **发布面最低支持线 = go 1.26**：`core` / `bindings/golang` / `tests/smoke`
  的 go 指令统一 `1.26.0`。依据：编译进 DLL 的依赖里要求最高的是
  `golang.org/x/net v0.59.0`（go ≥1.26.0）；uTLS v1.8.2 / fhttp v0.6.9 /
  quic-go-utls 只需 ≥1.24。
- **测试面 `tests/e2e` = go 1.27.0**：第二指纹预言机链
  `gospider007/{fp,gtls,ja3,...}` 的 go.mod 要求 1.27.0，属测试专用依赖，
  不影响发布面。
- CI 钉 `go-version: '1.27'`（同时满足两面）；release-pypi.yml 用
  `go-version-file: core/go.mod`（=1.26 线，正确）。
- 规则：发布面升线只看"编进 DLL 的依赖"的最低要求；测试面可独立更高。

## 许可证与发布阻塞项（D-7 复核 2026-09-28；自身许可证 2026-09-29 已定）

- **本项目自身许可证：MIT**（根目录 `LICENSE`）。三处元数据同步：根 `LICENSE`、
  `bindings/python/pyproject.toml`（`license = "MIT"` + classifier）、
  `bindings/nodejs/package.json`（`"license": "MIT"`）。`LICENSE` 与 `LICENSES.md`
  随 wheel 分发（setuptools 的 `LICEN[CS]E*` 默认通配）。
- 见根目录 [LICENSES.md](../LICENSES.md)：全闭包审计**无 GPL/LGPL**。
  剩余注意项：**上游 fhttp 无显式 LICENSE**（风险登记，未关闭）、JA4+ 的许可证/商标边界
  （只依赖 JA4 本体）。两条都**不因**本项目选 MIT 而消失。

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
| macOS x86_64 | `macosx_11_0_x86_64`（CI 在 arm64 runner 上交叉编译；`macos-13` 已下架） |
| Windows x64 | `win_amd64` |

**不发 sdist**：从源码构建需要 Go 工具链 + C 编译器（失败率高），因此只发布 wheel；
不支持的平台由绑定在加载库时给出明确报错。
| npm | tgz（geektls-0.1.5.tgz，含动态库） | 本地构建+安装验证通过；上传待账号 |
| Go module | `github.com/geektls/golang` | 发布前需移除 go.mod 里的本地 replace（见下） |

## Go module 发布步骤（届时执行，本次不做）

1. 把 `github.com/geektls/*` 推到远端（core 仓库根即 `github.com/geektls/core`）。
2. `bindings/golang/go.mod`：删 `replace github.com/geektls/core => ../../core`，
   改为 `require github.com/geektls/core v0.1.5`；删 quic-go-utls 的本地
   replace（改为 pin 上游版本 + 把 third_party patch 以 fork 仓形式发布为
   `github.com/geektls/quic-go-utls`，或保留 vendor 目录随 core 仓分发——
   vendor 目录已在 core 仓内，Go module 会随仓拉取，无需额外动作）。
3. 打 tag：`core/v0.1.5` 与 `bindings/golang/v0.1.5`（Go 多仓模块要求
   子目录独立 tag）。
