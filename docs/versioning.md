# 版本策略（P7-T5）

## 版本号

- **core/bindings 统一语义化版本**：`0.1.8`（当前）。
- **四处**单一事实源（发布时四处必须同步；升级流程见 docs/maintenance.md）：
  - core：`core/version/version.go`（`Core = "0.1.8"`，`gtls_version()` 输出）
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
- 当前 `abi = 1`，与包版本 `0.1.8` 无锁定关系——abi 升位只在 ABI 破坏时发生。
- **绑定启动核对 abi**：三语言绑定的 `version()` 已断言 `abi == EXPECTED_ABI`
  （不匹配报清晰错误——这是 noble-tls 用户最常见的坑，动态库与包错配）。
- **core 版本核对**：绑定在 `version()` 里同时回读 `core` 字段；建议上层应用
  在升级动态库后断言绑定声明的 `MIN_CORE`（当前不强制，0.1.x 阶段 ABI 内
  兼容；1.0 起把 core 版本也纳入硬校验）。
- **`utls` 字段 = 指纹栈溯源**（2026-09-29 接线）：报告动态库里实际链接的
  uTLS / fhttp / quic-go-utls 版本，由二进制 build info 推导（`core/version.UTLSVersion`），
  本地 replace 的 vendor fork 显示为 `v0.6.9 => ./third_party/fhttp`；取不到时为空串。
  它与 `LICENSES.md` 登记的版本/commit 互为运行时与静态两面——自主化 SC-1~SC-3 完成后，
  这条字段会变成"自有代码 + 上游基线"的形态，是那条迁移最直接的观测点。

## Go 版本线（2026-09-28 统一）

- **发布面最低支持线 = go 1.26**：`core` / `bindings/golang` / `tests/smoke`
  的 go 指令统一 `1.26.x`。依据：编译进 DLL 的依赖里要求最高的是
  `golang.org/x/net v0.59.0`（go ≥1.26.0）；uTLS v1.8.2 / fhttp v0.6.9 /
  quic-go-utls 只需 ≥1.24。
  2026-09-29 起实际为 **1.26.3**（gVisor 依赖的 go.mod 要求；netstack 档）。
- **测试面 `tests/e2e` = go 1.27.0**：第二指纹预言机链
  `gospider007/{fp,gtls,ja3,...}` 的 go.mod 要求 1.27.0，属测试专用依赖，
  不影响发布面。
- CI 钉 `go-version: '1.27'`（同时满足两面）；release-pypi.yml 用
  `go-version-file: core/go.mod`（=1.26 线，正确）。
- 规则：发布面升线只看"编进 DLL 的依赖"的最低要求；测试面可独立更高。

## 许可证与发布阻塞项（D-7 复核 2026-09-28；自身许可证 2026-09-29 已定）

- **本项目自身许可证：MIT**（根目录 `LICENSE`）。三处元数据同步：根 `LICENSE`、
  `bindings/python/pyproject.toml`（`license = "MIT"` 的 SPDX 表达式；按 PEP 639
  **不能**再加 `License ::` classifier，新版 setuptools 会报 InvalidConfigError）、
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
| npm | tgz（geektls-0.1.8.tgz，含动态库） | 本地构建+安装验证通过；上传待账号 |
| Go module | 见下：**当前 go.mod 发不出去** | 需先对齐 module path + 解决两个 vendor fork |

## Go module 发布（2026-09-30 第二次修订：发布形态已落地）

**与 PyPI 的根本差别**：Go module **没有"上传"动作**——发布 = 在 git 仓打 tag，proxy 抓源码，
**消费者自己编译**。所以门槛不在"构建流水线"，而在"依赖能不能被消费者解析"：

| | PyPI | Go module |
|---|---|---|
| 发布动作 | `python -m build` + twine upload | `git tag` + push（等 proxy 抓取） |
| 交付物 | 预编译 wheel（含动态库） | 源码，消费端编译 |
| 依赖解析 | 已打进 wheel，消费端不解析 | 消费端按你的 go.mod 自己解析；**`replace` 只在主 module 生效，对消费者一律无效** |
| 撤回 | yank（可标记） | **删不掉**（proxy 缓存 + sum.golang.org 校验和永久）；只能在新版本 `retract` 提示 |
| 私有依赖 | 无 | 需 `GOPRIVATE`/凭证，或内化掉 |

### ✅ 发布形态已落地（0.1.8）

前版记录的"三道闸门"已全部关闭：

1. **module path 已迁移**：`github.com/geektls/core` → `github.com/geekbyter/geektls/core`、
   `github.com/geektls/golang` → `github.com/geekbyter/geektls/bindings/golang`、
   `github.com/geektls/tests/*` → `github.com/geekbyter/geektls/tests/*`（全仓 import 同步重写）。
   旧路径在 proxy 上是 404（不是被占用的命名空间）；新路径与真实仓一致。
2. **三个 vendor fork 已内联进 core 模块**：`core/third_party/{fhttp,quic-go-utls,utls-bogdanfinn}`
   删除各自的 go.mod/go.sum，成为 core 的普通子目录包 ⇒ **没有 replace 可被忽略**，
   消费者 `go get` 到的就是带完整补丁的代码。fork 内部互引与其依赖（qpack/circl/mlkem
   等）由 core 的 go.mod 统一管理。
3. **上游测试套件改为 opt-in**：三个 fork 内联后，它们的上游测试（fhttp 的 net/http 套件
   39 处、utls 的 crypto/tls 套件 64 处、quic-go-utls 的 self 集成测试）首次纳入
   `go test ./...` 范围，对 Go 版本漂移敏感（期望与新版 Go 行为的偏差，非 geektls 回归）。
   处理：挂 opt-in build tag（`geektls_upstream_nethttp_tests` /
   `geektls_upstream_utls_tests` / `geektls_upstream_quic_integrations`），默认不跑；
   需要时 `go test -tags geektls_upstream_nethttp_tests ./third_party/fhttp/` 显式开启。
   geektls 自身行为由 e2e/parity 套件覆盖。
4. **许可证**：`fhttp` 上游无显式 LICENSE 的问题依旧存在（发布为公开 Go module = 公开
   再分发源码）——LICENSES.md 阻塞项 1 仍需闭环。

### 发布步骤（走通后每次照做）

1. **前置（本地就能跑，别省）**：
   ```bash
   cd core && go mod tidy && go build ./... && go test ./... -count=1
   grep -c '^replace' go.mod            # 必须为 0
   grep -c bogdanfinn go.mod            # 必须为 0（fork 已内联，不再引用上游路径）
   ```
2. **打 tag（顺序：被依赖的先生效；这次只需要两个）**：
   ```bash
   git tag core/v0.1.8 && git push origin core/v0.1.8                       # 先 core
   git tag bindings/golang/v0.1.8 && git push origin bindings/golang/v0.1.8
   ```
   **Go 只认 tag，不看分支**；子目录 module 的 tag 必须带子目录前缀（`core/v0.1.8`
   解析的就是仓内 `core/`）。仓库根的 `v0.1.8` tag 是 PyPI 流水线的开关，照打不误——
   它对 Go 无害（根没有 go.mod，不会形成可用的根模块）。
3. **发布后验证（照抄；首次抓取 1–3 分钟）**：
   ```bash
   curl -s https://proxy.golang.org/github.com/geekbyter/geektls/core/@v/list   # 应列出 v0.1.8
   cd "$(mktemp -d)" && go mod init t
   go get github.com/geekbyter/geektls/core@v0.1.8 && go build ./...            # 真消费者验收
   go list -m -versions github.com/geekbyter/geektls/core
   ```
   用**默认**的 `GOSUMDB` 跑一遍（确认 sum.golang.org 能收录，而不是靠 GOPRIVATE 绕）。
4. **撤回机制**：发错不能删——在新版本的 go.mod 里 `retract v0.1.8` 并在 tag 的 release
   note 说明；消费者 `go get -u` 会看到提示。
5. **大版本**：core 若升到 v2，module path **必须**带 `/v2` 后缀（语义化导入版本规则）。
⚠️ `bindings/golang/go.mod`：`require github.com/geekbyter/geektls/core v0.1.8`（fork 依赖
由 core 传递，不必重复 require）；本地开发用的 `replace => ../../core` 保留即可（消费者忽略）。
