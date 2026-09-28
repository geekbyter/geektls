# PyPI 发布方案（2026-09-28）

目标：`pip install geektls` 装完即可 `import geektls` 直接用（会话/请求/预设/自校验）。

> 名字已核对：`https://pypi.org/pypi/geektls/json` 返回 **404 ⇒ 名字可用**（先到先得，
> 建议尽早发布一个 0.1.0 占位版本）。

---

## 0. 结论（三个决策 + 你要做的三件事）

**决策**

- **D1｜wheel 形态**：本包是**纯 Python（ctypes）+ 包内原生动态库**，所以发布
  **平台标签 wheel**（`py3-none-<plat>`），**绝不能用 `py3-none-any`**
  （`docs/versioning.md` 现在的写法是错的，已在本方案中修正）。
  好处：与 CPython ABI 无关 ⇒ **一个平台一个轮子（5 个），不是每个 Python 版本一个（30 个）**。
- **D2｜平台矩阵（v0.1）**：`manylinux_2_28_x86_64`、`manylinux_2_28_aarch64`、
  `macosx_11_0_arm64`、`macosx_10_15_x86_64`、`win_amd64`（共 5 个）。
  musllinux / Windows ARM64 / 32 位**暂不做**（见 §8）。
- **D3｜不发 sdist**：源码包装了也没法编译（要 Go 工具链 + C 编译器），只会招来一堆
  “install failed” issue。**只发 wheel**；不支持的平台由绑定给出清晰报错。

**你要做**

1. 注册/登录 PyPI + TestPyPI，创建项目 `geektls`；
2. 在 PyPI 项目页配置 **Trusted Publishing**（GitHub OIDC，绑定仓库 + workflow 名 +
   `pypi` environment），这样 CI 上传**不需要 token**；
3. 拍板 §8 里"暂不做"的取舍（尤其 **D-7 许可证复核**——PyPI 会展示 License，
   `quic-go-utls` 标 MIT vs 上游 BSD-3 的复核建议在公开发布前完成）。

---

## 1. 现状盘点

**已经有（关键）**：

| 部件 | 位置 | 状态 |
|---|---|---|
| C ABI 动态库 | `core/ffi` + `core/ffi/geektls.h`；`make build` → `build/geektls.{dll,so,dylib}` | ✅ |
| Python 绑定 | `bindings/python/geektls/`（ctypes，零编译依赖） | ✅ |
| 包内库加载顺序 | `_ffi.py`：`GEEDTLS_LIB` → **包内** → 仓库 `build/` → 系统路径 | ✅ 已为分发设计好 |
| `pyproject.toml` | `bindings/python/pyproject.toml`（setuptools + `package-data` 收 `*.dll/*.so/*.dylib`） | ✅ 骨架在 |
| 本地 wheel 试装 | `docs/06-task-list.md` P3-T5：干净 venv 装后 import/version/list_presets 通过 | ✅ |
| Python e2e | `tests/e2e/python/test_engine.py`（pytest，预设矩阵 × selfcheck） | ✅ |

**缺（本方案要补）**：

1. wheel 的平台标签（现在是 `py3-none-any`，Linux 上装完会加载 `.dll` 失败）；
2. 跨平台构建脚本 + CI（仓库根**还没有 `.github/`**，见风险登记 D-8）；
3. 元数据（license/readme/urls/classifiers）；readme 在仓库根，setuptools 不允许
   `bindings/python` 引用项目目录外的文件 ⇒ CI 里先拷进来；
4. 把入库的 22MB 动态库移出仓库（风险 D-3）；
5. 上传流水线与发布 checklist。

---

## 2. 产物矩阵（v0.1）

| 平台 | wheel 标签 | 构建环境 | C 工具链 | 校验 |
|---|---|---|---|---|
| Linux x86_64 | `manylinux_2_28_x86_64` | `quay.io/pypa/manylinux_2_28_x86_64` 容器 | 镜像自带 gcc | `objdump -T libgeektls.so \| grep GLIBC_` 最高 ≤ 2.28 |
| Linux aarch64 | `manylinux_2_28_aarch64` | 同上（arm64 runner） | 同上 | 同上 |
| macOS arm64 | `macosx_11_0_arm64` | GitHub `macos-14`（arm64） | Xcode CLT | `otool -L` 只依赖系统库 |
| macOS x86_64 | `macosx_10_15_x86_64` | GitHub `macos-13`（x86_64） | 同上 | 同上 |
| Windows x64 | `win_amd64` | GitHub `windows-2022` | mingw-w64（`choco install mingw`） | `dumpbin /dependents` 只依赖系统 DLL |

> 为什么在 manylinux 容器里构建：Go 的 c-shared 库会链接 glibc，**glibc 版本决定
> wheel 标签能不能标 `manylinux_2_28`**。在旧镜像里构建 = 天然满足基线，比事后
> `auditwheel repair` 稳（且 `auditwheel repair` 对"非扩展模块里塞 .so"并不适用）。
>
> FFI 是 ctypes 而非 CPython C-API ⇒ **不需要 cibuildwheel 的多解释器矩阵**，
> 每个平台一个轮子即可。

---

## 3. 本地出一个轮子（命令级）

```bash
# 1) 构建动态库（当前平台）
make build                      # → build/geektls.dll | libgeektls.so | libgeektls.dylib

# 2) 把库拷进包内（package-data 会收走它）
cp build/libgeektls.so bindings/python/geektls/

# 3) 把仓库根 README 拷进构建目录（元数据用）
cp README.md bindings/python/README.md

# 4) 构建 wheel（纯 Python 骨架）
cd bindings/python && python -m build --wheel

# 5) 打上平台标签（关键一步；标签按 §2 表）
python -m wheel tags --platform-tag manylinux_2_28_x86_64 dist/*.whl

# 6) 干净环境验证
python -m venv /tmp/v && /tmp/v/bin/pip install dist/*.whl
/tmp/v/bin/python -c "import geektls,json;print(json.dumps(geektls.version()))"
/tmp/v/bin/python -m pytest ../../tests/e2e/python -v    # 装了 wheel 也能跑 e2e
```

Windows 对应：`copy build\geektls.dll bindings\python\geektls\`，标签 `win_amd64`。

---

## 4. CI 流水线（GitHub Actions）

仓库根新建 `.github/workflows/release-pypi.yml`，骨架：

```yaml
name: release-pypi
on:
  push:
    tags: ["v*"]           # v0.1.0 触发
  workflow_dispatch:        # 手动跑（先发 TestPyPI）
jobs:
  build:
    strategy:
      matrix:
        include:
          - { runner: ubuntu-24.04,      tag: manylinux_2_28_x86_64,  container: "quay.io/pypa/manylinux_2_28_x86_64" }
          - { runner: ubuntu-24.04-arm,  tag: manylinux_2_28_aarch64, container: "quay.io/pypa/manylinux_2_28_aarch64" }
          - { runner: macos-14,          tag: macosx_11_0_arm64 }
          - { runner: macos-13,          tag: macosx_10_15_x86_64 }
          - { runner: windows-2022,      tag: win_amd64 }
    runs-on: ${{ matrix.runner }}
    container: ${{ matrix.container }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version-file: core/go.mod }
      - name: 安装 C 工具链（macOS/Windows）
        if: runner.os == 'macOS' || runner.os == 'Windows'
        run: |
          # windows: choco install mingw -y ; macOS 自带 Xcode CLT
          true
      - name: 构建动态库
        run: make build
      - name: 组装 wheel
        shell: bash
        run: |
          cp build/*geektls.* bindings/python/geektls/
          cp README.md bindings/python/README.md
          python -m pip install --upgrade build wheel
          cd bindings/python && python -m build --wheel
          python -m wheel tags --platform-tag ${{ matrix.tag }} dist/*.whl
      - uses: actions/upload-artifact@v4
        with: { name: wheel-${{ matrix.tag }}, path: bindings/python/dist/*.whl }

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: pypi
    permissions: { id-token: write }        # Trusted Publishing（无需 token）
    steps:
      - uses: actions/download-artifact@v4
        with: { merge-multiple: true, path: dist }
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/   # 先 TestPyPI；正式发布时删掉这行
```

要点：

- **TestPyPI 先行**：`repository-url` 指 TestPyPI，装一次确认无误再切正式；
- Go 版本跟 `core/go.mod`（避免风险 D-5 的版本漂移）；
- 加 `-ldflags "-s -w" -trimpath` 到 `make build`（体积从 ~22MB 降下来，见 §8）；
- 不构建 sdist（`--wheel`）⇒ 不会出现"从源码装需要 Go"的失败。

---

## 5. 需要改动的文件清单

| 文件 | 改动 |
|---|---|
| `bindings/python/pyproject.toml` | 补 `readme`/`license`/`authors`/`[project.urls]`/`classifiers`/`keywords`；`requires-python = ">=3.9"` 保留；`[tool.setuptools.package-data]` 保留 |
| `docs/versioning.md` | **修正**：`geektls-0.1.0-py3-none-any.whl` → 平台标签表（§2）；补"只用 wheel、不发 sdist" |
| `Makefile` | `build` 加 `-trimpath -ldflags "-s -w"`；新增 `wheel` 目标（本地一把出轮子） |
| `.github/workflows/release-pypi.yml` | 新增（§4） |
| `bindings/python/geektls/__init__.py` | 加 `__version__`、`list_presets()`、`describe()` 的薄封装；**不支持平台时报错里带上支持的标签列表** |
| `.gitignore` | 忽略 `build/`、`bindings/python/dist/`、`bindings/python/geektls/*.{so,dylib,dll}`（风险 D-3：修掉 22MB 库入库） |
| `tests/e2e/python/test_engine.py` | 支持"装好的包"模式（不设 `GEEDTLS_LIB`、不插 `sys.path`）以便 CI 验 wheel |

---

## 6. 发布 checklist

1. `make wheel` 本地出轮子 → 干净 venv 装 → `geektls.version()` + 本地 echo 请求通过；
2. 推 tag（`v0.1.0`）→ CI 出 5 个轮子 → **TestPyPI** 上传；
3. `pip install -i https://test.pypi.org/simple/ geektls` 在三平台各试一次（至少 Linux + 你的平台）；
4. 切正式 PyPI（去掉 `repository-url`）；
5. `pip install geektls` 后再跑一次 `tests/e2e/python`（装的必须是**已发布**的轮子）；
6. 打 tag 前确认：`core/version`、`pyproject.version`、`bindings/nodejs/package.json` 三处一致（`docs/versioning.md` 的单源规则）。

---

## 7. 与 npm 的对称（同一套库）

Node 侧同理：`bindings/nodejs` 把库打进 tgz（已有），或用
`optionalDependencies` 拆成 `@geektls/darwin-arm64` 之类的子包。**先做 PyPI，npm 复用同一份
CI 产物**（同一批 `build/*geektls.*`）。

---

## 8. 暂不处理（存 plan）

| 项 | 为什么先不做 | 什么时候做 |
|---|---|---|
| musllinux（Alpine） | glibc/musl 不兼容，需在 `musllinux_1_2` 容器里各出一套 | 有用户提需求（wheels 变 8 个） |
| Windows ARM64 / anylinux 32 位 | 用户占比低，构建矩阵成本高 | 有明确需求 |
| macOS 代码签名/公证 | wheel 内是 `.dylib` 而非可执行文件，`pip` 不触发 Gatekeeper | 若做独立 CLI 二进制时需要 |
| **D-7 许可证复核** | PyPI 会展示 License；`quic-go-utls` 的 MIT vs BSD-3、JA4+ 商用边界需先定 | **公开发布前**（建议与 §0 第 3 条一起拍） |
| 体积优化（22MB → ?） | 已用 `-s -w -trimpath`；再压会伤调试符号，UPX 会破坏 Go 运行时特性 | 观察用户反馈 |
| 从源码安装（sdist） | 需要 Go + C 工具链，失败率高、issue 成本高 | 明确不提供（文档写清楚） |

数据侧的待办（锚点 S10/S11、S8/S9）继续留在 `docs/08-plan-pending-samples.md`。

---

## 9. 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| wheel 标签写错（当前 `py3-none-any`） | Linux 装完加载 `.dll` 失败，差评/issue | 本方案 D1 + `docs/versioning.md` 修正 |
| manylinux 基线不达标 | 老发行版加载失败 | 在 manylinux 容器内构建 + 每次 CI 校验 `GLIBC_` 最高版本 |
| Trusted Publishing 配错 | 上传 403 | 先 TestPyPI 验证，OIDC 无 token 泄露风险 |
| 名字被抢注 | 得换名（如 `geektls-client`） | 尽早发 0.1.0 占位（已确认当前可用） |
| ABI/包版本错配 | 运行时崩溃 | 已有 `version()` 的 ABI 断言；升级文档保持"包内库与包版本锁死" |

---

## 10. 工期估算

| 步骤 | 工作量 |
|---|---|
| 元数据 + 本地 `make wheel` + 干净环境验证 | 0.5d |
| `release-pypi.yml`（5 平台矩阵）+ TestPyPI 跑通 | 1–1.5d（Windows cgo 工具链最费时） |
| 正式发布 + 三平台安装验证 + 文档（versioning/README 安装段） | 0.5d |
| **合计** | **约 2–2.5d** |
