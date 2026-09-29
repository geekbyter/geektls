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
  `macosx_11_0_arm64`、`macosx_11_0_x86_64`、`win_amd64`（共 5 个；macOS x86_64 在
  arm64 runner 上交叉编译，见 §8.5-7）。
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
| macOS x86_64 | `macosx_11_0_x86_64` | GitHub `macos-14` + `clang -arch x86_64` **交叉编译**（见 §8.5-7） | 同上 | `lipo -info` 断言为 x86_64 |
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
          - { runner: macos-14,          tag: macosx_11_0_x86_64 }   # 交叉编译，别用 macos-13
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
5. `pip install geektls` 后再跑一次 `tests/e2e/python`（装的必须是**已发布**的轮子）。
   ⚠️ 现状：`tests/e2e/python` / `tests/e2e/node` 的**默认库名与 echo-server 名已改平台感知**
   （2026-09-29；此前硬编码 `geektls.dll` / `echo-server.exe`，在 Linux/macOS 上只能靠外部
   设 `GEEDTLS_LIB`），现在三平台都能直接跑；但它仍是**源码树模式**（插 `bindings/python`
   到 `sys.path`、用仓库 `build/` 的库），要验"装好的包"仍需临时脚本化
   （clean venv + 真实请求，见 §8.6 的方法）。想变成常规项需要 e2e 支持 wheel 模式（§5 表格最后一行）；
6. 打 tag 前确认：**四处**版本字面量一致——`core/version`、`pyproject.version`、
   `bindings/nodejs/package.json`、**`bindings/python/geektls/__init__.py` 的 `__version__`**
   （第三处清单漏了最后一处，2026-09-29 修正）。已自动化，不用靠人眼：
   - `ci.yml` 的 **"version literals must agree (四处)"** 步（pytest/node:test 不在 CI 里，
     所以这条检查必须放在 CI 能跑到的地方）；
   - `release-pypi.yml` 的 **"版本四处一致 + 与 tag 匹配"** 步：tag 触发的构建若
     `v0.1.5` 与版本源不符，直接红。

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

## 8.5 首次发布踩到的坑（0.1.0/0.1.1 实录，已修进流水线）

1. **`py3-none-any` 绝不能上传**：`python -m build` 先产出 `any` 包，再由
   `wheel tags --platform-tag <t>` 生成平台包——若不加 `--remove`，两个都会留在
   `dist/`，上传时会把 `any` 一起传上去（其他平台装完加载库失败）。**已加 `--remove`**。
2. **只清包目录不够**：setuptools 的暂存目录 `bindings/python/build/lib/geektls/`
   会保留上一次构建的动态库 ⇒ 只删 `geektls/*.so` 后重新打包，wheel 里
   **仍会带上旧的 `.dll`**（0.1.0 的 Linux wheel 就这样混装了 dll）。
   **修法：每次打包前 `rm -rf bindings/python/build`**。
3. **上传后必须核对索引**：0.1.0 的 Windows wheel 上传成功（twine 200）并当场能装，
   但一小时后 `https://pypi.org/simple/geektls/` 上**只剩 Linux wheel**（原因未明，
   疑似新项目复核/文件被移除）。⇒ 发布流程末尾必须核对
   `pip download geektls --platform <plat> --only-binary=:all:` 能否取到各平台文件，
   不能只看 twine 的"成功"。
4. **验证要避开本地目录**：在含 `geektls/` 源码目录的 cwd 下 `pip install geektls`
   可能被本地目录影响 ⇒ 一律在**干净目录**装，并确认 `dist-info/direct_url.json`
   **不存在**（存在 = 装的是本地目录，不是索引）。
5. 本地补平台的可行性：Windows 用 llvm-mingw（免安装，~182MB，`CC=x86_64-w64-mingw32-gcc`）
   ✓；Linux 在 WSL 里下 Go + 用系统 gcc ✓（glibc 底线取决于构建机 ⇒ 本次为
   `manylinux_2_34`，想降到 2.28 需在 manylinux 容器里构建 ⇒ 只能靠 CI）。
   **macOS / Linux-aarch64 无法本地构建，必须 CI**。
6. **step 的 `env:` 进不了 `docker run`**：Linux 那步用 `env: {GOARCH: ...}` 传给
   `docker run ... bash -c '...${GOARCH}...'`，容器里根本没有这个变量 ⇒ 在
   `set -u` 下直接 `bash: line 2: GOARCH: unbound variable`（两个 Linux 平台同时红）。
   **修法：要进容器的参数一律 `docker run -e KEY=VAL` 显式传**；同时别再在容器里
   `curl go.dev/VERSION` 取 latest（会和 `core/go.mod` 漂移）——直接把 runner 上
   setup-go 的那套 `$GOROOT` 挂进去（同一路径 + `-e GOROOT`），容器里只负责用
   **容器自己的 gcc** 链接（glibc 底线仍由镜像决定）。留了容器内下载同版本作为兜底。
7. **`macos-13` 已下架**：它是 GitHub 托管池里最后的 Intel runner，写它只会永远停在
   `Waiting for a runner to pick up this job`（不报错、不超时，看着像"卡死"）。
   **修法：在 `macos-14`（arm64）上交叉编译 x86_64**——`GOARCH=amd64` +
   `CC=clang` + `CGO_CFLAGS/CGO_LDFLAGS="-arch x86_64"`（编译和链接两侧都要，SDK 本身
   是 universal 的；Go 1.26 的 darwin 底线是 11.0，所以标签跟着改
   `macosx_11_0_x86_64`，压不回 10.15）。两个必须加的护栏：
   - 构建后用 `lipo -info` **断言** dylib 架构（交叉编译最怕"成功但产出宿主架构"，
     那样 wheel 标签就是假的）；
   - 校验步骤不能直接用 runner 的 arm64 Python 装 x86_64 轮子（必然
     `incompatible architecture`）。有 Rosetta 就 `arch -x86_64 /usr/bin/python3`
     起个 x86_64 解释器真加载；没有则退化为"拆包 + lipo 断言"（打 warning 不红）。
   顺带补了一条 Linux 护栏：`objdump -T` 取 `GLIBC_` 符号，出现 >2.28 的直接失败，
   防止误标 `manylinux_2_28`。
8. **glibc 基线护栏别用字符串比版本**：第一版写成
   `[ "$MAX" \> "GLIBC_2.28" ]`，字典序下 `GLIBC_2.3.2` 被判成 > `GLIBC_2.28`
   （第 8 位 `3` > `2`）⇒ x86_64 误报失败（`GLIBC_2.3.2` 其实是最老的符号之一，
   aarch64 那侧最高是 2.17，字典序恰好没事，所以只有一边红）。
   **修法：按版本号逐段数值比较**（awk：`$1>2 || ($1==2 && $2>28)`），
   并把全部符号版本打出来便于定位。

## 8.6 0.1.4 发布后核对（2026-09-28，逐个拆轮子验的）

**PyPI 0.1.4 共 6 个文件**：CI 的 5 个平台（macOS arm64/x86_64、manylinux_2_28
aarch64/x86_64、win_amd64）**+ 1 个多余的** `manylinux_2_34_x86_64`（06:49，本地 WSL
构建，早于 CI 那批 07:19–07:26）。

已核对的项（方法可复用）：

| 检查 | 结果 |
|---|---|
| 每个 wheel 里的原生库架构 | mac arm64 / mac x86_64 / linux aarch64 / linux x86_64 / win x86_64 全部正确（交叉编译的 x86_64 dylib 真的是 x86_64） |
| macOS dylib 最低系统版本与依赖 | `minOS=11.0.0`（与标签 `macosx_11_0_*` 一致）；只依赖 `libSystem.B` / `libresolv` / `CoreFoundation` / `Security`，无 Homebrew 路径 |
| Linux glibc 符号 | 2_28 x86_64 最高 `GLIBC_2.3.2`、2_28 aarch64 最高 `GLIBC_2.17`、本地 2_34 最高 `GLIBC_2.34`（**标签不假**）；三者均无 `GLIBCXX_/CXXABI_` |
| 文件名/内部 Tag 一致 | 5 个 CI 轮子都无 `py3-none-any` 混入 |
| 运行期（真实请求，本地 echo server + selfcheck + redirect/cookie/POST/流式/H3/错误路径） | Windows：从 **PyPI 装到的包**全绿；Linux（WSL Ubuntu 26.04）：**PyPI 装到的 2_34** 与 **CI 的 2_28** 各跑一遍全绿 |

**由此得出的两个待办**：

1. **0.1.4 有两个 Linux x86_64 轮子，现代 glibc 上 pip 会优先取 2_34**（本地 WSL 构建），
   而不是 CI 的 2_28。两者都能用（上面已各验一遍），但发布策略上应只留兼容面更大的
   `manylinux_2_28` ⇒ 建议在 PyPI 网页上把 0.1.4 的 `manylinux_2_34_x86_64` **yank**
   （别删版本、别删文件）。**只能人工在网页操作**。
2. **macOS 是唯一没有运行期验证的平台**：CI 只能做静态断言（x86_64 还是在 arm64
   runner 上交叉编译的）。需要在**一台 Intel Mac + 一台 Apple Silicon Mac** 上各
   `pip install geektls` 跑 `version()` + 一次真实请求，之后才对外宣传 mac 支持。

顺带记一个观测：同一预设连续两次请求，`ja3_hash` 会变（GREASE 随机），`ja4` 稳定
⇒ **对拍/回归断言只能锁 JA4 与扩展指纹，不能锁 JA3 哈希**。

## 8.7 0.1.5 发布准备（2026-09-29）

**发布内容与差集见根目录 [CHANGELOG.md](../../CHANGELOG.md)**（不是照抄提交记录，是把
已发布的 0.1.4 wheel 拆开跟当前仓库逐项比对得到的）。

差集实测（0.1.4 win wheel 的 `geektls.dll` vs 当前仓库）：

| 项 | 0.1.4 | 0.1.5 |
|---|---|---|
| 内置预设数 | 362 | **363**（新增 `chrome_154_windows`） |
| `HeadlessChrome` 令牌 | **2 处**（chrome_149_windows / edge_153_windows） | **0 处** |
| `hpack_strategy` | 只在 schema 里有字段（无预设带值） | **249/363 条预设带值** |
| `ja4=` 入参（错误码 `ja4_resolved_to_preset`） | 无 | 有 |
| 自洽归一告警 `psk_placeholder_added` | 无 | 有 |

**发布动作（三步）**：

1. 四处版本号已是 `0.1.5`（§6 第 6 条，已自动守门）；
2. 打 tag 并推：`git tag v0.1.5 && git push origin v0.1.5`
   ⇒ `release-pypi.yml` 出 5 平台 wheel 并发布（想先试 TestPyPI 就把 publish 步的
   `repository-url: https://test.pypi.org/legacy/` 放开，核完再删）；
   或 `workflow_dispatch` 手工触发（此时 tag 匹配检查会跳过，只查四处一致）。
3. 发布后核对（方法沿用 §8.6）：下载 5 个轮子逐个拆包验原生库架构/`minOS`/glibc 符号，
   再用干净 venv 装**已发布的**轮子跑一遍真实请求 e2e。

**跨 0.1.4 仍未关闭的两项**（不阻塞发布，但别忘）：

- **macOS 的运行期验证**：CI 只能静态断言（x86_64 还是在 arm64 runner 上交叉编译的），
  需要在真 Intel Mac + Apple Silicon Mac 上各 `pip install geektls` 跑一次；
- **License 元数据**：PyPI 页仍显示 License 未声明（§8 D-7）。

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
