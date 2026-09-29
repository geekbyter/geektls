# 更新日志

本项目遵循语义化版本（版本号规则与"四处单一事实源"见 [docs/versioning.md](docs/versioning.md)）。
更早的发布过程记录见 [docs/plans/2026-09-28-pypi-release-plan.md](docs/plans/2026-09-28-pypi-release-plan.md) §8.5/§8.6。

## 0.1.5（2026-09-29）

### 新增

- **预设 `chrome_154_windows`**（E1r 真机字段级实测）：桌面 Chrome 154 / Windows 形态。
  它的 JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99` 与 `chrome_154_macos` / `chrome_154_android`
  / `chrome_152_macos` **逐字符相同**，同时把"152→154 的 TLS 面无漂移"从只在 macOS 验证
  扩展到了 Windows。内置预设总数 **362 → 363**。
- **HPACK 编码策略（T-HPACK）**：`http2.hpack_strategy` 四档
  （`generic` / `chrome` / `firefox` / `safari`），通过 vendor fork
  `core/third_party/fhttp` 生效（patch 清单见 `core/third_party/fhttp/GEEKTLS_PATCHES.md`）。
  这是与 JA3/JA4/Akamai 独立的又一个 H2 指纹维度：**249/363 条预设**已带（工具族与
  栈归属不明的内嵌浏览器**刻意留空**，理由见 [docs/p2-h2-capability.md](docs/p2-h2-capability.md) §覆盖面）。
  证据分级：`chrome` 档有 Chromium QUICHE 源码级证据、`firefox` 档有 Firefox 59 字节级证据、
  `safari` 档是保守近似（全 literal，待 E1 校验）。
- **只给 `ja4=` 也能用**：短哈希（`t13d1516h2_<12位>_<12位>`）会在内置预设里反查同一指纹并采用
  其参数（`ja4_resolved_to_preset` 告警）；给 JA4R 文本则按 raw 编译。哈希不可逆，找不到会
  明确报错，不会编近似指纹。
- **`profile=` 直接接受 profile JSON 文本**（不必先 `json.loads`）。
- **身份层守门测试**：任何预设不得带 headless 令牌；`user-agent` 与 `sec-ch-ua` 的平台
  （`Windows NT`↔`"Windows"`、`Macintosh`↔`"macOS"`）与主版本必须自洽。

### 修复

- **`chrome_149_windows` / `edge_153_windows` 的 UA 带 `HeadlessChrome` 令牌**（一眼假）。
  0.1.4 里这两条预设发的是：
  `… Safari/537.36` 前面挂 `HeadlessChrome/149.0.0.0`。真机抓包逐字段复核表明
  无头与有头的 ClientHello/H2 **完全一致**，只有这枚令牌露馅 ⇒ 三处一起修：
  采集端 `cmd/e1-browser` 落盘时归一为有头形态（`sanitizeHeaders`）、两条 E1 记录改值、
  经生成器重跑刷新预设。现 `edge_153_windows` 的 UA 是正确的
  `… Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0`。
- **带 ECH 的 JA4R 整条不可用**：`FromJA4R` 漏了 65037(ECH) 的负载处理，编译期直接报
  `ech config is required for extension 65037`。而 Chrome 152+ 的 JA4R **全都带 `fe0d`**
  ⇒ 这条入口对最主要的一类目标等于堵死。现按与 JA3 入口一致的策略处理（GREASE 近似 +
  `ech_assumed_grease` 告警）+ 回归测试。
- **用户自带指纹的自洽性**：新增 `NormalizeForReplay`。从 JA3/JA4R/hex/手写 profile 构造的
  指纹若声明 TLS 1.3 却没有 `pre_shared_key(41)` 占位，一旦会话复用命中票据，uTLS 会 panic
  （被 `Handshake` 兜成错误，表现为"第二次请求莫名失败"）。现按与内置预设**同一套**规则补齐：
  1.3 必须有 41 空占位且位于扩展末尾、非 1.3 必须没有。占位不上线、不计入 JA3/JA4，
  首次握手指纹不变。

### 变更

- 预设数据：`chrome_154_windows` 等新增/刷新（生成器 + 第三方导入器两条链路都跑过，
  CI 的"预设必须等于生成器产物"逐字节守门仍为 0 差异）。

### 发布工程

- **补齐许可证元数据：本项目定为 MIT**（此前 PyPI 上 License 字段为空）。新增根目录
  `LICENSE`；`bindings/python/pyproject.toml`（`license = "MIT"` + MIT classifier）与
  `bindings/nodejs/package.json`（`"license": "MIT"`）同步；`LICENSE` 与 `LICENSES.md`
  随 wheel 分发（依赖的 BSD-3 类"保留声明"要求据此满足）。见 [LICENSES.md](LICENSES.md)。

- 版本源从**三处**修正为**四处**（补上 `bindings/python/geektls/__init__.py` 的 `__version__`，
  0.1.4 之前的清单漏了它），并加守门测试
  `tests/e2e/python/test_engine.py::test_version_sources_agree`（绑定 `__version__` 必须等于
  动态库 `gtls_version()["core"]`）。
- PyPI 流水线（`.github/workflows/release-pypi.yml`）在 0.1.4 期间踩过并修好的三处：
  `docker run` 不继承 step `env` ⇒ 参数必须 `-e` 显式传；`macos-13` 已下架 ⇒ x86_64 在
  arm64 runner 上交叉编译（`lipo` 断言架构）；glibc 基线护栏改按版本号逐段比较
  （字典序会把 `GLIBC_2.3.2` 误判为 > `GLIBC_2.28`）。

### 文档

- README 大幅扩写：指纹的**整体/局部**传法（六种入参 + 自洽性）、Python/Node/Go 三语言
  API 参考（方法、属性、逐参数说明）、10 个使用场景、预设体系与证据分级、
  与 30+ 同类项目的分组对比（优势/劣势/借鉴）。
- [docs/p2-h2-capability.md](docs/p2-h2-capability.md) 新增 HPACK 策略覆盖面小节与维护提醒。

## 0.1.4（2026-09-28）

- 首次覆盖五平台 wheel：`manylinux_2_28_x86_64` / `manylinux_2_28_aarch64` /
  `macosx_11_0_arm64` / `macosx_11_0_x86_64` / `win_amd64`。
- Linux x86_64 的标签从 `manylinux_2_34` **改标 `manylinux_2_28`**（glibc 基线 2.34 → 2.28，
  兼容面明显变大）；macOS 与 Linux aarch64 从这一版才开始提供（0.1.0 只有 Linux x86_64，
  0.1.1–0.1.3 是 Linux x86_64 + Windows，都没有 macOS/aarch64）。
- 发布后逐个拆轮子核对（架构、macOS `minOS`、glibc 符号、运行期真实请求），记录见
  [docs/plans/2026-09-28-pypi-release-plan.md](docs/plans/2026-09-28-pypi-release-plan.md) §8.6。
