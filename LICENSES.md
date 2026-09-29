# LICENSES — 依赖许可证登记（D-7 复核，2026-09-28 全量重审）

> 审计方法：`go mod graph` 全量传递闭包 + `go list -m all`（core /
> bindings/golang / tests/e2e 三模块）+ `go list -deps ./ffi`（CGO 开启，
> 取**实际编进 DLL** 的包集）+ 逐仓读 module 缓存 LICENSE 文件 + npm
> koffi 包内 license 字段 + Python 侧 pyproject 核对。
> 结论先行：**发布面无 GPL/LGPL 污染**；两个注意项见文末「阻塞项」。

## 一、发布面（编进 geektls.dll / wheel / npm 包 / Go module 的全部第三方代码）

`go list -deps ./ffi` 的完整外部模块集（13 个，逐一核过 LICENSE 原文）：

| 依赖 | 版本 | 许可证 | 用途 | fork |
|---|---|---|---|---|
| github.com/refraction-networking/utls | v1.8.2 | BSD-3-Clause | ClientHello 伪造核心（TLS 指纹面） | 否 |
| github.com/bogdanfinn/fhttp | v0.6.9 | **无显式 LICENSE**（见注意项 1） | H2 帧层（SETTINGS/优先级/伪头序/HPACK） | **是**（vendor：core/third_party/fhttp，HPACK 策略钩子） |
| github.com/bogdanfinn/quic-go-utls | v1.0.10-utls | MIT（quic-go 派生，LICENSE 在 fork 内） | QUIC + H3 | **是**（vendor：core/third_party/quic-go-utls，ClientHelloSpec 注入 + TP blob 直通） |
| github.com/bogdanfinn/utls | v1.7.8-barnius | BSD-3-Clause | fhttp/http3 传递依赖（uTLS 同族 fork） | 否 |
| github.com/quic-go/qpack | v0.6.0 | MIT | H3 的 QPACK（quic-go-utls 传递） | 否 |
| github.com/cloudflare/circl | v1.6.2 | BSD-3-Clause | ML-KEM 等后量子算法（uTLS 传递） | 否 |
| github.com/andybalholm/brotli | v1.2.0 | MIT | 证书压缩 brotli（uTLS 传递） | 否 |
| github.com/klauspost/compress | v1.18.2 | Apache-2.0 | fhttp gzip/br 解码（传递） | 否 |
| golang.org/x/net | v0.59.0 | BSD-3-Clause | h2 server（测试）/hpack/publicsuffix/SOCKS5 | 否 |
| golang.org/x/crypto | v0.57.0 | BSD-3-Clause | uTLS 传递 | 否 |
| golang.org/x/sys | v0.48.0 | BSD-3-Clause | setsockopt 等 | 否 |
| golang.org/x/text | v0.42.0 | BSD-3-Clause | 响应编码兜底（GB18030） | 否 |

## 二、绑定层

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| koffi（npm） | ^2.5.0（实装 2.16.3） | MIT（包内 license 字段确认） | Node.js FFI |
| Python 运行时依赖 | — | — | **零**（纯 ctypes + 标准库，pyproject 无 dependencies） |
| psutil（pip） | 仅 tests/perf/stress_leak.py | BSD-3-Clause | 测试工具，**不随发布物分发** |

## 三、测试面（tests/e2e 独有，不进任何发布物）

模块图全量 80+ 项逐仓核过 LICENSE（含 gin/certmagic/pebble 链、gospider007
第二预言机链、prometheus 链等）。值得登记的：

| 依赖 | 许可证 | 说明 |
|---|---|---|
| github.com/gospider007/{fp,gtls,ja3,conf,kinds,re,tools} | **无 LICENSE 文件** | 第二指纹预言机（fp_oracle_test.go）；仅测试用，不进发布物 |
| github.com/hashicorp/golang-lru/v2 | MPL-2.0 | 测试链传递；弱 copyleft（文件级），非 GPL |
| github.com/letsencrypt/pebble/v2、challtestsrv | MPL-2.0 | certmagic 测试链传递；同上 |
| github.com/zeebo/blake3、code.pfad.fr/check | CC0-1.0（公有领域） | 测试链传递 |
| 其余（gin、sonic、gjson、quic-go、caddyserver 等） | MIT / Apache-2.0 / BSD-3-Clause | 测试工具链 |

CycleTLS / gospider 的 GPL/LGPL 主项目**从未引入**（go.mod 无迹；gospider007/fp
是其二进预言机库而非 GPL 主仓代码，且无 LICENSE 文件项已在上方登记）。

## 四、结论与阻塞项

**GPL/LGPL 污染：零**（全闭包核对；三个 MPL-2.0 均为测试面文件级弱
copyleft，不污染发布物）。

公开发布（PyPI/npm/Go module）阻塞项：

1. **fhttp 无显式 LICENSE**（上游 bogdanfinn/fhttp 及父链 Carcraftz/fhttp →
   useflyent/fhttp 均无 LICENSE 文件，GitHub API `license: null`）。主体代码
   派生自 golang.org/x/net（BSD-3，各文件头保留 The Go Authors 声明），
   bogdanfinn 的增量部分无授权条款——**严格讲属"无授权使用"风险项**。
   缓解：行业惯例（tls-client/cclient 全生态同此依赖）；若要彻底排除，
   需要向上游要授权或替换实现（成本极高，暂无替代）。如实登记，不挡本轮发布。
2. ~~**本项目自身许可证未定**~~ → ✅ **已关闭（2026-09-29）：定为 MIT**（根目录 `LICENSE`）。
   理由：发布面 13 个依赖全为宽松许可（BSD-3-Clause / MIT / Apache-2.0），无 copyleft 冲突，
   MIT 与之一致；同类项目（curl_cffi 等）也走 MIT。三处元数据已同步：
   `bindings/python/pyproject.toml`（`license = "MIT"` + `License :: OSI Approved :: MIT License`
   classifier）、`bindings/nodejs/package.json`（`"license": "MIT"`）、根 `LICENSE`。
   `LICENSE` 与 `LICENSES.md` 随 wheel 分发（setuptools 的 `LICEN[CS]E*` 默认通配 ⇒ BSD-3 类
   依赖"保留声明"的要求由此满足）；npm 侧需在打包前把两者拷进包目录（见 package.json 的 comment）。

   ⚠️ 两条**不因本项目选 MIT 而消失**的风险，仍留在登记里：① 上游 fhttp 无显式 LICENSE
   （阻塞项 1）；② JA4+ 的许可证/商标边界（README 对比表已登记"只依赖 JA4 本体"）。

> 历史注记：2026-09-22 初版登记表里 fhttp 误标 BSD-3、quic-go-utls 误标
> "MIT（quic-go 原作者 & Google）"（实为 quic-go 派生 MIT，表述保留），
> 版本号亦有漂移——本轮已全部按 module 缓存原文订正。
