# 代码审计补充差距与执行计划（2026-09-29）

> 输入：对当前工作树的**逐文件代码审计**（非文档转述）。
> 定位：**不重复** [`2026-09-29-parity-and-improvement-plan.md`](2026-09-29-parity-and-improvement-plan.md)
> 已登记的 G1–G11 与 SC-1~SC-4；本文件只收**那份计划没写、但代码里确实存在**的差距。
> 编号用 `A*`（audit），与 `G*`（生态差距）、`S*`（待采样）、`H3-*` 不冲突。
> 每条都给了证据位置（`file:line`）、影响、成本、优先级、关闭判据。

## 0. 一句话结论

指纹引擎本身健康（`cd core && go build ./... && go test ./...` 本次审计**全绿**，exit 0）。
真正的差距不在指纹能力面，而在三处：①**工程卫生**（仓库一个 commit 都没有，release 计划无法启动）；
②**"实测闭环"不可持续**（网络类测试在 CI 里全被 skip，证据只活在开发机上）；
③**requests 语义的空白面**（mTLS、CA、读超时/取消、WS 扩展头、DNS 控制）。
其中 **A1/A3/A5 是今天就该动手的**，A5 和 A7 属"用户会踩且我们自称严谨"的类别。

## 1. P0 · 工程卫生（阻断发布，成本极低）

### A1｜仓库没有任何提交，`geektls` 只是父目录里的未跟踪子目录

```
$ git rev-parse --show-toplevel   → D:/work/tls        ← 不是 geektls！
$ git log --oneline               → fatal: your current branch 'master'
                                     does not have any commits yet
$ git status --short              → 21 条 ??，含 ./ （整个 geektls 目录未跟踪）
                                     以及 adapter/ bench/ core/ nginx_build.sh …
```

`D:\work\tls` 下还混着另一批未跟踪内容（`src/ http2/ patches/ tls_fingerprints/ nginx_*.sh`，
疑似 nginx 指纹项目），且启用了 git-lfs filter。后果：

- parity 计划"阶段 0.1 = 0.1.5 打 tag 走 Actions"**当前不可执行**——没有 commit 就没有 tag，
  CI（`ci.yml`）**从未在本仓跑过一次**，所有"CI 守门"能力（四处版本一致、预设必须等于生成器产物）
  都还是纸面声明；
- 任何重构（尤其 SC-1~SC-3 那种 2–3 周的大改）**没有回滚点**，364 预设的"逐比特不变"门禁
  失去了对比基线。

**做法**：在 `D:/work/tls/geektls` 独立 `git init`（不要复用父仓），补一份本仓 `.gitignore`
（至少 `build/`、`.pytest_cache/`、`bindings/nodejs/node_modules/`），首次提交 → 打 `v0.1.5` →
确认 Actions 出一次全绿。父目录里的其它项目**不要提交进来**。
**判据**：`git log` 有历史；GitHub 上 `ci.yml` 与 `release-pypi.yml` 各有一次绿色运行记录。
**成本**：0.5 天。**优先级：P0，且排在 parity 计划阶段 0 之前。**

### A2｜`version.UTLS` 恒为空，与既有文档互相矛盾

- `core/version/version.go:9` — `UTLS = ""`，注释写"P0 尚未接入，为空"；
- 但 `README.md:72` 示例输出 `"utls": ""`（这点诚实），而 parity 计划 G9 的"现状证据"
  写的是 `version()["utls"]` **可见 `=> ./third_party/*`** —— 那句证据在当前代码里不成立。

vendor fork 的 commit 是 SC-2/SC-3 内化时"逐比特不变"的对照锚点，现在拿不到。
**做法**：填 `third_party/fhttp`、`quic-go-utls`、`utls` 三个来源的 `upstream@commit` 串；
`ci.yml` 加一条断言 `gtls_version().utls != ""`；顺手修 G9 的证据描述。
**成本**：0.5 天。**P1**（依赖 A1 先完成）。

### A3｜核心卖点"实测闭环"在 CI 里全被跳过

全仓 `t.Skip` 出现 **159 处**，网络类门控是环境变量：

| 测试 | 门控 | 默认 | CI 实际 |
|---|---|---|---|
| `core/tls/resumption_live_test.go:100` | `GEEKTLS_LIVE` | 未设 → skip | skip |
| `tests/e2e/e1_h3_test.go:105` | `GEEKTLS_E1_H3_BROWSER` | 未设 → skip | skip |
| 外部 oracle（tls.peet.ws / curl-impersonate L3） | 需外网 | — | 不进 CI |

`ci.yml` 只跑离线 `go test ./...`（本次审计已验证全绿，这一点没问题）。但结论是：
**README 里所有"✅ 实测 MATCH"目前无法在 CI 上复现**，全靠开发者手跑，因此会**无声漂移**
（fork 默认值变化、依赖升级、真浏览器版本更新都可能让某项"已实测"过期而无人知）。

**做法**：加 `.github/workflows/oracle-nightly.yml`（`schedule` + `workflow_dispatch`）：
①`GEEKTLS_LIVE=1` 跑 resumption/oracle；②nginx L2 套件（WSL2 或 ubuntu runner + root）；
③跨语言三引擎 JA4 全等；失败 → 自动开 issue（含 diff 维度）。并在 README 的"实测"列
注明**该证据最近一次 CI 绿色日期**（取自 nightly 运行）。
**判据**：nightly 至少连续 7 天绿，且 issue 自动创建路径被真实触发过一次。
**成本**：1–2 天。**P0**。

**状态（2026-09-30）：✅ 落地 `.github/workflows/oracle-nightly.yml`（判据的两条"运行类"
条件要等 A1 建仓才能验证，见末尾）**。四个 job：

| job | 内容 | 为什么这样切 |
|---|---|---|
| `oracle` | `TestExternalOracle` + `TestExternalOracleH2`（断言档）、`TestRealECHLive`、`GEEKTLS_LIVE=1` 复用探针 | 纯 Go 栈，**不需要动态库**，所以它能在没有 cgo 工具链的 runner 上稳定跑 |
| `crosslang` | `make build` + `build/echo-server` → `TestCrossLangConsistency`，再 pytest 全量 + node:test 全量 | 这是**唯一**在 CI 里真打构件的 job（Windows 档带 mingw，与 `ci.yml` 的 smoke 同套） |
| `h3-browser-e1` | `TestE1RealBrowserH3` | 仓库变量 `GEEKTLS_E1_H3_BROWSER` 没配就整 job skip——没有"与采集机同版本浏览器"时结论无意义，不愿它产出一条假信号 |
| `nginx-l2` | `verify_l2.py` | 同上：需要 patched nginx（不在仓库里），走自建 runner + `GEEKTLS_NGINX_L2_URL` |

**过程中补的三个真实前提**（不补的话 job 会"绿得没有内容"）：

1. **`GEEKTLS_ORACLE_PRESETS` 子集开关**（`tests/e2e/external_oracle_test.go`，
   `h2_oracle_test.go` 共用）：两条 oracle 原本恒遍历 `profiles.List()`=364 条，
   每条都要真打一次第三方 oracle ⇒ CI 里既慢又像是压测。默认仍是全量（本地完整对拍
   不变），支持 `chrome_*` 通配；**名单里的模式一个都没命中 ⇒ 直接失败**（拼错的预设名
   会把"oracle 全绿"变成"什么都没测"，与 A5-1/A9 的"未知即报错"同口径）。
2. **`GEEKTLS_ORACLE_ASSERT=1` 断言档**：这两条测试按 V-3 只打印 MATCH/DIFF，
   于是"跑 oracle 的 nightly"只能证明握手打得通，证不了 README 那列"实测 MATCH"没过期。
   现在 JA4/JA3 串/Akamai 四段不一致在断言档下判红；默认关闭保留 V-3（oracle 自己的
   解析口径也会变，日常手动跑不该因此炸）。
3. **复用探针的结果闸门**：`TestLiveResumptionProbe` 全是 `t.Logf`（"只打印不断言"），
   nightly 里额外要求日志出现 `resumed=true`，否则判红——不然这条 job 是空的。
   另：`crosslang` 需要 `build/echo-server` **二进制**（没有就 `t.Skip`），workflow 里
   显式 `go build -o ../../build/echo-server$(go env GOEXE)`，Windows 的 `.exe` 由
   `GOEXE` 给出而不是赌 `go build` 自动补后缀。

**本地已验证**（命令与 workflow 里逐字一致）：默认 7 预设子集 × 两条 oracle 全绿，
`chrome_154_{windows,macos}/chrome_150/edge_153_windows/firefox_156_windows/
safari_18_macos/opera_122_windows` 的 JA3/JA4/Akamai **逐项 MATCH**（`ASSERT=1` 档），
`TestCrossLangConsistency` 三绑定 JA4 全等 PASS。**顺带修掉一个测试入口缺陷**：
`bindings/nodejs` 的 `npm test` 在 Windows + Node 22 下整轮失败（`node --test <目录>`
被当成模块路径解析，`Cannot find module …\tests\e2e\node`），改为显式列文件——
CI 里那档 node:test 从来就没真跑过。

**复用闸门按真实日志校准过**（`GEEKTLS_LIVE=1` 实跑一次，55.5s）：探针打印 30 次
`成功: resumed=…`，其中 4 次是 `B cache #2（应复用）` 且 `resumed=true`
（tls.peet.ws / www.cloudflare.com × 两预设；www.google.com 侧读票据 i/o timeout，
属外网条件而非回归）。据此把闸门改成两段：`成功: resumed=` **计数为 0 ⇒ 判红并说明
"这轮什么都没测"**（端点不可达不能让 job 悄悄绿），计数 >0 而无 `resumed=true` ⇒
按"PSK 复用回归"判红。另修 `docs/maintenance.md` 里手抄命令的模块边界错误——
core / tests/e2e / bindings/golang 各自独立 module（根目录无 go.mod、无 go.work），
`go test ./tests/e2e/` 在仓库根直接报 "cannot find main module"，全部改成 `cd` 后跑。

**还没满足的判据**：①"连续 7 天绿"与②"issue 自动创建被真实触发过一次"都要仓库有
remote 且 cron 生效才能观察——本仓库目前**零提交、无远端**（A1 被明确暂缓），
所以 cron 表达式与 `gh issue create` 路径只做到了静态核对（`permissions: issues: write`
已声明、label 不存在时先建、同一时间只维护一条开放 issue、基建类失败不建 issue
——用 `steps.check.outputs.rc` 而非 `failure()` 卡条件）。A1 完成后需人工确认首跑。

## 2. P1 · requests 语义空白（真实能力差距，现计划未列）

### A4｜无 mTLS 客户端证书

全仓（`core/engine`、`core/tls`、`core/ffi`、三语言绑定）**无任何** client cert / `GetClientCertificate`
入口，只有 `InsecureSkipVerify`（`core/engine/dial.go:137`）。
对标：curl_cffi（`cert=`/`client_cert=`）、tls-client、impersonator、gospider 系都有。
影响：企业内网、银行/开放 API（Stripe、部分政务）走不了；对"requests 平替"是硬伤。
成本：低（uTLS/fhttp 路径都是标准 `tls.Certificate`，只需 FFI 增 `cert_pem_b64/key_pem_b64`，
ABI 只增不改）。**判据**：本地 mTLS 服务端双向认证通过 + 三语言用例。

**状态（2026-09-29）：✅ 已落地**。与计划的出入：ABI 签名一行没动，会话选项 JSON 追加
`ca_bundle` / `client_cert` / `client_key` 三个字段即可（`gtls_session_new` 直接反序列化成
`engine.SessionOptions`，没有手写映射表）。证书材料在 `NewSession` 一次性加载
（`core/engine/tls_opts.go`），TCP 侧进 `utls.Config`、QUIC 内层进 `core/h3.TLSSettings`，
配错即 `invalid_config`。判据落在 `core/engine/certs_test.go`：离线自建 CA，std TLS 服务端
`RequireAndVerifyClientCert`，内联 PEM / 文件 / 目录三种取值 × h1/h2 两条路径全绿。
遗留：三语言**功能性**用例要重新构建动态库才跑得动（本机无 cgo 工具链，`build/geektls.dll`
仍是改动前的版本），现阶段只有绑定层的入参归一用例（python/node 各一条）+ Go 绑定字段映射用例。

### A5｜无 CA bundle，且 `verify="/path/ca.pem"` 现在**静默失效**

`bindings/python/geektls/__init__.py:519` 只判 `if verify is False`；传字符串/Path 会被**丢弃**，
既不报错也不生效 → 用户以为用了内部 CA，实际拿到一句 `x509: certificate signed by unknown authority`。
Node 同形（`bindings/nodejs/index.js:482`，仅 `verify === false`）。
讽刺点：请求级 `verify` 我们已经**主动报错**防静默失效（`__init__.py:556`），会话级反而漏了。

**做法（两步，第一步是 bug 修复不是新功能）**：
1. 会话级 `verify` 非 `bool` 立即 `ValueError`（三语言一致），半天；
2. 支持 `verify=<path>`/`ca_bundle=<pem>`：`tls.Config.RootCAs` 接线，与 A4 同一批 ABI 增量。
**优先级：P1**（第 1 步建议立刻做，属"我们自己的诚实标准"没落到位）。

**状态（2026-09-29）：✅ 两步同批完成**。第 1 步：Python `ValueError` / Node `TypeError`
（`_apply_verify`、`applyVerify`，含空串与非文本类型），并把 `cert` 一并列入"只能在
`Session(...)` 给"的请求级拒收清单——Node 的 `request()` 此前对 `verify`/`cert`/
`allowRedirects` 是**静默忽略**，现同样报错（与 Python 对齐）。第 2 步见 A4。
`cert=None, cert_key=<path>` 这种"只给私钥"的形态选择透传给引擎报错，而不是在绑定层
再维护一份错误消息。

### A6｜超时只覆盖到响应头：流式 body 不可超时、不可取消

`core/engine` 里唯一的 deadline 是 `dial.go:61`（`net.Dialer{Timeout: time.Until(deadline)}`）与
`ws.go:224`；**全引擎没有一处 `context.WithTimeout`**。`SessionOptions.TimeoutMs` 的注释也如实写了
覆盖范围是"dial+TLS+响应头"（`engine.go:34`），但绑定层把它当"请求超时"卖：慢速/挂死的 body
会让 `gtls_response_read` **永久阻塞**，而 FFI 没有 cancel 入口 → Node 侧一个坏连接能把 worker 线程
吃掉（Python `asyncio` 是 `to_thread`，同样吃线程池额度）。
对标：requests `(connect, read)` 元组、httpx `read_timeout`、curl_cffi 可读超时抛异常。

**做法**：`read_timeout_ms`（每次 `response_read` 一段 deadline，空闲即报 `Timeout`）+
`gtls_request_cancel(handle)`（ABI 只增）。
**判据**：echo-server 加 `/slow-body` 端点，Python/Node/Go 三语言在 N 秒内拿到结构化超时错误且不泄漏 handle。
**成本**：2–3 天。**P1**。

**状态（2026-09-29）：✅ 已落地**。与计划的出入有二。① 没有新增
`gtls_request_cancel`：`gtls_response_close` 的契约本来就是"未读完即关闭 = 取消"，
缺的只是**读侧的 deadline**，再加一个 cancel 入口是同一能力的第二个名字。
② 取消不能用 `Close` 实现——stdlib 的 HTTP/1.1 chunked body `Close()` 为了把连接
放回池里会先排空剩余字节，挂死的服务端能把"超时本身"挂住 30s（实测）。因此
`core/engine/timeout.go` 认 `abortableBody`（`h1Body.abort` / 协议层透传），并且
超时包装层必须叠在解压层**之前**才认得出这个入口。`read_timeout_ms=0/省略` 时
`newTimeoutReader` 原样返回，默认路径零开销、行为逐字节不变。
判据落地：`timeout_test.go`（h1/h2 自建挂死服务端，亚秒返回 + handler 收到取消 +
非超时不误报）、`h3_test.go::TestReadTimeoutH3`、echo-server `/stall` 端点上的
`test_a6_read_timeout`（Python）与 a6 用例（Node，旧构建动态库自动 skip），
超时风暴 30 次后 fd 13→13 不增长。附带修掉一个既有缺陷：错误槽是线程局部的，
Node 的 `.async` 在 worker 线程写、主线程读 ⇒ 所有异步路径的失败都退化成无名错误，
现按对象回收（C ABI 追加 `gtls_error_of(handle)`，签名只增）。

### A7｜WS 握手默认不发 `sec-websocket-extensions`，与真 Chrome 头部集不一致

`core/engine/ws.go:114-117` 明确注释"默认不发（我们不实现 permessage-deflate）"。
但真 Chrome 的 Upgrade 请求**必发** `sec-websocket-extensions: permessage-deflate; client_max_window_bits`。
当前形态：TLS/H2 指纹全对，一到 wss 握手，H1 头集合就少一项 → 对做"Upgrade 头集"检测的站点是一眼假。

两档方案，**必须选一档**（不能继续停在中间态）：
- **A7-lite（1 天）**：把该头按 profile 发出，服务端接受后**明确报错**"协商到了不支持的扩展"，
  并在 README/capability-matrix 登记为已知边界；
- **A7-full（3–4 天）**：实现 permessage-deflate 帧层（rsv1 位 + `context_takeover` 关闭模式 +
  分片续接），并把该头纳入 `header_order` 可控集。
**判据**：`ws://`/`wss://` 对 echo-server 抓握手，头集与 `chrome_*` 预设的 `http1.header_order` 一致。
**注意**：依赖 A9 的明文 `ws://`（parity 计划 G5）才有本地可复现用例，建议与 G5 同批做。

**状态（2026-09-29）：✅ 选了 A7-full**（帧层实现，不是"报错收工"那一档）。**与判据有一处刻意出入**，
先说清：

- ① **帧层**：`core/engine/wsdeflate.go`——RSV1 只允许出现在消息首帧（分片消息的续帧必须 0）、
  控制帧永不压缩（§6.2.2）、`00 00 ff ff` 空 stored block 发送侧剥 / 接收侧补、
  分片整条重组后一次解压、解压上限 64 MiB（压缩炸弹防御）。
- ② **context takeover 的实现约束**（原计划没预料到的点）：stdlib `flate` 的
  `decompressor.Reset(r, dict)` 会**清空**历史，只把 dict 当预置字典 ⇒ 跨消息上下文只能靠
  "喂回最近 ≤32 KiB 已解明文"模拟（RFC 1951 距离上限正是 32 KiB）。这条不变量不是推理出来的，
  是先用 `build/wsflate/probe.go` 实测：dict=nil 时第二条消息 `flate: corrupt input`，
  喂尾巴时三条全 match，对照组（不带 dict 的独立流）2/3 失败。
- ③ **压缩窗口不可配置 ⇒ 不承诺**：Go 的 flate 写侧恒 32 KiB（15 bit，`windowSize` 常量）。
  所以对端把 `client_max_window_bits` 限到 <15 时**握手报错**，而不是发一条不合规的流过去；
  offer 里也因此只发裸 `permessage-deflate`，不替 Chrome 发 `client_max_window_bits`
  （裸参数被原样回声 = "接受默认 15 bit"，那条路径是通的，有用例钉住）。
- ④ **失败优先于"先连着看"**（RFC 7692 §9）：对端回声我方没请求的参数、协商不认识的扩展、
  我方没发 offer 却被协商、畸形扩展头 ⇒ `DialWS` 直接失败并关连接；
  读帧侧 RSV1 未协商 / RSV2 / RSV3 / 带 RSV1 的控制帧 / continuation 带 RSV1 全部报错。
  **"对端压缩了我们却把压缩字节当明文返回"是这条链唯一不可接受的失败模式**，所以它没有兜底路径。
- ⑤ **头纳入可控集**：`sec-websocket-extensions` 现在固定排在 `sec-websocket-key` 之后
  （Chrome 形态）。顺手修掉一个真缺陷：调用方手写该头时它会被 `applyIdentity` 带到 key **前面**，
  而 `ws.go` 顶部的头序注释声称它在最后（既有测试只断言到 key，没覆盖这一项，所以一直没暴露）。
  `profile.http1.header_order` 照旧整体覆盖（364 个预设没有一个列了 `sec-websocket-*`，
  所以默认形态就是代码里的那条序）。
- ⑥ **默认仍不发这个头**（← 与原判据的出入）：`WSRequest.compress` / Python
  `websocket(..., compress=True)` / Node `{compress:true}` 才发。理由与"不发是因为不会解"
  已经无关（现在会解了），纯粹是证据问题：仓里**没有**逐浏览器 WS 握手的 E1 采集，
  Chrome 的 Upgrade 头集里 `pragma`/`cache-control` 这些项我们也一样没补——
  在没有字节级证据时把"Chrome 必发"当成事实去改默认头集，正好是 04-roadmap §0 禁止的那类自我授权。
  判据的"头集一致"因此改为：**调用方要求时形状一致且顺序可控**，默认形态不变（老用例零影响）。
- ⑦ **没等 G5**：本地可复现用例不需要明文 `ws://`——测试自己起 `tls.Listen` 自签证书即可，
  `DialWS` 走 `insecure_skip_verify` 的会话连它。A7 与 G5 因此解耦。
- 测试与真实状态：`core/engine/ws_deflate_test.go` 的对端是**独立写的 stdlib flate 实现**
  （不调用 core 的压缩层，否则"两边错得一致"也能过）。发方向把我方发出的压缩块原样拼接、
  每条补回空块尾，交给普通 `flate.NewReader` 整体解开并比对明文 ⇒ 证明是合法连续 DEFLATE 流。
  用例：双向 takeover、两侧 `no_context_takeover`（反向每条独立可解）、分片+穿插 ping
  （pong 必须不带 RSV1）、空消息不压、裸参数回声可用、7 条握手拒绝、4 条违规帧、
  扩展头解析（引号内不切分）。`cd core && go build ./... && go test ./...` 全绿；
  `-race` 本机跑不了（Windows 无 cgo）。
- ⑧ **顺带堵住一个绑定面不对称**（A14 的一项提前结案）：`bindings/golang` 此前
  **完全没有 WebSocket 入口**（engine / FFI / Python / Node 都有），而且 `Session`
  没有 `Close()`（`eng` 字段非导出 ⇒ 调用方无法释放连接池）。现补
  `DialWS(*WSRequest)` + `WSRequest`/`WSConn` 类型别名 + opcode 常量 + `Close()`，
  用例 `TestSessionDialWS` 手写最小 wss echo 服务端钉住"offer 真上线 / 默认不发 /
  Send-Recv-Close 可用"。
- **明确还没做**（不粉饰）：
  - `compress` 只是 url_json 新键（签名不变），**本机 `geektls.dll` 是旧的 ⇒ Python/Node 侧
    拿不到这个行为**，e2e 暂无该用例；重建构件需要 cgo 工具链。
    （绑定层的**参数透传**本身是可查的：Python `WebSocket.__init__` / Node `websocket()`
    只在 `compress` 为真时写这个键，不依赖构件版本。）
  - 测试用 echo-server（`tests/e2e/cmd/echo-server/ws.go`）没实现该扩展，所以它不会回声
    `Sec-WebSocket-Extensions`——写一个"对端能压"的 e2e 服务端等于再造一套实现，
    在没有可运行构件时属于无法验证的代码，故先不写（引擎侧的独立对端已覆盖同一判据）。
  - 默认头集要不要随 `chrome_*` 预设发该头：等 E1 采样（docs/08 侧的浏览器 WS 握手抓取）。

### A8｜代理形态不全

`SessionOptions.Proxy` 注释与实现覆盖 HTTP CONNECT + SOCKS5(+h)（`dial.go:240` 的 CONNECT 路径）。缺：
- **socks4 / socks4a**（CycleTLS 有，`README.md:447` 对比表里正是这么写对手的）；
- `NO_PROXY` 与标准环境变量（`HTTP(S)_PROXY`/`ALL_PROXY`）识别 —— requests 用户默认预期；
- **H3/QUIC 过代理**的语义未文档化（QUIC 走 CONNECT 隧道 vs 需 `DATAGRAM` 扩展，边界要说清）。
**判据**：三项各有测试或在 `docs/02`/README"已知边界"里明确写"不做"。

**状态（2026-09-29）：✅ 三项全部落地（不是"写明不做"）**。新增 `core/engine/proxy.go`
（形态与解析）+ `proxy_test.go`/`proxytest_test.go`（假代理与断言），`dial.go` 改为按
scheme 分派。与计划的出入与补充：

① **SOCKS4/4A 是手写的**：x/net 的 `proxy` 包只有 SOCKS5，没有 SOCKS4，所以
`0x04/0x01` 请求、`DSTIP`/`DSTPORT`/`USERID`/`HOST` 的排布与 8 字节回包（拒绝码翻成
可读错误）全部自己实现。两条协议硬限制选择**暴露而非掩盖**：IPv6 目标报错（socks4
线上放不下 16 字节地址）、URL 带口令报错（只有 USERID 位）——静默降级会让用户以为
鉴权/双栈都过了。
② **`socks5` 与 `socks5h` 此前是同一代码路径**（域名一律交给代理 ⇒ 实现上恒为
`socks5h`，注释却写了两种语义）。现在 `socks5` 在本地 `LookupIPAddr`（受 deadline
约束、优先 IPv4），解析失败**报错而不降级**——DNS 泄漏位置是用户显式选的，不能自动改道。
③ **H3 一侧的实现原本完全不看代理**：`force_http3` 直接 UDP 直发（= 指纹漏到直连路径），
racing 与 Alt-Svc 升级同样。现统一为"有代理 ⇒ H3 不参与"，`force_http3` + 代理在拨号前
报 invalid（CONNECT-UDP/RFC 9298 未实现，属"暂无法很好落地"项，已在 `docs/02` 记为边界）。
④ 顺带修的两处：CONNECT 与 SOCKS4 握手段**没有 deadline**（只有 dial 有，代理端口
被防火墙黑洞时会挂到进程级超时）；`poolKey` 与拨号**同源**（此前各自解析一次，
`NO_PROXY` 一类分支下可能出现"键说直连、实际连了代理"的连接复用）。
⑤ `NO_PROXY` 刻意不做 DNS（Go 的 `ProxyFromEnvironment` 会解析，且**解析失败即直连**
——域名写错时代理被静默跳过，正是指纹库最不该有的失败模式）；但按 Chrome/Go 规则
对**回环目标**豁免 env 派生代理（显式 `proxy` 对回环仍生效，否则本地经代理的测试跑不了）。

判据核对：socks4/4a ⇒ `TestSocks4EndToEnd` + `TestSocks4ARemoteResolve`（假代理逐字段
核对 ATYP/DSTIP/DSTPORT/HOST/USERID 线上字节）；env + `NO_PROXY` ⇒
`TestProxySpecPrecedence` + `TestNoProxyBypass`（17 例：`*`/前导点/FQDN 尾点/端口限定/
CIDR/IPv6 括号/回环豁免/大小写）；H3 语义 ⇒ `TestH3RefusedWithProxy` + `docs/02` §代理
形态与已知边界 + README 两处表格。`core` 全量 `go test ./...` 绿，`bindings/golang`
（含新增 `ProxyFromEnv` 透传断言）绿。绑定层新增 Python `trust_env` / Node
`proxyFromEnv`|`trustEnv` / Go `Options.ProxyFromEnv`。
本机限制如实记录：Windows 无 cgo 工具链、WSL 无 Go，`geektls.dll`/`libgeektls.so` 均为
A8 之前的构建 ⇒ **Python/Node 侧的 e2e 用例在当前环境是 skip 态**（`test_a8_*` 与
`engine.test.js` 的 a8 用例都以"动态库是否读代理环境变量"为能力探针，探针不过就
skip，不会假通过）。探针本身不需要真代理也不打网络：借 `force_http3` + 代理的
拨号前冲突错误当信号。语义等价的完整判据已在 engine 层与 Go 绑定层（不需要 cgo）跑绿。

### A9｜无 DNS 控制面

无 `resolve`（域名→固定 IP）、无 `local_address`（出网网卡/IP 绑定）、无 IPv4/IPv6 偏好。
curl_cffi/httpx 都有。影响两处：**指纹调试**（L2 采集端在 WSL，现在只能改 hosts）和
**TCP 指纹验证**（A1 之后跑 netstack 档需要能钉目标）。成本：中（拨号层已分平台，加 hook 即可）。

**状态（2026-09-29）：✅ 三项落地**（`resolve` / `local_address` / `ip_version`，都是
`SessionOptions` 的 JSON 键 ⇒ **ABI 签名未动**，符合"只增不改"）。集中在
`core/engine/target.go`：一处定义"这次实际连到哪"，各处拨号只消费它的结论。与计划的出入：

① **指纹不变量是这一项的成败关键**：钉位只换拨号地址，`cfg.ServerName`、`Host`、伪头、
selfcheck 一律用 URL 里的原域名。断言方式不是"看起来没变"，而是**同一预设钉位前后的
JA4 全等**（`TestResolvePinsDialButKeepsSNIAndHost`）。参照请求必须用**域名**形态：
直连 IP 字面量时线上合法地省略 SNI，JA4 的 SNI 位（`t13d…` vs `t13i…`）本就不同，拿 IP 目标当
参照会把"正确行为"测成回归。
② **生效范围按"谁做解析"划档**，写死在 `usesRemoteDNS`：直连 / netstack / `socks5` /
`socks4` 由引擎解析 ⇒ 三项生效；CONNECT 隧道 / `socks5h` / `socks4a` 把域名原样交给
代理 ⇒ `resolve`/`ip_version` **不参与**。这里不做"能钉就钉"：绕过代理解析等于改变代理
语义，用户选 `socks5h` 就是为了让对方解析。`TestResolveAcrossProxyModes` 用假代理核对
五种形态的线上目标字节（ATYP/DSTIP/HOST/CONNECT 行）。
③ **netstack 反而因这几项才可用**：用户态栈要求目标是 IPv4 字面量，此前只能手填 IP（SNI
也就没了），现在 `resolve` 供给字面量而域名照旧上线。反向的边界也补了：`local_address`
在 netstack 下**报错**（源地址固定为 TUN 侧拓扑地址）而不是静默忽略。
④ `socks4` 的本地解析改走同一入口（`socks4Connect` 变成 Session 方法 + `localResolve(v4Only)`），
此前它自己 `LookupIP`，感知不到 `resolve`/`ip_version`。IPv6 目标仍按协议限制报错。
⑤ **冲突在建会话时就报**（`invalid_config`）：值不是 IP 字面量、键写成网卡名、`ip_version`
与源地址/钉位不同族、归一后重复键。`ip_version` 兼容 curl 写法（`4`/`v4`/`ipv4`/`any`/空）。
⑥ **H3 一侧选择拒绝而非偷换路径**：QUIC 拨号没接地址控制，`force_http3` + 任一项直接报错
（同 A8 的"有代理 ⇒ 禁 H3"口径）；profile 自己开着 H3 只是"优先尝试"，那一路静默让位 H2
是安全的。**这条静默分支没有测试**——要区分它需要同一服务同时听 TCP 与 UDP 的 fixture，
本机没有，如实登记。
⑦ 三语言绑定同步：Python `resolve/local_address/ip_version`、Node `resolve`/`localAddress`/
`ipVersion`、Go `Options`。顺带堵掉一个同源隐患：**core 的两处 JSON 解码都不严格**
（`gtls_client_new` 只查指纹入参那六个键、`SessionOptions` 忽略未知字段），所以
`local_addr`、`insecure_skip_verfy` 这类拼错会**静默消失**——而这几项恰好决定连接走哪条
路。白名单做在绑定层（Python `_SESSION_LEVEL_FIELDS`/`_REQUEST_LEVEL_FIELDS`，Node
`CLIENT_CONFIG_KEYS`/`SESSION_OPTION_KEYS`），未知键立即报错。这是 A5-1 口径的延伸。

判据核对：`TestNormalizeNetControl` / `TestPinnedPrecedence` / `TestNetworkNarrowing` /
`TestUsesRemoteDNS` / `TestResolvePinsDialButKeepsSNIAndHost` / `TestResolveAcrossProxyModes` /
`TestLocalAddressBinding`（含绑 TEST-NET-1 必失败）/ `TestNewSessionRejectsBadNetControl` /
`TestH3RefusedByAddressControl` 全绿；`core` `go test ./...` 绿、`bindings/golang` 绿。
Python `20 passed / 7 skipped`、Node `18 pass`：其中 A9（与 A8、A6 一样）的**打动态库**用例
在本机是 skip 态——Windows 无 cgo、WSL 无 Go，`geektls.dll`/`libgeektls.so` 仍是 A8/A9 之前
的构建。skip 判据是能力探针（`ip_version="7"` 必须报错），探针不过就 skip，不会假通过；
探针本身不打网络。语义等价的完整判据已在 engine 层与 Go 绑定层跑绿。

**明确不做**（写进 `docs/02` 与 README 边界）：网卡名绑定（`SO_BINDTODEVICE` 跨平台不对齐，
Go 的 `Dialer.LocalAddr` 只认地址）；`resolve` 的通配/子域匹配（curl 也不做，静默连带钉子域
更危险）；QUIC 侧地址控制（要接 quic-go 的 `DialAddr`/`LocalAddr`，与 A10 的 0-RTT 一并评估）。

### A10｜0-RTT 长期停在"可做未做"，缺一个明确决定

`docs/capability-matrix.yml:83` `tls.session_resumption_0rtt: not_controlled`，`docs/07` G2b 已取证
"TCP 侧依赖栈不可做、**H3 侧可做**（quic-go `allow0RTT`/`DialEarly` + 会话缓存）"，
但 parity 计划与 roadmap 都**没有给它排期**——一个"可做但决定不做"和"没人再提"是两回事。
**做法**：二选一并写进矩阵：①列 SC 阶段后的一项（真 Chrome 的 0-RTT 主要就发生在 QUIC）；
②结案为"不做"，理由：会话缓存与 H3 连接复用形态需先实测其对 JA4(QUIC) 的影响。**P2**，但**不要悬空**。

**状态（2026-09-30）：✅ 选 ②，并补了一个实测事实把"不做"限定清楚**。
原计划给的理由（"需先实测其对 JA4(QUIC) 的影响"）其实不必等真机——本地就能把
"声明侧"与"协议侧"切开：

- **声明侧：已可控**（这是本库主旨范围内的事，不需要任何栈改动）。预设里写
  `{"type": 42}` 走"未识别类型透传"（`GenericExtension`），线上 CH 就多一枚
  early_data；实测 `core/tls/early_data_test.go`：JA3 扩展段出现 42、JA4 由
  `t13d1517h2_…` 变 `t13d1518h2_…`（扩展计数 0x17→0x18，密文哈希不动、扩展哈希变），
  且 `FromClientHelloHex` 能把 42 以零负载原样读回（转录/回放路径可用）。
- **协议侧：不做**，两条独立理由，都不是"没人排期"：
  ① TCP 侧无钩子（G2b/docs-08 L1 已取证）；
  ② H3 侧的前提塌了——`DialEarly` 要求 QUIC 会话缓存，而 spec 模式下 `StoreSession`
  是 no-op 且无可补导出面（docs/06 P7-T2 的实测结论），首飞 Initial datagram 布局
  本身又已结案为不可控（docs/08 L3 / G6）。即便接上，也控制不了那一次首飞的字节。
- **顺带钉住的边界**：只带 42、不带 PSK 的 CH 会被标准服务端直接拒
  （Go：服务端 `client sent unexpected early data`，客户端看到 `unsupported extension`，
  RFC 8446 §4.2.10 的 MUST NOT）。所以 early_data **不能设计成一个会话开关**——
  开了就打不通握手，而不是"退化成 1-RTT"。这一条写进了矩阵与 01/07/08/p4 四处口径。

### A11｜profile schema 有两处"看起来可控实际不可表达"

`docs/07` §5.7 登记的转换期限制，本质是**引擎表达力缺口**，与"逐字段可控"这个第一卖点冲突：

1. `http2.window_update: 0` 与"未设置"同义（fhttp 补默认 15663105）→ **无法表达"不发连接级
   WINDOW_UPDATE"**，Safari 9.1.3 这类条目因此被导入器跳过；
2. **无法表达"首个请求用 `stream_id=3`"**（真 Firefox 实测如此），本库恒为 1。

**做法**：schema 增显式 `window_update_skip: true` 与 `first_stream_id`（或 `stream_id_start`），
两者都在 H2 帧层可控范围内，不需要 fork。**判据**：上面两条各一条线上断言（`tests/e2e/h2_*`），
且导入器不再跳过 Safari 9.1.3。**成本**：2 天。**P1**。

**状态（2026-09-29）：✅ 已落地**。与计划的出入有三处，都已核对。
① 没有引入 `window_update_skip` 布尔：改成把 `http2.window_update` 本身做成
`*uint32` 三态（省略 = 引擎补 15663105 / `0` = 不发这帧 / `N` = 发 N）。理由是
RFC 7540 §6.9.1 禁止增量为 0 的连接级 WINDOW_UPDATE，所以"0"在线上唯一可能的
含义就是**帧缺席**——再配一个布尔位就会多出一组可互相矛盾的组合（`skip:true` +
`window_update:5`），且采集侧（`import-pcap`/`gen-profiles`）本来就只看到一个数字。
旧形态的真问题是 `uint32 + omitempty`：0 在 marshal 时被吞掉，预设 JSON **写不出**
"不发"这一档，回读就成了"未设置"。
② "不需要 fork"不成立：连接级 WINDOW_UPDATE 与首流号都在 `fhttp` 传输层写死，
仍需 vendor fork 补丁（`Transport.ConnectionFlow *uint32`、`Transport.InitialStreamID`，
见 `third_party/fhttp/GEEKTLS_PATCHES.md`）。`InitialStreamID` 必须放在 PRIORITY 帧
簿记**之后**覆盖，否则被 `nextStreamID = priority.StreamID + 2` 冲掉。
③ 顺带修掉一个由此暴露的既有缺陷：`connFlow == 0` 时 fork 里连接级窗口的**补充量**
也是 0，条件永不成立 ⇒ 响应超过 65535 字节就永久挂起。"初始不发"≠"永不补货"，
现回落到 `initialWindowSize`（net/http 同语义）。
判据落地：`TestH2FrameCaptureTriState` 在原始帧层验四种组合（帧有无 + 增量 +
首请求流号 + SETTINGS 全序）全 PASS；`fp_oracle`/`h2_oracle` 的期望键经 `flowOnWire`
与实际线上形态一致；导入器不再跳过 Safari 9.1.3（`connection_flow: null` 曾被误读为
"对方要求不发"，实为**未采集**，现按未指定处理并告警），`safari_9_1_3_macos` 已入库，
预设 363 → 364。`firefox_145_windows` 补 `first_stream_id: 3`。
字节影响面（对照 `docs/CONTRACT-FREEZE.md`）：与导入前的语料备份 `diff -rq` 只有两处差异
——新增 `safari_9_1_3_macos`、`firefox_145_windows` 多一行 `first_stream_id: 3`；其余 362 条
逐字节相同，且全语料**没有任何预设**写 `window_update: 0`（已核对），故既有预设的发出字节
不受本次改动影响。L2 nginx 采集端终审需要 WSL 环境，本轮**未重跑**。

## 3. P2 · 覆盖与新鲜度（可并行）

### A12｜预设新鲜度没有自动检测

`docs/maintenance.md` 定的是"Chrome 2 周人工 SLA"，但没有任何机制发现"Chrome 已发新版而
builtin 最高还是 154"。parity 计划 G1 只讲发布面，没讲新鲜度。
**做法**：weekly workflow 比对上游版本 feed（Chrome Desktop-Versions、Firefox releases、
Safari/WebKit 版本）与 `core/profiles/builtin/` 的最高版本，落后即开 issue（附待采清单）。
**判据**：一次真实的"新版本发布 → 自动 issue"闭环记录。

**状态（2026-09-30）：✅ 机制落地，且首轮就抓到一个真落后**。
新增 `scripts/preset_freshness.py`（stdlib-only）+ `.github/workflows/preset-freshness.yml`
（周一 02:07 北京时间，落后即建/评论 `preset-staleness` issue，产物上传 artifact）。

- 实测输出（本机跑，2026-09-30）：`chrome 154 vs 154.0.8037.57 = OK`、
  **`firefox 156 vs 157.0 = BEHIND`** —— Firefox 157 发布于 2026-09-29（昨天），
  builtin 最高仍是 `firefox_156_*`。这正是这条项要防的事，且它不是假设：
  待采清单即 `docs/08 §C` 的固定动作（判定族/版本 → 转录或生成 → 对拍 → 钉回归 → 登记）。
- 覆盖面写死在脚本里并**如实声明边界**：只有 Chrome / Firefox 有稳定、无需 key 的
  JSON stable feed；Edge 跟 Chrome 的列车看，Safari/Opera/国产浏览器没有机器可读 feed
  ⇒ 仍走人工 SLA，脚本把这些族列进 `unscored_families`，**避免"job 绿"被读成"全族新鲜"**。
- 退出码分三档：0 新鲜 / 1 落后 / **2 取不到 feed**——"取不到"绝不静默算"没落后"。
- `docs/maintenance.md` 的"Chrome 2 周人工 SLA"一节已接上这条自动发现路径（含手动命令）。
- **判据的"自动 issue"半边**与 A3 同因未验证：无 remote、cron 未生效（A1 暂缓）。

### A13｜`docs/08` §E 的整族缺口仍未开工，且导入器有硬编码

- 上游 `tls-client@master` profiles 有而我们没有的**整族 19 条**：brave(2)、cloudscraper(1)、
  confirmed(2)、mesh(6)、mms(4)、nike(2)、zalando(2)，外加 okhttp4_android_10..13；
- 阻塞项在 `docs/08` 已列：`tests/e2e/cmd/import-tlsconfig` **只吃 `tls_config` JSON 快照**，
  不吃上游 Go 源码；`main.go:416` 把 `source` 写死成 `"tls_config-0.0.2/" + c.Const`
  → 换来源必须同步改，否则 provenance 的 `source` 字段**说谎**（这是 E1/E3 分级体系的地基）。
**做法**：导入器加 Go 源码解析入口 + `source` 参数化（CLI flag），并把 `source` 格式写进
`provenance_test.go` 的正向断言。**P2**（`cloudscraper` 若单独有需求可提前）。

**状态（2026-09-30）：✅ `source` 参数化 + 正向断言落地；Go 源码入口这次不做，且审计发现
它不是当前真正的阻塞**。

已做的半边（可复现，全部实跑过）：

- `import-tlsconfig`：`convert(...)` 改收 `source` 参数，新增 `-source` flag，默认值
  `defaultSource = "tls_config-0.0.2"` 与被替换掉的写死字面量**逐字符相同** ⇒ 再次导入
  产生的 `source` 不变；本次**没有重写任何预设文件**（`-dry` 全量跑通：339 条快照记录，
  报告与改动前同形）。`-source ""` 直接报错退出，不静默回落——空前缀会让 `source`
  变成 `"/<常量名>"`，正是"说谎"的另一种形态。
- `core/profiles/provenance_test.go::TestE3SourceTraceable`：正向断言从"E3 有 source"
  升级为"source 能回到仓库里真实存在的快照"——`<数据集>` 必须在
  `profiles/evidence/thirdparty/` 有同名 `.json`，`<常量名>` 必须是该快照某条的 `_const`。
  实跑 **320/320 通过**，并且同一条测试带 6 个合成负例（空、缺 `/`、数据集不存在、
  常量不存在…）证明这道门会判红。**这一步比参数化本身更值**：光有 `-source`，忘了传
  依然没人发现；有了"回到快照"的对拍，忘了传就是一次 FAIL。

**没做的那半边以及为什么**：原以为阻塞是"导入器不会解析 Go 源码"。实际核对
`profiles/evidence/thirdparty/` 里的两份 dump（`profiles.go` 6.6 KB +
`internal/browser_profiles.go` 91 KB）后发现——`Mesh*/Nike*/Zalando*/Confirmed*`
在映射表里只是**引用**，定义文件根本没入库；`Mms*`/`Cloudscraper` 在两份 dump 里
**一次都没出现**。所以顺序应该反过来：**第一步是把上游 `profiles/` 目录整个抓下来
入库（或拿到含这些族的新版 `tls_config` 快照），第二步才是解析**。先写 AST 解析器
只会解析出 0 条新族，属于"为了改而改"，故留在滚动区。登记同步在 `docs/08 §E`
"开工前要先解决的"第 1、2 条。

### A14｜文档与代码已出现口径漂移（低成本清理）

| 位置 | 说的是什么 | 代码实际 |
|---|---|---|
| `docs/08` §E 待修项 | `chrome_149_windows` UA 含 `HeadlessChrome` | **已修**：`builtin_identity_test.go` 守门通过，预设里查无 headless 令牌 |
| parity 计划 G9 证据 | `version()["utls"]` 可见 `./third_party/*` | `UTLS=""`（见 A2） |
| `docs/03`/生成链 | "生成预设禁止手改，否则 CI 判红" | 该守门只在 `runner.os == 'Linux'` 生效（`ci.yml:71`）——口径要写清 |

**做法**：一次纯文档 PR。**P2**，但每次审计都顺手清，别让"如实登记"变成"如实过期"。

**状态（2026-09-30）：✅ 表里三条 + 审计中另找到的 10 处漂移全部清完**。

| 位置 | 处理 |
|---|---|
| 表①：`docs/08 §E` 的 headless 待修项 | 改为"已修"并写清两层修法（源头 `cmd/e1-browser` 的 `sanitizeHeaders` + `builtin_identity_test.go` 三条身份门禁），核对 `core/profiles/builtin/` 现查无 headless 令牌 |
| 表②：parity 计划 G9 的 `version()["utls"]` 证据 | **不再需要改**——A2 落地后 `UTLSVersion()` 由 build info 推导，vendor fork 确实显示成 `=> ./third_party/…`，`core/engine/version_stack_test.go` 硬断言这条；G9 那句话从"不成立"变回成立 |
| 表③：`docs/03`/生成链的"禁止手改否则 CI 判红" | `docs/12-pcap-import.md` 一处口径补精确：那条守门只在 **Linux job** 跑，且 E1/pcap 记录要**显式加进 `ci.yml` 的 `-record` 清单**才被覆盖（生成器只自动吃内嵌 hex 标本，"自动生效"是不成立的） |
| 另：`docs/07:16` 对比表"HPACK 索引 ✗" | T-HPACK 已落地四档 ⇒ 改为"有序 SETTINGS/WINDOW_UPDATE/PRIORITY/伪头序 + HPACK 索引策略四档" |
| 另：`docs/07` G5 行、`docs/01` 维度 5 | 同上一致化（原本一处 ✅ 一处 ✗，互相矛盾） |
| 另：`docs/maintenance.md`"外部 oracle 周检" | 原文写"7 预设 × …"，实际 `TestExternalOracle` 恒遍历 364 条 ⇒ 改成子集开关的真实用法 + nightly job 表 + 断言档说明；`conftest.py` 里 `needs_nginx` 的启用变量名拼错（`GEEDTLS_NGINX_L2`，代码读的是 `GEEKTLS_NGINX_L2`）一并修正——照文档设变量会永远 skip |
| 另：`docs/01:17`、`docs/01:67`、`docs/07` G2b/汇总两处、`docs/08 L1`、`docs/p4-h3-capability.md` | 0-RTT 口径统一为"声明侧可控 / 协议侧不做"（A10 结案），不再是"未接线，随 P7-T2 一起做"（P7-T2 已完成并取证） |
| 另：`capability-matrix.yml` | `as_of` 2026-09-24 → 2026-09-30；`tls.session_resumption_0rtt` `not_controlled`→`partial`；verification 里"external 只打印不断言（阶段 1 修）"更新为断言档实况；`baseline_date` 2026-09-24 → 2026-09-30（`cd core && go build ./... && go test ./...` 重跑全绿）；补"第十五轮"登记 A2~A15 与全量复核数字 |
| 另：README 工程段 | 新增 nightly/周检两条（`.github/workflows/oracle-nightly.yml`、`preset-freshness.yml`）与 oracle 子集+断言档的手动命令；同步 `bindings/python/README.md` 镜像（两文件逐字节相同，改一处必须复制） |
| 另：README 绑定用例计数 | 重测核对：pytest `20 passed / 7 skipped`、node:test `18 pass` 与文档一致（数字没漂） |
| 另：`tests/e2e/nginx-l2/verify_p6t3.py:21` | 读的是 `GEEDTLS_NGINX_L2_URL`，而同目录 `verify_l2.py` 与 workflow 设的都是 `GEEKTLS_NGINX_L2_URL` ⇒ 同一概念两种拼写，按 CI 变量名设值时 p6t3 会静默用默认端点。统一成 `GEEKTLS_*`（注意 `GEEDTLS_LIB` 是构件路径变量的**真实**名字，不是笔误，保持不动） |
| 另：`docs/06-task-list.md` P1-T8 行 | 同一变量名的历史记述也写成 `GEEDTLS_NGINX_L2`，按它操作今天会得到永久 skip；只改这个名字，其余实况记录不动 |
| 另：`docs/maintenance.md` 手抄命令块 | 原写 `go test -tags external ./tests/e2e/`（在仓库根）⇒ 三个 module 相互独立且根目录无 go.mod，该命令直接报 "cannot find main module"；改为 `cd` 后跑并在块首写明模块边界 |

**顺带（不在原表里、属于口径之外的事实核对）**：`bindings/nodejs` 的 `npm test` 脚本
传目录参数在 Windows + Node 22 下必失败 ⇒ 见 A3 段末。这类"文档说 CI 覆盖了、其实那档
从没跑起来"的漂移，比措辞过期更值得清。

### A15｜npm 包的二进制分发形态未定

parity 计划 G1 说"发 npm"，但没回答：`geektls.dll/.so/.dylib` 怎么进包？
候选：①主包 + `optionalDependencies` 分平台子包（`@geektls/win32-x64-msvc` 等，swc/esbuild 形态）；
②`postinstall` 下载（被企业网和 `--ignore-scripts` 生态抵制，不建议）；③单包塞三平台（体积 ×3）。
**这决定 CI 产物布局，必须在 A1 之前定**（否则要重构 workflow）。**成本**：0.5 天决策 + 2 天实现。

**状态（2026-09-30）：✅ 定为 ①（主包 + `optionalDependencies` 平台子包），只决策不实现**。

决定的支点是一个事实：我们的动态库是**纯 C ABI**，Node 侧经 koffi 按路径 `dlopen`
（`bindings/nodejs/index.js` 的 `loadLibrary`），**不与 Node ABI 耦合**（没有 node-gyp、
不需要按 Node 大版本出多份产物）。所以 swc/esbuild 那套"按 `os`/`cpu` 自动选子包"的形态
可以照搬且成本更低——每个子包的 `package.json` 只写 `os`/`cpu`（musl 再加 `libc`）+ 一个
`.dll`/`.so`/`.dylib`，npm 在不匹配的平台**根本不下载**它。

- 首发矩阵（与 `release-pypi.yml` 的 5 平台对齐）：`@geektls/win32-x64-msvc`、
  `@geektls/darwin-x64`、`@geektls/darwin-arm64`、`@geektls/linux-x64-gnu`、
  `@geektls/linux-arm64-gnu`；musl（`linux-x64-musl`）等 Alpine 有需求再加，
  加一档就要在发布流水线里多一个构建目标（musl 的 `.so` 不能在 glibc 机器上产）。
- 主包 `geektls` 只含 `index.js`/`index.d.ts`/LICENSE(S) + `optionalDependencies` 指向
  上述 scoped 包（全部 `os`/`cpu` 限定 ⇒ 装不上也不会失败，这是 optional 的语义）。
- **代价**：动态库不再"就在包根"，所以加载搜索序要加一档（`@geektls/<平台>` 子包的
  `require.resolve`）——现有 `candidatePaths()` 只有 env→包内→仓库 build/→系统路径，
  改约 10 行，且 `GEEDTLS_LIB` 逃生通道原样保留。实现时同步改
  `bindings/nodejs/package.json` 的 `files`（现在写着 `*.dll/*.so/*.dylib`，是 ③ 的形态）。
- 不选 ②：`postinstall` 下载脚本被企业代理与 `--ignore-scripts` 生态抵制，且引入
  "安装期打网络"的供应链观感问题。
- 不选 ③：单包塞三平台体积 ×3（Windows 侧一个 `.dll` 就近 24MB，未 strip 更大），
  且多数用户只用一个平台——这也是 Python 侧走 per-platform wheel 的同一条理由。
- 与 A1 的关系：本决定只影响 `release` workflow 的**产物布局**，不影响 `ci.yml`；
  真正的发布实现排在 parity 计划 G1（发 npm）里，与账号、`LICENSES.md` 拷贝同批。

## 4. 排期（把本文件并入 parity 计划阶段 0 之前）

| 顺序 | 项 | 工作量 | 备注 |
|---|---|---|---|
| 0 | A15 决策（npm 分发形态） | 0.5 天 | 只决策，不实现 ✅ 2026-09-30（定为 ①：主包 + `optionalDependencies` 平台子包，5 平台矩阵对齐 `release-pypi.yml`；未动 `bindings/nodejs`，实现随 parity G1） |
| 0 | **A1 建仓 + 首次提交 + tag + CI 绿** | 0.5 天 | **一切的前置** — 等用户授权，未动 git 状态 |
| 0 | **A3 oracle/nightly CI** | 1–2 天 | 让"已实测"变成可复现 ✅ 2026-09-30（`oracle-nightly.yml` 4 个实测 job 落地；新增 `GEEKTLS_ORACLE_PRESETS`/`GEEKTLS_ORACLE_ASSERT` 两个开关；本机无 remote/cron ⇒ "连续 7 天绿 + 自动 issue"判据未满足） |
| 0 | A5 第 1 步（`verify` 非 bool 报错） | 0.5 天 | bug 修复，不引入新行为 ✅ 2026-09-29 |
| 1 | A2 `version.UTLS` 落值 + 断言 | 0.5 天 | ✅（`core/version.UTLSVersion` 走 build info） |
| 1 | **A6 读超时 + cancel** | 2–3 天 | ABI 只增不改 ✅ 2026-09-29（未加 cancel 入口，`response_close` 已是取消；另加 `gtls_error_of`） |
| 1 | A7 WS 扩展头（先 lite，再评估 full） | 1 天 / 3–4 天 | ✅ 2026-09-29（直接做 full：RFC 7692 帧层 + 严格协商 + RSV 规则；offer 仍默认不发，改由 `compress` 开关请求，理由是无 WS 握手的 E1 证据；该头位置修正为 key 之后；不依赖 G5，测试自起 `tls.Listen`；构件未重建 ⇒ 绑定层行为暂只有引擎级验证） |
| 1 | A11 schema 两处表达力 | 2 天 | 直接服务"逐字段可控"卖点 ✅ 2026-09-29（未加 `window_update_skip`，改把 `window_update` 做成 `*uint32` 三态；仍需 vendor fork；另修 0 窗口卡死） |
| 2 | A4 mTLS + CA bundle | 3 天 | 与 A5 第 2 步同批 ✅ 2026-09-29（ABI 签名未动，只加 JSON 字段） |
| 2 | A8 代理补全 | 3–4 天 | ✅ 2026-09-29（socks4/4a 手写、socks5 本地解析真正生效、env+NO_PROXY、有代理即禁 H3；顺带补握手 deadline 与池键同源） |
| 2 | A9 DNS 控制（`resolve` / `local_address`） | 2 天 | ✅ 2026-09-29（`resolve`/`local_address`/`ip_version` 只加 JSON 键，ABI 未动；钉位有 JA4 全等断言；按"谁做解析"分档生效，远程解析那几档不参与；netstack 靠它才可用；H3 侧明确拒绝；顺带给 Python/Node 加会话选项白名单） |
| 3 | A12 新鲜度 workflow + A13 整族补齐 + A14 文档清理 | 滚动 | 与 SC-1~SC-3 并行；A12 ✅ 2026-09-30（含 firefox 157 落后实测）；A14 ✅ 2026-09-30（10 类口径漂移已清，含 nodejs `npm test` 脚本缺陷修复）；A13 前半 ✅ 2026-09-30（`-source` 参数化 + `TestE3SourceTraceable` 正向断言），后半（整族 19 条）阻塞改判：缺的是上游源码文件，不是解析器 |
| 3 | A10 0-RTT / early data | — | ✅ 2026-09-30 结案为"协议侧不做、声明侧可控"（`core/tls/early_data_test.go` 实测 JA4 `t13d1517h2`→`t13d1518h2`；只带扩展 42 的 CH 必被标准服务端拒绝 ⇒ 不能做成会话开关） |

**与既有门禁的衔接**：A4/A6/A7/A11 全部会动 FFI 或 profile schema ⇒ 必须守
`docs/CONTRACT-FREEZE.md` 的"ABI 签名只增不改"+ **364 预设指纹输出逐比特不变**；
A7/A11 会改变**发出字节**（新增请求头 / 新增或去掉一帧），因此需要
①新增预设或在 preset 内显式声明，②`geektls.h`/ctypes/koffi/`index.d.ts` 四处同步，
③L2 nginx 采集端重跑一遍确认 JA3/JA4/Akamai 四段未受影响。

**明确不做（本文件新增）**：在 `core/` 里 import `golang.org/x/net/http2`（上游编码器"一切皆可入动表"
与三档实测族策略都不同，会静默毁掉 T-HPACK 的线上断言）；密码学/压缩原语自写（roadmap §0 已划界）。
