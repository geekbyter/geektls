# 更新日志

本项目遵循语义化版本（版本号规则与"四处单一事实源"见 [docs/versioning.md](docs/versioning.md)）。
更早的发布过程记录见 [docs/plans/2026-09-28-pypi-release-plan.md](docs/plans/2026-09-28-pypi-release-plan.md) §8.5/§8.6。

## 0.1.6（2026-09-30）

### 新增

- **明文 `http://` 与 `ws://`（G5）**：引擎不再只认 https/wss。明文档只做 TCP——
  不握手、不发 ClientHello，`SelfCheck` 恒为零值、`UsedProtocol` 恒为 `http/1.1`
  （h2c 不在承诺面内）；拨号决策抽成 `planDial`，TLS 档与明文档共用同一份
  代理 / 地址控制 / TCP 指纹（setsockopt）决策，避免两条路径行为分叉。
  - scheme 相关的三处硬编码一并修正：缺省端口按 scheme（https 443 / http 80）、
    连接池键含 scheme（明文与 TLS 连接绝不复用）、`NO_PROXY` 匹配用同一套缺省端口。
  - 代理环境变量改为**按目标 scheme 取**：https/wss 读 `HTTPS_PROXY`，http/ws 读
    `HTTP_PROXY`，都没命中再退 `ALL_PROXY`，**不跨 scheme 取**（curl/requests 同语义，
    "用 http_proxy 代理 https" 仍是拒绝的误配面）。明文经 HTTP 代理走 CONNECT 隧道。
  - `ws://` 与 `wss://` 共用同一套帧实现（掩码/分片/控制帧/permessage-deflate），
    差别只在拨号那一步；明文 ws 没有 ALPN 收窄这一步。
  - `force_http3` 与 `http://` 互斥，直接报错而不是静默换路径。
  - 测试：`core/engine/plaintext_test.go`（基本请求/零值 selfcheck/cookie/连接复用/
    重定向/流式上传/明文 WS/代理环境变量分 scheme，7 条）+ `tests/e2e/python/test_requests_parity.py`。
- **命令行入口 `geektls`（G6）**：`core/cmd/geektls`（`make cli` 构建），
  子命令 `version` / `presets`（`--json` / `--grade` / `--name`）/ `describe` /
  `check-profile`（预设名 / JA3 / JA4 / JA4R / hex）/ `request`（`--profile|--ja3|--ja4|
  --ja4r|--clienthello-hex`、`-X/-H/-d`、`--timeout/--read-timeout`、`--proxy`、
  `--http3`、`--insecure`、`--resolve/--local-address/--ipv4/--ipv6`、`--redirect-max`、
  `-i`、`--selfcheck`、`--fail`）。
  - 指纹构造走与绑定**同一批入口** + 同一套 `NormalizeForReplay` 自洽归一；
    `--selfcheck` 写 stderr ⇒ stdout 只放正文，可直接管道；
  - 退出码：0 = 传输成功（含 4xx/5xx，curl 口径；`--fail` 让 4xx/5xx 变 1）、
    1 = 配置/传输错误、2 = 用法错误；
  - 测试：`core/cmd/geektls/main_test.go`（五个子命令 + 退出码口径 + 明文请求）。
- **Python 请求语义对齐（G7 及同族缺口）**：
  - **cookie jar**：新增 `Cookies`（MutableMapping：`get`/`set`/`update`/`clear`/`get_dict`/
    `copy`），`Session(cookies=…)` 接受 dict / list[tuple] / `"a=1; b=2"` / `Cookies` / bool；
    `Session.cookies` 每请求渲染成 `Cookie` 头，`Response.cookies` 解析本响应 `Set-Cookie`
    并自动并入会话 jar；请求级 `cookies=` 覆盖会话级。优先级：显式 `Cookie` 头 > 请求级
    > 会话 jar。
  - **`timeout` 支持 `(connect, read)` 元组**（connect → `timeout_ms`，read → `read_timeout_ms`，
    任一项可为 `None`）。
  - **`auth=(user, password)`**（或带 `username`/`user` + `password` 属性的对象）⇒ HTTP Basic；
    自己传了 `Authorization` 头时以调用方为准。
  - **请求级 `allow_redirects` / `max_redirects` / `proxies`**（均覆盖会话级）；
    `proxies` 是 dict 时按**目标 scheme** 每请求选一个（`{"http": …, "https": …}`，`"all"` 兜底）。
  - **`data=list[tuple]` 按 requests 语义走表单编码**（此前会被当成可迭代 body 走 chunked
    上传，等于换个方法发错东西）；生成器/迭代器仍走 chunked 流式上传（行为不变）。
  - `raise_for_status()` 抛 `HTTPError`（`GeekTLSError` 子类，挂 `.response`），
    读超时抛 `Timeout`（同为子类，`code="read_timeout"`），旧 `except GeekTLSError` 照旧可用。
  - asyncio 视图补齐 `header()` / `elapsed` / `cookies` / `http_version` / `iter_content()`，
    `iter_lines` 支持 `decode_unicode`。
  - 测试：`tests/e2e/python/test_requests_parity.py`（10 条，本地明文服务端，零外部依赖）。
- **QUIC 首 datagram 尺寸可控（G3/G6 的尺寸半边）**：`profile.http3.initial_packet_size`
  （1200–1452，0/不设 = 上游默认 1280）经上游 `quic.Config.InitialPacketSize` 生效，
  即"PADDING 填到多少"可配。**不碰 fork、默认路径逐字节不变**（364 条预设无一带该键）；
  越界在建 transport 时报错而不是被上游静默夹到 1452。真实线上验证：
  `tests/e2e/quic_sniff_test.go` 的 `TestQUICInitialPacketSize`（1350→`[1350 1350]`、
  1200→`[1200 1200]`、不设→`[1280 1280]`）。coalesce 阈值与 CRYPTO 分片表仍不可控（= SC-3）。

### 修复

- **`gtls_error_of` 的按对象归因**：此前 handle→error 的写入依赖"本线程最近 lookup 过的
  那个 handle"，worker 线程（Node/koffi 的 `.async`、Python 的 `run_in_executor`）
  直接对着一个 response/upload/ws handle 报错时，主线程查回来是 `{}`。
  现在凡是"错误点上手里已有 handle"的入口都**直接**记到该 handle（请求/建流/WS 握手
  失败记 session，读 body 失败记 response，写/收尾失败记 upload，收发失败记 ws）。
  关闭过的 handle 仍可查（`gtls_request_finish` 失败即回收 upload handle，绑定正是在
  那一刻回头查错）；未知 handle 仍返回 `{}`（**不是** invalid_handle，绑定据此回落线程槽）。
  测试：`core/ffi/errors_test.go`。
- **引擎 Cookie 合并**：显式 `Cookie` 头不再让引擎 jar "整段让位"，改为**按名合并**
  （同名以显式头为准）。让位会静默丢掉"重定向中间跳设置的 cookie"——最终响应里看不到它们，
  绑定层的会话 jar 也就补不上。

### 变更

- `HTTP3Profile.initial_layout` 明确标注为**占位**（不生效）：padding 的可行部分改由
  `initial_packet_size` 表达，coalesce/分片表归入 SC-3；结构体保留以便既有 profile 仍能解析。
- 版本源四处同步为 `0.1.6`（`core/version/version.go`、`bindings/python/pyproject.toml`、
  `bindings/nodejs/package.json`、`bindings/python/geektls/__init__.py`）。

### 文档

- README：功能矩阵补明文/CLI/请求语义对齐三行；`Session`/`Response`/WebSocket/Node 表按实现
  校正（WS `send`/`recv` 签名、`json()` 语义、`iter_content` 参数名、Node 导出清单含 `errorOf`）；
  新增「命令行（`geektls` CLI）」一节；已知边界补明文三条与 QUIC Initial 的现状。
- `docs/03-profile-format.md`（`initial_packet_size`）、`docs/07-capability-gaps.md`（G6 部分关闭）、
  `docs/p4-h3-capability.md`（Initial 布局改为"尺寸可控、布局仍不可控"）、
  `docs/plans/2026-09-29-parity-and-improvement-plan.md`（G5/G6/G7 状态与落地说明）、
  `core/ffi/geektls.h`（`request_json` 新键 `redirect_max`、url 支持明文、错误归因语义）。

### 说明

- **仍未做（不在本次范围）**：npm 与 Go module 发布、musllinux / Windows ARM64 wheel、
  macOS 真机运行期验证、Safari 侧证据（E1）、SC-1/SC-2/SC-3 内化、pcap 导入工具
  （`import-pcap`）、MCP server。

### 先前内容（0.1.6 之前的未发布改动）

- **body 读取超时（`read_timeout` / `read_timeout_ms`）**：超时从此分两段——
  `timeout_ms` 管"dial+TLS+响应头"，`read_timeout_ms` 管**每次读 body** 的空闲
  上限（会话级设默认，请求级覆盖；0/省略 = 不限，未设时行为与旧版逐字节一致）。
  - 触发时 `gtls_response_read` 返回 -1、错误 `code="read_timeout"`，调用线程
    毫秒级返回（不再被挂死的服务端钉在 read 上），底层连接当场作废、本次 body
    之后只重复同一错误；连接池与会话不受拖累。
  - 取消走 `abortableBody`（`h1Body.abort` / `connClosingReader.abort`）而不是
    `Close`：stdlib 的 HTTP/1.1 chunked body `Close()` 为了复用连接会先排空剩余
    字节，慢服务端能把"超时本身"挂住 30s（实测）。超时包装层必须在解压层之前
    包住协议层 body，才认得出这个 abort 入口。
  - 测试：`core/engine/timeout_test.go`（h1/h2 自建挂死服务端，断言亚秒返回 +
    服务端 handler 收到取消 + 非超时时不误报）、`h3_test.go`（`TestReadTimeoutH3`，
    QUIC 内层同上）、`tests/e2e/python/test_engine.py::test_a6_read_timeout`、
    `tests/e2e/node/engine.test.js` 的 a6 用例（三语言同判据；旧构建动态库自动 skip）。
- **C ABI 追加 `gtls_error_of(handle)`**：错误槽原本是线程局部的
  （`gtls_last_error`），而把阻塞调用放到 worker 线程执行的绑定（Node/koffi
  `.async`）在回调里查的是主线程的空槽——于是所有 async 路径的失败都退化成
  无名错误。新入口按对象取"最近一次失败"，与线程无关（只读不清槽，handle
  关闭即回收）。Node 绑定的 request/read/upload/websocket 错误回收全部改走它，
  Python `ctypes` 声明同步补齐（其自身错误检查同线程，无需改）。
- **自持信任库 + mTLS（requests 的 `verify=<path>` / `cert=(crt, key)`）**：
  会话选项新增 `ca_bundle` / `client_cert` / `client_key`（JSON 字段追加，
  C ABI 签名不变，四处同步只改 geektls.h 注释）。
  - `ca_bundle` 接受内联 PEM、证书文件、或含 `.pem/.crt/.cer` 的目录
    （requests `capath` 语义）；**替换**系统根证书池而非叠加。
  - `client_cert` 可为"证书+私钥同文件"的 PEM；`client_key` 省略即走该形态。
    带口令的加密私钥不支持（明确报错）。
  - TCP（uTLS Config）与 QUIC/H3 内层握手共用同一份证书材料
    （`core/h3.NewTransport` 改收 `TLSSettings{InsecureSkipVerify, RootCAs, Certificates}`，
    含 bogdanfinn/utls 与 refraction/utls 两套 `Certificate` 类型的映射）。
  - 配置错误在 `gtls_session_new` 阶段即失败（`code=invalid_config`），
    不会退化成"用系统根继续"。测试：`core/engine/certs_test.go`（离线自建
    PKI，std `crypto/tls` 服务端 `RequireAndVerifyClientCert` 做判据，覆盖
    h1/h2 两条路径与内联/文件/目录三种取值）。
  - 绑定层：Python `Session(verify=…, cert=…, cert_key=…)`、
    Node `new Session({verify, caBundle, cert, certKey})`（`cert` 支持路径 /
    `[证书, 私钥]` / `{cert, key}`）、Go `Options{CABundle, ClientCert, ClientKey}`。
- **`verify` / `cert` 不再可能被静默丢弃**：非 `bool` 且非路径/PEM 的取值立即
  报错（Python `ValueError` / Node `TypeError`）；`cert` 只在 `Session(...)` 给，
  传到 `request()` 一律报错而不是当作没看见（Node 侧此前会静默忽略）。
- **TCP 指纹做穿（P6 收官）**：`profile.tcp` 新增 `df` 与 `mode` 字段。
  - **setsockopt 档增强**（三平台）：Linux window 夹击法（`SO_RCVBUF=win×4` +
    `TCP_WINDOW_CLAMP=win`，超内核 rmem_max 告警不中止）；DF 位
    （Linux `IP_MTU_DISCOVER=DO` / macOS `IP_DONTFRAG` / Windows
    `IP_DONTFRAGMENT`，best-effort）；双栈 TTL（`IP_TTL` + `IPV6_UNICAST_HOPS`
    同设）。WSL 读回断言全过（clamp=设定值、DF=2、hops=42）。
  - **netstack 档**（Linux root，`mode:"netstack"`）：gVisor 用户态 TCP 栈挂
    TUN 设备，SYN 的 TTL/DF/MSS/window/wscale 全可控，产出 `net.Conn` 直接交
    uTLS 握手（指纹链路零改动）。**P6-T3 结案**：打 WSL nginx 采集端，
    ja4tcp 五分量与设定逐项 MATCH（`tests/e2e/nginx-l2/verify_p6t3.py`）。
    已知边界（如实记录，docs/tcp-platform-matrix.md）：选项顺序固定 Linux 族
    （gVisor 硬编码）、TS 恒开、IP ID/TSval 不可控、仅 IPv4 字面量目标、
    与代理互斥、非 Linux 报 linux-only 结构化错误。
- **WebSocket（wss://，RFC 6455）**：握手走 geektls 自己的拨号 + TLS 指纹链路
  （同 profile 的 ClientHello，ALPN 收窄到 http/1.1——Upgrade 在 h2 上无效；
  detail 副本收窄 ALPN 扩展内容，不只改本地偏好）。Upgrade 请求头序默认对齐
  真 Chrome（host → connection → upgrade → origin → 身份头 →
  sec-websocket-version → sec-websocket-key），`profile.http1.header_order`
  非空时整体再过排序器（可自定义）。帧层自实现（stdlib，无新依赖）：
  text/binary/ping/pong/close、客户端 masking（RFC 强制）、分片重组、
  控制帧 125 字节限制、UTF-8 宽松透传、ping 自动回 pong。
  - ABI 追加（只增不改）：`gtls_ws_connect` / `gtls_ws_send` / `gtls_ws_recv`
    （opcode 经 out 参数返回）/ `gtls_ws_close`；geektls.h / ctypes / koffi /
    index.d.ts 四处同步。
  - Python `session.websocket(url)` → `ws.send()/recv(timeout)/close()`；
    Node `await session.websocket(url)` 同款；拉模型，不做回调式。
  - H2 上的 WS（RFC 8441）不做（Chrome 实际仍以 H1 Upgrade 为主，
    capability-matrix `ws.rfc8441_h2` 登记）。
- **Python asyncio API**：`geektls.asyncio.AsyncSession`——方法签名镜像
  `Session`（含 `websocket()`），内部 `asyncio.to_thread` 包同步调用。
  **诚实标注：线程池异步，非原生异步**；async generator 包流式 `iter_bytes`/
  `iter_lines`；高并发压测请用多线程 + 同步 Session（docstring 有性能语义）。
- **响应透明解压（T-DECOMP，对齐 curl_cffi/libcurl/requests）**：引擎按响应
  `Content-Encoding` 自动解压 body——gzip / deflate（zlib 头 + raw flate 容错，
  curl 同语义）/ br / zstd 四种全支持；多重编码链（如 `gzip, br`）按声明顺序
  逆序解开。全链路懒初始化、流式生效：`gtls_response_read` 读出的就是解压后字节，
  `r.text` / `r.json()` / `iter_*` 均基于解压结果（charset 探测在解压之后）。
  - 开关：`auto_decompress` 默认开，会话级与请求级可关（请求级覆盖会话级）。
  - headers 保留线上原值（`Content-Encoding`/`Content-Length` 不篡改，与 requests
    一致）；response info 新增 `content_encoding` / `decoded` / `warnings` 三字段，
    Python（`r.content_encoding` / `r.decoded` / `r.warnings`）与 Node 同名透出。
  - 未知编码值原样透传不报错，记 warning（容忍非标服务器）。
- **echo-server 压缩端点**：`/gzip` `/deflate` `/deflate-raw`（无 zlib 头的原始
  flate）`/br` `/zstd` `/multi`（双重编码）`/x-enc`（未知编码）。
- **模块级快捷 API（requests 风格）**：Python `geektls.get/head/post/put/patch/delete/options/request`
  与 Node `geektls.get/head/post/put/patch/del/options/request`，走**进程级共享默认会话**
  （`default_session()` / `defaultSession()` 首次调用可配置，之后只读）；对齐 requests /
  curl_cffi / CycleTLS 的顶层用法。附带守门测试（pytest / node:test）。
- **生态对比复核（docs/10 + README）**：逐仓拉取 31 个同类项目 README 原文核对能力声明；
  剔除 `akamai/uls`（实为 Akamai 日志流 SIEM 工具，非指纹库）；补回 `cyCronet`
  （[2833844911/cyCronet](https://github.com/2833844911/cyCronet)，Python + Chromium Cronet
  真栈）——此前按名字猜 slug 查不到就断言"仓库不存在"，是错的：**查不到 ≠ 不存在**；
  修正 httpcloak 的 TCP 声明、specter 的 RFC 8441 说法、impersonator 的 Initial 布局单元格；
  README 对比表增加 WebSocket / 四层 TCP 现状与自主化进度（SC-1~3 未开始）。
- **`version()["utls"]` 接线（指纹栈溯源）**：该字段此前是空常量（声明了但从未接线，文档还写成
  "既定状态"）。现由二进制 build info 推导（`core/version.UTLSVersion`），报告实际链接的
  `refraction-networking/utls` / `bogdanfinn/utls` / `fhttp` / `quic-go-utls` 版本，vendor fork
  显示为 `v0.6.9 => ./third_party/fhttp`；**跟随 go.mod 自动更新**（不会像手写常量那样漂移），
  取不到 build info 时为空串（调用方须容忍）。附守门测试
  `core/engine/version_stack_test.go`。ABI 不变——只是把已有字段填上。
- **H2 连接级 `window_update` 三态 + `first_stream_id`（A11）**：
  - `http2.window_update` 由 `uint32` 改为指针（`*uint32`），因为值形态的 0 在
    `omitempty` 下与"未设置"不可分——预设 JSON 根本写不出"不发"这一档。三态：
    **省略** = 引擎补 Chrome 默认 15663105；**0** = **不发**这帧（RFC 7540 §6.9.1
    禁止增量为 0 的连接级 WINDOW_UPDATE，故捕获到的 0 只能意味着帧缺席——
    Safari 9.1.3 实测形态）；**N** = 发 N。生效路径 `core/h2` → fork
    `Transport.ConnectionFlow`。
  - `http2.first_stream_id`（正奇数，省略 = 1）：这条连接上第一个请求的流号。
    真 Firefox 用 3，此前预设里带上也无效（导入器判"流号未建模"）。生效路径
    fork `Transport.InitialStreamID`（在 PRIORITY 帧簿记**之后**覆盖，避免被冲掉）；
    `firefox_145_windows` 补齐，`gen-profiles` 新增 `h2_first_stream_id` 谱系字段。
  - 断言：`tests/e2e/h2_capture_test.go::TestH2FrameCaptureTriState` 在**原始帧层**
    验四种组合（连接级 WINDOW_UPDATE 有无 + 增量 + 首请求流号 + SETTINGS 全序），
    `h2_oracle_test.go` / `fp_oracle_test.go` 的期望键改走 `flowOnWire`（nil → 15663105），
    Akamai 四段第二格从此与实际线上形态一致。
  - 导入器（`tests/e2e/cmd/import-tlsconfig`）：`connection_flow: null`（第三方
    未采集）不再被误读为 0、进而编造成"对方说不发"——改用 `json.RawMessage`
    分三态，null/缺失 = 未指定（沿用引擎默认）并登记告警。**此前因此被跳过的
    Safari 9.1.3 现已入库**（`safari_9_1_3_macos`，E3），预设 363 → 364。
- **代理形态补齐（A8）**：`proxy` 从"HTTP CONNECT + SOCKS5(+h)"扩到六种 scheme，
  并接上标准环境变量。
  - **`socks4` / `socks4a`**（`core/engine/proxy.go`，手写握手）：x/net 的
    `proxy` 包根本没有 SOCKS4，故自己发 `0x04/0x01` 请求、按 4A 形态用
    DSTIP=`0.0.0.1` + HOST 字段把域名交给代理、读 8 字节回包并把拒绝码翻成
    可读错误。老协议的两条硬限制如实暴露：**只有 IPv4 目标**（IPv6 直接报错，
    不悄悄丢包）、鉴位只有 NUL 结尾的 user id（**没有口令**，给了口令会报错）。
  - **`socks5` 与 `socks5h` 的差别第一次真实存在**：此前两条走同一代码，
    域名一律原样交给代理（即恒为 `socks5h`）。现在 `socks5` 在本地
    `LookupIPAddr`（受 deadline 约束、优先 IPv4）后交代理解 IP；解析不出来
    **直接报错**，不静默降级成 `socks5h`（那会把 DNS 泄漏位置换掉，用户不会
    期望这种"自动改道"）。
  - **环境变量**：不给 `proxy` 时读 `HTTPS_PROXY` → `ALL_PROXY`（大小写都认），
    `NO_PROXY` 豁免；新增会话选项 `proxy_from_env`（Python `trust_env` /
    Node `proxyFromEnv`|`trustEnv` / Go `Options.ProxyFromEnv`）可整条关掉。
    `NO_PROXY` 只做字面量/`*`/端口限定/CIDR 匹配，**不对目标做 DNS**（Go 的
    `ProxyFromEnvironment` 会解析，解析失败即"直连"——域名写错时代理被静默
    跳过、指纹漏发；我们同一 URL 每次走同一条路），并按 Chrome/Go 规则对回环
    目标豁免**派生**代理（显式 `proxy` 对回环仍生效，否则本地测试无法经代理）。
  - **代理与 H3 的语义写死**：有代理时 racing / Alt-Svc 升级一律不参与
    （QUIC 过代理需 CONNECT-UDP/RFC 9298，未实现），`force_http3` + 代理在
    拨号前报 invalid，而不是悄悄直发。此前 H3 路径完全不看代理。
  - 池键与拨号**同源**：`poolKey` 与 `dial` 共用 `proxySpecFor`，避免"键里说
    直连、实际连了代理"这类复用错连接；`parseProxySpec` 在 `NewSession` 阶段
    就拒绝非法 scheme。CONNECT / SOCKS4 握手补上 deadline（此前只在 dial 上有）。
  - 测试：`core/engine/proxy_test.go` + `proxytest_test.go`（自建 SOCKS4/4A/5 与
    CONNECT 假代理，逐字段核对线上握手字节：ATYP/DSTIP/DSTPORT/HOST/USERID、
    `Proxy-Authorization`），含 `NO_PROXY` 17 例、优先级四例、H3 拒绝。
    绑定层 `tests/e2e/python/test_engine.py::test_a8_*` 与
    `tests/e2e/node/engine.test.js` 的 a8 用例同判据（用 `force_http3` + 代理的
    冲突错误当探针，不需要真代理也不打网络；旧构建动态库自动 skip）。
- **目标地址控制（A9，无 DNS 也能定向）**：会话选项新增 `resolve` /
  `local_address` / `ip_version`（仍是 JSON 字段追加，C ABI 签名不变）。
  - `resolve`（curl `--resolve`）：`{"host": "IP"}` 或 `{"host:port": "IP"}`，
    键精确匹配、不做通配/子域，值必须是 IP 字面量。**只改"连到哪"**：SNI、
    `Host`、伪头、ClientHello 一律沿用 URL 里的原域名，钉位前后 JA3/JA4 全等
    （测试以此为判据，且参照请求用域名形态——直连 IP 字面量时线上合法地省略
    SNI，JA4 的 SNI 位本就不同）。
  - `local_address`（curl `--interface` 的 IP 形态 / httpx `local_address`）：
    只收 IP 字面量（网卡名需 `SO_BINDTODEVICE`，跨平台不对齐，明确不支持）。
  - `ip_version`（curl `-4`/`-6`）：`"4"`/`"6"`（`4`/`v4`/`ipv4`/`any`/空同义），
    收窄解析与拨号族；目标族不符或解析结果全被过滤时明确报错，不"挑一个能连的"。
  - 生效范围按**谁做解析**分档：直连 / `tcp.mode=netstack` / `socks5` / `socks4`
    由引擎本地解析 ⇒ 三项生效；`socks5h` / `socks4a` / CONNECT 隧道把域名交给
    代理 ⇒ `resolve`/`ip_version` 不参与（那几档生效等于绕过代理语义）。
    `local_address` 绑的是到代理那一条 socket。netstack 反而靠 `resolve` 才可用
    （它要求 IPv4 字面量目标，现在域名照旧上线）；其源地址固定为 TUN 侧拓扑，
    故 `local_address` 在它上面**报错**而不是忽略。
  - 冲突在 `gtls_session_new` 阶段即 `invalid_config`：非 IP 字面量、写成网卡名、
    `ip_version` 与源地址/钉位不同族、归一后重复键。`force_http3` 与三者同给也
    报错（QUIC 拨号未接地址控制，沿用 A8"宁可报错也不偷换路径"的口径）。
  - 绑定层：Python `Session(resolve=, local_address=, ip_version=)`、
    Node `new Session({resolve, localAddress, ipVersion})`、Go
    `Options{Resolve, LocalAddress, IPVersion}`。
  - **顺带堵掉"未知会话选项静默失效"**：core 的两处 JSON 解码都不严格
    （`gtls_client_new` 只查指纹入参那六个键，`SessionOptions` 忽略未知字段），
    所以 `local_addr`、`insecure_skip_verfy` 这类拼错会无声消失——而这几项决定
    校验开不开、超时走不走、连接钉到哪。绑定层加白名单：Python
    `_SESSION_LEVEL_FIELDS`/`_REQUEST_LEVEL_FIELDS`、Node
    `CLIENT_CONFIG_KEYS`/`SESSION_OPTION_KEYS`（引擎原名照常透传，名单外的键
    立即 `ValueError`/`TypeError`）。与 A5-1 同口径。
  - 测试：`core/engine/target_test.go`（归一/优先级/族收窄/`usesRemoteDNS`/
    钉位保留 SNI+Host+JA4 全等/五种代理形态线上目标字节/绑 TEST-NET-1 必失败/
    冲突与 H3 拒绝），`bindings/golang` 透传断言，Python/Node 各一条 a9 用例
    （能力探针 `ip_version="7"` 必须报错；本机动态库为 A9 之前构建 ⇒ skip 态）。
- **WebSocket permessage-deflate（A7，RFC 7692）**：帧层补齐（`core/engine/wsdeflate.go`），
  wss 握手从此可以真的谈下这个扩展，而不是"头发了却看不懂载荷"。
  - 收发对调用方仍是**明文**：RSV1 只在消息首帧、控制帧永不压、分片消息整条重组后再解，
    `00 00 ff ff` 空块发送侧剥、接收侧补。
  - context takeover 用 stdlib `flate` 的 `Reset(r, dict)` 入口模拟——该调用会**清空**历史，
    所以把最近 ≤32 KiB 已解明文当预置字典喂回去（RFC 1951 的距离上限正好 32 KiB）。
  - 协商严格按 RFC 7692 §7.1/§9，失败优先于"看起来能用"：对端回声我方没请求的参数、
    协商不认识的扩展、把 `client_max_window_bits` 限到 <15 bit（stdlib 压缩窗固定 15 bit，
    不可配置 ⇒ 绝不发不合规的流）一律握手报错；没协商却收到 RSV1、以及 RSV2/RSV3、
    带 RSV1 的控制帧，读帧时报错而不是把压缩字节当文本返回。
  - **offer 默认仍不发**：`WSRequest.compress` / Python `websocket(..., compress=True)` /
    Node `websocket(url, {compress:true})` 才补发裸 `permessage-deflate`（不带参数——
    无逐浏览器 WS 握手的字节级证据，不承诺 Chrome 的 `client_max_window_bits`）；
    要精确控制参数就把那个头写进 `headers`。该头固定排在 `sec-websocket-key` 之后
    （Chrome 形态；此前若由调用方手写，会被 `applyIdentity` 挪到 key 前面），
    `profile.http1.header_order` 照旧可整体覆盖。
  - ABI 只增：`gtls_ws_connect` 的 url_json 多一个 `compress` 键，签名不变；
    代价是旧构件静默忽略它且 `gtls_version()` 查不出来，口径写进 docs/02。
  - **Go 绑定从此有 WebSocket**（此前 Python/Node 有、Go 绑定没有）：
    `bindings/golang` 新增 `Session.DialWS(*WSRequest)` 与 `WSRequest`/`WSConn`
    类型别名（直接 re-export engine 的形状，避免第二份定义漂移）、
    opcode 常量，并补上缺失的 `Session.Close()`——`eng` 字段是非导出的，
    没有它长期运行的进程无法释放连接池。用例 `TestSessionDialWS` 手写了一个
    最小 wss echo 服务端（stdlib 无 WS 服务端），钉住"握手走本会话指纹链路 /
    `Compress=true` 的 offer 真的上线 / 默认不发该头 / Send-Recv-Close 可用"。
  - 测试：`core/engine/ws_deflate_test.go` 的对端是**独立写的 stdlib flate 实现**
    （真 TLS 监听，不调用 core 的压缩层），双向验证——收方向覆盖 takeover /
    两侧 no_context_takeover / 分片+穿插 ping / 裸参数回声；发方向把我方发出的压缩块
    原样拼接后交给普通 `flate.NewReader` 整体解开，证明是合法连续 DEFLATE 流而非
    私有格式；另有 7 条握手拒绝与 4 条违规帧用例。
- **外部 oracle 可选择性跑 + 可断言**（让"实测 MATCH"变成 CI 里可复现的东西）：
  `-tags external` 的两个对拍用例（JA3/JA4 与 Akamai H2）原本固定遍历全部 364 条
  预设且**只打印不断言**（V-3 口径），既无法进 CI，也不会在回归时报红。
  - 新增 `GEEKTLS_ORACLE_PRESETS`：逗号分隔的 glob 子集（未设 = 全量），
    名单里任一模式**一个都没匹配到就失败**——拼错预设名会让"oracle 全绿"
    变成"什么都没测"。
  - 新增 `GEEKTLS_ORACLE_ASSERT=1`：JA4/JA3/Akamai 不一致即 `t.Errorf`。
    默认仍关闭（对第三方服务的断言不该把网络抖动变成主干红），nightly 显式打开。
- **nightly 实测 CI**：新增 `.github/workflows/oracle-nightly.yml`（定时 + 手动
  dispatch，dispatch 可传本轮 oracle 子集）。4 个实测 job：`oracle`（对拍断言档 +
  ECH + `GEEKTLS_LIVE=1` 会话恢复真机，并用 `set -euo pipefail` + `grep resumed=true`
  把"恢复真的发生了"钉成硬门禁）、`crosslang`（Linux/Windows 双平台 `make build` →
  Go/Python/Node 三语言一致性 + 两套绑定 e2e）、`h3-browser-e1`、`nginx-l2`
  （两者按 `vars` 是否有值自动跳过，不硬编码仓库私有端点）。失败时只在
  `schedule` 触发下汇总进一个复用的 open issue。
- **预设新鲜度守门**：新增 `scripts/preset_freshness.py`（纯标准库）与
  `.github/workflows/preset-freshness.yml`（每周 + 手动）。按家族比对内置预设的
  最高主版本与官方渠道版本，落后 exit 1、取不到 feed exit 2（**"取不到"不等于
  "没落后"**，不把它伪装成绿）。未参与比对的家族会在 `--json` 的
  `unscored_families` 里如实列出。首轮即测出 `firefox` 内置 156 已落后官方 157。
- **early_data（扩展 42）声明侧可用性的固定用例**：`core/tls/early_data_test.go`
  用真 CH 编译 + 与标准 `crypto/tls` 服务端握手，钉住三件事——只带 42 的 CH 会被
  JA4 认出来（`t13d1517h2` → `t13d1518h2`：扩展计数 +1、ALPN 码不变、密码套件哈希
  不变、扩展哈希变），`FromClientHelloHex` 能无损读回该扩展，且**只声明不携带
  PSK 的 early_data 必被服务端拒绝**（`unexpected early data` / `unsupported
  extension`）。这条边界决定了 0-RTT 不能设计成"会话级开关"（见 A10 结案）。
- **第三方预设的来源可追溯（provenance 正向断言）**：`import-tlsconfig` 原本把
  provenance 的 `source` 前缀写死成 `"tls_config-0.0.2/" + 常量名`——换来源忘了改，
  这个字段就**指向一个不含该常量的快照**，而 `source` 正是 E1/E3 分级体系的地基。
  - 新增 `-source` flag（`convert` 改收参数）；默认前缀与被替换掉的写死字面量
    逐字符相同 ⇒ 再次导入产生的 `source` 不变，本次也**没有重写任何预设文件**
    （`-dry` 全量跑通：339 条快照记录、报告与改动前同形）。`-source ""` 直接报错
    退出，不静默回落。
  - 新增 `core/profiles/provenance_test.go::TestE3SourceTraceable`：每条 E3 的
    `<数据集>` 必须在 `profiles/evidence/thirdparty/` 有同名 JSON 快照，`<常量名>`
    必须是该快照某条的 `_const`。实跑 320/320 通过，并带 6 条合成负例（空 / 缺 `/` /
    数据集不存在 / 常量不存在）证明这道门会判红，而不是恒真断言。
  - 未做（如实登记）：上游 Go 源码解析入口。核对 `profiles/evidence/thirdparty/` 的
    两份 dump 后发现 `Mesh*/Nike*/Zalando*/Confirmed*` 只有**引用**、定义文件没入库，
    `Mms*/Cloudscraper` 完全没出现 ⇒ 整族补齐的第一步是抓全上游文件，不是先写解析器
    （`docs/08 §E` 同步改判）。

### 修复

- **fhttp 内置单层解压与引擎解压层双重解压的风险**：vendor fork 新增
  `Transport.SkipResponseDecompress`（只关响应侧、不影响请求侧自动补
  `Accept-Encoding` 的线上形态），core/h2 恒置位——解压语义统一收归引擎
  （多编码链/zstd/warning 才能一致）。H3 路径经查证天然安全（quic 层自动解压
  仅在它自己补发 `Accept-Encoding: gzip` 时触发，且会同时删除响应头里的
  `Content-Encoding`，引擎层据此自然不会重复解）。
- **`window_update: 0` 会让大于 64 KiB 的响应卡死**：fork 里连接级 inflow 的补充量
  原本直接取 `cc.connFlow`，为 0 时"该补窗口"的条件永不成立，对端把初始 65535
  字节用完即停——表现为 body 读到一半永久挂起。"`0` = 初始不发这帧"不等于
  "永不给连接窗口补货"，故补充量在 0 时回落协议默认 `initialWindowSize`
  （与 net/http 一致）。新增预设 `safari_9_1_3_macos` 正是这一档的首个使用者。
- **`npm test` 在 Windows + Node 22 下必失败**：脚本原本是 `node --test ../../tests/e2e/node/`
  （传目录）。该形态只有 Node ≥22 在非 Windows 上能用，Windows 下直接把目录当模块
  加载并报 `Cannot find module …\tests\e2e\node`——于是"CI 覆盖了 Node 绑定"这句
  话从没真实现过。改为显式列出用例文件（`engines.node>=18` 皆可），并在
  `package.json` 的 `comment` 里记下原因，避免有人"顺手改回目录"。

### 文档

- `docs/08-plan-pending-samples.md` 新增 **S12**：Accept-Encoding 连锁检查结论——
  139/363 条预设广告压缩编码（113 条含 zstd，引擎全部可解）；33 条 E3 预设
  （chrome_61~122 / edge_92~122）广告的 zstd 与该版本真机矛盾（zstd 自 Chrome 123
  起才出现在 Accept-Encoding）——数据反映的是采集工具而非真机，保持与来源
  数据集一致暂不修正，待真机采样按流程修。
- `LICENSES.md`：klauspost/compress 随解压层从传递依赖转为直接依赖
  （许可证 Apache-2.0，发布面清单不变）。
- 新增 [docs/11-lowlevel-forgery.md](docs/11-lowlevel-forgery.md)（TLS 以下的指纹伪造：分层
  可行性、一致性红线、参考仓库）与 [docs/12-pcap-import.md](docs/12-pcap-import.md)
  （pcap 抓包 → 装载：分层可见性矩阵、五个坑、`import-pcap` 设计与端到端实测——
  pcap 里的 CH 装载后重放，JA4/ja3_hash 与采集端三方一致）。
- H2 帧层口径同步：`docs/01-fingerprint-dimensions.md` 维度表把 `window_update`
  标为三态并新增"首请求流号"一行；`docs/03-profile-format.md` §2 补两字段语义；
  `docs/07-capability-gaps.md` 对应两条限制结案（并说明第三方 `null` 按"未指定"
  处理，真机是否需要"不发 WINDOW_UPDATE"档转入 `docs/08` 采样待办）；
  `docs/capability-matrix.yml` 新增 `h2.first_stream_id`、`h2.window_update` 注记，
  counts 改 364；README / bindings/python/README / docs/10 / evidence README 预设计数对齐。
- 文档口径与实测对齐（A14）：`docs/07` 比较表里"HPACK 索引 ✗"修正为四档已落地；
  `docs/08` §E 的 headless-token 待修项改记已修（并说明该守门只在 Linux job 跑）；
  `docs/12` 中"CI 对 pcap 记录自动生效"修正为**必须把记录加进 `ci.yml` 显式的
  `-record` 名单**，否则不会校验；`tests/e2e/nginx-l2/conftest.py` 的开关名笔误
  `GEEDTLS_NGINX_L2` → `GEEKTLS_NGINX_L2`（按原文档操作会永远 skip）；
  README 的绑定用例计数重测核对（Python 20 passed / 7 skipped、Node 18 pass）。
- 0-RTT 结案同步（A10）：`docs/01`（维度 8、17）、`docs/07`（G2b 与判断段）、
  `docs/08`（L1）、`docs/p4-h3-capability.md`、`docs/capability-matrix.yml`
  （`tls.session_resumption_0rtt` → `partial`，`as_of` 改 2026-09-30）统一改为
  **协议侧不做、声明侧可控**，并把"只带扩展 42 的 CH 必被标准服务端拒绝"这条
  实测边界写进文档。
- `docs/maintenance.md`：外部 oracle 周检改写为 nightly 4-job 表 + 手动命令
  （含 echo-server 构建的 `$(go env GOEXE)` 与 `resumed=true` 门禁的理由），
  预设入库流程第 4 步改用 `GEEKTLS_ORACLE_PRESETS=<新预设名>` 跑对拍，
  SLA 段补 A12 新鲜度轮检的判读口径（含 exit 2 = 取不到 feed ≠ 没落后）。
- `docs/plans/2026-09-29-audit-gap-plan.md`：A3/A10/A12/A14 状态与 A15 决策
  （npm 分发定为"主包 + `optionalDependencies` 平台子包"，只决策不实现）登记，
  §4 排期表相应行标注完成与未满足的判据。

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
  `LICENSE`；`bindings/python/pyproject.toml`（`license = "MIT"`，SPDX 表达式）与
  `bindings/nodejs/package.json`（`"license": "MIT"`）同步；`LICENSE` 与 `LICENSES.md`
  随 wheel 分发（依赖的 BSD-3 类"保留声明"要求据此满足）。见 [LICENSES.md](LICENSES.md)。
  注：按 PEP 639，设了 `license` 表达式就**不能**再写 `License ::` classifier
  （新版 setuptools 直接 `InvalidConfigError`，且在 `get_requires_for_build_wheel`
  阶段就炸，与平台无关）。

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
