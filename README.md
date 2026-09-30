# geektls

多语言 TLS/HTTP 全栈指纹伪造库：对 **ClientHello 逐字节可控**，覆盖 TLS（JA3/JA4）、HTTP/2（Akamai 指纹 + HPACK 编码策略）、HTTP/3 + QUIC、TCP 四层指纹，提供 **Python / Node.js / Go** 三种语言的一等 API。

> 当前状态：**P0–P7 完成（一期收工）**。其中 **TLS/H2 已交付并经 E2 外部 oracle 验证**；**H3/QUIC：Chrome 149 H3 已完成 E1 真机采集**（QUIC 内层 JA4 与真机逐字符一致，详见功能矩阵），**Firefox/Safari H3 尚未实测**；**TCP 仅 TTL/MSS 可承诺**（window/window_scale/options 仅 Linux 探测模式，不影响真实连接）。P1-T8（nginx 采集端 L2 终审）**已通过**（7 预设 × 35 断言全绿，tests/e2e/nginx-l2/）；P6-T3（JA4TCP 验收）需真实二层网络，回环无意义仍待。精确现状见 [docs/01-fingerprint-dimensions.md](docs/01-fingerprint-dimensions.md) 与 [docs/capability-matrix.yml](docs/capability-matrix.yml)。

## 目录

- [功能矩阵](#功能矩阵)
- [安装](#安装)
- [快速上手](#快速上手)
- [指纹怎么传：整体与局部](#指纹怎么传整体与局部)
- [Python API 参考](#python-api-参考)
- [Node.js API 参考](#nodejs-api-参考)
- [Go API 参考](#go-api-参考)
- [使用场景](#使用场景)
- [预设体系](#预设体系)
- [自校验](#自校验)
- [性能摘要](#性能摘要docsbenchmarksmd)
- [与同类项目对比](#与同类项目对比)
- [已知边界与不足](#已知边界与不足如实)
- [开发与发布](#开发与发布)
- [文档索引](#文档索引)
- [非目标](#非目标)

## 功能矩阵

| 维度 | 状态 | 验证 |
|---|---|---|
| TLS ClientHello 逐字段（ciphers/扩展序/GREASE/key_share/MLKEM/ALPS/RSL/DC/padding/ECH） | ✅ | tls.peet.ws 实测 7 预设 JA3/JA4 全 MATCH；RFC 9001 Initial 嗅探字节级 |
| 真 ECH（config_list 注入） | ✅ | cloudflare-ech.com 实测 `ECHAccepted=true` |
| 指纹入口：完整 profile / JA3 / JA4 / JA4R / ClientHello-hex + 自算 JA3/JA4 回读 | ✅ | FoxIO 官方向量 + 线上 round-trip；JA4 短哈希走内置预设反查（哈希不可逆） |
| HTTP/2 帧层（SETTINGS 序/WINDOW_UPDATE（三态：默认/指定/不发）/priority/伪头序/首流号） | ✅ | tls.peet.ws Akamai 四段全 MATCH；三态与首流号另有原始帧断言（`TestH2FrameCaptureTriState`：帧有无 + 流号 + SETTINGS 全序） |
| HTTP/3 + QUIC（SETTINGS/伪头序/GREASE 帧/内层 ClientHello 同 profile） | ✅（机制） | Chrome 149 H3 E1 真机采集完成（tests/e2e/e1_h3_test.go，证据 profiles/evidence/browsers/chrome_windows_h3.json）；QUIC 内层 JA4 与真机逐字符相同（钉在 quic_sniff_test.go）；transport params 顺序/非标参数经 T4-1 blob 直通可控；**Initial 布局仍不可控、quic_grease_frames 未验证、Firefox/Safari H3 未实测**（见能力矩阵） |
| HTTP/2 HPACK 编码策略（chrome/firefox/safari/generic 四档，vendor fork fhttp） | ✅ **250/364 预设已带** | 逐字节块表示断言（索引/literal/Huffman/动表复用）；chrome 档有 QUICHE 源码级证据，firefox 档有 Firefox 59 字节级证据，safari 档为保守近似待 E1；工具与无法归族的内嵌浏览器**刻意留空**（见 docs/p2-h2-capability.md §覆盖面） |
| H2/H3 racing + Alt-Svc | ✅ | 本地实测（含负缓存） |
| 连接池（H2 多路复用/H1 keep-alive/H3 共享 transport，并发安全） | ✅ | go test -race 零竞争；echo 侧连接数断言 |
| 流式上传（H1 chunked / H2 DATA，三语言绑定迭代器入参） | ✅ | 线上字节逐字节断言 |
| 响应自动解压（gzip/deflate/br/zstd + 多编码链，流式同步生效） | ✅ | 六路径矩阵 + 跨压缩块边界流式断言 |
| WebSocket（wss / **ws，RFC 6455 + permessage-deflate，握手走指纹链路，自动 masking/ping-pong） | ✅ | 手写 RFC 服务端断言头序/帧/关闭码（wss 与明文 ws 各一组）；独立 stdlib flate 对端断言压缩流 |
| 明文 `http://` / `ws://` | ✅（H1；无 TLS ⇒ selfcheck 恒为零值） | 引擎用例（基本请求/连接复用/重定向/流式上传/明文 WS/代理环境变量）+ pytest 一组；`force_http3` 与明文互斥（明确报错，不静默换路径） |
| 命令行入口 `geektls`（version / presets / describe / check-profile / request） | ✅ | `go test ./cmd/geektls` 五个子命令冒烟 + 退出码口径（0/1/2） |
| Python asyncio（AsyncSession，线程池异步，docstring 如实标注） | ✅ | asyncio 并发 20 请求用例 |
| TCP（TTL/MSS setsockopt 档，按平台分文件：linux/darwin/windows/其它 Unix） | ✅（Windows 无 MSS；BSD 档 TTL+MSS，DF 如实告警） | getsockopt 读回；CI **cross-OS compile gate** 保证每个 GOOS 恰好一份实现 |
| Python 请求语义对齐（cookie jar / timeout 元组 / auth / 重定向开关 / 表单编码） | ✅ | pytest `test_requests_parity.py`（10 条，本地明文服务端，零外部依赖） |
| Python / Node / Go 绑定 | ✅ | pytest 34 passed / 2 skipped、node:test 18、`go test` 全绿；跨语言 JA4 三方全等 |

## 安装

```bash
pip install geektls          # Python（manylinux_2_28 x86_64/aarch64、macOS 11.0+ arm64/x86_64、Windows x64，动态库随 wheel 分发）
npm install geektls          # Node.js（⚠️ 尚未发布到 npm，当前请用仓库内 bindings/nodejs）
go get github.com/geektls/core   # Go（⚠️ 模块尚未推送到公网仓库，当前用本地 replace）
```

已发布到 PyPI 的 wheel（0.1.5 起）覆盖五平台：**manylinux_2_28 x86_64 / aarch64、macosx_11_0 arm64 / x86_64、win_amd64**
（构建矩阵见 [.github/workflows/release-pypi.yml](.github/workflows/release-pypi.yml)；其余平台安装会提示无匹配版本；
**不提供 sdist**——从源码构建需要 Go + C 工具链，本库只发 wheel）。

⚠️ **老版本的平台覆盖（实测 PyPI 索引）**：

| 版本 | 已上传的平台 | 说明 |
|---|---|---|
| 0.1.0 | 仅 `manylinux_2_34_x86_64` | 没有 Windows；Linux 基线是 **glibc 2.34** |
| 0.1.1 – 0.1.3 | `manylinux_2_34_x86_64` + `win_amd64` | 同上 |
| **≥ 0.1.4** | 五平台：`manylinux_2_28` x86_64/aarch64、`macosx_11_0` arm64/x86_64、`win_amd64` | Linux 基线 2.34 → **2.28**（兼容面更大）；**macOS 与 Linux aarch64 从这里才开始提供** |

⇒ macOS、Linux aarch64、或 glibc < 2.34 的系统上 pin 到 0.1.0–0.1.3 会直接
`No matching distribution found`；本库**不发 sdist**，没有源码安装这条退路。

Python 一行自检：

```bash
python -c "import geektls,json;print(json.dumps(geektls.version()));print(len(geektls.list_presets()),'presets')"
# {"abi": 1, "core": "0.1.6", "utls": "refraction-networking/utls v1.8.2; bogdanfinn/utls v1.7.8-barnius; ..."} / 364 presets
```

> `version()["utls"]` 是**指纹栈溯源**：报告动态库里实际链接的 uTLS / fhttp / quic-go-utls
> 版本（由二进制 build info 推导，跟随 `go.mod` 自动更新，不会漂移），vendor fork 会显示成
> `bogdanfinn/fhttp v0.6.9 => ./third_party/fhttp`。出问题时把这一串贴进 issue 即可定位栈版本；
> 极端裁剪的构建可能为空串，调用方需容忍。

## 快速上手

**Python**（`pip install geektls`，动态库随包）：

```python
from geektls import Session

with Session(impersonate="chrome_150") as s:
    r = s.get("https://example.com")
    print(r.status_code, r.ok, r.used_protocol)   # 200 True h2
    print(r.headers["content-type"])             # 大小写不敏感
    print(r.text[:200])                          # 直接当文本用
    print(r.selfcheck["ja4"])                    # 本次握手的 JA4 自算
    for line in r.iter_lines():                  # 需要流式时才用迭代
        ...
```

**Node.js**（`npm install geektls`）：

```js
const { Session } = require('geektls');

const s = new Session({ impersonate: 'chrome_150', timeout: 20 });
const r = await s.get('https://example.com', { params: { q: 1 } });
console.log(r.statusCode, r.ok, r.reason);     // 200 true OK
console.log(r.header('content-type'));         // 大小写不敏感
console.log(await r.text());                   // 直接当文本用
console.log((await r.json()).slideshow);       // 直接当 JSON 用
for await (const chunk of r.iterContent()) { ... }   // 需要流式时才迭代
s.close();
```

**Go**（`import "github.com/geektls/golang"`）：

```go
// 引擎直连（要用到响应便捷方法时走这条；只要 net/http 习惯可用上面的 RoundTripper 形态）
p, _ := profiles.Get("chrome_150")
sess, _ := engine.NewSession(p, engine.SessionOptions{})
defer sess.Close()

resp, _ := sess.Do(&engine.Request{Method: "GET", URL: "https://example.com"})
defer resp.Close()
fmt.Println(resp.StatusCode(), resp.OK(), resp.Reason()) // 200 true OK
fmt.Println(resp.Header("content-type"))                 // 大小写不敏感
text, _ := resp.Text()                                   // charset → utf-8 → gb18030 → latin-1
var v map[string]any
_ = resp.JSON(&v)
```

## 命令行（`geektls` CLI）

不想先写代码就想看效果时：

```bash
make cli                                       # 构建到 build/geektls（Windows 下 build/geektls.exe）
build/geektls version
build/geektls presets --grade self             # 只看自测集；--json 结构化；--name 过滤
build/geektls describe chrome_154_windows | jq .tls.detail.extensions
build/geektls check-profile chrome_133         # 离线自检：预设名 / ja3: / ja4: / ja4r: / hex
build/geektls request https://example.com -i --selfcheck
build/geektls request http://127.0.0.1:8000/ --ja4 t13d1516h2_8daaf6152771_02713d6af862
```

- 指纹构造与绑定**同一批入口**（`profiles.Get` / `FromJA3` / `FromJA4R` / `FromClientHelloHex` /
  `ResolveJA4Profile`），用户自带输入同样过一遍 `NormalizeForReplay` 自洽归一 —— CLI 看到的就是代码里跑的；
- `--selfcheck` 把"本次握手实际发出的 JA3/JA4"打到 **stderr** ⇒ stdout 只放正文，可直接管道或重定向；
- 退出码：`0` = 传输成功（含 4xx/5xx，curl 口径；加 `--fail` 让 4xx/5xx 返回 1）、
  `1` = 配置或传输错误（原因在 stderr）、`2` = 用法错误。

## 指纹怎么传：整体与局部

`Session(...)` 的指纹入参**六选一**（互斥，同时给以靠前的为准，优先级按下列顺序）：

| 入参 | 语义 | 保真度 | 备注 |
|---|---|---|---|
| `impersonate="chrome_150"` | 用内置预设（364 条） | 高（多数有 E1/E2 证据） | 名字是**全名**：`chrome_154_macos`、`chrome_154_windows`、`okhttp_3_12_12`…（没有裸 `chrome_154`） |
| `profile={...}` | 自带**完整**指纹（profile JSON schema） | 完全按你给的来 | 也接受 **JSON 文本**（`profile='{"name":...}'`），免去 `json.loads` |
| `ja3="771,4865-...-23,4588-29-23-24,0"` | 只给 JA3 | 有损：扩展只有 type，负载全缺 | 缺失部分按引擎默认补齐，`check_profile` 会逐条列出 `warnings` |
| `ja4r="t13d1516h2_002f,..._..._..."` | 只给 JA4R（含 cipher/扩展/sig_algs 列表） | 中：列表有序化丢失（`extensions_sorted` 告警） | 想"逐字节复刻"用这个或完整 profile；带 ECH(65037) 时按 GREASE 近似并告警（`ech_assumed_grease`），因为 raw 串不含负载 |
| `ja4="t13d1516h2_8daaf6152771_d8a2da3f94cd"` | 只给 **JA4 短哈希** | 哈希**不可逆** | 引擎在内置预设里反查同一 JA4 并采用其参数（`ja4_resolved_to_preset` 告警）；找不到会明确报错，不会编近似指纹 |
| `clienthello_hex="160301..."` | 直接给原始 ClientHello 字节 | 最高（等于抓包重放的结构） | 与生成器/采集端同一条解析路径 |

**没传的部分如何保持自洽**（这是"局部指纹"能用的关键）：

1. **重放自洽归一**（`core/profiles/replay.go`）：带 `pre_shared_key(41)` 的双向约束——声明 TLS 1.3 就必须有 41 空占位且位于扩展末尾（RFC 8446），不声明就必须没有（否则 ClientHello 结构非法）。补的是**空占位**：无票据时线上省略、也不计入 JA3/JA4，所以首次握手的指纹不变；不补的话，一旦会话复用命中票据，uTLS 会直接 panic。
2. **如实告警**：JA3 入口会报 `grease_lost` / `extension_payloads_lost`；JA4R 会报 `extensions_sorted`；JA4 反查会报 `ja4_resolved_to_preset`。**宁可说清损失，也不假装保真。**
3. **离线验证**：`geektls.check_profile(...)` 不发包，直接告诉你"这么传会发出什么"（JA3/JA4/wire 长度/warnings）：

```python
import geektls

# 整体：完整 profile 文本
print(geektls.check_profile('{"name":"mine","tls":{"detail":{"ciphers":["grease","0x1301"],"extensions":[{"type":43,"versions":["grease","0x0304","0x0303"]}]}}}')["ja4"])

# 局部：只给 JA3（会看到补占位 + 负载丢失的告警）
print(geektls.check_profile("771,4865-4866-4867-49195-49199,43-10-11-13-16-23-5-0-65281,4588-29-23-24,0"))

# 只给 JA4 短哈希（反查内置预设）
print(geektls.check_profile("t13d1516h2_8daaf6152771_d8a2da3f94cd"))
```

## Python API 参考

### 模块级函数

| 函数 | 签名 | 说明 |
|---|---|---|
| `version()` | `-> dict` | `{"abi":1,"core":"0.1.6","utls":"<指纹栈版本串>"}`；启动时可用它断言 ABI 匹配，`utls` 用于溯源（见上文） |
| `init(options=None)` | `-> None` | 幂等初始化钩子（当前无全局状态，留作后续） |
| `last_error()` | `-> dict` | 最近一次失败的结构化错误（`code`/`message`/`op`） |
| `list_presets()` | `-> list[str]` | 全部内置预设名（排序，364 条） |
| `describe_preset(name)` | `-> dict` | 预设**展开后的规范 JSON**（ciphers/扩展/H2/H3/身份头全展开） |
| `check_profile(spec)` | `-> dict` | 离线自检：profile JSON / JA3 / JA4 / JA4R / hex → `{ja3,ja3_hash,ja4,wire_len,warnings}` |
| `GeekTLSError` | 异常类 | 所有失败都是它；`.code` 结构化错误码（`invalid_config`/`request_failed`/…） |
| `default_session(**options)` | `-> Session` | 模块级共享会话；**首次**调用可传 `Session(...)` 参数配置（之后只读，再传报错） |
| `get/head/post/put/patch/delete/options(url, **kwargs)`、`request(method, url, **kwargs)` | `-> Response` | requests 风格快捷 API，走 `default_session()`（连接池与 Cookie jar 随之共享；与 requests 的模块级 API 同语义） |

### `Session`

```python
Session(impersonate=None, *, profile=None, ja3=None, ja4=None, ja4r=None,
        clienthello_hex=None, headers=None, proxies=None, timeout=None,
        read_timeout=None, resolve=None, local_address=None, ip_version=None,
        verify=None, cert=None, cert_key=None, allow_redirects=None,
        max_redirects=None, cookies=None, auth=None, trust_env=None, **options)
```

| 参数 | 类型 | 说明 |
|---|---|---|
| `impersonate` / `profile` / `ja3` / `ja4` / `ja4r` / `clienthello_hex` | str / dict / str | 六选一（见上一节） |
| `headers` | dict / list[tuple] | 会话默认请求头（按给定顺序发出） |
| `proxies` | dict / str | requests 风格；引擎一次只用一个代理 URL（`{"https": ...}` / `{"all": ...}`）。scheme：`http`/`https`（CONNECT 隧道）、`socks5`（本地先解析域名）、`socks5h`（域名交给代理解析）、`socks4`/`socks4a`（仅 IPv4 目标；只有 user id 无口令位，URL 给口令即报错） |
| `trust_env` | bool | requests 同名，映射到引擎 `proxy_from_env`：`False` ⇒ 不读 `HTTPS_PROXY`/`ALL_PROXY`，只认显式 `proxies`；默认 `True` 会读，并按 `NO_PROXY` 与回环目标（`localhost`/`127.0.0.1`/`::1`）豁免 |
| `timeout` | float 秒 / `(connect, read)` | 单值映射到引擎 `timeout_ms`（覆盖"dial+TLS+响应头"）；元组时 connect 进 `timeout_ms`、read 进 `read_timeout_ms`（任一项可为 `None`），请求级可用 `timeout_ms=` 覆盖 |
| `read_timeout` | float 秒 | 映射到引擎 `read_timeout_ms`：**每次读 body** 的空闲上限（默认 0=不限，与旧行为一致）；请求级可用 `read_timeout_ms=` 覆盖。超时是结构化错误 `code="read_timeout"`，调用线程毫秒级返回，底层连接作废 |
| `resolve` | dict[str, str] | curl `--resolve`：`{"host": "1.2.3.4"}` 或 `{"host:8443": "..."}`（键精确匹配，不做通配/子域；值必须是 IP 字面量）。**只改"连到哪"**：SNI / Host / 伪头 / ClientHello 仍用 URL 里的原域名，指纹字节不变。只在引擎本地解析的那几档生效（直连 / netstack / `socks5` / `socks4`）；`socks5h`/`socks4a`/CONNECT 由代理解析，钉位不参与（不静默改道） |
| `local_address` | str | curl `--interface` 的 IP 形态 / httpx `local_address`：绑出网源地址，只收 IP 字面量（网卡名不支持）。隐含协议族，与 `ip_version`、`resolve` 取值冲突建会话即 `ValueError`；`tcp.mode=netstack` 下报错（用户态栈源地址固定）而不是忽略 |
| `ip_version` | str / int | curl `-4` / `-6`：`"4"` / `"6"`（`4`、`"v4"`、`"ipv4"` 同义），限定解析与拨号族；命中的地址全被过滤时是明确的解析错误 |
| `verify` | bool / str / bytes / Path | `True`（默认，系统信任库）/ `False`（跳过校验）/ CA bundle 路径、含 `.pem/.crt/.cer` 的目录、或内联 PEM（**自持信任库，替换系统根**）。其他类型直接 `ValueError`，不会静默退回系统根 |
| `cert` | str / bytes / Path / tuple | mTLS 客户端证书：路径或 PEM（证书+私钥可同文件）、`(证书, 私钥)`；三元组的 password 必须为 `None`（不支持加密私钥） |
| `cert_key` | str / bytes / Path | 单独给私钥（覆盖 `cert` 元组第二项） |
| `allow_redirects` | bool | `False` ⇒ 不跟随重定向（会话级；**请求级也可传**，请求级覆盖会话级） |
| `max_redirects` | int | 重定向上限（默认 10；会话级与请求级都可用） |
| `cookies` | dict / list[tuple] / str / `Cookies` / bool | dict 等形态 ⇒ 会话级 jar（每请求渲染成 `Cookie` 头，响应里的 `Set-Cookie` 自动并入）；`True`/`False` ⇒ 只开关引擎 jar |
| `auth` | tuple / 对象 | `(user, password)` 或带 `username`/`user` + `password` 属性的对象 ⇒ HTTP Basic；自己传了 `Authorization` 头时以你的为准 |
| `**options` | — | 其余按**引擎会话原名**透传（`proxy`/`proxy_from_env`/`timeout_ms`/`read_timeout_ms`/`redirect_max`/`insecure_skip_verify`/`auto_decompress`/`cookie_jar`/`ca_bundle`/`client_cert`/`client_key`/`resolve`/`local_address`/`ip_version`）；不在名单里的键绑定层直接 `ValueError` |

| 方法 | 说明 |
|---|---|
| `request(method, url, *, params=None, data=None, json=None, headers=None, body=None, timeout=None, timeout_ms=None, read_timeout=None, read_timeout_ms=None, proxy=None, proxies=None, cookies=None, auth=None, allow_redirects=None, max_redirects=None, stream=None, force_http3=None, **kwargs)` | 通用请求；**头到达即返回**，body 按需读取。`proxies` / `cookies` / `auth` / `allow_redirects` / `max_redirects` 请求级覆盖会话级 |
| `get / post / put / patch / delete / head / options(url, **kwargs)` | 便捷动词，等价于 `request` |
| `websocket(url, headers=None, timeout=None, compress=False)` | 升级 WebSocket（见下节），返回拉模型 `WebSocket`；`compress=True` 握手 offer permessage-deflate |
| `close()` | 释放会话（挂连接池/transport） |
| `with Session(...) as s:` | 自动 `close()` |

> ⚠️ `verify` / `cert` 是**会话级**：传给 `request()` 会**明确报错**而不是静默失效（要按请求切换就新建 Session）。`allow_redirects` / `max_redirects` / `proxies` / `cookies` / `auth` 请求级也能用。
>
> ⚠️ 拼错的关键字**不会静默吞掉**：core 的两处 JSON 解码都不严格（client config 只查指纹入参那六个键，`SessionOptions` 忽略未知字段），所以名单校验做在**绑定层**——`Session(...)` 收到未知会话选项、`request()` 收到未知请求级 kwargs 都立即报错（Node 侧同理：`new Session({insecure_skip_verfy: true})` 抛 `TypeError`）。这类选项决定"校验开不开、超时走不走、连接钉到哪"，绝不能配了却没生效。

### `Response`

| 成员 | 类型 | 说明 |
|---|---|---|
| `status_code` / `status` | int | HTTP 状态码（`status` 是 0.1.0 起的旧名，等价） |
| `ok` | bool | `< 400` 为 True（requests 语义）；对象真值即 `ok` |
| `reason` | str | 本地按 RFC 9110 映射的短语（非服务端原文） |
| `headers` | `CaseInsensitiveDict` | 大小写不敏感；保留插入原始大小写 |
| `raw_headers` | list[tuple] | 原始 (name, value) 顺序视图 |
| `used_protocol` | str | 实际协商到的协议：`h2` / `h3` / `http/1.1` |
| `selfcheck` | dict | **本次握手**的自算指纹与比对（见「自校验」） |
| `url` / `method` / `elapsed` / `encoding` / `apparent_encoding` | — | 请求元信息与编码推断 |
| `content` / `read()` / `bytes()` | bytes | 读完并缓存 body |
| `text` | str | 按响应编码解码（未声明 charset 时自动探测） |
| `json(**kwargs)` | Any | 按声明 charset（缺省 utf-8，剥 BOM）解 `content`；**不走** `text` 的探测链（省掉一次"猜编码再解码"） |
| `iter_content(chunk_size=65536, decode_unicode=False)` / `iter_bytes(chunk_size)` / `iter_lines(chunk_size, decode_unicode=False)` | 生成器 | 边收边处理大响应（`iter_bytes` 是旧名；`decode_unicode=True` 跨块多字节不会切坏） |
| `header(name, default=None)` | str | 取单个响应头 |
| `cookies` | `Cookies` | 本响应 `Set-Cookie` 的解析结果（requests 同名）；`session.cookies.update(r.cookies)` 可让它参与后续请求 |
| `raise_for_status()` | None | `>=400` 抛 `HTTPError`（`GeekTLSError` 子类，异常上挂 `.response`；`code="http_error"`） |
| `close()` | None | 释放响应句柄（未读完 body 时更要显式调用） |
| `content_encoding` | str | 线上 `Content-Encoding` 原值（不篡改，与 requests 一致） |
| `decoded` | bool | 本次响应是否被引擎透明解压过 |
| `warnings` | list[str] | 解压层非致命提示（未知编码原样透传等） |

### WebSocket（wss:// 与 ws://，RFC 6455）

`wss://` 握手走同一条拨号 + TLS 指纹链路；`ws://`（明文）只做 TCP —— 帧层与 TLS 无关，
两条路径共用同一套帧实现，差别只在拨号那一步（与 `http://` 同一条路）。
wss 的 ALPN 收窄到 `http/1.1`（Upgrade 在 h2 上无效；收窄的是 detail 副本里的 ALPN 扩展内容，
不只改本地偏好；明文 ws 没有 ALPN）。
Upgrade 请求头序默认对齐真 Chrome（host → connection → upgrade → origin → 身份头 →
sec-websocket-version → sec-websocket-key），`profile.http1.header_order` 非空时整体再过排序器。
帧层为自行实现（stdlib，无新依赖）：text/binary/ping/pong/close、客户端 masking（RFC 强制）、
分片重组、控制帧 125 字节上限、ping 自动回 pong。
**permessage-deflate（RFC 7692）已实现**：`compress=True` 让握手 offer `permessage-deflate`，
只有对端在 101 里按我方 offer 真的接受才启用——之后 `send`/`recv` 收发的仍是**明文**
（RSV1 位、跨消息压缩上下文、分片续接都在库里管理）。默认 `False` 不发这个头：
没有逐浏览器 WS 握手的字节级证据，就不承诺 Chrome 那个 `client_max_window_bits` 参数
（stdlib 的压缩窗固定 15 bit）。要精确控制 offer 参数（`server_no_context_takeover` 等）
直接把它写进 `headers`。

```python
with Session(impersonate="chrome_133") as s:
    ws = s.websocket("wss://ws.postman-echo.com/raw")
    ws.send("hello")                          # text 帧
    opcode, payload = ws.recv(timeout=8)      # (1, b'hello')；1=text 2=binary
    ws.close()                                # 或交给 Session 的 with 统一释放

    # 想要服务端按 RFC 7692 压缩载荷（收发仍是明文）：
    ws = s.websocket("wss://example.com/socket", compress=True)
```

- **拉模型**：`send(data)`（str ⇒ text 帧，bytes ⇒ binary；Python 可 `send(data, opcode)` 显式指定）/ `recv(timeout=None, buf_size=1<<20)`（秒）/ `close(code=1000)`，不做回调式。
- Node：`const ws = await session.websocket(url, { compress: true })` → `await ws.send(data)` / `ws.recvText(timeoutMs)` / `ws.close()`；asyncio 同款（`AsyncSession.websocket`）。
- **协商严格按 RFC，不做"看起来能用再说"**：对端回声我方没请求的参数、协商了不认识的扩展、
  把我方压缩窗限到 <15 bit，握手直接失败；没协商却收到 RSV1（以及 RSV2/RSV3、带 RSV1 的
  控制帧）也直接报错——"把压缩字节当文本返回"是绝不允许的失败模式。
- **不做 RFC 8441（WebSocket over H2）**：Chrome 实际仍以 H1 Upgrade 为主（capability-matrix `ws.rfc8441_h2` 登记）。
- 已验证：本地 echo-server 双向收发/分片/控制帧（pytest `test_websocket`、node `websocket`）+ 公网 `wss://ws.postman-echo.com/raw` 真实握手与回显；permessage-deflate 用 `core/engine/ws_deflate_test.go` 里**独立写的 stdlib flate 对端**（真 TLS 监听）双向验证——发方向的压缩块拼起来交给普通 `flate.NewReader` 整体解开，证明是合法连续 DEFLATE 流而非自家私有格式。

### 响应透明解压（默认开）

引擎按响应 `Content-Encoding` 自动解压 body：gzip / deflate（zlib 头 + raw flate 容错）/
br / zstd，多重编码链（如 `gzip, br`）按声明顺序逆序解开；全链路流式生效——
`r.content` / `r.text` / `r.json()` / `iter_*` 拿到的都是解压后的字节（charset 探测在解压之后）。

- 关闭：`Session(auto_decompress=False)`，或请求级 `request(..., auto_decompress=False)`（请求级覆盖会话级）。
- headers 保留线上原值：`Content-Encoding` / `Content-Length` 不篡改；解压状态看 `r.decoded` / `r.content_encoding`。
- 未知编码值原样透传不报错，记入 `r.warnings`。
- H3 路径同样生效（解压统一收归引擎；vendor fhttp 的内置单层解压已用 `SkipResponseDecompress` patch 关闭，杜绝双重解压）。

## Node.js API 参考

```js
const { Session, version, listPresets, describePreset, checkProfile,
        lastError, errorOf, GeekTLSError,
        request, get, post, del, options, defaultSession } = require('geektls');  // 后五个：requests 风格模块级快捷 API
```

| 成员 | 说明 |
|---|---|
| `new Session(options)` | `options` 同 Python：指纹入参六选一 + `proxy`/`proxies`、`proxyFromEnv`/`trustEnv`（`false` = 不读 `HTTPS_PROXY`/`ALL_PROXY`）、`timeoutMs`/`timeout`、`readTimeoutMs`/`readTimeout`（秒，body 读取空闲上限）、`redirectMax`/`allowRedirects`、`cookieJar`、`insecureSkipVerify`/`verify`（`true`/`false`/CA bundle 路径或 PEM）、`cert`（路径 / `[证书, 私钥]` / `{cert, key}`）+ `certKey`、`headers`、地址控制 `resolve`（`{'host[:port]': ip}`）/`localAddress`/`ipVersion`。也认引擎原名（`timeout_ms`/`insecure_skip_verify`/`resolve`…）；两个名单都不在的键抛 `TypeError`，不会静默消失 |
| `s.request({method, url, ...})` | 返回 `Promise<Response>`（不阻塞事件循环）；请求级可给 `timeoutMs`/`readTimeoutMs`/`proxy`，以及 `allowRedirects:false`（⇒ 引擎 `redirect_max=-1`） |
| `s.get/post/put/patch/delete/head/options(url, options)` | 便捷动词 |
| `await s.websocket(url, { headers, timeoutMs, compress })` | WebSocket（拉模型：`send` / `recv` / `recvText` / `close`）；`compress:true` 握手 offer permessage-deflate |
| `s.close()` | 释放会话 |
| `r.statusCode` / `r.ok` / `r.reason` / `r.headers` / `r.usedProtocol` / `r.selfcheck` | 同 Python 语义 |
| `r.contentEncoding` / `r.decoded` / `r.warnings` | 解压元信息（同 Python） |
| `await r.read()` / `r.bytes()` / `r.text()` / `r.json()` / `r.header(name)` | body 读取 |
| `r.iterContent(size)` / `r.iterLines(size)` | 异步迭代器（`for await`） |
| `r.close()` | 释放 |
| `version()` / `init()` / `lastError()` / `listPresets()` / `describePreset(name)` / `checkProfile(input)` | 与 Python 同名同语义 |
| `errorOf(handle)` | 按对象取最近一次错误（`gtls_error_of`；handle 查不到再回落 `lastError()`）。异步绑定在 worker 线程报的错靠它取回 |
| cookie | Node 侧**没有** Python 那样的显式 jar API：线上 `Set-Cookie` 的存取与重发由引擎 jar 自动完成（含重定向中间跳）；要带指定 cookie 就写 `Cookie` 头 |

## Go API 参考

两条路：**绑定层**（`github.com/geektls/golang`，`http.Client`/`RoundTripper` 形态）与**引擎直连**（`core/engine`，能力最全）。

| 包 | 关键 API | 说明 |
|---|---|---|
| `core/profiles` | `List()` / `Get(name)` / `Describe(name)` / `FromJA3` / `FromJA4R` / `FromClientHelloHex` / `NormalizeForReplay` / `Parse` | 预设与指纹入口（含上面说的自洽归一） |
| `core/tls` | `CompileDetail` / `ComputeJA3` / `ComputeJA4` / `JA3Hash` / `CheckProfile` / `ResolveJA4Preset` | 编译、自算、离线自检、JA4 反查 |
| `core/engine` | `NewSession(profile, SessionOptions)` → `Do(*Request)` → `*Response`（`StatusCode/OK/Reason/Header/Text/JSON/IterBytes/Close`）；`DialWS(*WSRequest)` → `*WSConn`（`Send/Recv/Close`，`WSRequest.Compress` 开 permessage-deflate） | 引擎直连；支持 H2/H3 racing、Alt-Svc、代理、流式、wss |
| `github.com/geektls/golang` | `NewSession(preset, *Options)` → `Do/Get` / `DialWS(*WSRequest)` → `*WSConn` / `Close()`；`NewRoundTripper(preset, *Options)` | 绑定层（不走 FFI，直接 import core）；`WSRequest`/`WSConn` 是 engine 类型的别名，不再包一层以免漂移 |
| `core/ffi` | `gtls_*` C ABI（见 [core/ffi/geektls.h](core/ffi/geektls.h)） | Python/Node 绑定的底座；`gtls_client_new` 的 `config_json` 支持 `impersonate/profile/ja3/ja4/ja4r/clienthello_hex` |

## 使用场景

**1) 单请求（最常用）**

```python
with Session(impersonate="chrome_154_windows") as s:
    print(s.get("https://tls.peet.ws/api/all").json()["tls"]["ja4"])
```

**2) 并发抓取（会话复用 + 连接池）**

```python
import concurrent.futures as cf
with Session(impersonate="chrome_150") as s:
    with cf.ThreadPoolExecutor(16) as ex:
        for r in ex.map(lambda u: s.get(u), urls):
            print(r.status_code, r.used_protocol)
```

**3) 会话复用/票据**（第二次握手带 PSK，`selfcheck` 里能看到）

```python
with Session(impersonate="firefox_156_windows") as s:
    s.get("https://example.com").close()
    r = s.get("https://example.com")     # resumed（同 origin 连接复用）
```

**4) 强制 HTTP/3 / H3 竞速**

```python
with Session(profile=geektls.describe_preset("chrome_154_macos")) as s:
    r = s.get("https://cloudflare.com", force_http3=True, timeout_ms=8000)
    print(r.used_protocol)               # h3（不支持则按策略回落 h2）
```

**5) 走代理 / 关校验 / 不跟随重定向**

```python
with Session(impersonate="edge_153_windows", proxies={"https": "http://127.0.0.1:8080"},
             verify=False, allow_redirects=False) as s:
    print(s.get("https://example.com").status_code)   # 3xx 原样返回
```

代理支持六种 scheme：`http`/`https`（CONNECT 隧道，带 `user:pass` 即发
`Proxy-Authorization`）、`socks5`（**本地**先解析域名再交代 IP）、`socks5h`
（域名原样交给**代理**解析）、`socks4`/`socks4a`（老协议：只有 IPv4 目标、
鉴位只有 user id 没有口令；`4a` 的域名由代理侧解析）。
`socks5` 遇到解析不出的域名会**直接报错**，不会静默降级成 `socks5h`。

不给 `proxies` 时读标准环境变量 `HTTPS_PROXY` → `ALL_PROXY`（大小写都认），并按
`NO_PROXY` 豁免；`trust_env=False` 可整条关掉（指纹调试要可复计时建议关）。
域名是字面量匹配，不做 DNS——真 Chrome 会先解析再判 `NO_PROXY`，geektls **故意不这么
做**：为的是"同一个预设、同一个 URL 每次走同一条路"。
回环目标（`localhost` / `127.0.0.1` / `::1`）不吃环境变量派生的代理，避免开发机
上挂了 `ALL_PROXY` 就连不上本地测试服务；显式给的 `proxies` 对回环仍然生效。

> ⚠️ **有代理时 H3/QUIC 一律不参与**（含 racing 与 Alt-Svc 升级）：QUIC 过 HTTP 代理
> 需要 CONNECT-UDP（RFC 9298），本库未实现。`force_http3=True` + 代理会**明确报
> invalid** 而不是偷偷直发漏指纹——这是"要么按你说的路走、要么报错"的一般原则。

**5b) 自持信任库 / mTLS（requests 的 `verify=<path>`、`cert=(crt, key)`）**

```python
with Session(impersonate="chrome_150",
             verify="/etc/ssl/certs/internal-ca.pem",          # 路径 / 目录 / PEM 文本皆可
             cert=("/etc/client/tls.crt", "/etc/client/tls.key")) as s:
    print(s.get("https://internal.example.com/api").status_code)
```

CA 解析不出来、或证书与私钥配不上对时，**建会话就报错**（`GeekTLSError`，
`code=invalid_config`），不会退化成"用系统根继续"。TCP（uTLS）与 QUIC/H3 内层
握手共用同一份证书材料。

**5c) 不走系统 DNS：把域名钉到固定 IP / 绑源地址 / 限协议族**

```python
with Session(impersonate="chrome_150",
             resolve={"api.example.com": "93.184.216.34",   # 键也可以是 "host:443"
                      "cdn.example.com": "104.16.132.249"},
             local_address="192.168.1.23",                  # 出网走这张网卡/这个 IP
             ip_version="4") as s:                          # 只要 A 记录
    print(s.get("https://api.example.com/v1").selfcheck["ja4"])
```

这三项只改"**连到哪、从哪连**"，一律不改线上指纹字节：SNI、`Host`、伪头、
ClientHello 用的还是 URL 里的原域名，所以钉位前后 JA3/JA4 完全一致（有测试守着）。
`local_address` 必须是**本机持有的 IP**——绑一个不属于它的地址会在拨号时明确报错，
不会"静默换一张网卡"。
和 netstack 组合时它是**正向**能力：用户态栈要求目标是 IPv4 字面量，`resolve` 正好
供给；源 IP 由 `ip_version`/`resolve` 的族隐含。

生效范围按"**谁做解析**"划分，不做静默改道：直连、`tcp.mode=netstack`、`socks5`、
`socks4` 由引擎本地解析 ⇒ 钉位/族收窄都生效；`socks5h`、`socks4a`、CONNECT 隧道把
域名原样交给代理 ⇒ `resolve`/`ip_version` 不参与（那两档生效就等于绕过代理语义）。
`local_address` 在 netstack 下**报错**（用户态栈源地址固定为 TUN 侧地址）而不是忽略。
取值互相冲突（`ip_version="4"` 配 IPv6 源地址、`resolve` 值不是 IP、键写成网卡名）
建会话即 `invalid_config`；`force_http3` 与三者同给也是明确报错——QUIC 拨号没接地址
控制，宁可失败也不"以为钉住了其实在乱走"。

**6) 对比两个预设的指纹差异（不发包）**

```python
import json
a = geektls.check_profile(json.dumps(geektls.describe_preset("chrome_152_macos")))
b = geektls.check_profile(json.dumps(geektls.describe_preset("chrome_154_macos")))
print(a["ja4"], b["ja4"], a["wire_len"], b["wire_len"])
```

**7) 自定义完整指纹（自己的 profile JSON）**

```python
mine = {
    "name": "mine_chrome_like",
    "tls": {"detail": {
        "legacy_version": "0x0303",
        "ciphers": ["grease", "0x1301", "0x1302", "0x1303", "0xc02b", "0xc02f"],
        "extensions": [
            {"type": 0, "sni": "auto"},
            {"type": 16, "alpn": ["h2", "http/1.1"]},
            {"type": 43, "versions": ["grease", "0x0304", "0x0303"]},
            {"type": 10, "groups": ["grease", "X25519MLKEM768", "X25519"]},
            {"type": 13, "sig_algs": ["0x0403", "0x0804", "0x0401"]},
            {"type": 41},                       # 空占位：会话复用要求它在末尾
        ],
    }},
    "http2": {"hpack_strategy": "chrome", "settings": [[1, 65536], [2, 0], [4, 6291456], [6, 262144]],
              "window_update": 15663105,              # 三态：不写=补默认 15663105 / 0=不发这帧 / N=发 N
              "first_stream_id": 1,                   # 客户端首流号（正奇数）；不写=1，真 Firefox 用 3
              "pseudo_header_order": ["m", "a", "s", "p"]},
}
geektls.check_profile(json.dumps(mine))          # 先离线自检：看 warnings 与 JA3/JA4
with Session(profile=mine) as s:
    print(s.get("https://example.com").selfcheck["ja4"])
```

**8) 从抓包迁移：JA3 / JA4R / 原始 hex**

```python
with Session(ja3="771,4865-4866-4867,43-10-11-13-16-23-5-0-65281,4588-29-23-24,0") as s:
    r = s.get("https://example.com")             # 其余字段按引擎默认补齐
r = geektls.check_profile("t13d1516h2_8daaf6152771_d8a2da3f94cd")   # 反查内置预设
```

**9) 抓包 → 预设（把线上真实指纹固化成文件）**

```python
import json, pathlib
r = Session(impersonate="chrome_150").get("https://tls.peet.ws/api/all")
cap = r.json()
spec = {  # 只保留指纹相关字段（tcp 节按宿主平台另配）
    "name": "my_captured_profile",
    "tls": {"detail": {"legacy_version": "0x0303", "ciphers": ["grease", "0x1301"], "extensions": []}},
    "http2": {"akamai": cap["http2"]["akamai_fingerprint"]},
}
pathlib.Path("my_profile.json").write_text(json.dumps(spec, ensure_ascii=False, indent=2))
```

> 更规范的做法是走仓库的 `tests/e2e/cmd/gen-profiles`（从原始 ClientHello 字节生成，落 `core/profiles/builtin/` 并带证据等级）。

**10) 回归/自校验（把指纹钉死在测试里）**

```python
JA4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"
with Session(impersonate="chrome_154_windows") as s:
    assert s.get("https://example.com").selfcheck["ja4"] == JA4
```

## 预设体系

- **数量与命名**：364 条，`core/profiles/builtin/<name>.json`，**文件名即预设名**（`chrome_154_windows`、`firefox_156_android`、`okhttp_3_12_12`、`curl_8_16_0`…）。**没有族级短名**，也没有别名匹配——`impersonate="chrome_154"` 会报 `preset not found`。
- **字段**：`tls.detail`（ciphers/扩展与负载/GREASE 策略）、`http2`（SETTINGS/`window_update`（三态）/伪头序/`first_stream_id`/`hpack_strategy`/`headers_priority`）、`http3`（transport params/inner hello 规约）、`identity`（导航头集合与顺序）、可选 `tcp`、`grade`、`source`。
- **证据分级**（`grade` 字段，详见 [docs/09-alignment-and-superiority.md](docs/09-alignment-and-superiority.md)）：
  - 留空 = **本项目自测**（E1 真机抓包 / E1r 字段级实测 / E2 本机可复现）→ 参与 E1 级断言；
  - `E2i` / `E2i-u` = 谱系内插（实测锚点 + 逐字段稳定性规则，`-u` 表示区间内有变化且边界未知）；
  - `E3` = 外部指纹集导入（只补覆盖，不做保真承诺）。
  - 4 个 E1 级测试（fp oracle / Chromium GT / Firefox GT / TLS1.2 回退）一律跳过 `grade != ""` 的预设——**没实测的不参与"实测"断言**。
- **怎么挑**：要稳就挑 `grade` 为空、且与目标族/版本/平台都对的（`describe_preset()` 看全貌）；只求覆盖面可用 `E3`。
- **怎么加**：见 [docs/maintenance.md](docs/maintenance.md) 的"预设入库流程"。**由 `gen-profiles` 生成的预设禁止手改**（CI 逐字节比对守门）。

## 自校验

每个响应带 `selfcheck`：实际发出 ClientHello 的自算 JA3/JA4 + JA3 fullstring、线上扩展序（含/剔 GREASE 双份）、GREASE 值与位置、协商 cipher/版本/ALPN、SNI 是否上链（IP 目标自动报 `i`）；JA3/JA4R 入口还含期望值比对；`gtls_check_profile` 支持 profile JSON / JA3 / JA4 / JA4R / hex 五入参离线自检。

身份层也有守门（`core/profiles/builtin_identity_test.go`）：**任何预设都不得带 headless 令牌**，且 UA 与 `sec-ch-ua` 的平台/版本必须自洽（`Windows NT` ↔ `"Windows"`、`Macintosh` ↔ `"macOS"`、Chrome/Edg 主版本 ↔ `"Chromium";v="N"`）。

## 性能摘要（docs/benchmarks.md）

- FFI 调用开销：`gtls_version` 6–7µs、`gtls_check_profile` 26–30µs（<50µs 目标达成）
- 回环吞吐（连接池开启，并发 100，10s）：共享 Session（同 origin 单连接，浏览器真实形态）≈5–9k req/s；每 worker 会话模型 Go 12.7k / Python 9.4k / Node 8.9k req/s
- 冷启动：Session 初始化 0.2ms、首请求 ~3.5ms

## 与同类项目对比

对比依据（2026-09-29 复核）：逐仓拉取下列项目 README 原文核对能力声明，结合
`tls-spoofing-library-matrix` 与 [docs/10-ecosystem-comparison.md](docs/10-ecosystem-comparison.md)。
三点口径：**① `akamai/uls` 实为 Akamai 的日志流 SIEM 工具，不是指纹库，已从对比剔除**
（此前表格误列）；**② `cyCronet` 的地址是 [2833844911/cyCronet](https://github.com/2833844911/cyCronet)**
（Python + Chromium Cronet 真栈）——此前按名字猜 slug（`cycronet/cycronet`）查不到就写"仓库不存在"，
是错的：**查不到 ≠ 不存在**，已补回对比行；**③ `bogdanfinn/tls-client` 的 README 本次拉取失败
（raw 与镜像均 404），其能力按既有文档与本项目 E3 导入记录描述**。单元格 `—` 表示公开材料未说明
该维度（不等于没有）。

### 完整客户端（TLS / H2 / H3 伪装客户端）

| 项目 | 栈 / 语言 | TLS 指纹 | H2 帧 + 头序 | H2 HPACK 策略 | H3 / QUIC | 四层 TCP | WebSocket | 预设与证据 | 响应内自校验 |
|---|---|---|---|---|---|---|---|---|---|
| **geektls** | Go（c-shared）+ Python / Node / Go 绑定 | ✅ uTLS fork + E1 真机采集链路 | ✅ | ✅ **四档**（generic/chrome/firefox/safari），250/364 预设带值 | ✅ 内层 ClientHello 同 profile + transport params blob 直通；Initial 布局不可控（SC-3 解锁） | ✅ TTL/MSS/DF/window/wscale：setsockopt 三平台 + **netstack 档**（Linux root，gVisor 栈） | ✅ RFC 6455 + permessage-deflate（握手走指纹链路） | ✅ 364 条 `grade`/`source` 分级：30 自测 / 6 E2i / 8 E2i-u / 320 E3 | ✅ selfcheck + `check_profile` 五入参 |
| `bogdanfinn/tls-client`（`hrequests`、`noble-tls`、`tls-client-sharp` 等绑定） | Go `fhttp` + `utls` | ✅ | ✅ | — | ✅ | — | — | 自带 profile 集；**与本项目 E3 覆盖（320 条）无直接来源关系**——E3 的 `source` 逐条指向第三方快照 `profiles/evidence/thirdparty/tls_config-0.0.2`（`TestE3SourceTraceable` 守门），profile 组织形态是同类参照 | — |
| `lexiforest/curl_cffi`（活跃）/ `lwthiker/curl-impersonate`（原始） | libcurl 补丁 + BoringSSL / NSS | ✅ | ✅ | — | ✅（curl_cffi 新版起） | ❌（libcurl 无 TCP 指纹面） | ✅ | 内置画像 + 自定义指纹；社区节奏最快 | — |
| `Danny-Dasilva/CycleTLS`、`cycletls_python` | Go `utls` + `fhttp` + `quic-go` | ✅（JA3 可配置） | ✅（fhttp 头序） | — | ✅ | — | ✅ | profile 清单；socks4/5/5h | — |
| `sardanioss/httpcloak` | Rust 栈，Python/JS/C# 绑定 | ✅ | ✅（WINDOW_UPDATE/priority 可调） | 部分（priority 侧） | ✅（H3 GREASE 帧） | ✅（TTL/MSS/Window，README 声明） | — | 内置 preset + "抓一次用到底"（JA3+Akamai 粘贴导入） | — |
| `jaredboynton/specter` | Rust + 自研 H2（RFC 9113）/ H3 | ✅ Chrome 142–148、Firefox 133–151+ESR | ✅（记录分帧/帧时序/池行为） | — | ✅ | — | ✅ | 内置 profile + UA-CH 算法文档 | — |
| `zhkl0228/impersonator` | Java / kwik（QUIC） | ✅ | ✅ OkHttp 形态 | — | ✅ **含 QUIC Initial 布局**（分片/乱序/PADDING 按浏览器拟真） | — | — | — | — |
| `sqdshguy/wreq-js` | Node（Rust wreq 内核） | ✅ | ✅ Akamai | — | — | — | ✅（WHATWG 风格 + 会话复用） | Chrome 至 149 / Firefox 151，声明"live capture 验证" | — |
| `daijro/hrequests` | Python（tls-client 内核） | ✅ | ✅ | — | — | — | — | requests 风格 + **BrowserForge 头生成 + 浏览器自动化** | — |
| `2833844911/cyCronet` | Python + Chromium **Cronet 真栈**（`libcronet.so`） | ✅ 真栈（默认 `chrome_144`，`tls_profiles.json` 可自定义） | ✅ 真栈 | —（真栈内置，策略不可控） | —（README 未见 H3/QUIC） | ❌ | ✅（WSS，TLS 指纹一致） | `chrome_144` + 自定义 json；SOCKS5 带鉴权 | ❌（无自校验回读） |
| `deedy5/primp`、`wangluozhe/requests-go`、`z402166914/pyhttpx`、`tocha688/curl-cffi-node` | 各语言封装 | ✅ 依赖上游 | ✅ 依赖上游（requests-go 另有 JA3 扩展随机化） | — | 部分 | — | 部分 | — | — |
| `thesatellite-ai/fetchr` | Go + CLI + MCP server | ✅（JA3/JA4） | ✅ | — | ✅ | — | — | 浏览器画像 | — |

### 采集 / 检测 / 代理（对照面，不是竞品）

| 项目 | 作用 | 与 geektls 的关系 |
|---|---|---|
| `gospider007/fp` | 独立 ClientHello 解析器 | E1 采集链路直接使用（`tests/e2e/cmd/e1-browser`） |
| `FoxIO-LLC/ja4`、`Crank-Git/ja4plus-go`、`XOR-op/ja-tools` | JA3 / JA4 / JA4+ 参考实现 | JA4 规范与测试向量来源；只依赖 JA4 本体（JA4+ 部分方法有许可证限制） |
| `wi1dcard/fingerproxy`、`LyleMi/ja3proxy`、`O-X-L/haproxy-ja4-fingerprint` | 反向代理 / 网关算指纹并透传 | 输出形态对照；selfcheck 做在响应里，不依赖网关 |
| `jaeles-project/gospider`、gitee `baixudong/gospider`、`Ecalose/gospider` | 爬虫 / 工具链（同名不同项目） | 爬虫侧用法参照 |
| `tlsmask/tlsmask`、`Easonliuliang/helloprint` | 指纹伪装 / 一致性工具 | UA ↔ TLS 一致性思路对照；落成身份层守门测试 |

### 上表里 geektls 的差异点

1. **四层一起**：TLS + H2（含 HPACK 编码策略四档）+ H3 / QUIC（内层 ClientHello 同 profile）+ TCP（TTL/MSS/DF/window/wscale：setsockopt 三平台 + Linux netstack 档）。上表其他客户端多数止步 TLS / H2；四层 TCP 只有 httpcloak 声明了同档能力。
2. **证据分级**：`grade`（30 自测 / 6 E2i / 8 E2i-u / 320 E3）+ `source` 守门 + E1 真机采集链路 + 语料回归 + 外部 oracle 周检；同类普遍只给一份清单，不区分实测与转写。
3. **响应内自校验**：本次握手实际发出的 JA3 / JA4 / 扩展序 / GREASE 值直接从响应取，可当回归断言；`check_profile` 支持五种入参离线自检。
4. **三语言同引擎**：Python / Node / Go 共用同一 C ABI，跨语言 JA4 三方全等，不需要为每种语言重写指纹栈。
5. **预设结构**：364 条按 `grade` 分层（30 自测可参与严格断言 + 6 E2i / 8 E2i-u 谱系内插 + 320 E3 导入），覆盖浏览器 / App / 工具 / 代理等 29 族，含跨平台同版本一致性断言（`chrome_152` / `chrome_154` 在 macOS / Android / Windows 上 JA4 逐字符相同）。
6. **部署形态**：Go 实现、CGO 只用于构建动态库，产物是单文件动态库 + 平台 wheel，无需 libcurl 补丁链。
7. **自主化路线**：指纹相关代码路径正向 100% 自有推进（uTLS / fhttp / quic-go-utls 内化裁枝四阶段，见 [docs/plans/2026-09-29-self-contained-roadmap.md](docs/plans/2026-09-29-self-contained-roadmap.md)）；密码学原语（circl / brotli / zstd）按行业共识保留成熟实现，不自写。
8. **能力面补齐**：WebSocket（wss / ws，握手走指纹链路）+ **明文 `http://`** + Python asyncio + 四编码自动解压 + **命令行入口** + requests 语义面（cookie jar / timeout 元组 / auth / 重定向开关 / 表单编码），与 CycleTLS / curl_cffi / noble-tls 的能力清单逐项对齐（逐库对照见 [docs/10-ecosystem-comparison.md](docs/10-ecosystem-comparison.md)）。

T-HPACK 四档的证据来源：chrome 档对齐 Chromium QUICHE `HpackEncoder` 的默认策略（源码级），
firefox 档对齐 Firefox 59 抓包（字节级），safari 档为保守近似（待 E1 校验）；上游 x/net 编码器
"一切皆可入动表"的行为与前三者都不同。

### 相对短板（同一张表下的客观差距）

| 维度 | 差距 |
|---|---|
| 生态与熟悉度 | 远不如 `curl_cffi` / `curl-impersonate`：Python 迁移成本、示例与社区最少；没有 `hrequests` 那种浏览器自动化集成 |
| 真栈行为级 | `curl_cffi`（libcurl + BoringSSL）与 `cyCronet`（Chromium Cronet 真栈）的行为级细节天然全真（含握手重试、协议栈内部实现）；这里靠逐维度对齐逼近，理论上存在未发现的行为差异 |
| 预设更新 | 依赖人工采样（SLA 2 周）；大量预设是 E3 转写而非实测，`curl_cffi` / `curl-impersonate` 靠社区补丁更快 |
| H3 可控面 | QUIC **首 datagram 尺寸 / PADDING 量可控**（`http3.initial_packet_size`，1200–1452），但 **coalesce 阈值与 CRYPTO 分片表仍不可控**（要动 vendor packer 层 = SC-3）；transport params 顺序靠 blob 直通；Firefox / Safari H3 未实测 |
| Safari 侧 | HPACK 的 safari 档是全 literal 保守近似；padding 用实测字节数表达；无 CFNetwork 字节级证据 |
| 四层 | Windows 仅 setsockopt 档（TTL/MSS/DF，MSS 项缺失）；netstack 档（window/wscale 精确控制）仅 Linux root；IP ID / TSval 不可控 |
| 发布面 | npm 与 Go module 尚未发布；wheel 只覆盖 5 平台（无 musllinux / Windows ARM64） |
| 依赖 fork | `fhttp`、`quic-go-utls` 是 vendor fork，升级上游要重打 patch 并跑回归（流程已登记，仍是维护成本） |
| 有损入口 | JA3 / JA4 入参天然丢负载，此处选择"如实告警"而不是"看起来像"，在只求"JA3 过检测"的场景不是最省事的路径 |

**自主化进度**（[docs/plans/2026-09-29-self-contained-roadmap.md](docs/plans/2026-09-29-self-contained-roadmap.md)）：
边界声明与依赖清单已完成；`gvisor.dev/gvisor`（netstack 档）已引入；`core/internal/` 目前只有
`registry` ⇒ **SC-1（uTLS 内化改写）/ SC-2（fhttp 裁枝内化）/ SC-3（quic-go-utls 内化）均未开始**，
"指纹路径 100% 自有"的终态尚未达成。不变量：ABI 签名只增不改、364 预设指纹输出逐比特不变、
每阶段全量回归 + L2 nginx 终审。

**能力对齐现状与追赶排期**（差距清单 + 关闭判据 + 明确不做的事）见
[docs/plans/2026-09-29-parity-and-improvement-plan.md](docs/plans/2026-09-29-parity-and-improvement-plan.md)：
指纹能力面已对等或领先。**形态面已补齐**（明文 `http://` / `ws://`、CLI、cookie 手感、
requests 语义面）；剩余差距集中在**发布面**（Node/Go 未发布、平台不全）与两条结构性差距
（QUIC Initial 的 coalesce / 分片表 = SC-3、真栈行为级 = 不可追平）。

## 已知边界与不足（如实）

| 边界 | 说明 |
|---|---|
| QUIC 内层 ECH 与 bogdanfinn 服务端 | 其 QUIC server 不处理 ECH-in-QUIC 会静默失败（客户端侧已合成 Chrome 等效 payload；真服务器按规范忽略 GREASE ECH） |
| QUIC Initial 布局 | **首 datagram 尺寸 / PADDING 量可控**（`http3.initial_packet_size`，1200–1452，默认不设 = 上游 1280）；**coalesce 阈值（Initial+Handshake 合并判据）与 CRYPTO 分片表仍不可控** —— 要动 vendor `packet_packer.go` / `crypto_stream.go`（SC-3），且必须按 perspective 分支，否则影响服务端路径 |
| 明文 `http://` 的边界 | 只走 H1（**不做 h2c**，无 `prior knowledge` / Upgrade 路径）；经 HTTP 代理时走 **CONNECT 隧道**（不发 absolute-form `GET http://…`）；明文没有 TLS 层 ⇒ `selfcheck` 恒为零值、`force_http3` + `http://` 直接报错 |
| 代理环境变量按 scheme 取 | https/wss 读 `HTTPS_PROXY`、http/ws 读 `HTTP_PROXY`，都不跨 scheme 取（curl/requests 同语义）；都没命中再退 `ALL_PROXY` |
| QUIC transport params 顺序/非标参数 | 已经 T4-1 blob 直通可控（顺序/值硬断言全绿）；个别残余值与 blob 整块替换冲突，待 fork 决策（能力矩阵 H3-7） |
| Windows TCP MSS | 不支持（WSAENOPROTOOPT 实测），跳过+warning；raw socket 档仅 Linux 探测模式 |
| uTLS PSK 复用 vs Go std 服务端 | binder 校验失败（上游 interop，发出侧已证正确） |
| JA4 短哈希入参 | 哈希不可逆 ⇒ 只能反查内置预设；想精确复刻必须给 JA4R 或完整 profile |
| nginx L2 终审 | ✅ 已通过（WSL2，35/35）；JA4TCP 验收仍需真实二层网络 |

## 开发与发布

```bash
make build                     # 构建动态库到 build/
make cli                       # 构建命令行入口到 build/geektls
make smoke                     # Go/Python/Node 三语言冒烟
cd core && go test ./...       # 引擎全量（含 E1/E2 门禁、语料回归）
cd tests/e2e && go test ./...  # e2e：生成器守门、HPACK/H2 回放、loopback、跨语言
GEEKTLS_ORACLE_PRESETS=chrome_154_* GEEKTLS_ORACLE_ASSERT=1 \
  go test -tags external -run Oracle -v   # 外部 oracle 对拍（子集 + 不一致即失败）
wsl -d Ubuntu -- bash scripts/wsl-test.sh   # Linux 侧验证（WSL，Go 自动装到 ~/.local）
```

- **发布**：`docs/versioning.md`（语义化 + ABI 规则 + 三处版本同步）；PyPI 流水线 `.github/workflows/release-pypi.yml`（五平台 wheel）、CI `.github/workflows/ci.yml`（含"预设必须等于生成器产物"逐字节守门）。
- **nightly 实测**：`.github/workflows/oracle-nightly.yml` — 外部 oracle（JA3/JA4 + Akamai H2）以**断言档**跑选定子集、ECH 与真机会话恢复（`resumed=true` 是硬门禁）、Go/Python/Node 三语言一致性与两套绑定 e2e（Linux + Windows 真构建动态库）。子集由 `GEEKTLS_ORACLE_PRESETS` 控制，手动 dispatch 可临时加新预设；每周另有 `.github/workflows/preset-freshness.yml` 比对内置预设与 Chrome/Firefox 官方渠道版本，落后即开 issue。
- **预设维护**：`docs/maintenance.md`（Chrome 2 周 SLA、入库五步、oracle 周检、fork rebase）。

## 许可证

本项目自身按 **MIT** 授权（见 [LICENSE](LICENSE)，2026-09-29 定）。

发布物（wheel / npm 包 / Go module / 编译进动态库的依赖）内含第三方代码，各依赖的许可证与
归属声明登记在 [LICENSES.md](LICENSES.md) 并随 wheel 一起分发：全量闭包审计**无 GPL/LGPL**；
两个如实登记的注意项是**上游 `fhttp` 无显式 LICENSE**（仅"无授权使用"风险，行业生态同此依赖）
与 **JA4+ 的许可证/商标边界**（只依赖 JA4 本体，见上文对比表）。

## 文档索引

| 文档 | 内容 |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | 各版本更新内容（0.1.5 起） |
| [docs/00-architecture.md](docs/00-architecture.md) | 技术选型、模块划分、FFI 模型 |
| [docs/01-fingerprint-dimensions.md](docs/01-fingerprint-dimensions.md) | 四层指纹维度清单 |
| [docs/02-ffi-abi.md](docs/02-ffi-abi.md) | C ABI 契约 |
| [docs/03-profile-format.md](docs/03-profile-format.md) | profile JSON schema + 预设体系 |
| [docs/06-task-list.md](docs/06-task-list.md) | 任务计划与完成状态 |
| [docs/07-capability-gaps.md](docs/07-capability-gaps.md) | 能力缺口与实测记录（含族横向对照） |
| [docs/08-plan-pending-samples.md](docs/08-plan-pending-samples.md) | 待补采样与后期扩充计划 |
| [docs/09-alignment-and-superiority.md](docs/09-alignment-and-superiority.md) | 证据分级与同类对比（内部版） |
| [docs/capability-matrix.yml](docs/capability-matrix.yml) | 机器可读能力矩阵（CI 断言/变量映射共用） |
| [docs/CONTRACT-FREEZE.md](docs/CONTRACT-FREEZE.md) | 已验证面冻结契约（防"改而改弱"） |
| [docs/plans/2026-09-24-geektls-hardening-and-h3-plan.md](docs/plans/2026-09-24-geektls-hardening-and-h3-plan.md) | 硬化与 H3 补齐方案（2026-09-24） |
| [docs/p1-utls-capability.md](docs/p1-utls-capability.md) / [p2-h2](docs/p2-h2-capability.md) / [p4-h3](docs/p4-h3-capability.md) | 各层能力摸底矩阵 |
| [docs/11-lowlevel-forgery.md](docs/11-lowlevel-forgery.md) | TLS 以下的指纹伪造：分层可行性、一致性红线、参考仓库 |
| [docs/12-pcap-import.md](docs/12-pcap-import.md) | pcap 抓包 → 装载：分层可见性、五个坑、import-pcap 设计与端到端实测 |
| [docs/tcp-platform-matrix.md](docs/tcp-platform-matrix.md) | TCP 指纹平台边界 |
| [docs/benchmarks.md](docs/benchmarks.md) | 性能基准 |
| [docs/versioning.md](docs/versioning.md) / [docs/maintenance.md](docs/maintenance.md) | 版本与运营机制 |
| [profiles/evidence/README.md](profiles/evidence/README.md) | 预设证据登记 |
| [LICENSES.md](LICENSES.md) | 依赖许可证审计 |
| [docs/10-ecosystem-comparison.md](docs/10-ecosystem-comparison.md) | 生态对比与差距分析（33 库逐维对照） |
| [docs/plans/2026-09-29-self-contained-roadmap.md](docs/plans/2026-09-29-self-contained-roadmap.md) | 自主化路线图（脱离第三方指纹栈） |

## 非目标

- 不做服务端指纹采集。
- 不做浏览器级 JS 环境模拟（Canvas/WebGL 等）。
- 不内置任何绕过具体站点防护的"开箱即用"策略——只提供精确的指纹原语。
