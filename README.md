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
| HTTP/2 帧层（SETTINGS 序/WINDOW_UPDATE/priority/伪头序） | ✅ | tls.peet.ws Akamai 四段全 MATCH |
| HTTP/3 + QUIC（SETTINGS/伪头序/GREASE 帧/内层 ClientHello 同 profile） | ✅（机制） | Chrome 149 H3 E1 真机采集完成（tests/e2e/e1_h3_test.go，证据 profiles/evidence/browsers/chrome_windows_h3.json）；QUIC 内层 JA4 与真机逐字符相同（钉在 quic_sniff_test.go）；transport params 顺序/非标参数经 T4-1 blob 直通可控；**Initial 布局仍不可控、quic_grease_frames 未验证、Firefox/Safari H3 未实测**（见能力矩阵） |
| HTTP/2 HPACK 编码策略（chrome/firefox/safari/generic 四档，vendor fork fhttp） | ✅ **249/363 预设已带** | 逐字节块表示断言（索引/literal/Huffman/动表复用）；chrome 档有 QUICHE 源码级证据，firefox 档有 Firefox 59 字节级证据，safari 档为保守近似待 E1；工具与无法归族的内嵌浏览器**刻意留空**（见 docs/p2-h2-capability.md §覆盖面） |
| H2/H3 racing + Alt-Svc | ✅ | 本地实测（含负缓存） |
| 连接池（H2 多路复用/H1 keep-alive/H3 共享 transport，并发安全） | ✅ | go test -race 零竞争；echo 侧连接数断言 |
| 流式上传（H1 chunked / H2 DATA，三语言绑定迭代器入参） | ✅ | 线上字节逐字节断言 |
| TCP（TTL/MSS setsockopt 档） | ✅（Windows 无 MSS） | getsockopt 读回 |
| Python / Node / Go 绑定 | ✅ | pytest 12 / node:test 10 / go test -race 全绿；跨语言 JA4 三方全等 |

## 安装

```bash
pip install geektls          # Python（manylinux_2_28 x86_64/aarch64、macOS 11.0+ arm64/x86_64、Windows x64，动态库随 wheel 分发）
npm install geektls          # Node.js（⚠️ 尚未发布到 npm，当前请用仓库内 bindings/nodejs）
go get github.com/geektls/core   # Go（⚠️ 模块尚未推送到公网仓库，当前用本地 replace）
```

已发布到 PyPI 的 0.1.5 wheel 覆盖五平台：**manylinux_2_28 x86_64 / aarch64、macosx_11_0 arm64 / x86_64、win_amd64**
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
# {"abi": 1, "core": "0.1.5", "utls": ""} / 363 presets
```

> `version()["utls"]` 为空是既定状态（uTLS fork 版本位尚未接线）。

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

## 指纹怎么传：整体与局部

`Session(...)` 的指纹入参**六选一**（互斥，同时给以靠前的为准，优先级按下列顺序）：

| 入参 | 语义 | 保真度 | 备注 |
|---|---|---|---|
| `impersonate="chrome_150"` | 用内置预设（363 条） | 高（多数有 E1/E2 证据） | 名字是**全名**：`chrome_154_macos`、`chrome_154_windows`、`okhttp_3_12_12`…（没有裸 `chrome_154`） |
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
| `version()` | `-> dict` | `{"abi":1,"core":"0.1.5","utls":""}`；启动时可用它断言 ABI 匹配 |
| `init(options=None)` | `-> None` | 幂等初始化钩子（当前无全局状态，留作后续） |
| `last_error()` | `-> dict` | 最近一次失败的结构化错误（`code`/`message`/`op`） |
| `list_presets()` | `-> list[str]` | 全部内置预设名（排序，363 条） |
| `describe_preset(name)` | `-> dict` | 预设**展开后的规范 JSON**（ciphers/扩展/H2/H3/身份头全展开） |
| `check_profile(spec)` | `-> dict` | 离线自检：profile JSON / JA3 / JA4 / JA4R / hex → `{ja3,ja3_hash,ja4,wire_len,warnings}` |
| `GeekTLSError` | 异常类 | 所有失败都是它；`.code` 结构化错误码（`invalid_config`/`request_failed`/…） |

### `Session`

```python
Session(impersonate=None, *, profile=None, ja3=None, ja4=None, ja4r=None,
        clienthello_hex=None, headers=None, proxies=None, timeout=None,
        verify=None, allow_redirects=None, cookies=None, **options)
```

| 参数 | 类型 | 说明 |
|---|---|---|
| `impersonate` / `profile` / `ja3` / `ja4` / `ja4r` / `clienthello_hex` | str / dict / str | 六选一（见上一节） |
| `headers` | dict / list[tuple] | 会话默认请求头（按给定顺序发出） |
| `proxies` | dict / str | requests 风格；引擎一次只用一个代理 URL（`{"https": ...}` / `{"all": ...}`） |
| `timeout` | float 秒 | 映射到引擎 `timeout_ms`；请求级可用 `timeout_ms=` 覆盖 |
| `verify` | bool | `False` ⇒ 跳过证书校验（**会话级**） |
| `allow_redirects` | bool | `False` ⇒ 不跟随重定向（**会话级**） |
| `cookies` | bool | 开关会话 Cookie jar（要带具体 Cookie 就往 `headers` 塞 `Cookie`） |
| `**options` | — | 其余原样透传引擎会话选项（`proxy`/`timeout_ms`/`redirect_max`/`insecure_skip_verify`/`cookie_jar`…） |

| 方法 | 说明 |
|---|---|
| `request(method, url, *, params=None, data=None, json=None, headers=None, body=None, timeout=None, timeout_ms=None, proxy=None, stream=None, force_http3=None, **kwargs)` | 通用请求；**头到达即返回**，body 按需读取 |
| `get / post / put / patch / delete / head / options(url, **kwargs)` | 便捷动词，等价于 `request` |
| `close()` | 释放会话（挂连接池/transport） |
| `with Session(...) as s:` | 自动 `close()` |

> ⚠️ `verify` / `allow_redirects` 是**会话级**：传给 `request()` 会**明确报错**而不是静默失效（要按请求切换就新建 Session）。
>
> ⚠️ 未知关键字会原样透传给引擎，写错了不会静默吞掉——引擎会对未知选项报 `invalid_config`。

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
| `json(**kwargs)` | Any | `json.loads(self.text, **kwargs)` |
| `iter_content(size)` / `iter_bytes(size)` / `iter_lines(size)` | 生成器 | 边收边处理大响应（`iter_bytes` 是旧名） |
| `header(name, default=None)` | str | 取单个响应头 |
| `raise_for_status()` | None | `>=400` 抛 `GeekTLSError`（异常上挂 `.response`） |
| `close()` | None | 释放响应句柄（未读完 body 时更要显式调用） |

## Node.js API 参考

```js
const { Session, version, listPresets, describePreset, checkProfile, lastError, GeekTLSError } = require('geektls');
```

| 成员 | 说明 |
|---|---|
| `new Session(options)` | `options` 同 Python：指纹入参六选一 + `proxy`/`proxies`、`timeoutMs`/`timeout`、`redirectMax`/`allowRedirects`、`cookieJar`、`insecureSkipVerify`/`verify`、`headers` |
| `s.request({method, url, ...})` | 返回 `Promise<Response>`（不阻塞事件循环） |
| `s.get/post/put/patch/delete/head/options(url, options)` | 便捷动词 |
| `s.close()` | 释放会话 |
| `r.statusCode` / `r.ok` / `r.reason` / `r.headers` / `r.usedProtocol` / `r.selfcheck` | 同 Python 语义 |
| `await r.read()` / `r.bytes()` / `r.text()` / `r.json()` / `r.header(name)` | body 读取 |
| `r.iterContent(size)` / `r.iterLines(size)` | 异步迭代器（`for await`） |
| `r.close()` | 释放 |
| `version()` / `init()` / `lastError()` / `listPresets()` / `describePreset(name)` / `checkProfile(input)` | 与 Python 同名同语义 |

## Go API 参考

两条路：**绑定层**（`github.com/geektls/golang`，`http.Client`/`RoundTripper` 形态）与**引擎直连**（`core/engine`，能力最全）。

| 包 | 关键 API | 说明 |
|---|---|---|
| `core/profiles` | `List()` / `Get(name)` / `Describe(name)` / `FromJA3` / `FromJA4R` / `FromClientHelloHex` / `NormalizeForReplay` / `Parse` | 预设与指纹入口（含上面说的自洽归一） |
| `core/tls` | `CompileDetail` / `ComputeJA3` / `ComputeJA4` / `JA3Hash` / `CheckProfile` / `ResolveJA4Preset` | 编译、自算、离线自检、JA4 反查 |
| `core/engine` | `NewSession(profile, SessionOptions)` → `Do(*Request)` → `*Response`（`StatusCode/OK/Reason/Header/Text/JSON/IterBytes/Close`） | 引擎直连；支持 H2/H3 racing、Alt-Svc、代理、流式 |
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
              "window_update": 15663105, "pseudo_header_order": ["m", "a", "s", "p"]},
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

- **数量与命名**：363 条，`core/profiles/builtin/<name>.json`，**文件名即预设名**（`chrome_154_windows`、`firefox_156_android`、`okhttp_3_12_12`、`curl_8_16_0`…）。**没有族级短名**，也没有别名匹配——`impersonate="chrome_154"` 会报 `preset not found`。
- **字段**：`tls.detail`（ciphers/扩展与负载/GREASE 策略）、`http2`（SETTINGS/WU/伪头序/`hpack_strategy`/`headers_priority`）、`http3`（transport params/inner hello 规约）、`identity`（导航头集合与顺序）、可选 `tcp`、`grade`、`source`。
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

对比依据：各项目公开 README / 文档，以及本机维护的库家族矩阵 `tls-spoofing-library-matrix`。
**未做逐行源码审计的项目在"栈 / 语言"列标注"未核实"**；单元格里的 `—` 表示公开材料未说明该维度
（不等于该库没有）。

### 完整客户端（TLS / H2 / H3 伪装客户端）

| 项目 | 栈 / 语言 | TLS 指纹 | H2 帧 + 头序 | H2 HPACK 策略 | H3 / QUIC | 四层 TCP | 预设与证据 | 响应内自校验 |
|---|---|---|---|---|---|---|---|---|
| **geektls** | Go（c-shared 动态库）+ Python / Node / Go 绑定 | ✅ uTLS fork + E1 真机采集链路 | ✅ | ✅ **四档**（generic / chrome / firefox / safari），249/363 预设带值 | ✅ ClientHello 注入 + transport params blob 直通；Initial 布局不可控 | ✅ TTL / MSS（Windows 无 MSS）；raw socket 仅 Linux 探测模式 | ✅ 363 条，`grade`/`source` 分级：30 自测 / 6 E2i / 8 E2i-u / 319 E3 | ✅ 响应带 selfcheck（JA3 / JA4 / 扩展序 / GREASE 实测值）+ `check_profile` 五入参离线自检 |
| `bogdanfinn/tls-client`（+ `hrequests`、`noble-tls`、`Rckov/tls-client-sharp`、`wreq-js` 等绑定） | Go `fhttp` + `utls` | ✅ | ✅ | — | ✅ | — | 自带 profile 集；geektls 的 319 条 E3 覆盖即导入自这里 | — |
| `lexiforest/curl_cffi`（活跃）/ `lwthiker/curl-impersonate`（原始） | libcurl 补丁 + BoringSSL / NSS | ✅ | ✅ | — | ❌ 只到 H2 | — | 内置若干浏览器画像；社区补丁节奏最快 | — |
| `Danny-Dasilva/CycleTLS`、`cycletls_python` | Go `utls` + `fhttp` + `quic-go` | ✅ | ✅ | — | ✅ | — | profile 清单 | — |
| `akamai/uls`（Unified TLS/HTTP spoofing） | Go（Akamai 内部实现开源版） | ✅ Chrome | ✅ Chrome | — | — | ❌ | 面向 Chrome | — |
| `sardanioss/httpcloak`、`azuretls-client` | Go fork 系（utls / fhttp / uquic） | ✅ | ✅ | — | ✅ 依赖 fork | — | 浏览器 profile + 头序 | — |
| `deedy5/primp`、`wreq` 系 | Rust + BoringSSL 风格控制 | ✅ | ✅ | — | 部分 | — | 未核实 | — |
| `jaredboynton/specter` | Rust + BoringSSL + 自研 H2 / H3 | ✅ | ✅ 记录分帧 / 帧时序 / 池行为 | — | ✅ | — | 未核实 | — |
| `zhkl0228/impersonator` | Java / BouncyCastle / OkHttp 改造 | ✅ | ✅ OkHttp 形态 | — | — | — | OkHttp 行为参照 | — |
| `wangluozhe/requests`、`requests-go`、`z402166914/pyhttpx`、`tocha688/curl-cffi-node` | 各语言 HTTP 客户端封装 | 依赖上游 | 依赖上游 | — | — | — | — | — |

### 采集 / 检测 / 代理（对照面，不是竞品）

| 项目 | 作用 | 与 geektls 的关系 |
|---|---|---|
| `gospider007/fp` | 独立 ClientHello 解析器 | E1 采集链路直接使用（`tests/e2e/cmd/e1-browser`） |
| `FoxIO-LLC/ja4`、`Crank-Git/ja4plus-go`、`XOR-op/ja-tools` | JA3 / JA4 / JA4+ 参考实现 | JA4 规范与测试向量来源；只依赖 JA4 本体（JA4+ 部分方法有许可证限制） |
| `wi1dcard/fingerproxy`、`LyleMi/ja3proxy`、`O-X-L/haproxy-ja4-fingerprint` | 反向代理 / 网关算指纹并透传 | 输出形态对照；selfcheck 做在响应里，不依赖网关 |
| `jaeles-project/gospider`、gitee `baixudong/gospider`、`Ecalose/gospider` | 爬虫 / 工具链（同名不同项目） | 爬虫侧用法参照 |
| `tlsmask/tlsmask`、`thesatellite-ai/fetchr`、`Easonliuliang/helloprint` | 指纹伪装 / 一致性工具 | UA ↔ TLS 一致性思路照面；落成身份层守门测试 |

### 上表里 geektls 的差异点

1. **四层一起**：TLS + H2（含 HPACK 编码策略四档）+ H3 / QUIC + TCP（TTL / MSS）。上表其他客户端多数止步 TLS / H2。
2. **证据分级**：`grade`（30 自测 / 6 E2i / 8 E2i-u / 319 E3）+ `source` 守门 + E1 真机采集链路 + 语料回归 + 外部 oracle 周检；同类普遍只给一份清单，不区分实测与转写。
3. **响应内自校验**：本次握手实际发出的 JA3 / JA4 / 扩展序 / GREASE 值直接从响应取，可当回归断言；`check_profile` 支持五种入参离线自检。
4. **三语言同引擎**：Python / Node / Go 共用同一 C ABI，跨语言 JA4 三方全等，不需要为每种语言重写指纹栈。
5. **预设结构**：363 条按 `grade` 分层（30 自测可参与严格断言 + 6 E2i / 8 E2i-u 谱系内插 + 319 E3 导入），覆盖浏览器 / App / 工具 / 代理等 29 族，含跨平台同版本一致性断言（`chrome_152` / `chrome_154` 在 macOS / Android / Windows 上 JA4 逐字符相同）。
6. **部署形态**：Go 实现、CGO 只用于构建动态库，产物是单文件动态库 + 平台 wheel，无需 libcurl 补丁链。

T-HPACK 四档的证据来源：chrome 档对齐 Chromium QUICHE `HpackEncoder` 的默认策略（源码级），
firefox 档对齐 Firefox 59 抓包（字节级），safari 档为保守近似（待 E1 校验）；上游 x/net 编码器
"一切皆可入动表"的行为与前三者都不同。

### 相对短板（同一张表下的客观差距）

| 维度 | 差距 |
|---|---|
| 生态与熟悉度 | 远不如 `curl_cffi` / `curl-impersonate`：Python 迁移成本、示例与社区最少；没有 `hrequests` 那种浏览器自动化集成 |
| 预设更新 | 依赖人工采样（SLA 2 周）；大量预设是 E3 转写而非实测，`curl_cffi` / `curl-impersonate` 靠社区补丁更快 |
| H3 可控面 | QUIC Initial 布局（分片 / PADDING / coalesce）不可控；transport params 顺序靠 blob 直通；Firefox / Safari H3 未实测 |
| Safari 侧 | HPACK 的 safari 档是全 literal 保守近似；padding 用实测字节数表达；无 CFNetwork 字节级证据 |
| 四层 | 只有 TTL / MSS（Windows 无 MSS）；window / window_scale / options 仅 Linux 探测模式 |
| 发布面 | npm 与 Go module 尚未发布；wheel 只覆盖 5 平台（无 musllinux / Windows ARM64） |
| 依赖 fork | `fhttp`、`quic-go-utls` 是 vendor fork，升级上游要重打 patch 并跑回归（流程已登记，仍是维护成本） |
| 有损入口 | JA3 / JA4 入参天然丢负载，此处选择"如实告警"而不是"看起来像"，在只求"JA3 过检测"的场景不是最省事的路径 |

## 已知边界与不足（如实）

| 边界 | 说明 |
|---|---|
| QUIC 内层 ECH 与 bogdanfinn 服务端 | 其 QUIC server 不处理 ECH-in-QUIC 会静默失败（客户端侧已合成 Chrome 等效 payload；真服务器按规范忽略 GREASE ECH） |
| QUIC Initial 布局（分片/PADDING/coalesce） | quic-go packet packer 无钩子，不可控（降级登记） |
| QUIC transport params 顺序/非标参数 | 已经 T4-1 blob 直通可控（顺序/值硬断言全绿）；个别残余值与 blob 整块替换冲突，待 fork 决策（能力矩阵 H3-7） |
| Windows TCP MSS | 不支持（WSAENOPROTOOPT 实测），跳过+warning；raw socket 档仅 Linux 探测模式 |
| uTLS PSK 复用 vs Go std 服务端 | binder 校验失败（上游 interop，发出侧已证正确） |
| JA4 短哈希入参 | 哈希不可逆 ⇒ 只能反查内置预设；想精确复刻必须给 JA4R 或完整 profile |
| nginx L2 终审 | ✅ 已通过（WSL2，35/35）；JA4TCP 验收仍需真实二层网络 |

## 开发与发布

```bash
make build                     # 构建动态库到 build/
make smoke                     # Go/Python/Node 三语言冒烟
cd core && go test ./...       # 引擎全量（含 E1/E2 门禁、语料回归）
cd tests/e2e && go test ./...  # e2e：生成器守门、HPACK/H2 回放、loopback、跨语言
wsl -d Ubuntu -- bash scripts/wsl-test.sh   # Linux 侧验证（WSL，Go 自动装到 ~/.local）
```

- **发布**：`docs/versioning.md`（语义化 + ABI 规则 + 三处版本同步）；PyPI 流水线 `.github/workflows/release-pypi.yml`（五平台 wheel）、CI `.github/workflows/ci.yml`（含"预设必须等于生成器产物"逐字节守门）。
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
| [docs/tcp-platform-matrix.md](docs/tcp-platform-matrix.md) | TCP 指纹平台边界 |
| [docs/benchmarks.md](docs/benchmarks.md) | 性能基准 |
| [docs/versioning.md](docs/versioning.md) / [docs/maintenance.md](docs/maintenance.md) | 版本与运营机制 |
| [profiles/evidence/README.md](profiles/evidence/README.md) | 预设证据登记 |
| [LICENSES.md](LICENSES.md) | 依赖许可证审计 |

## 非目标

- 不做服务端指纹采集。
- 不做浏览器级 JS 环境模拟（Canvas/WebGL 等）。
- 不内置任何绕过具体站点防护的"开箱即用"策略——只提供精确的指纹原语。
