# 02 - C ABI 契约（FFI 层）

core 以 Go c-shared 构建（`libgeektls.so/.dll/.dylib`）。ABI 设计原则：**JSON 进、JSON 出、handle 居中、拉式流式、无跨 ABI 回调**。所有函数线程安全；同一 handle 不得并发使用。

## 1. 函数表（v1）

### 生命周期与元信息

```c
char*  gtls_version();                        // 返回版本 JSON，调用方负责 gtls_free_string
int    gtls_init(const char* options_json);   // 全局初始化（日志级别等），幂等
```

### Client / Session

```c
// config_json: {"impersonate":"chrome_150"} 或 {"profile":{...完整 JSON...}}
//              或 {"ja3":"..."} / {"ja4r":"..."} / {"clienthello_hex":"..."}
uint64_t gtls_client_new(const char* config_json);        // 0 = 失败，查 gtls_last_error
int      gtls_client_close(uint64_t client);

// 会话：在 client 内建独立 cookie jar / 连接缓存
// session_opts_json: {"proxy":...,"proxy_from_env":true,"timeout_ms":30000,"read_timeout_ms":0,
//                     "resolve":{"host[:port]":"IP"},"local_address":"IP","ip_version":"4",...}
// timeout_ms 覆盖"dial+TLS+响应头"；read_timeout_ms 是每次 gtls_response_read
// 的空闲上限（0/省略 = 不限，与历史行为一致）。
uint64_t gtls_session_new(uint64_t client, const char* session_opts_json);
int      gtls_session_close(uint64_t session);
```

**未知键的口径（写新绑定必须知道）**：上面两段 JSON 的解码都**不严格**——
`gtls_client_new` 只从 config 里查 `impersonate`/`profile`/`ja3`/`ja4`/`ja4r`/
`clienthello_hex` 六个键，`SessionOptions` 忽略未知字段。也就是说 `local_addr`、
`insecure_skip_verfy` 这类拼错进到 ABI 就无声消失，而这些键决定"校验开不开、超时走不走、
连接钉到哪"。名单校验因此做在**绑定层**：Python `_SESSION_LEVEL_FIELDS` /
`_REQUEST_LEVEL_FIELDS`、Node `CLIENT_CONFIG_KEYS` / `SESSION_OPTION_KEYS`
（引擎原名允许透传，名单外的键立即报错）；Go 绑定是强类型结构体，天然拼不错。

#### 代理形态与已知边界（A8）

`proxy` 支持的 scheme：`http`/`https`（CONNECT 隧道，`user:pass` → `Proxy-Authorization`）、
`socks5`（本地解析域名后交代理解 IP）、`socks5h`（域名交给代理）、`socks4`/`socks4a`
（RFC 1928 之前的老协议：**只有 IPv4 目标**（IPv6 直接报错），鉴位只有 NUL 结尾的
user id、**没有口令**（URL 里给口令会在建会话时就报错，不会静默丢掉当匿名请求）；
`4a` 用 DSTIP=`0.0.0.1` + HOST 字段把域名交给代理解析，IPv6 目标直接报错）。
未显式给 `proxy` 时按 `HTTPS_PROXY` → `ALL_PROXY`（大小写都认）派生，`NO_PROXY` 豁免；
`proxy_from_env:false` 可完全关掉（curl 的 `--proxy` 与 requests 的 `trust_env=False` 同义）。
两条刻意的偏离：① `NO_PROXY` 只做字面量/CIDR 匹配、**不对目标做 DNS**（Go 的
`ProxyFromEnvironment` 会先解析目标，且**解析失败即返回"直连"**——域名写错或临时
解不出时代理被静默跳过，指纹就漏了；我们不解析，同一个 URL 每次走同一条路）；② 回环目标
（`localhost`/`127.0.0.1`/`::1`）不吃**环境变量派生**的代理（Chrome/Go 同规则），
显式给的 `proxy` 对回环仍生效——否则开发机挂上 `ALL_PROXY` 就连不上本地测试服务。
③ **有代理时 H3/QUIC 一律不参与**（racing、Alt-Svc 升级都跳过）：QUIC 过代理需要
CONNECT-UDP（RFC 9298），未实现；`force_http3` + 代理在拨号前就报 invalid，
而不是静默直发把指纹漏出去。

#### 目标地址控制（A9）

三项会话级选项，只改"连到哪 / 从哪出去"，**不改线上指纹字节**：SNI、`Host`/`:authority`、
伪头、ClientHello 全部沿用 URL 里的原域名——所以它们不属于 profile（profile 描述
"伪装成谁"，这三项描述"这次跑在哪台机器上"）。

| 键 | 形态 | 对齐 | 边界 |
| --- | --- | --- | --- |
| `resolve` | `{"host":"IP"}` 或 `{"host:port":"IP"}` | curl `--resolve` | 值必须是 IP 字面量（不再做一次 DNS）；键**不做通配**，钉 `example.com` 不连带钉 `cdn.example.com`；`host:port` 键优先于 `host` 键 |
| `local_address` | 源 IP 字面量 | curl `--interface` 的 IP 形态、httpx `local_address` | **不接受网卡名**（Go 的 `Dialer.LocalAddr` 只认地址，按网卡绑要 `SO_BINDTODEVICE`，跨平台不对齐）；代理场景绑的是到代理那一条 socket |
| `ip_version` | `"4"` / `"6"`（也认 `v4`/`ipv4`/`any`/空） | curl `-4`/`-6` | 与 `local_address`/`resolve` 取值矛盾时**建会话就报** `invalid_config`；目标是 IP 字面量且族不符同样报错，不会"挑一个能连的" |

生效范围按"谁做解析"划线：直连、`tcp.mode=netstack`、`socks5`、`socks4`（这几档我们
自己在本地解析）三项全生效；`CONNECT`、`socks5h`、`socks4a` 是把名字交给代理解析，
`resolve` 与 `ip_version` **不参与**（本地钉位掺进去等于偷偷把远端 DNS 换成本地 DNS，
那正是这几档要区分的唯一东西），`local_address` 仍生效。钉位命中时连的是 IP，但 SNI
照发（JA4 的 `d`/`i` 标志不变）——`selfcheck.sni_sent` 可核对。

`tcp.mode=netstack` 与 `resolve` 是互相成全的：netstack 只吃 IPv4 字面量目标，钉位正好
供给它；但 netstack 的源地址由 TUN 拓扑固定，`local_address` 在它上面**直接报错**而不是
静默不绑。地址控制没有接进 QUIC 拨号，故 `force_http3` + 任一项在建会话后的第一次请求
就报 invalid（与 A8 同一口径：宁可报错，也不发一条没按用户要求走的连接）。

### 请求与响应

```c
// request_json: {"method":"GET","url":"https://...","headers":[["k","v"],...],
//                "body_b64":"...", "timeout_ms":30000, "read_timeout_ms":5000,
//                "proxy":"socks5://...",
//                "force_http3":false, "stream":true, "auto_decompress":true}
// auto_decompress（T-DECOMP）：响应按 Content-Encoding 透明解压，默认 true；
// 请求级覆盖会话级同名开关（session_opts_json 里也可设）。
// read_timeout_ms 只作用在 body 读取阶段，请求级覆盖会话级。
uint64_t gtls_request(uint64_t session, const char* request_json);  // 返回 response handle；阻塞至响应头到达

// 响应元信息（头到达即可用）
char*    gtls_response_info(uint64_t resp);   // {"status":200,"headers":[...],"used_protocol":"h2",
                                             //  "selfcheck":{"ja3":"...","ja4":"...","ja3_match":true,...}}

// 拉式流式读 body：返回读取字节数；0=EOF；-1=错误
// 超过 read_timeout_ms 的空闲 → -1 且 code="read_timeout"；本次 body 之后只会
// 重复该错误，底层连接已作废（不会把调用线程挂住）。
int64_t  gtls_response_read(uint64_t resp, char* buf, int64_t buf_len);
int      gtls_response_close(uint64_t resp);  // 未读完即关闭 = 取消
```

### 流式上传（二期 T2 追加；ABI 号不变——只增不改）

```c
// 开始流式上传：request_json 同 gtls_request（body_b64 忽略）；
// 请求行与头部立即发出，body 逐块写。返回 upload handle；0 = 失败。
uint64_t gtls_request_begin(uint64_t session, const char* request_json);

// 写一块 body：H1 = 一个 chunk 帧（Transfer-Encoding: chunked），H2 = DATA 帧流。
// 返回写入字节数；-1 = 错误。空写（len 0）是 no-op。
int64_t  gtls_request_write(uint64_t upload, const char* buf, int64_t buf_len);

// 结束 body（H1 发终止 0-chunk）并阻塞至响应头到达，返回 response handle
// （之后与 gtls_request 返回值同样使用）；0 = 失败。成败 upload handle 都失效。
uint64_t gtls_request_finish(uint64_t upload);
```

### WebSocket（T-WS 追加；ABI 号不变——只增不改）

```c
// 建立 wss 连接（走指纹链路，ALPN 收窄 http/1.1，Upgrade 头序受控）。
// url_json: {"url":"wss://...","headers":[["k","v"],...],"timeout_ms":30000,
//            "compress":false}
//   compress=true ⇒ 握手补发 `sec-websocket-extensions: permessage-deflate`
//   （不带参数，排在 sec-websocket-key 之后，即 Chrome 形态）；只有对端在 101
//   里真的按我方 offer 接受才启用压缩，此后 send/recv 收发的仍是明文
//   （RFC 7692 的 RSV1 位与 context takeover 都在库里透明处理）。
//   默认 false：不发这个头也不压——没有逐浏览器 WS 握手的字节级证据，就不乱发。
//   要精确控制 offer 参数（server_no_context_takeover 等）自己写那个头。
uint64_t gtls_ws_connect(uint64_t session, const char* url_json);

// 发一帧（opcode 1=text 2=binary 8=close 9=ping 10=pong；客户端自动 masking）
int      gtls_ws_send(uint64_t ws, int opcode, const char* buf, int64_t buf_len);

// 收一条完整消息（分片重组；ping 自动回 pong）：返回字节数，
// opcode 经 opcode_out 返回（8=对端关闭）；-1 = 错误
int64_t  gtls_ws_recv(uint64_t ws, char* buf, int64_t buf_len, int timeout_ms, int* opcode_out);

// 发 close 帧并释放 handle（code<=0 不带状态码）
int      gtls_ws_close(uint64_t ws, int code);
```

注：H2 上的 WS（RFC 8441 Extended CONNECT）不做——Chrome 实际仍以 H1
Upgrade 为主（capability-matrix `ws.rfc8441_h2`）。

`compress` 只是 url_json 里多一个键，函数签名与 ABI 号不变（只增不改，见
CONTRACT-FREEZE）；代价是**旧构件会静默忽略它**，而 ABI 号又不会变，
`gtls_version()` 查不出差别。口径：压缩与否只以"握手真的协商成功"为准
（库不会把没压的说成压了），要这个行为就得确认构件是新的。

### 错误与内存

```c
char*    gtls_last_error();          // 当前线程最近错误详情 JSON；无错误返回 "{}"
char*    gtls_error_of(uint64_t h);  // handle h 最近一次失败的错误 JSON；无记录返回 "{}"
void     gtls_free_string(char* s);  // 释放本库返回的所有 char*
```

两个入口给两种绑定模型：错误槽默认是**线程局部**的（`gtls_last_error`），而
把阻塞调用挪到别的线程上执行的绑定（Node/koffi 的 `.async`、自建 executor）
调用在 worker 线程写槽、回到主线程查是自己的空槽——这类绑定按 handle 查
`gtls_error_of`（`gtls_request`/`gtls_ws_connect` 失败查 session handle，
`gtls_response_read` 失败查 response handle）。只读，不清槽。

### 预设与自校验

```c
char*    gtls_list_presets();                       // 预设清单 JSON
char*    gtls_describe_preset(const char* name);    // 预设展开为完整 profile JSON（= 期望值，测试直接消费）
char*    gtls_check_profile(const char* profile_json_or_ja3_or_ja4r);
        // 不发包，离线构造 ClientHello 并返回 {"ja3":...,"ja4":...,"wire_len":N,"warnings":[...]}
```

## 2. 内存与并发规则

1. 凡返回 `char*` 的函数，所有权移交调用方，必须 `gtls_free_string`。
2. handle 以 `uint64` 传递，core 内 `sync.Map` 注册；`close` 后立即失效，重复 close 返回错误（不崩溃）。
3. `gtls_response_read` 的 `buf` 由调用方分配，core 只写不持有。
4. 无回调：进度/异步一律 poll。需要后台下载的场景由绑定层在自己的线程里循环 `read`。
5. Go 侧 panic 在 FFI 边界全部 recover，转成 `gtls_last_error`——panic 绝不越过 ABI。
6. **并发（二期阶段 5 起）**：同一 **session** handle 可并发发 `gtls_request` /
   `gtls_request_begin`（引擎内连接池/缓存均加锁，Python 线程池、Node worker
   场景安全）；**response / upload handle 仍不可并发使用**（属于单次请求的状态）。

## 3. 绑定层形态

### Python（`bindings/python`，ctypes，零编译依赖）

```python
from geektls import Session

s = Session(impersonate="chrome_150")          # 或 profile={...} / ja3="..." / ja4r="..."
r = s.get("https://example.com")               # requests 风格：params/data/json/timeout 都支持
r.status_code, r.ok, r.used_protocol           # 200 True 'h2'
r.headers["content-type"]                      # 大小写不敏感
r.text, r.content, r.json()                    # 按需读取并缓存（无需手动 iter_bytes）
assert r.selfcheck["ja3_match"]
for line in r.iter_lines(): ...                # 需要流式时
```

- `ctypes.CDLL` 加载；`.content`/`.text`/`.json()` 内部循环 `gtls_response_read` 读完并缓存，
  大响应想边收边处理再用 `iter_content(chunk_size)`（旧名 `iter_bytes` 仍可用）。
- `__del__` + context manager 双保险释放 handle。
- 发布：纯 Python wheel + 按平台分发动态库（auditwheel/delocate 策略 P7 定）。

### Node.js（`bindings/nodejs`，koffi，无 node-gyp）

```js
const { Session } = require('geektls');
const s = new Session({ impersonate: 'chrome_150' });
const r = await s.get('https://example.com');       // Promise
for await (const chunk of r.body) { ... }           // Node Readable
console.log(r.selfcheck);
```

- koffi 做 FFI（免编译）；`Readable` 封装 read 循环。

### Go（`bindings/golang`）

不走 FFI，`import "github.com/geektls/core"` 的薄封装，暴露 `http.RoundTripper` 兼容接口：

```go
rt, _ := gbt.NewRoundTripper(gbt.Preset("chrome_150"))
client := &http.Client{Transport: rt}
```

## 4. ABI 版本化

- `gtls_version()` 返回 `{"abi":1,"core":"0.x.y","uTLS":"<commit>"}`。
- ABI 只增不改：新增函数追加，不删不改签名；破坏性变更升 `abi` 号，旧函数保留一个周期。
- 绑定层启动时核对 abi 号，不匹配报清晰错误（防止 Python 包和 DLL 版本错配——noble-tls 用户最常见的坑）。
