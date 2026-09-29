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
uint64_t gtls_session_new(uint64_t client, const char* session_opts_json);
int      gtls_session_close(uint64_t session);
```

### 请求与响应

```c
// request_json: {"method":"GET","url":"https://...","headers":[["k","v"],...],
//                "body_b64":"...", "timeout_ms":30000, "proxy":"socks5://...",
//                "force_http3":false, "stream":true}
uint64_t gtls_request(uint64_t session, const char* request_json);  // 返回 response handle；阻塞至响应头到达

// 响应元信息（头到达即可用）
char*    gtls_response_info(uint64_t resp);   // {"status":200,"headers":[...],"used_protocol":"h2",
                                             //  "selfcheck":{"ja3":"...","ja4":"...","ja3_match":true,...}}

// 拉式流式读 body：返回读取字节数；0=EOF；-1=错误
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

### 错误与内存

```c
char*    gtls_last_error();          // 当前线程最近错误详情 JSON；无错误返回 "{}"
void     gtls_free_string(char* s);  // 释放本库返回的所有 char*
```

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
