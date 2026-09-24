# geektls

多语言 TLS/HTTP 全栈指纹伪造库：对 **ClientHello 逐字节可控**，覆盖 TLS（JA3/JA4）、HTTP/2（Akamai 指纹）、HTTP/3 + QUIC、TCP 四层指纹，提供 **Python / Node.js / Go** 三种语言的一等 API。

> 当前状态：**P0–P7 完成（一期收工）**。P1-T8（nginx 采集端 L2 终审）与 P6-T3（JA4TCP 验收）待 Linux 环境，见文末遗留表。

## 功能矩阵

| 维度 | 状态 | 验证 |
|---|---|---|
| TLS ClientHello 逐字段（ciphers/扩展序/GREASE/key_share/MLKEM/ALPS/RSL/DC/padding/ECH） | ✅ | tls.peet.ws 实测 7 预设 JA3/JA4 全 MATCH；RFC 9001 Initial 嗅探字节级 |
| 真 ECH（config_list 注入） | ✅ | cloudflare-ech.com 实测 `ECHAccepted=true` |
| JA3/JA4R/ClientHello-hex 三入口 + 自算 JA3/JA4 回读 | ✅ | FoxIO 官方向量 + 线上 round-trip |
| HTTP/2 帧层（SETTINGS 序/WINDOW_UPDATE/priority/伪头序） | ✅ | tls.peet.ws Akamai 四段全 MATCH |
| HTTP/3 + QUIC（SETTINGS/伪头序/GREASE 帧/内层 ClientHello 同 profile） | ✅ | 本地 RFC 9001 嗅探；QUIC 内层 JA4 与 TCP 仅差 q/t |
| H2/H3 racing + Alt-Svc | ✅ | 本地实测（含负缓存） |
| TCP（TTL/MSS setsockopt 档） | ✅（Windows 无 MSS） | getsockopt 读回 |
| Python / Node / Go 绑定 | ✅ | pytest 8 / node:test 7 / go test 全绿；跨语言 JA4 三方全等 |

## 快速上手

**Python**（`pip install geektls`，动态库随包）：

```python
from geektls import Session

with Session(impersonate="chrome_150") as s:
    r = s.get("https://example.com", stream=True)
    print(r.status, r.used_protocol, r.selfcheck["ja4"])
    for chunk in r.iter_bytes(65536):
        ...
```

**Node.js**（`npm install geektls`）：

```js
const { Session } = require('geektls');

const s = new Session({ impersonate: 'chrome_150' });
const r = await s.get('https://example.com');
console.log(r.status, r.usedProtocol, r.selfcheck.ja4);
for await (const chunk of r.body) { ... }
s.close();
```

**Go**（`import "github.com/geektls/golang"`）：

```go
rt, _ := geektls.NewRoundTripper("chrome_150", nil)
client := &http.Client{Transport: rt}
resp, _ := client.Get("https://example.com")
```

## 自校验

每个响应带 `selfcheck`（实际发出 ClientHello 自算的 JA3/JA4，JA3/JA4R 入口还含期望值比对）；`gtls_check_profile` 支持 profile JSON / JA3 / JA4R / hex 四入参离线自检。

## 性能摘要（docs/benchmarks.md）

- FFI 调用开销：`gtls_version` 6–7µs、`gtls_check_profile` 26–30µs（<50µs 目标达成）
- 回环吞吐（每请求新连接，10s）：Go 2.6k / Python 3.4k / Node 0.95k req/s（并发 100）
- 冷启动：Session 初始化 0.2ms、首请求 ~3.5ms

## 已知边界（如实）

| 边界 | 说明 |
|---|---|
| QUIC 内层 ECH 与 bogdanfinn 服务端 | 其 QUIC server 不处理 ECH-in-QUIC 会静默失败（客户端侧我们已合成 Chrome 等效 payload；真服务器按规范忽略 GREASE ECH） |
| QUIC Initial 布局（分片/PADDING/coalesce） | quic-go packet packer 无钩子，不可控（降级登记） |
| QUIC transport params 顺序/非标参数 | 需更深 fork internal/wire（值可控子集已上线） |
| Windows TCP MSS | 不支持（WSAENOPROTOOPT 实测），跳过+warning；raw socket 档仅 Linux 探测模式 |
| uTLS PSK 复用 vs Go std 服务端 | binder 校验失败（上游 interop，发出侧已证正确） |
| nginx L2 终审 / JA4TCP 验收 | 待 Linux 环境（WSL2/CI） |

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/00-architecture.md](docs/00-architecture.md) | 技术选型、模块划分、FFI 模型 |
| [docs/01-fingerprint-dimensions.md](docs/01-fingerprint-dimensions.md) | 四层指纹维度清单 |
| [docs/02-ffi-abi.md](docs/02-ffi-abi.md) | C ABI 契约 |
| [docs/03-profile-format.md](docs/03-profile-format.md) | profile JSON schema + 预设体系 |
| [docs/06-task-list.md](docs/06-task-list.md) | 任务计划与完成状态 |
| [docs/p1-utls-capability.md](docs/p1-utls-capability.md) / [p2-h2](docs/p2-h2-capability.md) / [p4-h3](docs/p4-h3-capability.md) | 各层能力摸底矩阵 |
| [docs/tcp-platform-matrix.md](docs/tcp-platform-matrix.md) | TCP 指纹平台边界 |
| [docs/benchmarks.md](docs/benchmarks.md) | 性能基准 |
| [docs/versioning.md](docs/versioning.md) / [docs/maintenance.md](docs/maintenance.md) | 版本与运营机制 |
| [profiles/evidence/README.md](profiles/evidence/README.md) | 预设证据登记 |
| [LICENSES.md](LICENSES.md) | 依赖许可证审计 |

## 非目标

- 不做服务端指纹采集（那是隔壁 `D:\work\tls` nginx 套件的事，两者互为验证端）。
- 不做浏览器级 JS 环境模拟（Canvas/WebGL 等）。
- 不内置任何绕过具体站点防护的"开箱即用"策略——只提供精确的指纹原语。
