# 04 - 阶段计划与任务分解

总工期估算 **14–17 周**（单人全职当量）。每个阶段有明确交付物与验收标准；测试不是最后阶段，而是**从 P1 起每阶段内嵌**（详见 05 文档）。

## P0 — 脚手架与 ABI 冻结（~1 周）

| 任务 | 交付物 | 验收 |
|---|---|---|
| 仓库初始化、Go module、目录结构 | 可编译空壳 | `go build ./...` 通过 |
| 依赖审计与 fork 落地 | fork 决策记录 + LICENSE 汇总 | uTLS/fhttp/quic-go fork pin commit，许可证无 GPL 污染 |
| C ABI v1 头文件 + c-shared 构建脚本 | `ffi/geektls.h`、Makefile | 三平台产出动态库 |
| hello-world 三语言冒烟 | py/js/go 各 10 行调 `gtls_version` | 三语言拿到同一版本 JSON |
| CI 骨架（GitHub Actions） | 3 OS × 3 语言矩阵跑冒烟 | 绿 |

## P1 — TLS 核心（~3 周）★ 关键路径

| 任务 | 验收 |
|---|---|
| uTLS fork 集成，ClientHello 逐字段 API（01 文档 §1 全部 A 级维度，除 ECH） | 单测：profile→构造→解析 round-trip 一致 |
| JA3 / JA4R / hex 三个便捷入口 → detail 编译器 | JA3 入口 warnings 正确标注有损项 |
| 自算 JA3/JA4 回读器 | `gtls_check_profile` 输出与 FoxIO 官方示例向量一致（用 ja4plus-go 语料子集） |
| GREASE 值与位置控制、扩展洗牌开关 | 单测覆盖 RFC 8701 全部 16 个 GREASE 值 |
| 预设体系 v1：Chrome(近 3 版本) + Firefox + Safari 各 ≥2 | `gtls_describe_preset` 展开完整；入库自校验通过 |
| **阶段验收（L2 闭环首次通电）** | 对 tls.peet.ws 与各预设官方值 diff 全绿；对本地 nginx 采集端（05 文档 L2）21 个 ClientHello 字段 diff 全绿 |

## P2 — HTTP/2 帧层（~2 周）

| 任务 | 验收 |
|---|---|
| fhttp fork 集成：SETTINGS 序、WINDOW_UPDATE、伪头序、priority 帧 | Akamai 四段指纹与真实浏览器 pcap 逐段相等 |
| HPACK 策略 + preface 分帧时序 | 与 Chrome 抓包 diff（Wireshark 脚本化比对） |
| H2 下流式请求/响应体 | 1GB 流式上下行无内存膨胀 |
| **阶段验收** | nginx 端 `$http2_fingerprint_*` 四段与期望值全等；外部 oracle（tls.peet.ws akamai_fingerprint）一致 |

## P3 — Python 绑定 + engine 层（~2 周）

| 任务 | 验收 |
|---|---|
| ctypes 绑定全套 ABI（session/request/stream/error） | requests 风格 API；`iter_bytes` 流式；handle 无泄漏（压测 10 万请求 RSS 平稳） |
| engine：cookie jar、重定向、代理（HTTP/SOCKS5）、超时 | 行为测试绿 |
| e2e harness 产品化（pytest 插件形态） | 一条命令跑"全部预设 × nginx 采集端"断言矩阵 |
| **阶段验收** | Python 包 `pip install` 可用；e2e 矩阵全绿进 CI |

## P4 — HTTP/3 + QUIC（~3 周）

| 任务 | 验收 |
|---|---|
| bogdanfinn quic-go fork 集成：12+ transport params、H3 SETTINGS、伪头序 | nginx 端 `$quic_fingerprint_*` / `$http3_fingerprint_*` 与期望值一致 |
| Initial datagram 布局（分片/PADDING/coalesce）、QUIC GREASE 帧 | 对照 impersonator 维度清单逐项有结论（实现/标记不可控） |
| H2/H3 racing、Alt-Svc、0-RTT 行为 | 行为测试 |
| **阶段验收** | H3 链路四层指纹全绿；ja4plus-go 离线 pcap 交叉验证 JA4 一致 |

## P5 — Node + Go 绑定（~1.5 周）

| 任务 | 验收 |
|---|---|
| koffi Node 绑定（Promise + Readable） | 与 Python API 概念一一对应；npm 包可装 |
| Go 薄封装（RoundTripper） | `http.Client` 无缝替换 |
| 三语言 API 一致性测试（同一 profile 三语言各自发包，nginx 采集结果三者全等） | 跨语言一致性矩阵绿 |

## P6 — TCP 指纹（~2 周）

| 任务 | 验收 |
|---|---|
| setsockopt 档：TTL/MSS（Linux/macOS/Windows 尽力） | 对端 pcap 验证 TTL/MSS 生效 |
| raw socket 档（Linux root）：window/WS/options 序 | nginx 端 `$http_ssl_ja4tcp_*` 与设定一致 |
| 文档化平台边界 | 用户不会对 Windows raw socket 有错误预期 |

## P7 — 硬化与发布（~2 周，之后持续）

- ECH、session resumption/0-RTT 完整化
- fuzz：畸形 profile/hex 输入不 panic（ABI 边界 recover 验证）；tlsfuzzer 反向打我们的 TLS 栈
- 性能基准：目标 ≥ wreq-js 量级（10k+ req/s 本地回环）；FFI 开销单独量化
- 发布：三语言包（PyPI/npm/Go module）+ 动态库按平台分发 + 版本锁定策略文档
- 文档：API reference、预设列表、与真实浏览器一致性的 evidence 目录

## 里程碑视图

```
P0 脚手架 ──► P1 TLS核心 ★ ──► P2 H2 ──► P3 Python+engine ──► P4 H3/QUIC ──► P5 Node/Go ──► P6 TCP ──► P7 硬化
   1w           3w              2w         2w                  3w             1.5w        2w        2w
               └─ L2 闭环首次通电（本项目最关键的验证时刻：伪造端 ↔ 自家 nginx 采集端全字段对齐）
```

P1 风险最高（uTLS 改造深度未知），若超期优先砍 P6 而非压缩 P1/P4 的测试。
