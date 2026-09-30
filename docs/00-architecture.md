# 00 - 架构设计与技术选型

## 1. 核心问题

geektls 需要一个能**逐字节控制 ClientHello** 的 TLS 栈、能控制帧层的 H2 栈、能控制 transport params 的 QUIC 栈，然后以三种语言可用、可持续维护的方式交付。选型的本质是选"哪条现成的生态路线改造成本最低、天花板最高"。

## 2. 候选路线对比

业内魔改 TLS 指纹本质上是两条大路——**Go uTLS 二开**与**curl-impersonate（curl + 浏览器原生 TLS 栈）**——外加若干小众路线。全部对比如下：

| 路线 | 代表项目 | 优势 | 劣势 | 结论 |
|---|---|---|---|---|
| **Go: uTLS + fhttp + quic-go fork** | bogdanfinn/tls-client、CycleTLS、noble-tls、fp | uTLS 是 ClientHello 伪造事实标准；fhttp fork 已解决 H2 SETTINGS 序/伪头序；bogdanfinn 的 quic-go fork 已解决 H3 指纹；preset 生态现成；c-shared 交付模式被 noble-tls 验证；逐字段 API 与 hex 回放天然可行 | 一致性靠"演"，需测试闭环兜底；c-shared 带 Go runtime（体积、GC 驻留）；跨 FFI 不能回调，需 poll/read 模型 | **采用** |
| **curl-impersonate: curl + BoringSSL/NSS** | lwthiker/curl-impersonate、curl_cffi、primp | **直接编译浏览器自己的 TLS 栈**（Chrome→BoringSSL、Firefox→NSS），一致性是"构造性为真"；libcurl 纯 C API 绑定体验好，无 GC 驻留 | ① **H3/QUIC 可控度有限**（2026-09 修订）：原仓 `lwthiker/curl-impersonate` 停在 Chrome 116 时代且无 H3；活跃分支 `lexiforest/curl-impersonate` 2.0.0 已启用 H3/QUIC 指纹，但粒度是**预设级/有序条目级**——`ngtcp2_conn_set_local_transport_params_raw` 只接受整块序列化 blob，`nghttp3_conn_submit_settings` 只给 SETTINGS 条目序；GREASE 帧、伪头序、Initial 布局**仍不可控**；② 逐字段控制与 hex 回放要打进 BoringSSL 补丁，libcurl 抽象是"选项"不是"字节"；③ **维护成本高**（修订：不再是"已被证伪"，活跃分支正常跟进，维护成本仍是真问题）：每个新浏览器版本要重打 curl+BoringSSL+ngtcp2+nghttp3 四层补丁链（约 540KB 补丁）并跨平台重编 | 否决（不进产品；**进测试环**：其 Docker 镜像与 `tests/signatures` YAML 作为真浏览器栈 ground truth 裁决我们的输出，见 05 文档 L3；**ground truth 源统一改用活跃分支 `lexiforest/curl-impersonate`**） |
| Rust: BoringSSL + 自研 H2/H3 | specter(warpsock)、wreq | BoringSSL 是 Chrome 亲妈栈，Chrome 字节级一致性好；无 GC；PyO3/napi-rs 绑定干净 | h2 crate 不暴露 SETTINGS 顺序/GREASE/preface 时序（specter 因此自写整个 H2 栈）；H3 需 quiche 定制；自研量巨大，工期不可控 | 否决（作为远期备选记录） |
| Rust: rustls fork | XOR-op/ja-tools | rustls 纯净 | rustls 抽象层隐藏太多握手细节，ja-tools 需要 deep fork 且已落后上游 | 否决 |
| **真栈转发 / Cronet 嵌入** | cyTlsXhr（真 Chrome 转发）、cycronet（Chromium Cronet 编进 Python） | 真实性完美（就是真 Chrome 在握手）；Cronet 自带真实 Chrome QUIC/H3 行为 | 可控性极低（cyTlsXhr 几乎为零，cycronet 仅能换 cipher 列表）；重资产（装浏览器/Cronet 构建链）；只能演 Chrome；cyTlsXhr 作者已弃坑转向 cycronet | 否决（不进产品；**进测试环 L3**：作为"真 Chrome 栈"裁判。2026-09 复核注：`cyTlsXhr` 本体为来源不明的 Windows 预编译产物，**不集成、不运行**，仅取"真浏览器转发作基准"的思路并以 Playwright/CDP 自建替代） |
| Java: bctls fork | zhkl0228/impersonator | QUIC 指纹维度拆解最细 | JVM 分发重，三语言绑定体验差 | 否决（但其 QUIC 维度清单被吸收进 01 文档） |
| 纯 Python socket 手搓 | pyhttpx | 灵活 | 只能 TLS1.2/H1，非生产级 | 否决（吸收为 fuzz 发生器思路） |

**决策：Go 核心（uTLS 二开）+ C ABI + 三语言绑定。** 这是"指纹维度覆盖 × 交付速度 × 维护成本"的最优解；bogdanfinn/tls-client 已跟进到 Chrome 150 且月更，我们 fork 其依赖而非从零造。

**curl-impersonate 路线赢在哪、我们如何补偿**：它唯一的结构性优势是"用真浏览器的栈，一致性构造性为真"。我们的补偿方式是把这个优势搬进验证侧——curl-impersonate Docker 镜像 + 其 signatures 库 + 真实浏览器 pcap 作为裁决 oracle（05 文档 L3），配合自家 nginx 采集套件（L2）做主裁判：uTLS 构造的字节与真浏览器有任何 diff，测试环会抓到并驱动修复。即"用 uTLS 的可控性交付，用 BoringSSL 的真实性验收"。

2026-09-24 复核补充：`lexiforest/curl-impersonate` 的 `ngtcp2.patch` 用"调用方给整块序列化 transport params blob、库原样发出"实现参数顺序/非标参数可控——该**设计**已确认可移植到我们的 `quic-go-utls` fork（见方案 `docs/plans/2026-09-24-geektls-hardening-and-h3-plan.md` T4-1）；其 Initial 布局无钩子，印证该项为行业共性难点。

## 3. 仓库布局

```
geektls/
├── README.md
├── docs/                        # 本文档所在
├── core/                        # Go module: github.com/geektls/core
│   ├── profiles/                # 预设注册表 + JSON profile 解析 + JA3/JA4R/hex 输入
│   ├── tls/                     # uTLS fork 封装：ClientHello 构造、GREASE、ECH、自算 JA3/JA4
│   ├── h2/                      # fhttp fork 封装：SETTINGS/伪头序/priority/window
│   ├── h3/                      # quic-go fork 封装：transport params/Initial 布局/H3
│   ├── tcp/                     # setsockopt 子集 + raw socket 全量（分平台）
│   ├── engine/                  # Session: cookie jar、连接池、代理、重定向、流式
│   └── ffi/                     # C ABI 导出层（//export），handle 注册表
├── bindings/
│   ├── python/geektls/     # ctypes 封装，requests 风格 API
│   ├── nodejs/                  # koffi 封装，fetch/requests 混合风格 API
│   └── golang/                  # 薄封装，直接 re-export core（无 FFI）
├── profiles/                    # 内置浏览器预设 JSON（按 client@version 目录式管理）
├── tests/
│   ├── unit/                    # profile→字节→解析 round-trip
│   ├── e2e/                     # 打 nginx 采集套件 / 外部 oracle 的闭环
│   └── fuzz/
└── .github/workflows/           # CI 矩阵
```

## 4. 依赖 fork 策略

需要长期 fork 三个上游，全部 pin commit + 文档化 rebase 流程：

1. **`refraction-networking/utls`**（BSD 3-Clause）→ 扩展点：逐扩展负载自定义、GREASE 位置指定、ECH、后量子 key_share（X25519MLKEM768）、extension permutation。
2. **`bogdanfinn/fhttp`**（跟随其 license）→ H2 帧层控制。
3. **`bogdanfinn/quic-go` fork** → QUIC transport params、H3 SETTINGS。

优先**消费 bogdanfinn 的现成 fork**（tls-client 已经把这三者粘好了），我们的增量在：profile 体系、逐字段 API、自算回读、FFI 层、三语言绑定、测试闭环。不重复造他已经造好的轮子。

## 5. FFI 进程与内存模型

c-shared 模式的关键约束与对策：

- **handle 注册表**：core 内部 `sync.Map[uint64]any`，所有跨 ABI 对象（Client/Session/Response）以 uint64 handle 传递；Python/Node 侧只持有数字。
- **内存归属铁律**：谁分配谁释放。core 返回的字符串/缓冲由 core 提供 `gtls_free_string`/`gtls_free_response` 显式释放；绑定层在析构器/`finalizer` 里兜底。详见 `02-ffi-abi.md`。
- **并发模型**：goroutine 在 core 内部自由使用；跨 ABI 不传回调（c-shared 回调进 Python/Node 是事故温床），异步一律用"提交请求 → 拿 handle → poll/read"模型。流式响应用 `gtls_response_read(handle, buf, len)` 拉模式。
- **线程安全**：Go runtime 自己管线程；绑定层保证同一 handle 不并发调用（Python GIL + Node 单线程天然满足；文档明写约束）。
- **错误模型**：函数返回 int 状态码，线程局部 `gtls_last_error()` 取详情 JSON；把阻塞调用放到自己线程上的绑定按对象取 `gtls_error_of(handle)`（worker 线程写槽、主线程读自己的槽必然为空，Node/koffi 实测踩过）。
- **DLL 体积/冷启动**：c-shared 产物约 15–25MB，冷启动毫秒级（noble-tls 实测级别），可接受。

## 6. 三语言 API 形态（目标态）

同一概念模型：`Client(profile) → Session → request() → Response(streamable)`。

- **Python**：`geektls.Session(impersonate="chrome_150")`，requests 风格；`stream=True` 迭代块。
- **Node**：`new geektls.Session({impersonate:'chrome_150'})`，Promise + Node Readable stream。
- **Go**：`gbt.NewSession(gbt.Chrome150)`，net/http 兼容 `RoundTripper`。

## 7. 许可证风险登记

| 组件 | 许可证 | 行动 |
|---|---|---|
| uTLS | BSD 3-Clause（含 Go 标准库 BSD 代码） | 可用，保留 NOTICE |
| bogdanfinn/tls-client 系 | BSD 风格（落地前逐仓核对，尤其 fork 链） | P0 阶段完成许可证审计 |
| JA4 算法（仅 JA4 本体） | BSD 3-Clause | 可用 |
| JA4H/JA4T/JA4S 等其他 JA4+ 方法 | FoxIO License 1.1（商用需授权） | 我们只**生成**流量不**计算**这些指纹，风险低；自算校验模块仅限 JA3/JA4，文档标注边界 |
| CycleTLS / gospider | GPL-3.0 / LGPL-3.0 | **不看其源码实现细节**，只参考公开 API 形态，避免污染 |

## 8. 平台矩阵

| 平台 | TLS/H2/H3 | TCP 子集(setsockopt) | TCP 全量(raw socket) |
|---|---|---|---|
| Linux x86_64/arm64 | ✅ | ✅ | ✅(root) |
| macOS | ✅ | ✅ | ✅(root, 选项序受限) |
| Windows | ✅ | 部分(TTL 可，MSS 受限) | ❌(P6 不做，文档说明) |

开发主机是 Windows，但 nginx 验证端需要 Linux——e2e 闭环在 WSL2 或 Linux CI runner 跑，见 `05-testing.md`。
