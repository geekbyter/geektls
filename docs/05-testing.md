# 05 - 测试与验证体系

核心命题：**"伪造得好不好"不能靠自我感觉，必须靠独立采集端裁决。** 我们拥有同类库不具备的资产——`D:\work\tls` 的 nginx 指纹采集套件（39 个细粒度变量，覆盖 TLS/H2/H3/QUIC/JA4TCP 五层），它就是 geektls 的裁判。验证体系分五层，L0–L2 自动化进 CI，L3 定期，L4 手动。

## L0 — 单元测试（core 内部）

- profile → ClientHello 字节 → 自解析 round-trip：每个 A 级维度（01 文档）一个用例族。
- 自算 JA3/JA4 与已知向量比对（FoxIO 仓库示例、ja4plus-go 语料）。
- 三个便捷入口（JA3/JA4R/hex）→ detail 编译的有损标注正确性。
- GREASE 16 值全枚举、扩展洗牌分布统计校验。

## L1 — 本地回环 echo（自包含，任何机器可跑）

起一个本地采集端进程做裁判，两个候选（不重复造轮子）：
- **gospider007/fp**（Go，解析 JA3/JA4/JA4H/H2 + 全量 spec）——首选，Go 原生易嵌入测试；
- **wi1dcard/fingerproxy** 二进制备选交叉。

流程：geektls 以 profile P 请求本地 echo → echo 返回它算出的指纹 → 与 `gtls_describe_preset(P)` 的期望值自动 diff。

## L2 — nginx 采集套件闭环（权威裁判，Linux/WSL2/CI runner）★

这是"是否真的能伪造好"的终审：

```
geektls(profile P)  ──HTTPS──►  nginx（hirosumee + ngf patches）
                                          │ GET /ngf-debug 或 access log
                                          ▼
                              39 个采集变量 JSON
                                          │
断言器 ◄── diff ── 期望值（gtls_describe_preset(P) 展开）
```

**字段映射表**（断言配置的骨架，实现时落成 YAML）：

| profile 字段 | nginx 采集变量 |
|---|---|
| tls.detail（编译后 JA3） | `$http_ssl_ja3` |
| 自算 JA4 | `$http_ssl_ja4` / `$http_ssl_ja4one` |
| ciphers/extensions 序 | `$http_clienthello_ciphers_hex` / `extension_order_raw` |
| GREASE 值/位置 | `$http_ssl_ja3_grease_{ciphers,extensions,curves}` / `$http_clienthello_grease_{values,positions}` |
| sig_algs / groups / key_share / ALPN / SNI / supported_versions / psk_modes / ec_point_formats / padding | 对应 `$http_clienthello_*` 共 21 字段 |
| http2.settings/window/priorities/pseudo | `$http2_fingerprint_{settings,window_update,priorities,pseudo_headers}` |
| http3.quic_version/transport_params | `$quic_fingerprint_{version,transport_params}` |
| http3.settings/pseudo | `$http3_fingerprint_{settings,pseudo_headers}` |
| tcp.* | `$http_ssl_ja4tcp_{mss,window,window_scale,options}` |

矩阵：全部预设 × (H1/H2/H3) × (直连/代理)。Stream 侧（`$stream_ssl_*`）同样跑一遍，验证 1443/preread 两种拓扑。

已知边界（测试断言要绕开，不算失败）：nginx 的 `clienthello_raw` 是 OpenSSL 重建 bundle 而非 wire 字节（无 random/session_id）；JA3 GREASE 提取受上游规范化影响可能为空。这些写进断言配置注释。

## L3 — 外部独立 oracle（每周定期，防"两家一起错"）

- **tls.peet.ws `/api/all`**：回读 ja3/ja4/akamai_fingerprint 与期望值 diff（wreq-js 的验证方法论）。
- **ja4plus-go**：对我们的流量抓 pcap 离线分析（含 QUIC Initial 解密路径），交叉验证 JA4。
- **真实浏览器 pcap 对照**：curl-impersonate `tests/signatures` YAML + specter 的 evidence 文档作为字节级基线；脚本化 tshark diff。
- **cycronet（Chromium Cronet 真实栈）**：作为"真 Chrome 栈"裁判，重点补 curl-impersonate 无 H3 的缺口——同目标下对比我们构造的 H3/QUIC 指纹与 Cronet 真实指纹在 nginx 采集端的输出。

## L4 — 真实站点冒烟（手动/发布前）

Cloudflare / Akamai 防护站点 + 指纹展示站（browserleaks 等）确认不被判定异常。仅作最终确认，不作为正确性依据。

## 鲁棒性与性能

- **fuzz**：pyhttpx 式畸形输入（未知扩展类型、截断 hex、超长字段、非法 GREASE）打 profile 编译器与 ABI 边界——必须返回结构化错误，绝不 panic 越界。
- **性能**：wrk/自研压测，本地回环目标 ≥10k req/s；FFI 单次调用开销 <50µs；10 万请求 RSS 平稳（句柄泄漏检查）。
- **三语言一致性**：同 profile 三语言各发包，nginx 采集结果三者全等（P5 验收项）。

## CI 矩阵

| 层级 | 触发 | 环境 |
|---|---|---|
| L0+L1 | 每次 push | ubuntu/macos/windows |
| L2 | 每次 push | ubuntu runner 内构建 nginx 套件（缓存 `.work/build`） |
| L3 | 每周 cron | 需外网，失败告警不阻塞 |
| fuzz/perf | 每周 cron | ubuntu |
