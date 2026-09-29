# 性能基准（P7-T4）

> 复跑：
> ```bash
> # Go 直用
> cd tests/e2e && GEEDTLS_BENCH=1 go test -run TestBenchThroughput -v -count=1 .
> # Python FFI（含 FFI 开销 + 冷启动）
> python tests/perf/bench_python.py
> # Node FFI
> node tests/perf/bench_node.js
> ```

## 环境

| 项 | 值 |
|---|---|
| OS | Windows 11 (Windows_NT) |
| Go | 1.27.0 windows/amd64 |
| Python | 3.12.7 |
| Node | 22.19.0 / koffi 2.16.3 |
| 对端 | 本机回环 echo server（H2，自签） |

测量日：2026-09-22（基线）/ 2026-09-28（二期阶段 5 复测）。
请求模型：基线为**每请求一条新 TCP+TLS 连接**（P3 设计）；复测起默认
**per-origin 连接池**（H2 同 origin 单连接多路复用 / H1 keep-alive /
H3 共享 QUIC 连接，`behavior.connection_pool=false` 可关）——复用连接
不再付握手成本。

## 吞吐（req/s，10 秒 × 三档并发）

2026-09-28 复测（池开启；括号内为 2026-09-22 基线）：

| 并发 | Go 直用（共享 Session） | Python FFI（每 worker 会话） | Node FFI（每 worker 会话） |
|---|---|---|---|
| 10 | 5,387（1,609） | 7,931（1,433） | 7,471（950） |
| 50 | 5,252（2,504） | 9,489（2,442） | 9,120（930） |
| 100 | 5,121（2,577） | 9,359（3,355） | 8,922（918） |

补充模型（`TestBenchDiag`，c=100 / 5s）：共享 Session 一条 h2 连接 2,922 req/s；
每 worker 一个 Session（100 条池化 h2 连接）**12,716 req/s**。

读数：

- **≥10k req/s 达成**（每 worker 会话模型：Go 12.7k；Python/Node ~9.4k 接近，
  瓶颈转移到 FFI 调度与单连接/单 QUIC 流的序列化，不再是握手）。
- **协议路径差异要如实说**：Python/Node 基准用剥 ECH 变体，echo 的 Alt-Svc
  广告生效 ⇒ 稳态走 **H3**（共享 QUIC 连接复用）；Go 基准用完整 chrome_133
  （含 ECH，echo 的 H3 服务端拒 ECH）⇒ 一次 H3 失败后落 **h2 单连接**。
  共享 Session = 同 origin 一条 h2 连接（真 Chrome 形态），吞吐上限 ~5k 是
  单连接序列化的如实结果，不是缺陷；要高 RPS 就多会话（与浏览器多标签同构）。
- **提升幅度**：Python 5.5×/3.9×/2.8×，Node 7.9×/9.8×/9.7×，Go（共享）3.3×/2.1×/2.0×。
- **FFI 损耗 ≈ 0** 的结论不变（gtls_version 5.8µs、check_profile 26µs）。
- Node 的 ~950 天花板消失（每请求不再阻塞 worker 线程做整次握手）。

## FFI 单次调用开销（10 万次循环均值）

| 调用 | 耗时 |
|---|---|
| `gtls_version` | 6–7 µs ✅（目标 <50µs） |
| `gtls_check_profile`（JA3 入参，含编译+自算） | 26–30 µs ✅ |

## 冷启动

| 阶段 | 耗时 |
|---|---|
| 动态库加载（进程内首次 CDLL/koffi.load） | <1 ms（毫秒级，与 noble-tls 同量级） |
| Session 初始化（client+session handle） | 0.2–0.3 ms |
| 首个请求（TCP+TLS 握手+响应头） | 3.1–3.5 ms |
| 池化后的后续请求（同 origin 复用） | 0.1–0.4 ms |

## 内存平稳性（2026-09-28 复测）

Python FFI 10,000 请求（`tests/perf/stress_leak.py`）：RSS 35.2 → 37.6 MB，
后半程斜率 ~0.25 KB/请求（阈值 1KB），判定 PASS——连接池/handle 无泄漏。

## 基准过程中的实测发现（已修）

- **Alt-Svc 复活 bug**：H3 失败的主机被负缓存后，每个响应的 Alt-Svc 头
  又把它复活 → 每个请求都白烧一个 QUIC 握手超时。已改为显式负缓存优先。
- 负缓存生效前，任何 H3-capable 预设打"坏 H3 服务端"要付一次握手超时
  （已将 quic HandshakeIdleTimeout 从默认 5s 降到 3s）。本机 echo 的
  bogdanfinn H3 服务端拒 ECH（上游 server 兼容面），基准的稳态数字用
  剥 ECH 变体测量，预热行为差异如上一条所示。
