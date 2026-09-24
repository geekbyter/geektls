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

测量日：2026-09-22。请求模型：**每请求一条新 TCP+TLS 连接**（P3 设计，无连接池）——吞吐上限由握手成本决定，这是如实口径。

## 吞吐（req/s，10 秒 × 三档并发）

| 并发 | Go 直用 | Python FFI | Node FFI |
|---|---|---|---|
| 10 | 1,609 | 1,433 | 950 |
| 50 | 2,504 | 2,442 | 930 |
| 100 | 2,577 | 3,355 | 918 |

读数：

- **≥10k req/s 未达成**（任务书参照值）——瓶颈是"每请求一次完整 TLS 握手"
  （单次约 1.5–4ms）。连接池/会话复用是唯一的数量级级改进项，列入后续
  迭代（与 P7-T2 的复用机制同坑位）。不粉饰：当前架构就不是为高 RPS 设计的。
- **FFI 损耗 ≈ 0**（Python 与 Go 直用在并发 50 时基本打平，100 时反超——
  GIL 在 ctypes 阻塞调用期间释放，并发模型反而占优）。
- Node 稳定在 ~950：koffi async 每次请求约 1ms 额外开销（worker 线程
  往返），与并发无关。

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
| 首个请求（TCP+TLS 握手+响应头） | 3.2–3.8 ms |

## 基准过程中的实测发现（已修）

- **Alt-Svc 复活 bug**：H3 失败的主机被负缓存后，每个响应的 Alt-Svc 头
  又把它复活 → 每个请求都白烧一个 QUIC 握手超时。已改为显式负缓存优先。
- 负缓存生效前，任何 H3-capable 预设打"坏 H3 服务端"要付一次握手超时
  （已将 quic HandshakeIdleTimeout 从默认 5s 降到 3s）。本机 echo 的
  bogdanfinn H3 服务端拒 ECH（上游 server 兼容面），基准的稳态数字用
  剥 ECH 变体测量，预热行为差异如上一条所示。
