# 06 - 任务计划清单

> ## ⚠️ 状态说明（2026-09-28）
>
> 本清单覆盖**一期 P0–P7，已收工**，不再滚动更新。二期工作登记在
> [docs/plans/2026-09-24-geektls-hardening-and-h3-plan.md](plans/2026-09-24-geektls-hardening-and-h3-plan.md)
> 与 [07-capability-gaps.md](07-capability-gaps.md)、[08-plan-pending-samples.md](08-plan-pending-samples.md)、
> [capability-matrix.yml](capability-matrix.yml)。
>
> 本清单剩余未勾项的状态与阻塞原因汇总：
>
> | 未勾项 | 当前状态 | 阻塞原因 |
> |---|---|---|
> | P0 验收（CI） | CI 骨架已写；发布流水线 release-pypi.yml 已实跑（0.1.4 五平台 wheel 已上 PyPI） | "3 OS × 3 语言冒烟矩阵全绿 + ABI 冻结评审"未正式关闭 |
> | P1-T8（nginx 采集端 L2 终审） | ✅ 已通过：7 预设 × nginx 采集端 diff 全绿（tests/e2e/nginx-l2/verify_l2.py，35 项断言） | — |
> | P1 验收 | ✅ tls.peet.ws diff 全绿 + nginx 采集端 diff 全绿（P1-T8） | — |
> | P3 验收 | 0.1.4 已发布 PyPI 五平台 | `pip install geektls` 后 e2e 矩阵回归未正式记录 |
> | P6-T3（JA4TCP 验收） | ✅ 已通过（2026-09-29，netstack 档五分量 MATCH，verify_p6t3.py） | — |
>
> **二期阶段 5 登记（2026-09-28 第十轮）**：① per-origin 连接池落地并默认开启
> （H2 单连接多路复用 / H1 keep-alive 空闲池 / H3 共享 transport；
> `behavior.connection_pool=false` 恢复旧行为，CONTRACT-FREEZE #5 已附理由解除）；
> ② Session 并发安全（同一 session 多线程/多 goroutine 并发请求，100×100
> `-race` 零报告）；③ 吞吐复测：Python 9.4k / Node 9.1k / Go 每 worker 会话
> 12.7k req/s（回环 ≥10k 达成，详见 benchmarks.md 前后对照）；④ H1
> header_case 三档全量落地；⑤ 流式上传 ABI 追加（`gtls_request_begin/write/
> finish`，三处声明同步，H1 chunked 线上字节级断言）；⑥ selfcheck 深化
> （ja3_fullstring/扩展序两份/GREASE 标记/协商结果/sni_sent）。

> 与 `04-roadmap.md` 的阶段划分一一对应，展开为可勾选的原子任务。
> 约定：`[ ]` 未开始 / `[x]` 完成；工期为单人全职当量；**加粗**为关键路径。
> 依赖列表示该任务的前置任务 ID。

## P0 — 脚手架与 ABI 冻结（1 周）

- [x] **P0-T1 仓库初始化**：`core/` Go module、目录骨架（按 00 文档 §3）、README 状态徽章 — 0.5d
- [x] **P0-T2 依赖 fork 落地**（决策变更）：改为 go module pin 版本消费（uTLS v1.8.2 已进 `core/go.mod`），需要改造 uTLS 时再 fork + replace — 1d
- [x] **P0-T3 许可证审计**：产出 LICENSES.md，确认无 GPL 污染 — 0.5d
- [x] **P0-T4 C ABI v1 头文件**：`core/ffi/geektls.h`，按 02 文档函数表（version/init/client/session/request/read/free/last_error/check_profile/describe_preset/list_presets） — 1d
- [x] **P0-T5 c-shared 构建脚本**：Makefile，三平台（linux/macOS/Windows）产出 .so/.dylib/.dll — 0.5d，依赖 T4
- [x] **P0-T6 三语言冒烟**：py(ctypes)/js(koffi)/go(native) 各调 `gtls_version` 拿同一 JSON — 1d，依赖 T5
- [x] **P0-T7 CI 骨架**：GitHub Actions，3 OS × 3 语言矩阵跑冒烟（CI 文件已写，待推送 GitHub 后验证） — 0.5d，依赖 T6
- [ ] **P0 验收**：CI 全绿，ABI 冻结评审通过

## P1 — TLS 核心（3 周）★关键路径

- [x] **P1-T1 uTLS 集成基线**：core 引入 uTLS v1.8.2，`core/tls`（包名 tlscore）跑通 HelloChrome_Auto 握手，net.Pipe 内存测试通过（协商 TLS 1.3 / ALPN h2） — 1d，依赖 P0
- [x] **P1-T2 detail→ClientHello 构造器**：`core/profiles`（schema v1 解析+校验）+ `core/tls/compile.go`，逐字段控制（version/ciphers/extensions 顺序/sig_algs/groups/ALPN/SNI/auto 占位/key_share/psk_modes/cert_compression(27)/ALPS(17513)/record_size_limit(28)/delegated_credentials(34)/padding_to 策略） — 4d，依赖 T1
- [x] **P1-T3 GREASE 控制**：ciphers/extensions/groups 三处 GREASE 值与位置可控（字面量 "grease" + 显式 0x?a?a + grease 开关）；RFC 8701 全 16 值单测通过 — 1d，依赖 T2
- [x] **P1-T4 Chrome 扩展洗牌**：per-connection permutation 开关（随 T2 在 compile.go 实现，Chrome 式 GREASE/padding 位置不变，种子可注入），固定种子确定性单测通过 — 1d，依赖 T3
- [x] **P1-T5 JA3/JA4R/hex 三入口编译器**：`core/profiles/entries.go`；JA3 有损项（GREASE 位置/扩展负载）warnings 标注；JA4R 置 `extensions_sorted` + 计数交叉校验；hex 为无损路径 — 2d，依赖 T2
- [x] **P1-T6 自算 JA3/JA4 回读器**：`core/tls/fingerprint.go`（JA4 过 FoxIO 官方文档向量 `t13d1516h2_8daaf6152771_e5627efa2ab1`）；`gtls_check_profile` 落地（四入参形态，Python FFI 链路实测通过） — 2d，依赖 T2
- [x] **P1-T7 预设体系 v1**：`core/profiles/registry.go`（go:embed builtin/）+ chrome_131/133/150、firefox_120/135、safari_16/18 七预设；`gtls_list_presets`/`gtls_describe_preset` 落地；入库自校验 TestPresetsAreValid + L1 回环矩阵（tests/e2e）全绿；tls.peet.ws 外部 oracle 实测 JA3/JA4 全 MATCH — 2d，依赖 T5/T6
- [x] **P1-T8 L2 闭环首次通电**：nginx 套件（WSL2，hirosumee + ngf 补丁）起服于 127.0.0.1:8443；e2e 断言器 `tests/e2e/nginx-l2/verify_l2.py`（pytest，needs_nginx 标记，`GEEKTLS_NGINX_L2=1` 启用）对 7 自测预设 × 采集字段全绿（35 项断言）：`$http_clienthello_*`（ciphers_hex/extension_order_raw/supported_versions/signature_algorithms/supported_groups/key_share_groups/alpn/psk_key_exchange_modes/ec_point_formats/legacy_version/计数/GREASE 位置）逐项对齐 describe_preset 展开值，JA3 剔除采集端不可见扩展（ALPS 17613/ECH 65037/delegated_credential 34，OpenSSL pre_proc_exts 口径）后与 selfcheck 逐字符相等（safari 无裁剪、ja3_hash 直接相等），JA4 按采集端口径（无 ALPN 后缀、ja4_c 不拼 sigalgs 且剔 padding）分量对齐、ja4_b 逐字符相等，http2 settings/window_update/pseudo_headers/priorities（weight 线上值=规格+1）全中 — 2d，依赖 T7
- [x] **P1 验收**：tls.peet.ws diff 全绿（✅ 7 预设 JA3/JA4 实测 MATCH）+ nginx 采集端 diff 全绿（✅ 随 P1-T8，2026-09-28 通过）
- [x] **P1-T8 修复：采集端扩展盲区**（2026-09-28）：`patches/ngf-openssl-clienthello-raw.patch` 的 `SSL_client_hello_get_ngf_raw_data()` 原从 OpenSSL `pre_proc_exts`（只含已识别扩展）取数，ALPS(17613)/ECH(65037)/delegated_credential(34)/GREASE 扩展整体丢失；改为直接遍历 `CLIENTHELLO_MSG.extensions` 线上原始扩展块，全量按线序序列化（bundle 格式 NGFCH1 不变，patch 文件与 configure 内嵌 fallback 同步更新）。chrome_150 `extension_order_raw` 由 14 项增至 18 项（含 GREASE 首末位、17613、65037）。`verify_l2.py` 断言收紧：`extension_order_raw` 剔 GREASE 后与引擎发送记录逐位全量相等（不再做未知扩展裁剪），35 项全绿。注意：ja3/ja4 变量来自 hirosumee 参考实现（pre_proc_exts 口径，不经 NGFCH1 bundle），仍不含未知扩展，对应断言保留换算并已在 docstring 注明 — 依赖 T8。**【已于 2026-09-29 按所有者决定完整回滚：patch / configure fallback / WSL OpenSSL 源码与运行实例全部恢复旧实现，verify_l2.py 断言恢复"剔除未知扩展后比对"版本，采集端盲区维持原状】**

## P2 — HTTP/2 帧层（2 周）

- [x] **P2-T1 fhttp fork 集成**：fhttp v0.6.9（对齐 tls-client master go.mod）；`core/h2` 包，SETTINGS 自定义（值+顺序+GREASE id 可经 Settings map） — 2d，依赖 P1
- [x] **P2-T2 WINDOW_UPDATE / priority 帧 / 伪头序控制**：ConnectionFlow / Priorities / PseudoHeaderOrder（m,a,s,p 短码映射） — 2d，依赖 T1
- [x] **P2-T3 HPACK 策略与 preface 分帧时序**：preface 单段 Flush 与 Chrome 一致（oracle sent_frames 实测 SETTINGS WINDOW_UPDATE HEADERS）；HPACK 策略钩子 fhttp 未暴露，差异记入 docs/p2-h2-capability.md — 2d，依赖 T2
- [x] **P2-T4 H2 流式 body（上下行）**：2×100MB 流式回环，堆增长 1.5MB — 1d，依赖 T1
- [x] **P2-T5 Akamai 四段验收**：本地帧采集器（tests/e2e/h2_capture_test.go）逐帧断言全预设通过；tls.peet.ws 实测 7 预设 akamai_fingerprint 全 MATCH；nginx 端 `$http2_fingerprint_*` 部分随 P1-T8 延后（环境阻塞） — 2d，依赖 T3
- [x] **P2 验收**：tls.peet.ws akamai_fingerprint 一致（✅ 7 预设实测全 MATCH）

## P3 — Python 绑定 + engine 层（2 周）

- [x] **P3-T1 engine**：`core/engine`——cookie jar（cookiejar+publicsuffix）、重定向（301/302/303 改 GET、307/308 保 body，上限 10）、整体硬超时、HTTP CONNECT/SOCKS5 代理（带账密）、h2/h1 协议分发、selfcheck（JA3/JA4 自算+JA3/JA4R 入口期望值比对） — 2d，依赖 P1
- [x] **P3-T2 ctypes 绑定全套 ABI**：Session/request/stream/error；`iter_bytes`/`iter_lines` — 2d，依赖 T1
- [x] **P3-T3 handle 泄漏压测**：1 万请求回环实测 RSS 33.4→34.6MB（+1.1MB，≈0.12KB/req，GC 噪声级） — 1d，依赖 T2
- [x] **P3-T4 e2e harness 产品化**：`tests/e2e/python/test_engine.py`（fixture 起 Go echo server 子进程；预设矩阵 × selfcheck + 重定向/cookie/流式/POST/错误路径，6 项全绿） — 2d，依赖 P1-T8（以本地回环替代 nginx）
- [x] **P3-T5 PyPI 打包**：wheel 含 geektls.dll（package-data），干净 venv 安装后 import/version/list_presets 实测通过 — 1d，依赖 T2
- [ ] **P3 验收**：`pip install geektls` 后跑通 e2e 矩阵

## P4 — HTTP/3 + QUIC（3 周）

- [x] **P4-T1 quic-go fork 集成**：bogdanfinn/quic-go-utls v1.0.10-utls（对齐 tls-client master）；`core/h3` 包，UDP loopback H3 echo 跑通 — 2d，依赖 P1
- [x] **P4-T2 transport params 全控**（**降级**：值可控子集经 quic.Config——max_idle_timeout/initial_max_data/三个 stream 窗口(共值)/streams 数；顺序、max_udp_payload_size、非标参数不可控，需 fork internal/wire；逐项规定见 docs/p4-h3-capability.md，嗅探实证） — 3d，依赖 T1
- [x] **P4-T3 H3 SETTINGS / 伪头序 / GREASE 帧**：AdditionalSettings(+顺序)/PseudoHeaderOrder/SendGreaseFrames/PriorityParam 全控 — 2d，依赖 T1
- [x] **P4-T4 Initial datagram 布局**（**降级**：quic-go packet packer 无钩子，分片/PADDING/coalesce 不可控；实测证据（2×1280B datagram、CRYPTO 分片重组）与 Chrome 差异点记入 capability 文档，是否 deep fork 待 nginx 采集端量化后评估） — 3d，依赖 T2
- [x] **P4-T5 行为层**：H2/H3 racing（raceH3H2，h2_race_ms 延迟并发）、Alt-Svc 会话级缓存（pytest 实测升级）、0-RTT 未接线（依赖会话复用，随 P7-T2） — 2d，依赖 T3
- [x] **P4-T6 H3 验收**（替代裁判：无 nginx 环境）：tests/e2e 自研 QUIC Initial 解密嗅探器（RFC 9001），transport params 逐项断言全绿；nginx `$quic_fingerprint_*` 与 ja4plus-go pcap 交叉验证随 P1-T8 环境延后 — 2d，依赖 T4
- [x] **P4 验收**：四层指纹同一 profile 对齐（QUIC 内层 ClientHello 已经 vendor fork patch 解决并字节级实证；Initial 布局保持降级标注——packer 层不可控）

## P5 — Node + Go 绑定（1.5 周）

- [x] **P5-T1 koffi Node 绑定**：Promise API（koffi .async  worker 线程）+ Readable 流封装；node:test 7 项全绿（预设矩阵/流式/POST/H3/错误路径） — 2d，依赖 P3-T2（ABI 稳定后）
- [x] **P5-T2 npm 打包**：files 含动态库，`npm pack` tgz 临时目录安装实测 `require('geektls').version()` 通过 — 1d，依赖 T1
- [x] **P5-T3 Go 薄封装**：`NewRoundTripper(preset, opts)` 返回 http.RoundTripper（重定向/cookie 交还 http.Client），另有 Session 全量 API；echo 往返 + h2 断言通过 — 1d
- [x] **P5-T4 跨语言一致性测试**：tests/e2e/crosslang_test.go——chrome_133/firefox_120 × py/node/go 三绑定，JA4 三者全等、firefox JA3 hash 全等（chrome JA3 因洗牌逐连接变化属预期） — 1.5d，依赖 T1/T3
- [x] **P5 验收**：三语言 CI 矩阵全绿（本地替代：三语言冒烟 + node:test 7 项 + pytest 8 项 + 跨语言一致性实测全过；CI 待推送 GitHub 验证，同 P0-T7 注）

## P6 — TCP 指纹（2 周）

- [x] **P6-T1 setsockopt 档**：`core/tcp`（TTL 三平台全量；MSS Linux/macOS 可用、**Windows 实测不支持 TCP_MAXSEG（WSAENOPROTOOPT）→ 跳过+warning**）；engine/dial.go 接线（net.Dialer.Control 钩子保证 SYN 前生效）；本机验证到"设置+getsockopt 读回一致"，pcap 验证随 T3/nginx — 2d，依赖 P1
- [x] **P6-T2 raw socket 档（Linux root）**（**降级**：完整连接接管需 gVisor 级用户态协议栈（内核抢 RST+序列号/重传自管），超出本期范围；交付定制 SYN 探测模式 raw_linux.go（IP_HDRINCL 字节级构造+SYN-ACK 采集），GOOS=linux 编译通过，本地未验证待 Linux） — 4d，依赖 T1
- [x] **P6-T3 JA4TCP 验收**：nginx 端 `$http_ssl_ja4tcp_{mss,window,window_scale,options}` 与设定一致——**2026-09-29 通过**：netstack 档（gVisor/TUN 拓扑）打 WSL nginx，`tests/e2e/nginx-l2/verify_p6t3.py` 五分量逐项 MATCH（window 29184 / options 2-4-8-1-3 / mss 1460 / wscale 8） — 1d，依赖 T2
- [x] **P6-T4 平台边界文档**：docs/tcp-platform-matrix.md（字段×平台矩阵、raw 档形态与理由、代理/NAT/H3 边界） — 0.5d

## P7 — 硬化与发布（2 周，之后持续运营）

- [x] **P7-T1 ECH**：真 ECH 落地（`config.EncryptedClientHelloConfigList` + GREASE ECH 槽，profile schema `ech.mode=real + config_list_hex`）；对 cloudflare-ech.com 实测 `ECHAccepted=true`（external tag）；QUIC 侧 ECH GREASE 缺口用合成 payload 补齐（嗅探实测 QUIC JA4 与 TCP 仅差 q/t） — 3d
- [x] **P7-T2 session resumption / 0-RTT 完整化**（**部分降级**）：engine 接 ClientSessionCache（behavior.session_resumption 驱动）；预设补 pre_shared_key 占位（无票据线上省略、有票据线上出现，抓字节实证 148B payload）；**上游 interop 未解：refraction uTLS v1.8.2 与 Go std 服务端 PSK binder 校验失败（bad record MAC），bogdanfinn fork 对 std 服务端同样不复用，std-std 正常——发出侧已证正确，接受侧兼容属上游问题**；QUIC StoreSession 维持 no-op（UQUICConn 不发 QUICStoreSession 事件，无可补导出面） — 2d
- [x] **P7-T3 fuzz**：6 个 Go fuzzer（Parse/FromJA3/FromJA4R/FromClientHelloHex/CheckProfile/畸形 ServerHello）各 60s+ 零崩溃；ABI 边界 1000 次随机垃圾零崩溃、错误 JSON 结构完好；tlsfuzzer 项以自研畸形 ServerHello 生成器替代（本机无 Linux） — 2d
- [x] **P7-T4 性能基准**：docs/benchmarks.md——三链路回环吞吐（Go 2.6k/Python 3.4k/Node 0.95k req/s @并发100；**≥10k 未达成，瓶颈=每请求新握手，连接池列后续迭代**，如实登记）、FFI 开销 6–30µs 达标、冷启动 0.2ms+3.5ms；顺带修掉 Alt-Svc 负缓存复活 bug — 1.5d
- [x] **P7-T5 发布**：docs/versioning.md（语义化+ABI 规则+版本锁）；wheel/npm tgz 重建并全新安装实测；Go module 发布步骤成文（不实际发布）；`profiles/evidence/README.md` 7 预设证据等级登记；Node `index.d.ts` 补齐；README 总览重写 — 1.5d
- [x] **P7-T6 运营机制**：docs/maintenance.md——Chrome 新版 2 周 SLA、预设入库五步流程、oracle 周检清单、fork rebase 流程、情报源清单 — 0.5d

## 风险登记（随任务推进滚动更新）

| 风险 | 影响 | 缓解 |
|---|---|---|
| uTLS 对某些扩展（ALPS/record_size_limit）支持不全 | P1 超期 | ~~P1-T2 第一天先做能力摸底 spike~~ **已摸底（docs/p1-utls-capability.md）：P1 所需能力 uTLS v1.8.2 全部原生支持，无需 fork**；首个可能 fork 点推迟到 P4 QUIC params 或 P7 真 ECH 定制 |
| bogdanfinn fork 链上游变更断裂 | P2/P4 阻塞 | fork 全部 pin commit；rebase 流程文档化（P0-T2） |
| Windows 上 TCP raw socket 不可行 | P6 缩水 | 已在设计层声明边界，不算失败 |
| ~~本机无 Linux 环境（WSL2 Hyper-V 未启用）~~ | ~~P1-T8 及后续 L2 e2e 阻塞~~ | **已解除**：WSL2 nginx 采集端起服，P1-T8 已通过（2026-09-28）；P6-T3 同链路可用 |
| H3 Initial 布局 quic-go 抽象拿不到 | P4-T4 降级 | 提前 spike；最坏情况标记"部分可控"并进文档 |
| JA4H/JA4TCP FoxIO 商用授权 | 法务 | 只做生成不做计算；文档标注（00 文档 §7） |
