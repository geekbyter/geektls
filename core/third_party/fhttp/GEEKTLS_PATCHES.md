# geektls 对 fhttp 的 vendor patch 登记

> 基线：`github.com/bogdanfinn/fhttp v0.6.9`（tls-client master 在用版本）。
> **上游仓库无显式 LICENSE 文件**（GitHub API `license: null`，父链
> Carcraftz/fhttp → useflyent/fhttp 同样无）；主体代码派生自
> `golang.org/x/net`（BSD-3，各文件头保留 The Go Authors 版权声明）。
> 审计结论见 LICENSES.md（D-7）。
> 通过 `core/go.mod` 的
> `replace github.com/bogdanfinn/fhttp => ./third_party/fhttp` 生效
> （replace 不传递：tests/e2e、bindings/golang、tests/smoke 的 go.mod 同稿声明）。
> 所有改动处均有 `geektls patch` 注释。原则：只加不改签名兼容面。

## 动机（T-HPACK，2026-09-28）

上游 HPACK 编码器（x/net 系）"一切皆可入动表"：`:path` 等伪头也会被
incremental indexing 插入动态表——真实浏览器不这么做。HPACK 编码特征是
独立的指纹维度（① 哪些头走索引 ② Huffman 用否 ③ 动表插入时机
④ 编码顺序 ⑤ 首请求 table size update），需要策略钩子。

证据与四档语义见 `docs/p2-h2-capability.md`（Chrome=QUICHE 源码级、
Firefox=真实抓包字节级、Safari=保守近似待 E1）。

## 改动清单

0. **`http2/transport.go`（T-DECOMP，2026-09-29）**：`Transport` 新增
   `SkipResponseDecompress bool`——只关**响应侧**自动解压
   （`roundTrip` 里 `http.DecompressBody` 调用点加守卫），请求侧自动补
   `Accept-Encoding` 的行为不变（线上形态不动）。动机：geektls engine 统一
   在自己的解压层处理（多编码链逆序、zstd、未知编码透传+warning），
   fhttp 内置的单层解压会双重解压。

1. **`http2/hpack/encode.go`**：
   - `Encoder` 新增字段 `indexPolicy func(name string, pseudo bool) bool` 与
     `huffmanMode int`，及对应 setter `SetIndexPolicy` / `SetHuffmanMode`
     （纯新增，不动既有方法签名）。
   - `shouldIndex`：策略钩子非 nil 时接管动表插入决策（`Sensitive`/超尺寸
     守卫保持上游语义，默认路径逐字节不变）。
   - `appendNewName` / `appendIndexedName` / `appendHpackString` 改为
     `Encoder` 方法（huffmanMode 需要读编码器状态：0=更短才用（上游默认）
     /1=总是/2=禁用）。调用点全在本文件内。

2. **`http2/hpack_strategy_geek.go`（新文件）**：四档策略常量
   （`HpackStrategyGeneric/Chrome/Firefox/Safari`）与 `applyHpackStrategy`
   装配函数（策略→编码器钩子映射，含逐档证据注释）。

3. **`http2/transport.go`**：
   - `Transport` 新增字段 `HpackStrategy string`（空串 = 上游默认）。
   - `NewClientConn` 在 `hpack.NewEncoder` 之后调 `applyHpackStrategy`。

geektls core 侧接线：`core/h2/h2.go` 的 `TransportFromProfile` 校验并透传
`profile.http2.hpack_strategy`。

## 升级流程（rebase 上游时）

1. 用新版本模块缓存内容覆盖本目录（保留本文件）。
2. 重打上述 3 处（均有 `geektls patch` 锚点可 grep）。
3. 跑 `tests/e2e` 的 `TestH2Capture*`（HPACK 特征断言）+ `TestFPSecondOracle`
   回归。

## 已知上游测试失败（与本 patch 无关，纯净 v0.6.9 复现）

- `http2.TestTransportRejectsConnHeaders`：fhttp 有意转发用户显式设置的
  Content-Length（检查的是小写 map 键），与 vendored x/net 时代测试的期望
  不符——上游逐字复现，非本 patch 引入。fork 自测以 `./http2/hpack/` 为准。
