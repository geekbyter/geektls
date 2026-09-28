# geektls 对 quic-go-utls 的 vendor patch 登记

> 基线：`github.com/bogdanfinn/quic-go-utls v1.0.10-utls`（tls-client master 在用版本），
> MIT 许可证（LICENSE 保留在本目录）。通过 `core/go.mod` 的
> `replace github.com/bogdanfinn/quic-go-utls => ./third_party/quic-go-utls` 生效。
> 所有改动处均有 `geektls patch` 注释。原则：只加不改签名兼容面（新增字段/参数追加在末尾）。

## 动机

上游 `internal/handshake/crypto_setup.go` 的客户端握手固定用普通
`tls.QUICClient`（bogdanfinn/utls 默认 hello），ClientHelloSpec 无法注入——
QUIC 内层 TLS 指纹不可控。本 patch 让它在 `quic.Config.ClientHelloSpec != nil`
时改用 `tls.UQUICClient` + `ApplyPreset`（bogdanfinn/utls 自带但被上游闲置的
uTLS QUIC 路径）。

## 改动清单

1. **`interface.go`**（`Config` 结构体）：新增字段
   `ClientHelloSpec *tls.ClientHelloSpec`（文档注释注明 geektls patch）。

2. **`config.go`**（`populateConfig`）：补复制 `ClientHelloSpec` 字段——
   否则 populateConfig 重建 Config 时丢字段，注入静默失效（实踩的坑）。

3. **`internal/handshake/crypto_setup.go`**：
   - 新增 `quicTLSConn` 接口（Start/NextEvent/Close/HandleData/
     SetTransportParameters/StoreSession/SendSessionTicket/ConnectionState），
     `cryptoSetup.conn` 字段类型由 `*tls.QUICConn` 改为该接口（原类型满足接口，
     行为不变）。
   - 新增 `presetErr` 字段：`ApplyPreset` 失败延迟到 `StartHandshake` 报出
     （构造函数签名不带 error，不改公共面）。
   - `NewCryptoSetupClient` 追加尾参 `clientHelloSpec *tls.ClientHelloSpec`
     （nil = 原行为）；非 nil 时走 UQUICClient+ApplyPreset。
   - `StartHandshake` 开头检查 `presetErr`。
   - 构造末尾 `SetTransportParameters` 调用加 nil 守卫（presetErr 时 conn 为 nil）。

4. **`internal/handshake/uquic_spec_conn.go`（新文件）**：
   - `uquicSpecConn` 适配器：`StoreSession` no-op（QUIC 会话缓存依赖 uTLS
     未导出逻辑，随 geektls P7-T2 再做；UQUICConn 默认不发 QUICStoreSession
     事件，实际不会被调到）。
   - `SetTransportParameters`：preset 模式下 UQUICConn 的实现不会把参数写进
     ClientHello（上游注释自认），这里把裸字节解析为
     `tls.FakeQUICTransportParameter` 列表填进 spec 内的
     `QUICTransportParametersExtension` 占位（透传不改字节）。

5. **`connection.go`**（`newClientConnection` 内 `NewCryptoSetupClient` 调用点）：
   传入 `conf.ClientHelloSpec`。

6. **`fuzzing/handshake/cmd/corpus.go`、`fuzzing/handshake/fuzz.go`、
   `internal/handshake/crypto_setup_test.go`**：调用点补尾参 `nil`
   （签名变更的机械跟随，无行为变化）。

## patch #7（2026-09-24）：transport params blob 直通

动机：QUIC transport params 此前只能经 `quic.Config` 映射 6 个键的值，
**顺序、非标参数、GREASE 参数位置不可控**。设计移植自
`lexiforest/curl-impersonate` 的 `ngtcp2_conn_set_local_transport_params_raw()`
（调用方给整块有序参数、库原样发出，而非逐项 setter）。

改动清单（同样只加不改）：

1. **`interface.go`**：`Config` 新增 `TransportParamsOverride tls.TransportParameters`
   ——非空时原样写入 ClientHello 的 quic_transport_parameters 扩展（顺序即线上顺序）。
2. **`config.go`**（`populateConfig`）：补复制该字段（同 ClientHelloSpec 的坑）。
3. **`internal/handshake/crypto_setup.go`**：`NewCryptoSetupClient` 追加尾参
   `transportParamsOverride tls.TransportParameters`，构造 `uquicSpecConn` 时注入。
4. **`internal/handshake/uquic_spec_conn.go`**：适配器新增 `tpOverride` 字段；
   `SetTransportParameters` 中 override 非空时优先使用（空则维持原解析填充路径）。
5. **`connection.go`**：调用点传入 `conf.TransportParamsOverride`。
6. **`fuzzing/handshake/cmd/corpus.go`、`fuzzing/handshake/fuzz.go`、
   `internal/handshake/crypto_setup_test.go`（3 处）**：调用点补尾参 `nil`。

注意：override 只改变 wire 上的扩展内容；quic-go 的流控行为仍由其 Config 字段
驱动——geektls core 侧（`core/h3/transport_params.go` 的 `applyKnownRawTP`）
负责把已知流控键值映射回 Config 保证 wire 声明与实际行为一致。

验证：`tests/e2e` 的 `TestQUICTransportParamsRaw`（顺序/非标/GREASE 位置断言）
+ 既有 `TestQUICInitialSniff`（map 路径回归）。

## 升级流程（rebase 上游时）

1. 用新版本模块缓存内容覆盖本目录（保留本文件与 `.patch` 语义）。
2. 重打上述 6 处（均有 `geektls patch` 锚点可 grep）。
3. 跑 `tests/e2e` 的 `TestQUICInitialSniff`（字节级断言内层 hello）+
   `TestQUICHelloBisect`（ECH 钳制回归守卫）验证。
