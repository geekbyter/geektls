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

## 升级流程（rebase 上游时）

1. 用新版本模块缓存内容覆盖本目录（保留本文件与 `.patch` 语义）。
2. 重打上述 6 处（均有 `geektls patch` 锚点可 grep）。
3. 跑 `tests/e2e` 的 `TestQUICInitialSniff`（字节级断言内层 hello）+
   `TestQUICHelloBisect`（ECH 钳制回归守卫）验证。
