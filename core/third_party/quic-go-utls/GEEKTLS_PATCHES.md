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

## patch #8（2026-09-30）：Initial 首飞布局（PADDING 位置 / CRYPTO 分片表 / coalesce 阈值）

动机：quic-go 的首飞布局此前完全写死——PADDING 写在 CRYPTO **之前**
（`appendPacketPayload` 先填零再写帧，Chrome/quiche 相反）、ClientHello 被
`initialCryptoStream` 的内置 scrambling 在 SNI/ECH 中点切片（Chrome 不切）、
coalesce 阈值是常量 `protocol.MinCoalescedPacketSize`(128)。布局是独立指纹维度。

改动清单（同样只加不改；nil = 上游默认逐字节不变）：

1. **`interface.go`**：新增 `InitialLayoutConfig` 类型（`PaddingEnd` /
   `DisableClientHelloScrambling` / `CryptoFragments` / `CoalesceMinSize`）与
   `Config.InitialLayout *InitialLayoutConfig` 字段。
2. **`config.go`**（`populateConfig`）：补复制 `InitialLayout`（同前两次的坑）。
3. **`crypto_stream.go`**：`initialCryptoStream` 新增 `fragQueue` 分片表 +
   `applyInitialLayout()`（关 scrambling / 装分片表）+ `popFragment()`
   （`scramble=false` 且有表时按表切 CRYPTO 帧；一片装不下当前包时下一包继续）。
4. **`packet_packer.go`**：
   - 新增 `paddingEnd` / `minCoalescedPacketSize` / `keepFrameOrder` 字段
     （`newPacketPacker` 里默认值 = 上游行为），`applyInitialLayout()`；
   - `appendPacketPayload`：`paddingEnd` 时 PADDING 改写到所有帧**之后**；
   - 分片表生效时（`keepFrameOrder`）跳过控制帧反固化洗牌——洗牌会把包内
     CRYPTO 分片打乱，分片表就失去意义；
   - `PackCoalescedPacket` 两处合并判据改为 `canCoalesce(size, maxSize)`：
     **空 datagram（size==0）永远可装**——否则"禁用合并"会连单独的
     Handshake 包都发不出去（握手死锁，实测踩过）；默认 128 时与上游
     `size < maxSize-128` 逐项等价。
5. **`connection.go`**：`preSetup` 里对 `initialStream` 应用布局；
   两个 `newPacketPacker` 调用点（client/server）应用 packer 布局。
6. **`config_test.go`**：`configWithNonZeroNonFunctionFields` 补
   `ClientHelloSpec`/`TransportParamsOverride`/`InitialLayout`/
   `MaxUDPPayloadSize`/`DatagramFrameSize` 五个 geektls 字段的 case
   （patch #6/#7 遗留的红——该测试要求 Config 每个字段都被登记，本次一并修复）。

验证：`tests/e2e/quic_layout_test.go`——`TestQUICInitialLayout`（默认路径
守门 / Chrome 形态 / 分片表逐项 / 非法值配置期报错）+ `TestQUICCoalesceThreshold`
（真服务端 + UDP 中继：默认第二飞 [initial handshake 1rtt] 合并；
`coalesce_min_size=-1` 拆成 [initial]+[handshake]）。

## patch #9（2026-09-30）：max_udp_payload_size / max_datagram_frame_size 的行为一致性

动机：transport params blob 直通（patch #7）能在线上声明任意值，但声明必须
与内部行为一致，否则是"骗对端"：
- 声明 `max_udp_payload_size=1472`（Chrome 真值）而接收缓冲只有 1452 ⇒
  对端发来的满尺寸包被静默截断、解密失败。
- 声明 `max_datagram_frame_size=65536`（Chrome 真值）而接收上限硬编码
  `wire.MaxDatagramSize=16383` ⇒ 对端发大 DATAGRAM 帧直接断连。

改动清单：

1. **`internal/protocol/protocol.go`**：新增 `MaxIncomingPacketSize = 1500`
   （接收专用；`MaxPacketBufferSize=1452` 仍管发送与默认宣告值——默认 wire
   字节不变）。1500 覆盖 IPv4 满 MTU（Chrome 的 1472 = 1500-28）。
2. **接收路径换用新常量**：`buffer_pool.go`（池容量 + putBack 检查）、
   `sys_conn.go`、`sys_conn_oob.go`、`internal/wire/pool.go`（StreamFrame
   数据缓冲）。`buffer_pool_test.go` / `sys_conn_test.go` /
   `sys_conn_oob_test.go` / `internal/wire/stream_frame_test.go`
   （"超长帧拒收"的阈值跟随新缓冲容量）四处断言同步。
3. **`interface.go`**：`Config.MaxUDPPayloadSize`（0 = 1452 默认）与
   `Config.DatagramFrameSize`（0 = `wire.MaxDatagramSize` 默认）。
4. **`config.go`**：`populateConfig` 补复制；新增 `maxUDPPayloadSize()` /
   `maxDatagramFrameSize()` 帮助函数。
5. **`connection.go`**：两端 `params.MaxUDPPayloadSize` /
   `params.MaxDatagramFrameSize` 改走配置（0 = 原值）；`handleDatagramFrame`
   的接收上限改走 `maxDatagramFrameSize()`。

配合 core 侧（`core/h3/transport_params.go` 的 `applyKnownRawTP`）：blob 里的
0x03/0x20 自动映射回这两个 Config 字段，且 0x03 超 1200..1500、服务端专属参数
（0x00/0x02/0x0d/0x10）、0x0f（钉不死逐连接随机 SCID）、重复 id 一律
**配置期报错**（不静默忽略）。

## 升级流程（rebase 上游时）

1. 用新版本模块缓存内容覆盖本目录（保留本文件与 `.patch` 语义）。
2. 重打上述各 patch（基础注入 6 处 + #7 + #8 + #9，均有 `geektls patch` 锚点可 grep）。
3. 跑 `tests/e2e` 的 `TestQUICInitialSniff`（字节级断言内层 hello）+
   `TestQUICHelloBisect`（ECH 钳制回归守卫）+ `TestQUICInitialLayout` /
   `TestQUICCoalesceThreshold`（布局 patch #8）验证；fork 自身至少跑
   `go test . -run 'TestConfig|TestBufferPool'`（patch #8 已修复该登记测试）。
