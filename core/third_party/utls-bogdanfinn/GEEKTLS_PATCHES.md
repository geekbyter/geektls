# geektls patch 清单：utls-bogdanfinn fork

本目录是 [bogdanfinn/utls](https://github.com/bogdanfinn/utls) 的内联 fork（quic-go-utls
的 TLS 依赖，也是 geektls 的 QUIC/H3 内层 ClientHello 与 0-RTT 的承载）。改动全部
可从上游 diff 复核；代码内以 `// [geektls patch]` 标记，行号以本仓当前状态为准。

背景：geektls 的 QUIC 客户端走 **spec 模式**（`ApplyPreset` + `BuildHandshakeState`），
而非上游默认的 makeClientHello 流程——下面多数 patch 都源于该路径与 0-RTT/会话恢复
组合时上游未曾覆盖的分支。

## patch #1（2026-09-30）：keyShareKeys 误杀检查

- **位置**：`key_schedule.go`（新增 `usable()`）、`handshake_client_tls13.go`（clientKey 三级回退）。
- **症状**：spec 模式把 ECDHE 私钥放在 `keyShareKeys.keys` map 里，而上游检查只认
  `keyShareKeys.ecdhe` ⇒ **每条恢复连接**都被 `internal error` 误杀。
- **修**：`usable()` 的判定口径与 key schedule 的动态查找一致；clientKey 选择补
  map → legacy → MLKEM 的优先级回退。
- **验证**：恢复连接（含 0-RTT）握手成功；`tests/e2e` 的 QUIC 组。

## patch #2（2026-09-30）：ApplyPreset 的 spec 污染

- **位置**：`u_parrots.go`。
- **症状**：`ApplyPreset` 生成的公钥写回**调用方共享的 spec**（`ext.KeyShares[i].Data`）；
  同一 spec 的**第二条连接**会因"Data 已有值"跳过密钥生成 ⇒ 私钥为空 ⇒ 握手失败。
- **影响面**：所有 H3 transport 的第二条连接（不止 0-RTT）。
- **修**：克隆 KeyShareExtension 再改 + `callerHasKey()` 门。

## patch #3（2026-09-30）：locked 会话路径的 early_data

- **位置**：`u_handshake_client.go`（`clientHandshake` 的 `sessionIsLocked` 分支）。
- **症状**：该分支绕过 `loadSession()`，而 0-RTT 判定（票据 EarlyData + 同 cipher
  suite + 同 ALPN ⇒ `hello.earlyData=true`）只写在 loadSession 的 QUIC 分支里 ⇒
  恢复连接 `hello.earlyData` 恒 false，不发 0-RTT、EE 不带 early_data、客户端自拒
  （`Err0RTTRejected`）。
- **修**：同口径补 QUIC 判定 + 动态插入**空 early_data(42) 扩展**（必须在
  pre_shared_key 之前——PSK 必须是最后一个扩展）+ `MarshalClientHello()` 重出字节 +
  接回 `hello.original` + 重算 PSK binder。
- **注意**：msg 级重 marshal 会丢 quic_transport_parameters（TP 的注入在 uconn 层
  spec 扩展对象上）——配套修复见 patch #4-B。

## patch #4（2026-10-08，0-RTT 收尾）：binder 收尾 + TP 回写

- **位置**：`u_handshake_client.go`（同一 locked 分支内）。
- **症状 A（真根因）**：`MarshalClientHello` 时 PSK 扩展**只写占位 binder**
  （见 `u_pre_shared_key.go` 头注释："using placeholder binders to maintain the
  correct length"）——真 binder 必须由 uTLS 的收尾步骤打进**已 marshal 的 Raw**：
  正常流程 = `uApplyPatch()`（`u_conn.go`）→ `sessionController.updateBinders()` →
  `PatchBuiltHello()`。locked 分支绕过了它 ⇒ 线上 binder 是占位值 ⇒ 服务端
  `hmac.Equal` 失败（`alertDecryptError`）⇒ 服务端"开 early_data + 装 0-RTT 读密钥"
  的分支（`handshake_server_tls13.go` 442）**永不执行** ⇒ `Used0RTT` 恒假、0-RTT
  数据只能经 1-RTT 重传到达。
- **修 A**：binder 重算（`computeAndUpdatePSK`）后补
  `sessionController.updateBinders()` + `setPskToUConn()`（`shouldUpdateBinders()`
  守卫；与 `uApplyPatch` 等价）。
- **症状 B（配套）**：uTLS 把 makeClientHello 的 TP 注入注释为
  "`[UTLS] We don't need this, since it is not ready yet`"（TP 只走 spec 扩展），
  而 msg 层 `quicTransportParameters` 空缺会破坏两处一致性：①
  `computeAndUpdatePSK` 的 binder 输入；② 发送后 `transcriptMsg(hello)` 的握手
  transcript（服务端从线上解析后重 marshal 是含 TP 的）。
- **修 B**：把 spec 的 `QUICTransportParametersExtension.marshalResult`（= 线上 57
  的 data 同一产物，见 quic-go-utls 的 `uquic_spec_conn.go` 填充逻辑；
  `transport_params_raw` 直通场景也以该对象为最终值）回写 `hello.quicTransportParameters`。
- **验证**：`tests/e2e` 的 `TestQUICZeroRTT` 三层断言全绿（client/server
  `Used0RTT=true` + 线上 0-RTT 长头包 + echo 数据面，0.06s）；matrix
  `h3.zero_rtt` → implemented。

## 维护约定

- 每处改动带 `// [geektls patch]` 注释与原因；调试用 `GEEKTLS-DEBUG` 打印只允许
  临时存在（0-RTT 的 8 处现场标记已于 2026-10-08 全部清除，勿再引入长期打印）。
- 上游升级（rebase 内联 fork）时按本清单逐项重放，并复核行号。
- 新增 patch 必须同步更新本文件、`docs/capability-matrix.yml` 与 CHANGELOG。
