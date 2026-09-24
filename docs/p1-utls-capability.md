# P1 能力摸底：uTLS v1.8.2 ClientHello 维度支持矩阵

> P1-T2 前置 spike（风险登记既定动作）。结论：**P1 所需能力全部原生支持，无需 fork**。
> fork 时机推后到 P4（QUIC transport params）或"逐扩展任意负载 + 完整生命周期"需求出现时。
> 排查依据：`$(go env GOMODCACHE)/github.com/refraction-networking/utls@v1.8.2` 源码。

| 维度（01 文档 §1） | 结论 | uTLS 入口 |
|---|---|---|
| cipher suites 顺序 | 原生 | `ClientHelloSpec.CipherSuites` |
| 扩展线上顺序 | 原生 | `ClientHelloSpec.Extensions`（数组即顺序） |
| 扩展洗牌（Chrome permutation） | 原生 | `ShuffleChromeTLSExtensions`（GREASE/padding/PSK 位置不变）；但不可注入种子，测试需确定性 → 我们在 `compile.go` 自实现同策略洗牌 |
| GREASE 值与位置（ciphers/groups/extensions） | 原生 | `GREASE_PLACEHOLDER`（0x0a0a）占位，握手时按 `GetBoringGREASEValue` 替换为随机 `0x?a?a`；扩展位用 `UtlsGREASEExtension{Value,Body}` |
| ALPS (application_settings) | 原生 | `ApplicationSettingsExtension`（codepoint 17513）；旧 draft codepoint 17613 用内嵌 `applicationSettingsExtension` |
| record_size_limit (28) | 原生 | `FakeRecordSizeLimitExtension{Limit}`（fake=只写不处理响应，客户端侧够用） |
| delegated_credentials (34) | 原生 | `FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms}`（别名 `DelegatedCredentialsExtension`） |
| psk_key_exchange_modes (45) | 原生 | `PSKKeyExchangeModesExtension{Modes}` |
| signature_algorithms_cert (50) | 原生 | `SignatureAlgorithmsCertExtension` |
| key_share 含 X25519MLKEM768 | 原生 | `KeyShareExtension{KeyShares []KeyShare{Group,Data}}`；`X25519MLKEM768 CurveID = 4588`（私钥生成走 Go 1.24 标准库 mlkem） |
| ECH（真 ECH / GREASE ECH） | 原生 | GREASE：`BoringGREASEECH()`；**真 ECH 已验证（P7-T1）**：`config.EncryptedClientHelloConfigList` + spec 内 GREASE ECH 占位槽（uTLS marshal 时替换为真负载）；对 cloudflare-ech.com 实测 `ECHAccepted=true`（tests/e2e/ech_external_test.go） |
| 自定义扩展负载 | 原生 | `GenericExtension{Id, Data}` |
| padding 策略 | 原生 | `UtlsPaddingExtension{GetPaddingLen}` functor 按未填充总长算 padding；内置 `BoringPaddingStyle`（对齐 512） |
| SNI(0)/status_request(5)/supported_groups(10)/ec_point_formats(11)/sig_algs(13)/ALPN(16)/SCT(18)/EMS(23)/session_ticket(35)/compress_certificate(27)/supported_versions(43) | 原生 | 各有对应 `TLSExtension` 实现 |

## 注意点（实现时）

- **扩展号勘误**：任务书曾写"23 = session_ticket"，实际 23 = extended_master_secret，session_ticket = **35**（IANA/uTLS common.go 一致）。实现按 IANA。
- GREASE 占位约定：ciphers/groups/key_share 的 group 里写 `GREASE_PLACEHOLDER`（0x0a0a），uTLS 在 marshal 时替换为随机 GREASE 值（BoringSSL 风格）。要求"固定具体 GREASE 值"时需绕开替换逻辑（`UtlsGREASEExtension.Value` 可固定扩展号）。
- `ShuffleChromeTLSExtensions` 用 crypto/rand 播种、不可注入种子，且会把 warning 打到 stdout——不满足测试确定性要求，自实现。
- 真 ECH 的 `ECHExtension` 接口含 unimplemented 嵌入方法，包外无法自实现新 ECH 类型——但内建 `GREASEEncryptedClientHelloExtension` 同时充当 real-ECH 槽位（P7-T1 实测），无需自实现。

## 结论

- **P1 不需要 fork uTLS**；P0-T2 的"go module pin 消费"决策继续成立。
- 首个可能触发 fork 的点：P4 QUIC transport params 全控（quic-go fork 侧）或 P7 真 ECH 定制。
