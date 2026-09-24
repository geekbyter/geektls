# 运营机制（P7-T6）

## Chrome stable 新版预设 SLA

- **目标**：Chrome stable 发布后 **2 周内**出新预设（对齐 curl_cffi 的更新节奏）。
- 流程：情报监控 → 抓包/参考 → 构造 detail → 自校验（`gtls_check_profile`
  + `TestPresetsAreValid`）→ L1 回环矩阵 → tls.peet.ws oracle（external tag）
  → evidence 登记 → 入库。

## 预设入库流程（一条命令）

1. `core/profiles/builtin/<name>.json` 落 detail（TLS/H2/H3/TCP 各节）。
2. `go test ./tls/ -run TestPresetsAreValid`（编译+自算+warnings 检查）。
3. `go test ./tests/e2e/ -run 'TestPresetsLoopback|TestH2FrameCapture'`
   （L1 字节级）。
4. `go test -tags external ./tests/e2e/ -run 'TestExternalOracle'`（oracle diff）。
5. `profiles/evidence/README.md` 表格补行（等级/依据/日期）。

## 外部 oracle 周检

external tag 测试清单（每周 cron 或手动）：

```bash
go test -tags external ./tests/e2e/ -run 'TestExternalOracle$|TestExternalOracleH2|TestRealECHLive' -v
```

- `TestExternalOracle`：7 预设 × tls.peet.ws JA3/JA4 diff
- `TestExternalOracleH2`：7 预设 × Akamai 四段 diff
- `TestRealECHLive`：cloudflare-ech.com 真 ECH 接受
- 输出报告制（不硬断言），DIFF 出现即人工介入。

## fork rebase 流程

- **vendor fork**：`core/third_party/quic-go-utls`（replace 落地）。
  升级步骤：`third_party/quic-go-utls/GEEKTLS_PATCHES.md` §升级流程——
  覆盖源码 → 重打 6 处 patch（`geektls patch` 锚点可 grep）→ 跑
  `TestQUICInitialSniff` + `TestQUICHelloBisect` 回归。
- **上游 pin**：refraction-networking/utls（go.mod pin v1.8.2）、
  bogdanfinn/fhttp v0.6.9、bogdanfinn/utls v1.7.8-barnius（跟随 fhttp）。
  升级时先跑 `go test ./...` 全模块 + L1 矩阵再谈。

## 情报源清单

| 源 | 用途 | 频率 |
|---|---|---|
| Chrome stable release notes | 新预设触发 | 每版 |
| bogdanfinn/tls-client releases & profiles diff | 预设参数基准 | 每周 |
| curl_cffi releases | 交叉核对 + 更新节奏参照 | 每周 |
| refraction-networking/utls releases | TLS 栈升级 | 每周 |
| FoxIO ja4 spec / ja4plus-go | JA4 规则与向量更新 | 每月 |
| tls.peet.ws 行为变化 | oracle 基线漂移 | 周检时顺带 |

## 版本号升级规则

见 docs/versioning.md：core/bindings 三处同步；ABI 破坏性变更才升 abi 号；
发布前三语言冒烟 + pytest + node:test 全绿是门禁。
