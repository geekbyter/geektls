# LICENSES — 依赖许可证登记

> 逐仓核对结论：**无 GPL 污染**。若日后对 uTLS 做 fork 改造（P0-T2 决策变更后暂不 fork），改造前需复核 fork 链全部传递依赖。

## core（Go module，go.mod 直接/传递依赖）

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| github.com/refraction-networking/utls | v1.8.2 | BSD 3-Clause | ClientHello 伪造核心 |
| github.com/andybalholm/brotli | v1.0.6 | MIT | uTLS 传递依赖（证书压缩等） |
| github.com/klauspost/compress | v1.17.4 | BSD 3-Clause | uTLS 传递依赖 |
| golang.org/x/crypto | v0.36.0 | BSD 3-Clause | uTLS 传递依赖 |
| golang.org/x/sys | — | BSD 3-Clause | 传递依赖 |
| github.com/bogdanfinn/fhttp | v0.6.9 | BSD 3-Clause（Go Authors，net/http fork） | H2 帧层（P2） |
| github.com/bogdanfinn/utls | v1.7.8-barnius | BSD 3-Clause | fhttp 传递依赖（我们不直接调用） |
| github.com/cloudflare/circl | v1.6.2 | BSD 3-Clause | fhttp/utls 传递依赖（ML-KEM 等） |
| golang.org/x/net | v0.59.0 | BSD 3-Clause | 测试端 H2 server / hpack 解码 / proxy(SOCKS5) / publicsuffix |
| github.com/bogdanfinn/quic-go-utls | v1.0.10-utls | MIT（quic-go 原作者 & Google） | QUIC + H3（P4） |
| golang.org/x/text | — | BSD 3-Clause | 传递依赖 |

## 绑定层

| 依赖 | 许可证 | 用途 |
|---|---|---|
| koffi（npm） | MIT | Node.js FFI |

## 边界声明（承 00 文档 §7）

- 自算校验模块仅限 JA3/JA4（BSD 3-Clause）；JA4H/JA4T/JA4S 等 JA4+ 方法为 FoxIO License 1.1，本库只**生成**流量不**计算**这些指纹。
- CycleTLS / gospider 为 GPL-3.0 / LGPL-3.0：不看其源码实现细节，仅参考公开 API 形态。
