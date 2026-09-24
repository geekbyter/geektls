# P2 能力摸底：fhttp v0.6.9 H2 帧层支持矩阵

> P2 前置 spike 结论（承 P1 的 capability 文档惯例）。
> 依据：`$(go env GOMODCACHE)/github.com/bogdanfinn/fhttp@v0.6.9/http2` 源码。
> fhttp 版本对齐 bogdanfinn/tls-client master 的 go.mod（v0.6.9）。

| 维度（01 文档 §2） | 结论 | fhttp 入口 |
|---|---|---|
| SETTINGS 值 + 顺序 | 原生 | `Transport.Settings` map + `SettingsOrder []SettingID`（顺序受控） |
| GREASE / 任意 setting id | 原生 | Settings map 接受任意 uint16 id（如 0x0a0a） |
| WINDOW_UPDATE 初始增量 | 原生 | `Transport.ConnectionFlow`（preface 后立即写 `WindowUpdate(0, connFlow)`） |
| PRIORITY 帧序列 | 原生 | `Transport.Priorities []Priority`（preface 后按序写出） |
| HEADERS 伪头序 | 原生 | `Transport.PseudoHeaderOrder`（全名形式，我们在 h2 包做 m/a/s/p 短码映射） |
| HPACK 策略（索引表/编码顺序） | 部分 | fhttp 用 x/net hpack 默认编码器，无策略钩子；`hpack_strategy` 字段在 schema 保留，未细分实现 |
| preface 分帧时序 | 达标 | preface+SETTINGS+WINDOW_UPDATE+priorities 经 buffered writer 一次 Flush（与 Chrome 单段 preface 一致）；不做像素级时序模拟（设计已声明不需要） |
| TLS 集成 | 绕行 | fhttp 的 `DialTLS`/`connectionStater` 绑定 bogdanfinn/utls 类型；我们不用它——tlscore 自握手后把 `net.Conn` 交给 `Transport.NewClientConn`，零耦合 |

## 注意点

- `Transport.Settings` 注释说"不要含 HEADER_TABLE_SIZE/INITIAL_WINDOW_SIZE"，但对应报错（`errSettingsIncludeIllegalSettings`）是死代码，从未被抛出——Chrome 的 `1:65536;4:6291456` 必须走 Settings map 才能控制顺序，实测工作正常（tls-client 同款用法）。
- preface 后 fhttp 会等服务端 SETTINGS 再发 HEADERS？——不，首个请求 HEADERS 紧随 preface 发出（oracle 端 sent_frames 实测：SETTINGS WINDOW_UPDATE HEADERS，与真 Chrome 一致）。
- 响应 `res.TLS` 恒 nil（我们的 conn 不满足 bogdanfinn/utls 的 connectionStater）——仅影响 metadata，无碍功能。
