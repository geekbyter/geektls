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
| HPACK 策略（索引表/编码顺序） | ~~部分~~ **已落地（T-HPACK，2026-09-28）** | vendor fork `core/third_party/fhttp` 加策略钩子（`Transport.HpackStrategy` ← `profile.http2.hpack_strategy`），四档见下节 |
| preface 分帧时序 | 达标 | preface+SETTINGS+WINDOW_UPDATE+priorities 经 buffered writer 一次 Flush（与 Chrome 单段 preface 一致）；不做像素级时序模拟（设计已声明不需要） |
| TLS 集成 | 绕行 | fhttp 的 `DialTLS`/`connectionStater` 绑定 bogdanfinn/utls 类型；我们不用它——tlscore 自握手后把 `net.Conn` 交给 `Transport.NewClientConn`，零耦合 |

## T-HPACK spike（2026-09-28）：真机 HPACK 编码行为证据

HPACK 编码特征是与 Akamai 四段独立的指纹维度：① 哪些头走索引表 vs
literal；② literal 用不用 Huffman；③ 动表插入（incremental indexing）时机；
④ 编码顺序；⑤ 首请求 table size update。spike 证据按等级列示：

### Chrome（E1r：Chromium 现网 HTTP/2 栈 = QUICHE `HpackEncoder`，源码逐行确认）

Chromium 的 HPACK 编码已迁入 QUICHE（`quiche/http2/hpack/hpack_encoder.cc`，
net/spdy README 明示"relies on the QUICHE library"）。其默认构造即 Chrome
线上行为：

- `enable_dynamic_table_=true / enable_huffman_=true /
  should_emit_table_size_=false / crumble_cookies_=true`；
- 索引策略 `DefaultPolicy`：**伪头只有 `:authority` 入动表**（"rarely changes,
  moderate length"），其余伪头 literal no-index；**常规头全部 incremental
  indexing**（动表插入）；
- Huffman：**更短才用**（`HuffmanSize(str) < str.size()`）；
- table size update：仅当对端 SETTINGS 的 HEADER_TABLE_SIZE 变化时才发
  （对默认 4096 的服务端首请求**不发**）；
- Cookie 拆 crumb（fhttp 的 enumerateHeaders 已有同形行为）。

### Firefox（E1 级二手字节证据：Firefox 59 真实 HEADERS 帧逐字节解析）

公开抓包（Stack Overflow #49437846 的 hex 逐字段标注）：

- `:method GET`/` :scheme https` 静态表精确命中 → indexed（`0x82`/`0x87`）；
- `:path` → literal **no-index** + Huffman 值（`05 …`）；
- `:authority`、`user-agent`、`accept*`、`referer`、`cookie` → **incremental
  indexing**（`41`/`7a`/`53`/`51`/`50`/`73`/`60`），全部 Huffman。

⇒ 在本轮实现的"编码器策略粒度"上 **Firefox 与 Chrome 同形**；族间可区分度
主要在 SETTINGS 表大小（Firefox 65536，已建模）与长会话的动表复用模式。
`firefox` 档独立命名，未来真机证据可分叉。

### Safari（无公开字节级证据——CFNetwork 闭源）

`safari` 档取**保守近似**：全 literal、不做动表插入（静态表精确命中仍走
indexed）。**标注：未验证**（列入 08 待补采样计划，待真机 H2 裸帧采样后校正）。

### generic（对照档）

上游 x/net 系默认：一切皆可入动表（含 `:path`）——即 geektls 引入策略前的
线上形态，保留为对照与旧行为复现。

### 落地面与断言

- fork 钩子：`hpack.Encoder.SetIndexPolicy`（动表插入策略）+
  `SetHuffmanMode`（0 更短/1 总是/2 禁用）+ `Transport.HpackStrategy`，
  登记见 `core/third_party/fhttp/GEEKTLS_PATCHES.md`。
- 线上断言：`tests/e2e/h2_hpack_strategy_test.go` 逐字节解析 HPACK block
  表示形式（indexed/incr/noidx/never/tsu + Huffman 位），四档各一条用例 +
  动表复用（chrome 第二请求 `:authority` 命中动表走 indexed，safari 档不命中）。

### 覆盖面（2026-09-29 铺开）

| 组 | 条数 | 策略 | 依据等级 |
|---|---|---|---|
| 手写枢纽预设（chrome_131/133/150、firefox_120/135、safari_16/18） | 7 | chrome / firefox / safari | 与上面 spike 同级（E1r / E1 / 近似） |
| 生成器产物（标本 + E1 记录：chrome_137…152_macos、chrome_149_windows、edge_141/153、firefox_140/144、safari_18/26_macos） | 12 | 按族/平台 | 同左（族级映射写进 `gen-profiles`） |
| 血缘内插（chrome_138/139/140/144…151_macos、firefox_141/142/143_macos） | 14 | 按族 | E2i（继承链路，非实测） |
| 第三方导入 E3（含 opera/yabrowser 等 Chromium 系、iOS 上的 UC/微信） | 217 | 按族/平台 | **族级继承（E4 推断）**：栈归属明确才给，见 `import-tlsconfig` 的 `hpackStrategy` |
| **刻意留空**（curl/okhttp/charles/fiddler/reqable/powershell/ie/postman + 微信/UC/QQ/夸克/小米/华为/三星等内嵌浏览器） | 114 | 空 = 上游默认 | 它们的栈是各自 fork 或非浏览器，**没有证据就不编** |

合计 250/364 带策略。平台优先规则：**iOS 上任何浏览器都按 safari**（WebKit，依据
`presets_test.go` 的 `TestIOSBrowsersShareWebKitShape`），所以 `chrome_148_ios` /
`edge_148_ios` / `ucbrowser_*_ios` / `wechat_*_ios` 都是 safari 档。

维护提醒：`gen-profiles` 与 `import-tlsconfig` 各有一份同名 `hpackStrategy`（两个 cmd
互相独立、刻意重复），改一处要同步另一处，并重跑 `go test ./core/...` + e2e。
- 编码顺序（维度④）已由 `pseudo_header_order` + `HeaderOrderKey` 覆盖，不在本轮。
- 降级说明：深改方案（策略钩子直进编码器状态机）**已试到底并落地**，
  无需启用"Huffman 开关 + TSU 控制"的降级档。

## 注意点（延续）

- `Transport.Settings` 注释说"不要含 HEADER_TABLE_SIZE/INITIAL_WINDOW_SIZE"，但对应报错（`errSettingsIncludeIllegalSettings`）是死代码，从未被抛出——Chrome 的 `1:65536;4:6291456` 必须走 Settings map 才能控制顺序，实测工作正常（tls-client 同款用法）。
- preface 后 fhttp 会等服务端 SETTINGS 再发 HEADERS？——不，首个请求 HEADERS 紧随 preface 发出（oracle 端 sent_frames 实测：SETTINGS WINDOW_UPDATE HEADERS，与真 Chrome 一致）。
- 响应 `res.TLS` 恒 nil（我们的 conn 不满足 bogdanfinn/utls 的 connectionStater）——仅影响 metadata，无碍功能。
