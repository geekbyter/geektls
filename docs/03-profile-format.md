# 03 - Profile 格式与预设体系

Profile 是 geektls 的一等公民：**一份 JSON 完整描述一个客户端的四层指纹**。它是预设的存储形式、跨语言 API 的输入、测试期望值的载体（`gtls_describe_preset` 展开即期望值，httpcloak 的 describe_preset 思路验证过这个形态）。

## 1. Schema（v1 草案）

```jsonc
{
  "name": "chrome_150_windows",
  "extends": "chrome_150",            // 可选：继承并覆盖
  "tls": {
    // —— 三种便捷入口（互斥，优先级高于下方 detail）——
    "clienthello_hex": "160301...",   // 无损回放（tlsmask 式）
    "ja3": "771,4865-4866-...-23-...",
    "ja4r": "t13d1516h2_002f003c..._0005000a..._04030807",

    // —— 规范形式：逐字段 detail ——
    "detail": {
      "legacy_version": "0x0303",
      "ciphers": ["0x0a0a", "0x1301", "0x1302", "0x1303", "0xc02b", "..."],
      "extensions": [                  // 数组 = 线上顺序
        {"type": 0, "sni": "auto"},    // auto = 取目标 host
        {"type": 23, "data": ""},      // session_ticket
        {"type": 43, "versions": ["0x2a2a", "0x0304", "0x0303"]},
        {"type": 51, "key_shares": ["grease", "X25519MLKEM768", "X25519"]},
        {"type": 16, "alpn": ["h2", "http/1.1"]},
        {"type": 13, "sig_algs": ["0x0403", "0x0804", "..."]},
        {"type": 21, "padding_to": 512},   // padding 策略：对齐总长
        {"type": 65037, "ech": {"mode": "grease"}}   // ECH
      ],
      "extension_permutation": true,   // Chrome 式每连接随机扩展序
      "grease": {"ciphers": true, "extensions": true, "groups": true},
      "cert_compression": ["brotli"],
      "alps": true,
      "record_size_limit": null,
      "delegated_credentials": null
    }
  },
  "http2": {
    "settings": [[1, 65536], [2, 0], [4, 6291456], [6, 262144]],  // 有序
    "settings_grease": true,
    "window_update": 15663105,          // 省略=引擎补默认；0=不发该帧；N=发 N
    "first_stream_id": 3,               // 省略=1；必须是正奇数
    "pseudo_header_order": ["m", "s", "a", "p"],
    "priorities": [{"stream_id":3, "exclusive":true, "stream_dep":0, "weight":255}],
    "hpack_strategy": "chrome"
  },
  "http3": {
    "enabled": true,
    "quic_version": "0x00000001",
    "transport_params": {"max_idle_timeout": 30000, "..." : "..."},
    "transport_params_raw": [                  // T4-1：有序 blob 直通（优先于 transport_params）
      [8, 100],                                // [id, 数值] → varint
      [4660, "hex:deadbeef"],                  // [id, "hex:..."] → 原始字节（非标参数）
      [1, 30000],
      ["grease", 8]                            // 随机 GREASE id + 8 字节随机数据，位置任意
    ],
    "initial_packet_size": 1280,               // 首个 Initial datagram 尺寸（= PADDING 填到多少），1200..1452
                                               // 不设 = 上游默认 1280；越界在建 transport 时报错（不静默夹取）
    "initial_layout": {                        // 首飞 Initial 布局（vendor patch #8；不设 = 上游默认逐字节不变）
      "padding": "end",                        // PADDING 在包尾（Chrome 形态）；缺省 = 上游（PADDING 在 CRYPTO 前）
      "disable_scramble": true,                // 关内置 ClientHello scrambling（SNI/ECH 中点切割）
      "crypto_fragments": [600, 600],          // CRYPTO 帧分片表（隐含关 scramble；表内分片保序）
      "coalesce_min_size": -1                  // 0=上游默认 128；-1=禁用 Initial+Handshake 合并；>0=自定义阈值
    },
    "grease_frames": true,
    "settings": [[7, 268435456]],
    "pseudo_header_order": ["m", "s", "a", "p"],
    "h2_race_ms": 300                          // H2/H3 竞速偏好
  },
  "tcp": {                                     // 平台允许时才生效
    "ttl": 128,                                // Windows 浏览器典型值 128，Linux 64
    "mss": 1460,
    "window_size": 65535,                      // 需 root raw socket
    "window_scale": 8,
    "options_order": ["mss", "sack", "ts", "nop", "ws"]
  },
  "http1": {
    "header_order": ["host", "connection", "..."],
    "header_case": "preserve"                  // 或 "lower"/"title"
  },
  "behavior": {
    "redirect_max": 10,
    "cookie_jar": true,
    "session_resumption": true,
    "connection_pool": true                     // 默认开；false = 每请求新连接（旧行为）
  },
  "identity": {
    "headers": [
      ["sec-ch-ua", "\"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\", \"Not/A)Brand\";v=\"99\""],
      ["sec-ch-ua-mobile", "?0"],
      ["sec-ch-ua-platform", "\"Windows\""],
      ["user-agent", "Mozilla/5.0 ... Chrome/150.0.0.0 Safari/537.36"],
      ["accept", "*/*"],
      ["accept-language", "en-US,en;q=0.9"],
      ["accept-encoding", "gzip, deflate, br, zstd"]
    ]
  }
}
```

## 2. 关键语义

- **规范形式是 detail JSON**；`clienthello_hex` / `ja3` / `ja4r` 是三个"便捷入口"，加载时编译为 detail。编译信息有损时（JA3 丢扩展序/GREASE 位置）在 `gtls_check_profile` 的 `warnings` 里明示，不静默造假——**字段无依据时宁可报错/留空也不伪造**（沿用 nginx 套件的原则）。
- `ja4r` 输入按 FoxIO JA4 raw 语义解析：cipher/扩展段为**排序后**形式，无法还原原始顺序——因此 ja4r 入口得到的 profile 其扩展顺序标记为 `sorted`，`warnings` 提示与真实浏览器的差异。
- `"sni": "auto"` 等运行时占位符在发请求时解析。
- `extension_permutation: true` 时 detail.extensions 是"基准顺序"，core 每次连接做 Chrome 同算法的 Fisher-Yates 洗牌（含 GREASE 固定位）。
- **`transport_params_raw`（T4-1，2026-09-24 起）**：QUIC transport parameters 的有序 blob 直通——顺序、非标参数、GREASE 参数位置全可控（移植 lexiforest `ngtcp2` 的 blob 直通设计，经 `quic-go-utls` vendor patch #7 原样上 wire）。每项 `[id, value]`：id 为数值或 `"grease"`（随机 GREASE id + value 长度的随机数据）；value 为数值（varint 编码）或 `"hex:..."`（原始字节）。设置后优先于 `transport_params`（map 形态）——**两者同设在配置期报错**（2026-09-30 起，不静默选边）。冲突校验（同日起，全部配置期报错）：服务端专属参数（0x00/0x02/0x0d/0x10）、`initial_source_connection_id`(0x0f，钉不死逐连接随机 SCID)、重复 id、`max_udp_payload_size`(0x03) 越出 1200..1500。已知键的行为映射：流控键（1/4/5/6/7/8/9）映射回 `quic.Config` 流控；0x03 → `Config.MaxUDPPayloadSize`、0x20 → `Config.DatagramFrameSize`（patch #9，接收行为与 wire 声明一致）。
- **`identity`（T2-1，2026-09-24 起）**：profile 携带的缺省请求头身份，解决"TLS 指纹是浏览器但 `user-agent` 却是 `Go-http-client`"的身份分裂。语义：
  - engine 在 H1/H2/H3 三条协议路径统一注入；**用户请求里的同名头（大小写不敏感）优先**，不覆盖；表内顺序即线上顺序。
  - 头部名一律小写（H2 强制小写；H1 下大小写整形由 `http1.header_case` 另行控制）。
  - 禁止伪头（`:` 开头）与空头名，加载即校验。
  - `accept-encoding` 一旦显式下发，HTTP 栈不再自动解压（body 为原始流，解码归调用方）——与库的流式 API 语义一致。
  - 无 `identity` 节的 profile 行为与注入机制引入前完全一致。
- **`behavior.connection_pool`（二期阶段 5，2026-09-28 起，默认开）**：per-origin
  连接复用——H2 同 origin 单连接多路复用、H1 keep-alive 空闲池（每键上限 8、
  空闲 90s 淘汰）、H3 共享 transport（quic-go 按 host 复用 QUIC 连接）。
  池键 = scheme+host:port+生效代理 URL；池挂在 Session 上（profile 恒定不串）。
  复用连接不发新 ClientHello，selfcheck 报告本连接握手时的指纹。显式 `false`
  完整恢复"每请求一条新连接"的旧行为（CONTRACT-FREEZE #5 的解除开关）。
- **`http1.header_case` 三档（2026-09-28 起全量落地）**：`preserve`（默认，
  原样保留）/ `lower`（全小写）/ `title`（逐 dash 段首字母大写，如
  `User-Agent`）；Host 头名随档（preserve/lower 档 `host`，title 档 `Host`），
  头值不变换。
- **流式上传（二期 T2）**：绑定层把可迭代 body（Python 迭代器/生成器、Node
  Iterable/AsyncIterable）映射到 `gtls_request_begin/write/finish`——H1 线上为
  chunked 编码（每写一块一个 chunk 帧，终止 0-chunk 由 finish 发，用户给的
  content-length 被剥离），H2 为 DATA 帧流；H3 不支持（明确报错）。
- **`http2.hpack_strategy`（T-HPACK，2026-09-28 起生效）**：HPACK 编码策略四档
  `chrome`/`firefox`/`safari`/`generic`（空 = generic = 上游默认）。语义与证据
  等级见 docs/p2-h2-capability.md「T-HPACK spike」；safari 档为保守近似（未验证）。
- **`http2.window_update` 三态（A11，2026-09-29 起）**：省略 = 引擎补 15663105
  （Chrome 形状）；`0` = **不发**连接级 WINDOW_UPDATE（RFC 7540 §6.9.1 把增量 0
  判为 PROTOCOL_ERROR，故 0 只能解释为"不发"；此时读路径退回协议默认窗口做补充
  额度，长响应不会卡死）；`N` = 发 N。之所以是可选指针而非 `uint32`：值形态的 0
  会被 `omitempty` 在 marshal 时吞掉，预设 JSON 写不出"不发"这一档。
- **`http2.first_stream_id`（A11，2026-09-29 起）**：这条连接上第一个请求的 stream
  id，省略 = 1，必须是正奇数（`core/h2` 在建连接前校验，偶数/≥2³¹ 直接报
  `invalid_config`），后续请求按 +2 递增。第三方 tls_config 对 Firefox 135/145/
  l_latest 记的是 3 ⇒ 已写入对应 E3 预设；自测预设一律留空（无 E1 实测依据）。
  Akamai 四段式不含流号，故此维度是 oracle 之外的可观测形态。

## 3. 预设体系

### 3.1 命名规范（2026-09-30 统一，守门测试 `core/profiles/naming_test.go`）

```
<家族>_<版本>[_<变体>][_<平台>]
```

- **平台后缀 = `windows` / `macos` / `linux` / `android` / `ios`**，能判定就必须写；
  **确实判不定的留空**（工具 / App 族：`okhttp_3_12_12`、`curl_8_16_0`、`postman_11_30_3`…）。
- **浏览器族（chrome / edge / firefox）必须带平台后缀** —— 它们跨平台并存，缺后缀等于说不清
  是哪一个：已按此把 `chrome_131/133/150`、`firefox_120/135` 改名为 `*_windows`
  （平台依据 = 该预设 `identity` 里的 UA）。
- **Safari 也带 `_macos`**：Safari 同时存在于 macOS 与 iOS（`safari_18_6_ios`、`safari_18_7_ios`…），
  不加后缀说不清是哪一个 ⇒ macOS 写 `_macos`、iOS 写 `_ios`，后缀只允许这两个值。已按此把
  `safari_16` → `safari_16_macos`；`safari_18`（无实测来源的历史构造，13 扩展 / wire ≈2.9KB，
  与真机差得远）**直接删除**，旧名 `safari_18` 改指实测导航形态 `safari_18_macos`。
- 变体标记排在平台之前：`chrome_101_109_safe_windows`（`safe` = 该谱系的保守档）。
- **旧名 = 别名**：改名过的预设旧名继续可用（`core/profiles/alias.go` 的映射表，
  `impersonate="chrome_133"` 与 `"chrome_133_windows"` 取到同一份形态）。映射表**只增不删**，
  新代码请用规范名。仍然**没有**族级短名/前缀匹配（`impersonate="chrome_154"` 依然报
  `preset not found`，要写全名或 `"chrome_154_windows"`）。

- 目录式管理（借 ja3proxy 的 `client@version` 形态）：`profiles/chrome/150/windows.json` …，继承链 `chrome_150` → `chrome_150_windows`。
- 首批预设来源优先级：
  1. bogdanfinn/tls-client profiles（BSD，Chrome/Firefox/Safari/OkHttp 全版本，H2+H3 对齐）；
  2. curl_cffi / curl-impersonate `tests/signatures`（交叉核对）；
  3. 自抓：真实浏览器 + Wireshark 落盘进 `profiles/evidence/`（specter 的证据文档做法，每个预设附 pcap 出处）。
- 每个预设必须通过 `gtls_check_profile` 自算 JA3/JA4 与公开权威值（tls.peet.ws 记录）一致才能入库——**预设入库即测试**。
- 版本跟进策略：跟踪 Chrome stable 节奏，目标是新版浏览器发布后 2 周内出预设（对标 curl_cffi 的更新 SLA）。

## 4. 与采集端的互操作

`gtls_describe_preset(name)` 输出的完整 JSON 可直接喂给测试断言器；nginx 采集端 `$http_fingerprint_json` 的字段名与本 schema 的对应关系在 `05-testing.md` 的映射表中定义。两边术语刻意对齐（如 `pseudo_header_order` ↔ `$http2_fingerprint_pseudo_headers`）。
