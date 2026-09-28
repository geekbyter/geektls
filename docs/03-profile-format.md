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
    "window_update": 15663105,
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
    "initial_layout": {"padding": "chrome", "coalesce": true},
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
    "session_resumption": true
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
- **`transport_params_raw`（T4-1，2026-09-24 起）**：QUIC transport parameters 的有序 blob 直通——顺序、非标参数、GREASE 参数位置全可控（移植 lexiforest `ngtcp2` 的 blob 直通设计，经 `quic-go-utls` vendor patch #7 原样上 wire）。每项 `[id, value]`：id 为数值或 `"grease"`（随机 GREASE id + value 长度的随机数据）；value 为数值（varint 编码）或 `"hex:..."`（原始字节）。设置后优先于 `transport_params`（map 形态）。注意：已知流控键（1/4/5/6/7/8/9）的值会自动映射回 `quic.Config`，保证 wire 声明与实际流控行为一致——不要写与真实意图矛盾的值。
- **`identity`（T2-1，2026-09-24 起）**：profile 携带的缺省请求头身份，解决"TLS 指纹是浏览器但 `user-agent` 却是 `Go-http-client`"的身份分裂。语义：
  - engine 在 H1/H2/H3 三条协议路径统一注入；**用户请求里的同名头（大小写不敏感）优先**，不覆盖；表内顺序即线上顺序。
  - 头部名一律小写（H2 强制小写；H1 下大小写整形由 `http1.header_case` 另行控制）。
  - 禁止伪头（`:` 开头）与空头名，加载即校验。
  - `accept-encoding` 一旦显式下发，HTTP 栈不再自动解压（body 为原始流，解码归调用方）——与库的流式 API 语义一致。
  - 无 `identity` 节的 profile 行为与注入机制引入前完全一致。

## 3. 预设体系

- 目录式管理（借 ja3proxy 的 `client@version` 形态）：`profiles/chrome/150/windows.json` …，继承链 `chrome_150` → `chrome_150_windows`。
- 首批预设来源优先级：
  1. bogdanfinn/tls-client profiles（BSD，Chrome/Firefox/Safari/OkHttp 全版本，H2+H3 对齐）；
  2. curl_cffi / curl-impersonate `tests/signatures`（交叉核对）；
  3. 自抓：真实浏览器 + Wireshark 落盘进 `profiles/evidence/`（specter 的证据文档做法，每个预设附 pcap 出处）。
- 每个预设必须通过 `gtls_check_profile` 自算 JA3/JA4 与公开权威值（tls.peet.ws 记录）一致才能入库——**预设入库即测试**。
- 版本跟进策略：跟踪 Chrome stable 节奏，目标是新版浏览器发布后 2 周内出预设（对标 curl_cffi 的更新 SLA）。

## 4. 与采集端的互操作

`gtls_describe_preset(name)` 输出的完整 JSON 可直接喂给测试断言器；nginx 采集端 `$http_fingerprint_json` 的字段名与本 schema 的对应关系在 `05-testing.md` 的映射表中定义。两边术语刻意对齐（如 `pseudo_header_order` ↔ `$http2_fingerprint_pseudo_headers`）。
