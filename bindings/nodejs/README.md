# geektls（Node.js 绑定）

geektls 的 Node.js 绑定：TLS/HTTP 指纹伪装（Session/Response，requests 风格）。
底层用 [koffi](https://koffi.dev) 驱动随包分发的动态库——**无 node-gyp、无编译**，
`npm install` 装完即用。

## 安装

    npm install geektls

## 平台支持（0.2.0）

| 平台 | 支持 |
|---|---|
| Windows x64 | ✅ |
| Linux x64 | ✅（较新 glibc 基线） |
| macOS Apple Silicon (arm64) | ✅ |
| **macOS Intel (x64)** | ❌ **暂不支持**——按架构分发动态库（`process.arch`选拼库名）在 roadmap（P7），落地前 Intel Mac 用户请用 Python/Go 绑定 |

## 最小示例

```js
const { Session } = require('geektls');

(async () => {
  const s = new Session({ impersonate: 'chrome_150', timeout: 20 });
  const r = await s.get('https://example.com', { params: { q: 1 } });
  console.log(r.statusCode, r.ok, r.reason);   // 200 true OK
  console.log(r.header('content-type'));       // 大小写不敏感
  console.log(await r.text());                 // 直接当文本用
  console.log((await r.json()).slideshow);     // 直接当 JSON 用
  for await (const chunk of r.iterContent()) { /* 需要流式才迭代 */ }
  s.close();
})();
```

指纹自洽（`selfcheck`）、协议选择（h1.1/h2/h3）、请求头序三档、WebSocket、代理等
完整文档见仓库根 [github.com/geekbyter/geektls](https://github.com/geekbyter/geektls)。

## pcap 直导入（v0.2.0）

Wireshark/tcpdump 抓包直接变指纹——Node 内两步直通（与 CLI `import-pcap` 同一解析核）：

```js
const geektls = require('geektls');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0';

const res = geektls.importPcap({ path: 'chrome.pcapng', ua: UA });  // ① 文件进
const rec = res.records[0];                        // 记录出（自算指纹 + TCP 形态）
console.log(rec.ja3, rec.ja4, rec.sni, rec.tcp.mss);

const client = new geektls.Session({ clienthello_hex: rec.clienthello_hex }); // ② 直通装载
const r = await client.get('https://tls.peet.ws/api/all');           // 用抓包的 ClientHello 发请求
console.log(r.selfcheck);                          // 线上对拍：实际 JA3/JA4 vs 期望
client.close();
```

### 抓来的 ClientHello，TLS 面是这样处理的

- **装载内容**：`clienthello_hex` 是抓包里 ClientHello **record 层原始字节**
  （`16 03 01` 开头，含 record 头 + 完整握手消息）——装载后 TLS 面（cipher 序、
  扩展序与载荷、groups、sig_algs、ALPN、ECH 外层、padding）**逐字节复现**；
- **随机项重生成**：client_random / session_id / key_share 公钥 / GREASE 值由引擎
  按浏览器语义**每次重算**（不会把"抓包那一次"的随机值冻进会话）；
- **三层验证（由离线到线上）**：
  1. `importPcap` 已自算：`rec.ja3 / rec.ja3_hash / rec.ja4`；
  2. 离线细看：`geektls.checkProfile(rec.clienthello_hex)`——完整解析 + 告警（不联网）；
  3. 线上对拍：请求后 `r.selfcheck`——本次握手**实际发出**的 JA3/JA4 与期望比对，
     与第 1 步的值一致即复现成功；
- **边界**：hex 装载只覆盖 **TLS 面**；**TCP 面**（TTL/MSS/窗口/选项序，即记录里的
  `tcp`）要经预设（`tcp` 节）才生效——见节尾"CLI 工具链"。

### 常规用法

```js
// 多流：全部导出——pcap 没有"域名"概念，用记录里的 sni 区分同名/异名流
const all = geektls.importPcap({ path: 'many.pcapng', all: true });
for (const rec of all.records) console.log(rec.sni, rec.source);   // pcap:many#1 / #2 …

// 挑第 N 条流（1-based）；只要 TCP 形态（不要求 ClientHello）
const one = geektls.importPcap({ path: 'many.pcapng', stream: 2 });
const tcp = geektls.importPcap({ path: 'syn-only.pcap', tcpOnly: true });

// 不落盘的字节入口（Buffer / Uint8Array）；未给 ua 时记录带 warnings
const rec2 = geektls.importPcap({ data: require('node:fs').readFileSync('chrome.pcapng') }).records[0];
console.log(rec2.warnings);      // ['missing_ua：pcap 明文看不到 HTTP 头；…']
```

**被拒的流怎么读**：`res.skipped` 逐流给原因，`records` 为空 = 全被拒（不抛异常）：

```js
console.log(geektls.importPcap({ path: 'second-visit.pcapng' }).skipped);
// ['192.168.1.10:51001 → CH 带非空 PSK(41)（resumption 形态，装载到别的目标必失败）']
```

拒绝项：resumption（带 PSK binder——**只采首访 fresh 连接**）、缺 SYN、抓包缺口、
无 CH。支持 pcapng 与 pcap classic（含 `tcpdump -i any` 的 cooked 链路）。

### CLI 工具链（生成可入库预设时才需要）

```bash
build/geektls import-pcap --pcap chrome.pcapng --ua "$UA" -o fp.json   # 同一解析核
tests/e2e/cmd/gen-profiles -record fp.json -out ./presets             # 记录 → 完整预设（含 tcp 节）
```

设计与边界见 [docs/12-pcap-import.md](../../docs/12-pcap-import.md)。

## 许可

MIT（本包）；依赖许可登记见包内 `LICENSES.md`。
