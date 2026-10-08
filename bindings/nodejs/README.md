# geektls（Node.js 绑定）

geektls 的 Node.js 绑定：TLS/HTTP 指纹伪装（Session/Response，requests 风格）。
底层用 [koffi](https://koffi.dev) 驱动随包分发的动态库——**无 node-gyp、无编译**，
`npm install` 装完即用。

## 安装

    npm install geektls

## 平台支持（0.1.8）

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

## 许可

MIT（本包）；依赖许可登记见包内 `LICENSES.md`。
