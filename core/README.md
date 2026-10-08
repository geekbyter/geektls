# geektls core

geektls 的 Go 核心模块——TLS/HTTP 指纹伪装引擎：ClientHello（JA3/JA4/JA4R）、
HTTP/2（HPACK 四档策略、SETTINGS/头序/伪头序，Akamai 指纹级）、QUIC/H3（Initial
布局、transport params 直通、内层 ClientHello 同 profile），内置 **368 条按证据分级
（E1/E2/E3）**的浏览器预设，每条可追溯到采集来源。

完整文档、Python/Node.js 绑定与更多能力对照见仓库根
[github.com/geekbyter/geektls](https://github.com/geekbyter/geektls)。

## 安装

    go get github.com/geekbyter/geektls/core

## 最小示例（引擎直连）

```go
package main

import (
	"fmt"

	"github.com/geekbyter/geektls/core/engine"
	"github.com/geekbyter/geektls/core/profiles"
)

func main() {
	p, err := profiles.Get("chrome_154_windows")
	if err != nil {
		panic(err)
	}
	sess, err := engine.NewSession(p, engine.SessionOptions{})
	if err != nil {
		panic(err)
	}
	defer sess.Close()

	resp, err := sess.Do(&engine.Request{Method: "GET", URL: "https://tls.peet.ws/api/all"})
	if err != nil {
		panic(err)
	}
	defer resp.Close()

	fmt.Println(resp.StatusCode(), resp.OK(), resp.Reason())
}
```

## 两层 API

- **引擎直连**（`core/engine`）：`NewSession(profile, SessionOptions)` →
  `Do(*Request) → *Response`；能力最全——H2/H3 racing、Alt-Svc、代理、流式、wss、
  请求头序三档（preserve / input / random）。
- **net/http 形态**：`github.com/geekbyter/geektls/bindings/golang` 的
  `NewRoundTripper(preset, *Options)` 直接挂 `http.Client`。注意 `http.Header`（map）
  会抹平请求头顺序，指纹级头序控制走 Session。

## CLI（免编译试用）

```bash
go run github.com/geekbyter/geektls/core/cmd/geektls@v0.1.8 version
go run github.com/geekbyter/geektls/core/cmd/geektls@v0.1.8 check-profile chrome_154_windows
```

## 许可

MIT（仓库根 [LICENSE](https://github.com/geekbyter/geektls/blob/main/LICENSE)；
依赖许可登记见仓库根 LICENSES.md）。
