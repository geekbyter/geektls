# geektls（Go 绑定层）

geektls 的 Go 绑定：requests 风格 `Session` 与 `http.RoundTripper` 形态。
包名 `geektls`，模块路径 `github.com/geekbyter/geektls/bindings/golang`
（直接 import 底层模块 `github.com/geekbyter/geektls/core` 可获得全部引擎能力）。

## 安装

    go get github.com/geekbyter/geektls/bindings/golang

## 最小示例

```go
package main

import (
	"fmt"

	gtls "github.com/geekbyter/geektls/bindings/golang"
)

func main() {
	sess, err := gtls.NewSession("chrome_154_windows", nil)
	if err != nil {
		panic(err)
	}
	defer sess.Close()

	resp, err := sess.Get("https://tls.peet.ws/api/all")
	if err != nil {
		panic(err)
	}
	defer resp.Close()

	fmt.Println(resp.StatusCode(), resp.OK(), resp.Reason())
}
```

## RoundTripper 形态

```go
rt, err := gtls.NewRoundTripper("chrome_154_windows", nil)
if err != nil {
	panic(err)
}
client := &http.Client{Transport: rt}

resp, err := client.Get("https://example.com")
```

注意：`http.Header`（map）会丢失请求头顺序/大小写——指纹级头序控制请用 `Session`
（profile 的 `http1.header_order`）；`RoundTripper` 面向"拿来即用"的兼容场景。

完整文档（请求头序三档、H3 开关、身份自洽、WebSocket）见仓库根
[github.com/geekbyter/geektls](https://github.com/geekbyter/geektls)。
