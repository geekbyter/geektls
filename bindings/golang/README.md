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

## pcap 直导入（v0.2.0）

Wireshark/tcpdump 抓包直接变指纹——Go 内两步直通（与 CLI `import-pcap` 同一解析核）：

```go
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0"

res, err := gtls.ImportPcap("chrome.pcapng", &gtls.PcapOptions{UA: UA}) // ① 文件进
if err != nil {
	panic(err)
}
rec := res.Records[0] // 记录出（自算指纹 + TCP 形态）
fmt.Println(rec.JA3, rec.JA4, rec.SNI, rec.TCP.MSS)

s, _, err := gtls.NewSessionFromClientHelloHex(rec.ClientHelloHex, nil) // ② 直通装载
if err != nil {
	panic(err)
}
defer s.Close()
resp, err := s.Get("https://tls.peet.ws/api/all") // 用抓包的 ClientHello 发请求
if err != nil {
	panic(err)
}
defer resp.Close()
fmt.Println(resp.SelfCheck.JA3Hash, resp.SelfCheck.JA4) // 线上对拍：实际 JA3/JA4 vs 期望
```

### 抓来的 ClientHello，TLS 面是这样处理的

- **装载内容**：`ClientHelloHex` 是抓包里 ClientHello **record 层原始字节**
  （`16 03 01` 开头，含 record 头 + 完整握手消息）——装载后 TLS 面（cipher 序、
  扩展序与载荷、groups、sig_algs、ALPN、ECH 外层、padding）**逐字节复现**；
- **随机项重生成**：client_random / session_id / key_share 公钥 / GREASE 值由引擎
  按浏览器语义**每次重算**（不会把"抓包那一次"的随机值冻进会话）；
- **三层验证（由离线到线上）**：
  1. `ImportPcap` 已自算：`rec.JA3 / rec.JA3Hash / rec.JA4`；
  2. 离线细看：`core/tls` 的 `CheckProfile(rec.ClientHelloHex)`——完整解析 + 告警（不联网）；
  3. 线上对拍：请求后读 `resp.SelfCheck`（结构体字段）——本次握手**实际发出**的 JA3/JA4 与期望
     比对，与第 1 步的值一致即复现成功；
- **边界**：hex 装载只覆盖 **TLS 面**；**TCP 面**（TTL/MSS/窗口/选项序，即记录里的
  `TCP`）要经预设（`tcp` 节）才生效——见节尾"CLI 工具链"。

### 常规用法

```go
// 多流：全部导出——pcap 没有"域名"概念，用记录里的 SNI 区分同名/异名流
all, err := gtls.ImportPcap("many.pcapng", &gtls.PcapOptions{All: true})
for _, rec := range all.Records {
	fmt.Println(rec.SNI, rec.Source) // pcap:many#1 / pcap:many#2 …
}

// 挑第 N 条流（1-based）；只要 TCP 形态（不要求 ClientHello）
one, err := gtls.ImportPcap("many.pcapng", &gtls.PcapOptions{Stream: 2})
tcp, err := gtls.ImportPcap("syn-only.pcap", &gtls.PcapOptions{TCPOnly: true})

// 不落盘的字节入口；未给 UA 时记录带 Warnings
data, _ := os.ReadFile("chrome.pcapng")
rec2, err := gtls.ImportPcapBytes(data, nil, "chrome") // 第三参数 = sourceBase
fmt.Println(rec2.Records[0].Warnings)                  // [missing_ua：…]
```

**被拒的流怎么读**：`res.Skipped` 逐流给原因，`Records` 为空 = 全被拒（不是 error）：

```go
res, _ := gtls.ImportPcap("second-visit.pcapng", nil)
for _, s := range res.Skipped {
	fmt.Println(s) // 192.168.1.10:51001 → CH 带非空 PSK(41)（resumption 形态，装载到别的目标必失败）
}
```

拒绝项：resumption（带 PSK binder——**只采首访 fresh 连接**）、缺 SYN、抓包缺口、
无 CH。支持 pcapng 与 pcap classic（含 `tcpdump -i any` 的 cooked 链路）。

### CLI 工具链（生成可入库预设时才需要）

```bash
build/geektls import-pcap --pcap chrome.pcapng --ua "$UA" -o fp.json   # 同一解析核
tests/e2e/cmd/gen-profiles -record fp.json -out ./presets             # 记录 → 完整预设（含 tcp 节）
```

设计与边界见 [docs/12-pcap-import.md](../../docs/12-pcap-import.md)。

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
