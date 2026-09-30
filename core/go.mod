module github.com/geekbyter/geektls/core

go 1.26.3

require (
	github.com/andybalholm/brotli v1.2.0
	github.com/cloudflare/circl v1.6.2
	github.com/klauspost/compress v1.18.2
	github.com/quic-go/qpack v0.6.0
	github.com/refraction-networking/utls v1.8.2
	github.com/stretchr/testify v1.11.1
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	golang.org/x/text v0.42.0
	gvisor.dev/gvisor v0.0.0-20260224225140-573d5e7127a8
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/time v0.15.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// geektls vendor fork：QUIC 内层 ClientHelloSpec 注入（见 third_party/GEEKTLS_PATCHES.md）

// geektls vendor fork：HPACK 编码策略钩子（见 third_party/fhttp/GEEKTLS_PATCHES.md）

// geektls vendor fork：UQUICConn 会话事件/StoreSession（0-RTT 链路，见
// third_party/utls-bogdanfinn/GEEKTLS_PATCHES.md）。注意：这只覆盖 QUIC 侧
// （bogdanfinn/utls）；TCP 侧用的是 refraction-networking/utls，不受影响。
