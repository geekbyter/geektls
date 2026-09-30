module github.com/geektls/core

go 1.26.3

require (
	github.com/andybalholm/brotli v1.2.0
	github.com/bogdanfinn/fhttp v0.6.9
	github.com/bogdanfinn/quic-go-utls v1.0.10-utls
	github.com/bogdanfinn/utls v1.7.8-barnius
	github.com/klauspost/compress v1.18.2
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
	golang.org/x/text v0.42.0
	gvisor.dev/gvisor v0.0.0-20260224225140-573d5e7127a8
)

require (
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/time v0.15.0 // indirect
)

// geektls vendor fork：QUIC 内层 ClientHelloSpec 注入（见 third_party/GEEKTLS_PATCHES.md）
replace github.com/bogdanfinn/quic-go-utls => ./third_party/quic-go-utls

// geektls vendor fork：HPACK 编码策略钩子（见 third_party/fhttp/GEEKTLS_PATCHES.md）
replace github.com/bogdanfinn/fhttp => ./third_party/fhttp
