module github.com/geekbyter/geektls/tests/smoke

go 1.26.3

require github.com/geekbyter/geektls/bindings/golang v0.0.0

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/geekbyter/geektls/core v0.1.9 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260224225140-573d5e7127a8 // indirect
)

// replace 不随依赖传递，core 的 replace 必须在这里再写一遍。
replace (
	github.com/geekbyter/geektls/bindings/golang => ../../bindings/golang
	github.com/geekbyter/geektls/core => ../../core
)
