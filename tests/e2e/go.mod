module github.com/geektls/tests/e2e

go 1.26.0

require (
	github.com/bogdanfinn/fhttp v0.6.9
	github.com/bogdanfinn/quic-go-utls v1.0.10-utls
	github.com/bogdanfinn/utls v1.7.8-barnius
	github.com/geektls/core v0.0.0
	github.com/geektls/golang v0.0.0-00010101000000-000000000000
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

// replace 不随依赖传递，必须在本模块声明。
replace (
	github.com/bogdanfinn/quic-go-utls => ../../core/third_party/quic-go-utls
	github.com/geektls/core => ../../core
	github.com/geektls/golang => ../../bindings/golang
)
