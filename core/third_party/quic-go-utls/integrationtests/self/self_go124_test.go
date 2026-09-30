//go:build geektls_upstream_quic_integrations || !go1.25

package self_test

import tls "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"

func getCurveID(connState tls.ConnectionState) tls.CurveID {
	return 0
}
