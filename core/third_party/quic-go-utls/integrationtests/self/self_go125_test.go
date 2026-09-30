//go:build geektls_upstream_quic_integrations

package self_test

import tls "github.com/geekbyter/geektls/core/third_party/utls-bogdanfinn"

func getCurveID(connState tls.ConnectionState) tls.CurveID {
	return connState.CurveID
}
