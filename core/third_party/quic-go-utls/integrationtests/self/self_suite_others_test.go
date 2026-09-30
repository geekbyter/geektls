//go:build geektls_upstream_quic_integrations || !linux

package self_test

func isPermissionError(err error) bool {
	return false
}
