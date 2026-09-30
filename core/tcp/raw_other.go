//go:build !linux

package tcp

import (
	"fmt"
	"net"
	"time"

	"github.com/geekbyter/geektls/core/profiles"
)

// ProbeSYN 非 Linux 平台：raw socket 档不可用（docs/tcp-platform-matrix.md）。
func ProbeSYN(dstIP net.IP, cfg *profiles.TCPProfile, timeout time.Duration) (*SYNProbeResult, error) {
	return nil, fmt.Errorf("tcp raw: probe mode is Linux-only this phase")
}
