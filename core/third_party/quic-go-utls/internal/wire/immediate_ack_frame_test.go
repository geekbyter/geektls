package wire

import (
	"testing"

	"github.com/bogdanfinn/quic-go-utls/internal/protocol"
	"github.com/bogdanfinn/quic-go-utls/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestImmediateAckFrame(t *testing.T) {
	frame := ImmediateAckFrame{}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)

	val, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	require.Equal(t, uint64(FrameTypeImmediateAck), val)
	require.Equal(t, len(b), l)

	require.Len(t, b, int(frame.Length(protocol.Version1)))
}
