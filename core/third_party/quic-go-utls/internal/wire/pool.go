package wire

import (
	"sync"

	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/internal/protocol"
)

var pool sync.Pool

func init() {
	pool.New = func() any {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxIncomingPacketSize), // geektls patch: was protocol.MaxPacketBufferSize
			fromPool: true,
		}
	}
}

func GetStreamFrame() *StreamFrame {
	f := pool.Get().(*StreamFrame)
	return f
}

func putStreamFrame(f *StreamFrame) {
	if !f.fromPool {
		return
	}
	if protocol.ByteCount(cap(f.Data)) != protocol.MaxIncomingPacketSize { // geektls patch: was protocol.MaxPacketBufferSize
		panic("wire.PutStreamFrame called with packet of wrong size!")
	}
	pool.Put(f)
}
