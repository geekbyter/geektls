package qlog

import (
	"context"

	"github.com/geekbyter/geektls/core/third_party/quic-go-utls"
	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/qlog"
	"github.com/geekbyter/geektls/core/third_party/quic-go-utls/qlogwriter"
)

const EventSchema = "urn:ietf:params:qlog:events:http3-12"

func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracerWithSchemas(ctx, isClient, connID, []string{qlog.EventSchema, EventSchema})
}
