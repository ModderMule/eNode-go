package ackhandler

import (
	"enode/internal/ed3k/iquic/internal/wire"
)

// FrameHandler handles the acknowledgement and the loss of a frame.
type FrameHandler interface {
	OnAcked(wire.Frame)
	OnLost(wire.Frame)
}

type Frame struct {
	Frame   wire.Frame // nil if the frame has already been acknowledged in another packet
	Handler FrameHandler
}

type StreamFrame struct {
	Frame   *wire.StreamFrame
	Handler FrameHandler
}
