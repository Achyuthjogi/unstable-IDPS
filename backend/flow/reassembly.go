package flow

import (
	"sort"
)

// StreamReassembler reconstructs TCP streams from packets.
type StreamReassembler struct {
	MaxDepth    int
	chunks      []chunk
	NextSeq     uint32
	Initialized bool
	Data        []byte
}

type chunk struct {
	seq  uint32
	data []byte
}

// NewStreamReassembler creates a new stream reassembler up to maxDepth bytes.
func NewStreamReassembler(maxDepth int) *StreamReassembler {
	return &StreamReassembler{
		MaxDepth: maxDepth,
		chunks:   make([]chunk, 0),
		Data:     make([]byte, 0),
	}
}

// Init sets the expected next sequence number.
func (sr *StreamReassembler) Init(seq uint32) {
	if !sr.Initialized {
		sr.NextSeq = seq
		sr.Initialized = true
	}
}

// AddSegment adds a TCP payload to the reassembler.
func (sr *StreamReassembler) AddSegment(seq uint32, payload []byte) {
	if len(payload) == 0 || len(sr.Data) >= sr.MaxDepth {
		return
	}

	if !sr.Initialized {
		// If not explicitly initialized, assume first seen segment is the start
		// (Best effort for flows captured mid-stream)
		sr.Init(seq)
	}

	// Calculate sequence difference to handle wraparound
	diff := int32(seq - sr.NextSeq)

	// Optimization: if it exactly matches the next expected sequence, append immediately.
	if diff == 0 {
		sr.appendData(payload)
		sr.NextSeq += uint32(len(payload))
		sr.drainChunks()
		return
	}

	// Drop if sequence is behind what we've already reassembled (duplicate/overlap)
	if diff < 0 {
		return
	}

	// Otherwise, it's out of order. Add to chunks and sort.
	// Limit chunk queue size to prevent memory exhaustion from missing packets.
	if len(sr.chunks) > 50 {
		return
	}

	sr.chunks = append(sr.chunks, chunk{seq: seq, data: append([]byte(nil), payload...)})
	sort.Slice(sr.chunks, func(i, j int) bool {
		return sr.chunks[i].seq < sr.chunks[j].seq
	})

	sr.drainChunks()
}

func (sr *StreamReassembler) appendData(payload []byte) {
	remaining := sr.MaxDepth - len(sr.Data)
	if remaining <= 0 {
		return
	}
	if len(payload) > remaining {
		sr.Data = append(sr.Data, payload[:remaining]...)
	} else {
		sr.Data = append(sr.Data, payload...)
	}
}

func (sr *StreamReassembler) drainChunks() {
	var keep []chunk
	for _, c := range sr.chunks {
		if c.seq == sr.NextSeq {
			sr.appendData(c.data)
			sr.NextSeq += uint32(len(c.data))
		} else if c.seq > sr.NextSeq {
			keep = append(keep, c)
		}
		// c.seq < sr.NextSeq implies overlapping or duplicate chunk, discard it
	}
	sr.chunks = keep
}
