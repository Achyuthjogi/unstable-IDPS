package flow

import (
	"sync"
	"time"
)

// State represents the connection state.
type State int

const (
	StateNew State = iota
	StateEstablished
	StateClosing
	StateClosed
)

// Flow represents a network connection.
type Flow struct {
	Key          Key
	State        State
	LastSeen     time.Time
	PacketCount  uint64
	ByteCount    uint64
	Mu           sync.Mutex

	// Stream reassembly
	ClientStream *StreamReassembler
	ServerStream *StreamReassembler

	// Track original direction to determine Client/Server
	OriginalSrcIP [16]byte
	OriginalSrcPort uint16
}

// Tracker manages active network flows.
type Tracker struct {
	flows         map[Key]*Flow
	mu            sync.RWMutex
	maxFlows      int
	idleTimeout   time.Duration
	maxReassembly int
}

// NewTracker creates a new flow tracker.
func NewTracker(maxFlows int, idleTimeout time.Duration, maxReassembly int) *Tracker {
	t := &Tracker{
		flows:         make(map[Key]*Flow),
		maxFlows:      maxFlows,
		idleTimeout:   idleTimeout,
		maxReassembly: maxReassembly,
	}
	go t.pruneLoop()
	return t
}

// GetOrCreate retrieves an existing flow or creates a new one.
// Returns the flow and a boolean indicating if it was newly created.
func (t *Tracker) GetOrCreate(key Key, pktSrcIP [16]byte, pktSrcPort uint16) (*Flow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, exists := t.flows[key]
	if exists {
		f.LastSeen = time.Now()
		return f, false
	}

	if len(t.flows) >= t.maxFlows {
		// Reached maximum flow tracking capacity
		return nil, false
	}

	f = &Flow{
		Key:             key,
		State:           StateNew,
		LastSeen:        time.Now(),
		ClientStream:    NewStreamReassembler(t.maxReassembly),
		ServerStream:    NewStreamReassembler(t.maxReassembly),
		OriginalSrcIP:   pktSrcIP,
		OriginalSrcPort: pktSrcPort,
	}
	t.flows[key] = f
	return f, true
}

// UpdateFlow updates the flow state with a new packet.
func (t *Tracker) UpdateFlow(f *Flow, pktSrcIP [16]byte, pktSrcPort uint16, payload []byte, seq uint32, tcpFlags uint8) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	
	f.LastSeen = time.Now()
	f.PacketCount++
	f.ByteCount += uint64(len(payload))

	isClientToServer := f.OriginalSrcIP == pktSrcIP && f.OriginalSrcPort == pktSrcPort

	// TCP state machine basic update
	// SYN (0x02), ACK (0x10), FIN (0x01), RST (0x04)
	if tcpFlags&0x02 != 0 && tcpFlags&0x10 == 0 {
		f.State = StateNew
	} else if tcpFlags&0x10 != 0 && f.State == StateNew {
		f.State = StateEstablished
	} else if tcpFlags&0x01 != 0 || tcpFlags&0x04 != 0 {
		f.State = StateClosing
	}

	if len(payload) > 0 {
		if isClientToServer {
			f.ClientStream.AddSegment(seq, payload)
		} else {
			f.ServerStream.AddSegment(seq, payload)
		}
	}
}

// Stats returns current flow tracking statistics.
func (t *Tracker) Stats() (activeFlows int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}

func (t *Tracker) pruneLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		now := time.Now()
		t.mu.Lock()
		for k, f := range t.flows {
			f.Mu.Lock()
			lastSeen := f.LastSeen
			state := f.State
			f.Mu.Unlock()
			if now.Sub(lastSeen) > t.idleTimeout || state == StateClosed {
				delete(t.flows, k)
			}
		}
		t.mu.Unlock()
	}
}
