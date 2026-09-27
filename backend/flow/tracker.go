package flow

import (
	"math"
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

	// ── ML Feature Tracking ──────────────────────────────────────────────
	CreatedAt    time.Time

	// Directional packet/byte counts
	FwdPacketCount uint64
	BwdPacketCount uint64
	FwdByteCount   uint64
	BwdByteCount   uint64

	// Per-packet sizes for min/max/mean/std calculation (capped at 1000 entries)
	FwdPacketLengths []int
	BwdPacketLengths []int

	// Inter-arrival times (microseconds)
	FwdIATs     []float64
	BwdIATs     []float64
	AllIATs     []float64
	LastFwdTime time.Time
	LastBwdTime time.Time
	LastPktTime time.Time

	// TCP flag counters
	SYNCount uint32
	FINCount uint32
	RSTCount uint32
	PSHCount uint32
	ACKCount uint32
	URGCount uint32

	// Directional flag counters
	FwdPSHFlags uint32
	BwdPSHFlags uint32
	FwdURGFlags uint32
	BwdURGFlags uint32

	// Header lengths (cumulative)
	FwdHeaderLen uint64
	BwdHeaderLen uint64

	// Initial TCP window sizes (set on first SYN/SYN-ACK)
	InitWinFwd    int32
	InitWinBwd    int32
	InitWinFwdSet bool
	InitWinBwdSet bool

	// Packets with payload in forward direction
	ActDataPktFwd uint32

	// ML prediction throttle
	LastMLCheck float64

	// ── Bulk tracking (CICFlowMeter definition: run of ≥4 consecutive
	// same-direction packets with no gap >1s between them) ────────────────
	FwdBulkBytes, BwdBulkBytes       uint64
	FwdBulkPackets, BwdBulkPackets   uint64
	FwdBulkDurationUs, BwdBulkDurationUs float64 // sum of completed-bulk durations (us)
	FwdBulkCount, BwdBulkCount       uint64

	// In-progress (not-yet-closed) bulk run state. Exported so the
	// detection package can peek at it when extracting live features
	// without needing an accessor method for every field.
	FwdBulkRunPackets uint64
	FwdBulkRunBytes   uint64
	FwdBulkRunStart   time.Time
	FwdBulkRunEnd     time.Time
	BwdBulkRunPackets uint64
	BwdBulkRunBytes   uint64
	BwdBulkRunStart   time.Time
	BwdBulkRunEnd     time.Time

	// ── Active/idle period tracking (gap >1s closes the active period and
	// opens an idle period) ─────────────────────────────────────────────
	ActivePeriods []float64 // durations of completed active bursts (us)
	IdlePeriods   []float64 // durations of completed idle gaps (us)
	ActiveStart   time.Time // start of the currently open (not yet closed) active period
	ActiveEnd     time.Time // last packet time within the currently open active period
}

const bulkIdleThresholdUs = 1e6 // 1 second, in microseconds

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
		f.Mu.Lock()
		f.LastSeen = time.Now()
		f.Mu.Unlock()
		return f, false
	}

	if len(t.flows) >= t.maxFlows {
		// Reached maximum flow tracking capacity
		return nil, false
	}

	now := time.Now()
	f = &Flow{
		Key:              key,
		State:            StateNew,
		LastSeen:         now,
		CreatedAt:        now,
		ClientStream:     NewStreamReassembler(t.maxReassembly),
		ServerStream:     NewStreamReassembler(t.maxReassembly),
		OriginalSrcIP:    pktSrcIP,
		OriginalSrcPort:  pktSrcPort,
		FwdPacketLengths: make([]int, 0, 64),
		BwdPacketLengths: make([]int, 0, 64),
		FwdIATs:          make([]float64, 0, 64),
		BwdIATs:          make([]float64, 0, 64),
		AllIATs:          make([]float64, 0, 128),
		InitWinFwd:       -1,
		InitWinBwd:       -1,
	}
	t.flows[key] = f
	return f, true
}

// UpdateFlowML updates the flow state with a new packet including ML-relevant metadata.
// headerLen is the transport header length in bytes (e.g. TCP header size).
// winSize is the TCP window size from the packet header (-1 if not TCP).
func (t *Tracker) UpdateFlowML(f *Flow, pktSrcIP [16]byte, pktSrcPort uint16, payload []byte, seq uint32, tcpFlags uint8, headerLen int, winSize int) {
	f.Mu.Lock()
	defer f.Mu.Unlock()

	now := time.Now()
	f.LastSeen = now
	f.PacketCount++
	pktLen := len(payload)
	f.ByteCount += uint64(pktLen)

	isClientToServer := f.OriginalSrcIP == pktSrcIP && f.OriginalSrcPort == pktSrcPort

	// ── IAT tracking ─────────────────────────────────────────────────────
	if !f.LastPktTime.IsZero() {
		iat := float64(now.Sub(f.LastPktTime).Microseconds())
		if len(f.AllIATs) < 1000 {
			f.AllIATs = append(f.AllIATs, iat)
		}

		// ── Active/idle period tracking ────────────────────────────────
		// A gap larger than the idle threshold closes the current active
		// burst and opens an idle period; otherwise the burst just extends.
		if iat > bulkIdleThresholdUs {
			if len(f.ActivePeriods) < 1000 {
				f.ActivePeriods = append(f.ActivePeriods, float64(f.ActiveEnd.Sub(f.ActiveStart).Microseconds()))
			}
			if len(f.IdlePeriods) < 1000 {
				f.IdlePeriods = append(f.IdlePeriods, iat)
			}
			f.ActiveStart = now
		}
		f.ActiveEnd = now
	} else {
		// First packet of the flow starts the first active period.
		f.ActiveStart = now
		f.ActiveEnd = now
	}
	f.LastPktTime = now

	// ── Directional stats ────────────────────────────────────────────────
	if isClientToServer {
		f.FwdPacketCount++
		f.FwdByteCount += uint64(pktLen)
		if len(f.FwdPacketLengths) < 1000 {
			f.FwdPacketLengths = append(f.FwdPacketLengths, pktLen)
		}
		if !f.LastFwdTime.IsZero() {
			iat := float64(now.Sub(f.LastFwdTime).Microseconds())
			if len(f.FwdIATs) < 1000 {
				f.FwdIATs = append(f.FwdIATs, iat)
			}
		}
		f.LastFwdTime = now
		f.FwdHeaderLen += uint64(headerLen)
		if pktLen > 0 {
			f.ActDataPktFwd++
			// ── Bulk tracking (fwd): run of ≥4 consecutive data-bearing
			// packets in the same direction with gaps ≤1s counts as a bulk.
			if f.FwdBulkRunPackets > 0 {
				gap := float64(now.Sub(f.FwdBulkRunEnd).Microseconds())
				if gap > bulkIdleThresholdUs {
					if f.FwdBulkRunPackets >= 4 {
						f.FwdBulkBytes += f.FwdBulkRunBytes
						f.FwdBulkPackets += f.FwdBulkRunPackets
						f.FwdBulkDurationUs += float64(f.FwdBulkRunEnd.Sub(f.FwdBulkRunStart).Microseconds())
						f.FwdBulkCount++
					}
					f.FwdBulkRunPackets = 0
					f.FwdBulkRunBytes = 0
					f.FwdBulkRunStart = now
				}
			} else {
				f.FwdBulkRunStart = now
			}
			f.FwdBulkRunPackets++
			f.FwdBulkRunBytes += uint64(pktLen)
			f.FwdBulkRunEnd = now
		}
	} else {
		f.BwdPacketCount++
		f.BwdByteCount += uint64(pktLen)
		if len(f.BwdPacketLengths) < 1000 {
			f.BwdPacketLengths = append(f.BwdPacketLengths, pktLen)
		}
		if !f.LastBwdTime.IsZero() {
			iat := float64(now.Sub(f.LastBwdTime).Microseconds())
			if len(f.BwdIATs) < 1000 {
				f.BwdIATs = append(f.BwdIATs, iat)
			}
		}
		f.LastBwdTime = now
		f.BwdHeaderLen += uint64(headerLen)
		if pktLen > 0 {
			// ── Bulk tracking (bwd): same rule as fwd, mirrored.
			if f.BwdBulkRunPackets > 0 {
				gap := float64(now.Sub(f.BwdBulkRunEnd).Microseconds())
				if gap > bulkIdleThresholdUs {
					if f.BwdBulkRunPackets >= 4 {
						f.BwdBulkBytes += f.BwdBulkRunBytes
						f.BwdBulkPackets += f.BwdBulkRunPackets
						f.BwdBulkDurationUs += float64(f.BwdBulkRunEnd.Sub(f.BwdBulkRunStart).Microseconds())
						f.BwdBulkCount++
					}
					f.BwdBulkRunPackets = 0
					f.BwdBulkRunBytes = 0
					f.BwdBulkRunStart = now
				}
			} else {
				f.BwdBulkRunStart = now
			}
			f.BwdBulkRunPackets++
			f.BwdBulkRunBytes += uint64(pktLen)
			f.BwdBulkRunEnd = now
		}
	}

	// ── TCP flags ────────────────────────────────────────────────────────
	if tcpFlags&0x02 != 0 { f.SYNCount++ }
	if tcpFlags&0x01 != 0 { f.FINCount++ }
	if tcpFlags&0x04 != 0 { f.RSTCount++ }
	if tcpFlags&0x08 != 0 {
		f.PSHCount++
		if isClientToServer { f.FwdPSHFlags++ } else { f.BwdPSHFlags++ }
	}
	if tcpFlags&0x10 != 0 { f.ACKCount++ }
	if tcpFlags&0x20 != 0 {
		f.URGCount++
		if isClientToServer { f.FwdURGFlags++ } else { f.BwdURGFlags++ }
	}

	// ── Initial window sizes ─────────────────────────────────────────────
	if winSize >= 0 {
		if isClientToServer && !f.InitWinFwdSet {
			f.InitWinFwd = int32(winSize)
			f.InitWinFwdSet = true
		} else if !isClientToServer && !f.InitWinBwdSet {
			f.InitWinBwd = int32(winSize)
			f.InitWinBwdSet = true
		}
	}

	// ── TCP state machine ────────────────────────────────────────────────
	if tcpFlags&0x02 != 0 && tcpFlags&0x10 == 0 {
		f.State = StateNew
		// SYN packet: Initial sequence number (ISN). Next expected byte is ISN + 1.
		if isClientToServer {
			f.ClientStream.Init(seq + 1)
		} else {
			f.ServerStream.Init(seq + 1)
		}
	} else if tcpFlags&0x10 != 0 && f.State == StateNew {
		f.State = StateEstablished
		if !isClientToServer && tcpFlags&0x02 != 0 {
			// SYN-ACK from server
			f.ServerStream.Init(seq + 1)
		}
	} else if tcpFlags&0x01 != 0 || tcpFlags&0x04 != 0 {
		f.State = StateClosing
	}

	// ── Stream reassembly ────────────────────────────────────────────────
	if pktLen > 0 {
		if isClientToServer {
			f.ClientStream.AddSegment(seq, payload)
		} else {
			f.ServerStream.AddSegment(seq, payload)
		}
	}
}

// UpdateFlow is the legacy entry point (for backwards compatibility).
func (t *Tracker) UpdateFlow(f *Flow, pktSrcIP [16]byte, pktSrcPort uint16, payload []byte, seq uint32, tcpFlags uint8) {
	t.UpdateFlowML(f, pktSrcIP, pktSrcPort, payload, seq, tcpFlags, 0, -1)
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

// ── Statistical helpers for ML feature extraction ────────────────────────────

func SliceMean(s []float64) float64 {
	if len(s) == 0 { return 0 }
	sum := 0.0
	for _, v := range s { sum += v }
	return sum / float64(len(s))
}

func SliceStd(s []float64) float64 {
	if len(s) < 2 { return 0 }
	m := SliceMean(s)
	sum := 0.0
	for _, v := range s { sum += (v - m) * (v - m) }
	return math.Sqrt(sum / float64(len(s)))
}

func SliceMax(s []float64) float64 {
	if len(s) == 0 { return 0 }
	mx := s[0]
	for _, v := range s { if v > mx { mx = v } }
	return mx
}

func SliceMin(s []float64) float64 {
	if len(s) == 0 { return 0 }
	mn := s[0]
	for _, v := range s { if v < mn { mn = v } }
	return mn
}

func SliceSum(s []float64) float64 {
	sum := 0.0
	for _, v := range s { sum += v }
	return sum
}

func IntSliceToFloat(s []int) []float64 {
	out := make([]float64, len(s))
	for i, v := range s { out[i] = float64(v) }
	return out
}
