package state

import (
	"sync"
)

type Device struct {
	IP        string  `json:"ip"`
	MAC       string  `json:"mac"`
	Name      string  `json:"name"`
	FirstSeen float64 `json:"first_seen"`
	LastSeen  float64 `json:"last_seen"`
}

type Alert struct {
	ID           string  `json:"id"`
	Timestamp    float64 `json:"timestamp"`
	RuleID       string  `json:"rule_id"`
	AlertType    string  `json:"alert_type"`
	Severity     string  `json:"severity"`
	Confidence   string  `json:"confidence"`
	SourceIP     string  `json:"source_ip"`
	DestIP       string  `json:"dest_ip"`
	Reason       string  `json:"reason"`
	Action       string  `json:"action"`
	ActionResult string  `json:"action_result"`
	Status       string  `json:"status"`
	ExpiresAt    float64 `json:"expires_at,omitempty"`
	Rate         float64 `json:"rate"`
}

type IPBlock struct {
	IP         string  `json:"ip"`
	RuleID     string  `json:"rule_id"`
	Reason     string  `json:"reason"`
	Confidence string  `json:"confidence"`
	CreatedAt  float64 `json:"created_at"`
	ExpiresAt  float64 `json:"expires_at"`
}

type TrafficLog struct {
	Timestamp float64 `json:"timestamp"`
	SrcIP     string  `json:"src_ip"`
	Domain    string  `json:"domain"`
	Proto     string  `json:"proto"`
}

type ThreatTimeline struct {
	Timestamp float64 `json:"timestamp"`
	Event     string  `json:"event"`
	Severity  string  `json:"severity"`
}

type AppState struct {
	Mu sync.RWMutex

	BlockedIPs  map[string]IPBlock
	Devices     map[string]*Device
	Alerts      []Alert
	PacketCount int

	ThreatTimeline []ThreatTimeline
	TrafficLog     []TrafficLog

	// Windowed tracking (timestamps)
	IPPacketTimestamps map[string][]float64
	IPICMPTimestamps   map[string][]float64
	IPUDPTimestamps    map[string][]float64
	IPSYNTimestamps    map[string][]float64
	IPSSHTimestamps    map[string][]float64

	// Port scan tracking: src_ip -> { dst_port -> timestamp }
	IPPortsAccessed map[string]map[uint16]float64

	// ARP spoofing tracking: src_ip -> { mac -> timestamp }
	IPMACMapping map[string]map[string]float64

	PortCounts      map[uint16]int
	ProtocolCounts  map[string]int

	ActiveConnections int
	LastAlertTimes    map[string]float64
}

func NewAppState() *AppState {
	return &AppState{
		BlockedIPs:         make(map[string]IPBlock),
		Devices:            make(map[string]*Device),
		Alerts:             make([]Alert, 0, 1000),
		ThreatTimeline:     make([]ThreatTimeline, 0, 500),
		TrafficLog:         make([]TrafficLog, 0, 200),
		IPPacketTimestamps: make(map[string][]float64),
		IPICMPTimestamps:   make(map[string][]float64),
		IPUDPTimestamps:    make(map[string][]float64),
		IPSYNTimestamps:    make(map[string][]float64),
		IPSSHTimestamps:    make(map[string][]float64),
		IPPortsAccessed:    make(map[string]map[uint16]float64),
		IPMACMapping:       make(map[string]map[string]float64),
		PortCounts:         make(map[uint16]int),
		ProtocolCounts:     make(map[string]int),
		LastAlertTimes:     make(map[string]float64),
	}
}

func (s *AppState) AddAlert(alert Alert) {
	s.Alerts = append(s.Alerts, alert)
	if len(s.Alerts) > 1000 {
		s.Alerts = s.Alerts[1:]
	}
}

func (s *AppState) AddTrafficLog(log TrafficLog) {
	s.TrafficLog = append(s.TrafficLog, log)
	if len(s.TrafficLog) > 200 {
		s.TrafficLog = s.TrafficLog[1:]
	}
}

func (s *AppState) AddThreatTimeline(tl ThreatTimeline) {
	s.ThreatTimeline = append(s.ThreatTimeline, tl)
	if len(s.ThreatTimeline) > 500 {
		s.ThreatTimeline = s.ThreatTimeline[1:]
	}
}
