package state

import (
	"sync"
	"time"
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
	MAC        string  `json:"mac"`
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

	BlockedIPs         map[string]IPBlock
	BlockedMACs        map[string]IPBlock
	Devices            map[string]*Device
	Alerts             []Alert
	PacketCount        int
	DroppedPacketCount int

	ThreatTimeline []ThreatTimeline
	TrafficLog     []TrafficLog

	// Windowed tracking (timestamps)
	IPPacketTimestamps   map[string][]float64
	IPICMPTimestamps     map[string][]float64
	IPUDPTimestamps      map[string][]float64
	IPDNSReplyTimestamps map[string][]float64
	IPSYNTimestamps      map[string][]float64
	IPSSHTimestamps      map[string][]float64
	IPARPTimestamps      map[string][]float64

	// Port scan tracking: src_ip -> { dst_port -> timestamp }
	IPPortsAccessed map[string]map[uint16]float64

	// ICMP Sweep tracking: src_ip -> { dst_ip -> timestamp }
	IPICMPSweep map[string]map[string]float64

	// ARP spoofing tracking: src_ip -> { mac -> timestamp }
	IPMACMapping map[string]map[string]float64

	// MAC Flood / DHCP Starvation tracking
	GlobalMACsSeen map[string]float64
	DHCPStarvation map[string]float64 // mac -> timestamp for DHCP discovers

	PortCounts      map[uint16]int
	ProtocolCounts  map[string]int

	ActiveConnections int
	LastAlertTimes    map[string]float64
}

func NewAppState() *AppState {
	st := &AppState{
		BlockedIPs:         make(map[string]IPBlock),
		BlockedMACs:        make(map[string]IPBlock),
		Devices:            make(map[string]*Device),
		Alerts:             make([]Alert, 0, 1000),
		ThreatTimeline:     make([]ThreatTimeline, 0, 500),
		TrafficLog:         make([]TrafficLog, 0, 200),
		IPPacketTimestamps:   make(map[string][]float64),
		IPICMPTimestamps:     make(map[string][]float64),
		IPUDPTimestamps:      make(map[string][]float64),
		IPDNSReplyTimestamps: make(map[string][]float64),
		IPSYNTimestamps:      make(map[string][]float64),
		IPSSHTimestamps:      make(map[string][]float64),
		IPARPTimestamps:      make(map[string][]float64),
		IPPortsAccessed:      make(map[string]map[uint16]float64),
		IPICMPSweep:          make(map[string]map[string]float64),
		IPMACMapping:       make(map[string]map[string]float64),
		GlobalMACsSeen:     make(map[string]float64),
		DHCPStarvation:     make(map[string]float64),
		PortCounts:         make(map[uint16]int),
		ProtocolCounts:     make(map[string]int),
		LastAlertTimes:     make(map[string]float64),
	}
	go st.cleanupLoop()
	return st
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

// cleanupLoop periodically prunes expired state to prevent memory exhaustion (OOM).
func (s *AppState) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := float64(time.Now().UnixNano()) / 1e9

		s.Mu.Lock()

		// Helper to clean timestamp arrays (expire after 5 minutes)
		cleanTimestamps := func(m map[string][]float64) {
			for k, ts := range m {
				if len(ts) == 0 || now-ts[len(ts)-1] > 300.0 {
					delete(m, k)
				}
			}
		}

		cleanTimestamps(s.IPPacketTimestamps)
		cleanTimestamps(s.IPICMPTimestamps)
		cleanTimestamps(s.IPUDPTimestamps)
		cleanTimestamps(s.IPDNSReplyTimestamps)
		cleanTimestamps(s.IPSYNTimestamps)
		cleanTimestamps(s.IPSSHTimestamps)
		cleanTimestamps(s.IPARPTimestamps)

		// Clean nested maps
		for srcIP, portMap := range s.IPPortsAccessed {
			for port, t := range portMap {
				if now-t > 300.0 {
					delete(portMap, port)
				}
			}
			if len(portMap) == 0 {
				delete(s.IPPortsAccessed, srcIP)
			}
		}

		for srcIP, ipMap := range s.IPICMPSweep {
			for ip, t := range ipMap {
				if now-t > 300.0 {
					delete(ipMap, ip)
				}
			}
			if len(ipMap) == 0 {
				delete(s.IPICMPSweep, srcIP)
			}
		}

		for srcIP, macMap := range s.IPMACMapping {
			for mac, t := range macMap {
				if now-t > 300.0 {
					delete(macMap, mac)
				}
			}
			if len(macMap) == 0 {
				delete(s.IPMACMapping, srcIP)
			}
		}

		// Clean flat maps
		for mac, t := range s.GlobalMACsSeen {
			if now-t > 300.0 {
				delete(s.GlobalMACsSeen, mac)
			}
		}

		for mac, t := range s.DHCPStarvation {
			if now-t > 300.0 {
				delete(s.DHCPStarvation, mac)
			}
		}

		for key, t := range s.LastAlertTimes {
			if now-t > 300.0 {
				delete(s.LastAlertTimes, key)
			}
		}

		// Clean up expired IP and MAC blocks manually if needed (though usually done by TTL, we can passively expire here)
		for ip, b := range s.BlockedIPs {
			if b.ExpiresAt > 0 && now > b.ExpiresAt {
				delete(s.BlockedIPs, ip)
			}
		}
		for mac, b := range s.BlockedMACs {
			if b.ExpiresAt > 0 && now > b.ExpiresAt {
				delete(s.BlockedMACs, mac)
			}
		}

		s.Mu.Unlock()
	}
}
