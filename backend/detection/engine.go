package detection

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"idps-backend/alert"
	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/flow"
	"idps-backend/inspect"
	"idps-backend/rules"
	"idps-backend/state"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Engine is the central detection coordinator.
type Engine struct {
	Tracker      *flow.Tracker
	RuleEngine   *rules.Engine
	HTTPInspect  *inspect.HTTPInspector
	DNSInspect   *inspect.DNSInspector
	SSHInspect   *inspect.SSHInspector
	
	State        *state.AppState
	Config       *config.Config
	Firewall     *firewall.FirewallManager
	AlertLogger  *alert.Logger
}

// NewEngine initializes the detection engine.
func NewEngine(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, re *rules.Engine, alertLogger *alert.Logger) *Engine {
	return &Engine{
		Tracker:     flow.NewTracker(100000, 120*time.Second, 65535),
		RuleEngine:  re,
		HTTPInspect: &inspect.HTTPInspector{},
		DNSInspect:  &inspect.DNSInspector{},
		SSHInspect:  &inspect.SSHInspector{},
		State:       st,
		Config:      cfg,
		Firewall:    fm,
		AlertLogger: alertLogger,
	}
}

// ProcessPacket is the main entry point for the new detection pipeline.
func (e *Engine) ProcessPacket(packet PacketInfo) {
	// 1. Run preserved rate-based heuristics and device tracking
	AnalyzePacket(e.State, e.Config, e.Firewall, e.AlertLogger, packet)

	// 2. Flow Tracking & Reassembly
	if packet.SrcIP == "" || packet.DstIP == "" || packet.Protocol == "ARP" {
		return
	}

	srcIP := net.ParseIP(packet.SrcIP)
	dstIP := net.ParseIP(packet.DstIP)
	if srcIP == nil || dstIP == nil {
		return
	}

	var proto flow.Protocol
	switch packet.Protocol {
	case "TCP":
		proto = flow.ProtoTCP
	case "UDP":
		proto = flow.ProtoUDP
	case "ICMP":
		proto = flow.ProtoICMP
	default:
		return
	}

	key := flow.NewKey(proto, srcIP, dstIP, packet.SrcPort, packet.DstPort)

	var pktSrc [16]byte
	copy(pktSrc[:], srcIP.To16())

	f, _ := e.Tracker.GetOrCreate(key, pktSrc, packet.SrcPort)
	if f == nil {
		return // Max flows reached
	}

	tcpFlags := uint8(0)
	if packet.IsTCPSYN {
		tcpFlags |= 0x02
	}
	if packet.IsTCPACK {
		tcpFlags |= 0x10
	}
	if packet.IsTCPRST {
		tcpFlags |= 0x04
	}

	e.Tracker.UpdateFlow(f, pktSrc, packet.SrcPort, packet.Payload, packet.Seq, tcpFlags)

	isClientToServer := f.OriginalSrcIP == pktSrc && f.OriginalSrcPort == packet.SrcPort

	// 3. Protocol Inspection for Anomalies
	if packet.DstPort == 80 || packet.SrcPort == 80 || packet.DstPort == 8080 {
		_, _, isAnomaly := e.HTTPInspect.InspectRequest(packet.Payload)
		if isAnomaly {
			e.triggerRuleAlert(packet.SrcIP, packet.DstIP, "HTTP Protocol Anomaly", "web-application-attack", 2, "NET-HTTP-ANOMALY", packet.SrcMAC)
		}
	} else if packet.DstPort == 22 || packet.SrcPort == 22 {
		if e.SSHInspect.Inspect(packet.Payload) {
			e.triggerRuleAlert(packet.SrcIP, packet.DstIP, "Deprecated SSH Version Detected", "policy-violation", 3, "NET-SSH-POLICY", packet.SrcMAC)
		}
	} else if (packet.DstPort == 53 || packet.SrcPort == 53) && packet.Protocol == "UDP" {
		dnsLayer := &layers.DNS{}
		if err := dnsLayer.DecodeFromBytes(packet.Payload, gopacket.NilDecodeFeedback); err == nil {
			if e.DNSInspect.Inspect(dnsLayer, true) {
				e.triggerRuleAlert(packet.SrcIP, packet.DstIP, "DNS Protocol Anomaly Detected", "protocol-command-decode", 3, "NET-DNS-ANOMALY", packet.SrcMAC)
			}
		}
	}

	// 4. Rule Evaluation (on reassembled stream)
	var searchPayload []byte
	f.Mu.Lock()
	if isClientToServer {
		searchPayload = make([]byte, len(f.ClientStream.Data))
		copy(searchPayload, f.ClientStream.Data)
	} else {
		searchPayload = make([]byte, len(f.ServerStream.Data))
		copy(searchPayload, f.ServerStream.Data)
	}
	f.Mu.Unlock()

	if len(searchPayload) > 0 && e.RuleEngine != nil {
		matchedRules := e.RuleEngine.Match(searchPayload)
		for _, r := range matchedRules {
			if !ruleHeaderMatch(r, packet.Protocol, packet.SrcIP, packet.DstIP, packet.SrcPort, packet.DstPort, isClientToServer) {
				continue
			}

			severity := "Medium"
			if r.Priority == 1 {
				severity = "Critical"
			} else if r.Priority == 2 {
				severity = "High"
			}
			
			ruleID := fmt.Sprintf("SID-%d", r.SID)
			
			e.State.Mu.Lock()
			triggerAlert(e.State, e.Config, e.Firewall, e.AlertLogger, float64(time.Now().UnixNano())/1e9, ruleID, r.Classtype, severity, "High", packet.SrcIP, packet.DstIP, r.Msg, 1.0, packet.SrcMAC)
			e.State.Mu.Unlock()
		}
	}
}

func ruleHeaderMatch(r *rules.Rule, proto string, pktSrcIP, pktDstIP string, pktSrcPort, pktDstPort uint16, isClientToServer bool) bool {
	if r.Protocol != "ip" && r.Protocol != "any" && strings.ToLower(r.Protocol) != strings.ToLower(proto) {
		return false
	}
	
	matchForward := ipMatch(r.SrcNet, pktSrcIP) && ipMatch(r.DstNet, pktDstIP) && portMatch(r.SrcPort, pktSrcPort) && portMatch(r.DstPort, pktDstPort)
	if matchForward {
		return true
	}

	if r.Direction == "<>" {
		matchBackward := ipMatch(r.DstNet, pktSrcIP) && ipMatch(r.SrcNet, pktDstIP) && portMatch(r.DstPort, pktSrcPort) && portMatch(r.SrcPort, pktDstPort)
		if matchBackward {
			return true
		}
	}

	return false
}

func ipMatch(ruleNet, pktIP string) bool {
	if ruleNet == "any" || ruleNet == "" {
		return true
	}
	// Check for CIDR
	if strings.Contains(ruleNet, "/") {
		_, ipNet, err := net.ParseCIDR(ruleNet)
		if err == nil && ipNet != nil {
			parsedIP := net.ParseIP(pktIP)
			if parsedIP != nil && ipNet.Contains(parsedIP) {
				return true
			}
			return false
		}
	}
	// Exact IP match
	return ruleNet == pktIP
}

// TODO: Full Snort-style variable expansion ($HTTP_PORTS, $HOME_NET, $EXTERNAL_NET) is not yet implemented
func portMatch(rulePort string, pktPort uint16) bool {
	if rulePort == "any" || rulePort == "" {
		return true
	}
	// Basic parsing: doesn't handle port ranges (like 1024:65535) or negation (!80) for this MVP
	p, err := strconv.Atoi(rulePort)
	if err == nil {
		return pktPort == uint16(p)
	}
	// Need variable expansion like $HTTP_PORTS here in a real implementation.
	// For now, unsupported specifications are treated as fail-closed.
	fmt.Printf("Warning: Unsupported port specification '%s' evaluated as fail-closed\n", rulePort)
	return false 
}

func (e *Engine) triggerRuleAlert(srcIP, dstIP, msg, classType string, priority int, ruleID string, srcMAC string) {
	severity := "Medium"
	if priority == 1 {
		severity = "Critical"
	} else if priority == 2 {
		severity = "High"
	}

	e.State.Mu.Lock()
	triggerAlert(e.State, e.Config, e.Firewall, e.AlertLogger, float64(time.Now().UnixNano())/1e9, ruleID, classType, severity, "High", srcIP, dstIP, msg, 1.0, srcMAC)
	e.State.Mu.Unlock()
}
