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
	Tracker     *flow.Tracker
	RuleEngine  *rules.Engine
	HTTPInspect *inspect.HTTPInspector
	DNSInspect  *inspect.DNSInspector
	SSHInspect  *inspect.SSHInspector
	MLClient    *MLClient

	State       *state.AppState
	Config      *config.Config
	Firewall    *firewall.FirewallManager
	AlertLogger *alert.Logger
}

// NewEngine initializes the detection engine.
func NewEngine(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, re *rules.Engine, alertLogger *alert.Logger, mlClient *MLClient) *Engine {
	return &Engine{
		Tracker:     flow.NewTracker(100000, 120*time.Second, 65535),
		RuleEngine:  re,
		HTTPInspect: &inspect.HTTPInspector{},
		DNSInspect:  &inspect.DNSInspector{},
		SSHInspect:  &inspect.SSHInspector{},
		MLClient:    mlClient,
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
	if packet.IsTCPPSH {
		tcpFlags |= 0x08
	}
	if packet.IsTCPURG {
		tcpFlags |= 0x20
	}
	if packet.IsTCPFIN {
		tcpFlags |= 0x01
	}

	// Use UpdateFlowML with header length and window size for ML feature extraction
	e.Tracker.UpdateFlowML(f, pktSrc, packet.SrcPort, packet.Payload, packet.Seq, tcpFlags, packet.TCPHeaderLen, packet.TCPWindow)

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
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("engine: recovered from panic during DNS decode: %v\n", r)
				}
			}()
			dnsLayer := &layers.DNS{}
			if err := dnsLayer.DecodeFromBytes(packet.Payload, gopacket.NilDecodeFeedback); err == nil {
				if e.DNSInspect.Inspect(dnsLayer, true) {
					e.triggerRuleAlert(packet.SrcIP, packet.DstIP, "DNS Protocol Anomaly Detected", "protocol-command-decode", 3, "NET-DNS-ANOMALY", packet.SrcMAC)
				}
			}
		}()
	}

	// 4. Rule Evaluation (on reassembled stream or packet payload fallback)
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

	// If stream reassembly buffer is empty, fall back to current packet payload
	if len(searchPayload) == 0 && len(packet.Payload) > 0 {
		searchPayload = packet.Payload
	}

	if e.RuleEngine != nil {
		matchedRules := e.RuleEngine.Match(searchPayload)
		for _, r := range matchedRules {
			// Cleartext credentials on the configured gateway admin endpoint
			// are expected management traffic, not an inbound attack.
			e.Config.Mu.RLock()
			gatewayIP := e.Config.GatewayIP
			e.Config.Mu.RUnlock()
			if r.SID == 1000601 && gatewayIP != "" && packet.DstIP == gatewayIP {
				continue
			}
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

	// 5. ML-based anomaly detection (async, throttled per-flow)
	// IMPORTANT: Only run ML detection on INBOUND-initiated flows.
	// If WE initiated the connection (outbound browsing), the remote server
	// is NOT an attacker — do not block web servers we are visiting.
	e.Config.Mu.RLock()
	mlEnabled := e.Config.MLEnabled
	e.Config.Mu.RUnlock()

	if mlEnabled && e.MLClient != nil && e.MLClient.IsAvailable() {
		f.Mu.Lock()
		totalPkts := f.PacketCount
		now := float64(time.Now().UnixNano()) / 1e9
		lastCheck := f.LastMLCheck
		// Determine if this flow was initiated by an external source (inbound)
		// OriginalSrcIP is the IP that sent the first packet of the flow.
		flowInitiatorIP := f.OriginalSrcIP
		f.Mu.Unlock()

		// Check if the flow initiator is an internal IP.
		// If the flow was initiated from inside our network (outbound), skip ML blocking.
		var flowInitiatorIPStr string
		initIP := net.IP(flowInitiatorIP[:])
		if initIP.To4() != nil {
			flowInitiatorIPStr = initIP.To4().String()
		} else {
			flowInitiatorIPStr = initIP.String()
		}
		isOutboundFlow := isLocalIP(flowInitiatorIPStr)

		// Only predict for INBOUND flows with >=10 packets, and throttle to once per 5 seconds per flow
		if !isOutboundFlow && totalPkts >= 10 && (now-lastCheck) > 5.0 {
			f.Mu.Lock()
			f.LastMLCheck = now
			f.Mu.Unlock()

			// Fire-and-forget: run ML prediction in a goroutine to avoid blocking the packet pipeline
			pktDstIP := packet.DstIP
			pktDstPort := packet.DstPort
			pktSrcMAC := packet.SrcMAC
			attackerIP := flowInitiatorIPStr
			if attackerIP == "" {
				attackerIP = packet.SrcIP
			}
			go func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("engine: recovered from panic during ML prediction: %v\n", r)
					}
				}()

				features := ExtractFlowFeatures(f, pktDstPort)
				resp, err := e.MLClient.Predict(features)
				if err != nil {
					// Silently ignore — ML is a best-effort enhancement
					return
				}

				if resp.Malicious && resp.Confidence >= 0.90 {
					ruleID := fmt.Sprintf("ML-%s-001", resp.Prediction)
					reason := fmt.Sprintf("ML Detection: %s (confidence: %.1f%%)", resp.Prediction, resp.Confidence*100)

					// Inbound-initiated flow — this is a real attacker. Block them.
					e.State.Mu.Lock()
					triggerAlert(e.State, e.Config, e.Firewall, e.AlertLogger, float64(time.Now().UnixNano())/1e9, ruleID, fmt.Sprintf("ML: %s Detected", resp.Prediction), "High", "High", attackerIP, pktDstIP, reason, resp.Confidence, pktSrcMAC)
					e.State.Mu.Unlock()
				}
			}()
		}
	}
}

// isLocalIP checks if an IP belongs to this machine's interfaces.
func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Check private ranges
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	if ip.IsLoopback() {
		return true
	}
	return false
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
	ruleNet = strings.TrimSpace(ruleNet)
	if ruleNet == "any" || ruleNet == "" {
		return true
	}
	// Snort variable expansion
	if strings.EqualFold(ruleNet, "$EXTERNAL_NET") {
		// In an IDPS, threats can originate from external WAN or untrusted LAN hosts.
		// Standard Snort rules default EXTERNAL_NET to "any" to inspect all inbound traffic.
		return true
	}
	if strings.EqualFold(ruleNet, "$HOME_NET") {
		// Matches private RFC1918 subnets, loopback, or local host interfaces
		return isInternalIP(pktIP) || isLocalIP(pktIP)
	}

	// Check for negation e.g. "!$HOME_NET"
	negate := false
	if strings.HasPrefix(ruleNet, "!") {
		negate = true
		ruleNet = strings.TrimPrefix(ruleNet, "!")
		if strings.EqualFold(ruleNet, "$HOME_NET") {
			res := !isInternalIP(pktIP) && !isLocalIP(pktIP)
			if negate {
				return res
			}
			return !res
		}
	}

	// Check for CIDR
	if strings.Contains(ruleNet, "/") {
		_, ipNet, err := net.ParseCIDR(ruleNet)
		if err == nil && ipNet != nil {
			parsedIP := net.ParseIP(pktIP)
			res := parsedIP != nil && ipNet.Contains(parsedIP)
			if negate {
				return !res
			}
			return res
		}
	}
	// Exact IP match
	res := ruleNet == pktIP
	if negate {
		return !res
	}
	return res
}

var httpPorts = map[uint16]bool{
	80:   true,
	8080: true,
	8000: true,
	8888: true,
	3000: true,
	5000: true,
	8008: true,
}

func portMatch(rulePort string, pktPort uint16) bool {
	rulePort = strings.TrimSpace(rulePort)
	if rulePort == "any" || rulePort == "" {
		return true
	}

	// Snort port variables
	if strings.EqualFold(rulePort, "$HTTP_PORTS") {
		return httpPorts[pktPort]
	}

	// Handle bracketed or comma-separated lists e.g. [80, 8080, 8000]
	cleanPort := strings.Trim(rulePort, "[]")
	if strings.Contains(cleanPort, ",") {
		for _, part := range strings.Split(cleanPort, ",") {
			if portMatch(strings.TrimSpace(part), pktPort) {
				return true
			}
		}
		return false
	}

	// Handle port ranges e.g. 1024:65535 or :1024 or 1024:
	if strings.Contains(cleanPort, ":") {
		parts := strings.Split(cleanPort, ":")
		if len(parts) == 2 {
			minPort := 0
			maxPort := 65535
			if parts[0] != "" {
				if p, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
					minPort = p
				}
			}
			if parts[1] != "" {
				if p, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					maxPort = p
				}
			}
			return int(pktPort) >= minPort && int(pktPort) <= maxPort
		}
	}

	p, err := strconv.Atoi(cleanPort)
	if err == nil {
		return pktPort == uint16(p)
	}

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
