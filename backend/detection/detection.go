package detection

import (
	"fmt"
	"time"

	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/state"

	"github.com/google/uuid"
)

func getTimestamp() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

type PacketInfo struct {
	SrcIP     string
	DstIP     string
	SrcMAC    string
	DstMAC    string
	Protocol  string
	SrcPort   uint16
	DstPort   uint16
	IsTCPSYN  bool
	IsTCPACK  bool
	IsTCPRST  bool
	Payload   []byte
}

func AnalyzePacket(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, packet PacketInfo) {
	currentTime := getTimestamp()

	if packet.SrcIP == "" {
		return
	}
	srcIP := packet.SrcIP
	dstIP := packet.DstIP
	if dstIP == "" {
		dstIP = "N/A"
	}

	// 1. Device tracking
	if packet.SrcMAC != "" {
		st.Mu.Lock()
		device, exists := st.Devices[packet.SrcMAC]
		if !exists {
			device = &state.Device{
				IP:        srcIP,
				MAC:       packet.SrcMAC,
				Name:      "Unknown",
				FirstSeen: currentTime,
				LastSeen:  currentTime,
			}
			st.Devices[packet.SrcMAC] = device
		} else {
			device.LastSeen = currentTime
			if device.IP != srcIP {
				device.IP = srcIP
			}
		}
		st.Mu.Unlock()
	}

	// Skip blocked IPs (IPS mode)
	st.Mu.RLock()
	if cfg.IDPSSecurityMode == "IPS" {
		if _, blocked := st.BlockedIPs[srcIP]; blocked {
			st.Mu.RUnlock()
			return
		}
	}
	st.Mu.RUnlock()

	st.Mu.Lock()
	st.PacketCount++
	st.ProtocolCounts[packet.Protocol]++
	if packet.DstPort != 0 {
		st.PortCounts[packet.DstPort]++
	}

	// Rate Tracking helper
	addTimestamp := func(timestamps *[]float64, current float64) int {
		ts := *timestamps
		// Remove timestamps older than 3 seconds
		keepIndex := 0
		for i, t := range ts {
			if current-t <= 3.0 {
				keepIndex = i
				break
			}
			if i == len(ts)-1 {
				keepIndex = len(ts)
			}
		}
		ts = ts[keepIndex:]
		ts = append(ts, current)
		*timestamps = ts
		return int(float64(len(ts)) / 3.0)
	}

	ts, exists := st.IPPacketTimestamps[srcIP]
	if !exists {
		ts = make([]float64, 0, 5000)
	}
	packetRate := addTimestamp(&ts, currentTime)
	st.IPPacketTimestamps[srcIP] = ts

	isPortScan := false
	scanKey := srcIP + "_NET-SCAN-001"
	if lastScan, ok := st.LastAlertTimes[scanKey]; ok {
		if currentTime-lastScan < 30.0 {
			isPortScan = true
		}
	}

	// ARP Spoofing
	if packet.Protocol == "ARP" && packet.SrcMAC != "" {
		macs, exists := st.IPMACMapping[srcIP]
		if !exists {
			macs = make(map[string]float64)
		}
		macs[packet.SrcMAC] = currentTime
		
		// Cleanup old
		for mac, t := range macs {
			if currentTime-t > 60.0 {
				delete(macs, mac)
			}
		}
		st.IPMACMapping[srcIP] = macs

		macCount := len(macs)
		if macCount > 1 {
			triggerAlert(st, cfg, fm, currentTime, "NET-ARP-001", "Duplicate IP / ARP Spoofing", "High", "Medium", srcIP, dstIP, fmt.Sprintf("ARP Spoofing (%d MACs)", macCount), float64(macCount))
		}
	}

	uniquePortsRate := 0
	if packet.Protocol == "TCP" {
		if packet.IsTCPSYN && !packet.IsTCPACK && !packet.IsTCPRST {
			if packet.DstPort != 0 {
				ports, exists := st.IPPortsAccessed[srcIP]
				if !exists {
					ports = make(map[uint16]float64)
				}
				ports[packet.DstPort] = currentTime
				for p, t := range ports {
					if currentTime-t > 3.0 {
						delete(ports, p)
					}
				}
				st.IPPortsAccessed[srcIP] = ports
				uniquePortsRate = len(ports)
			}

			// SYN Flood
			synTs, exists := st.IPSYNTimestamps[srcIP]
			if !exists {
				synTs = make([]float64, 0, 5000)
			}
			synRate := addTimestamp(&synTs, currentTime)
			st.IPSYNTimestamps[srcIP] = synTs

			if synRate > cfg.SYNFloodThreshold && uniquePortsRate <= 5 {
				triggerAlert(st, cfg, fm, currentTime, "NET-SYN-001", "SYN Flood", "High", "High", srcIP, dstIP, fmt.Sprintf("SYN Flood (%d pkts/s)", synRate), float64(synRate))
			}

			// SSH Brute Force
			if packet.DstPort == 22 {
				sshTs, exists := st.IPSSHTimestamps[srcIP]
				if !exists {
					sshTs = make([]float64, 0, 500)
				}
				sshRate := addTimestamp(&sshTs, currentTime)
				st.IPSSHTimestamps[srcIP] = sshTs

				if sshRate > cfg.SSHBruteForceThreshold {
					triggerAlert(st, cfg, fm, currentTime, "NET-SSH-001", "SSH Brute Force", "Critical", "High", srcIP, dstIP, fmt.Sprintf("SSH Brute Force (%d attempts/3s)", sshRate), float64(sshRate))
				}
			}
		}
	}

	if uniquePortsRate > 5 {
		isPortScan = true
	}

	if uniquePortsRate > cfg.PortScanThreshold {
		triggerAlert(st, cfg, fm, currentTime, "NET-SCAN-001", "Port Scan", "High", "High", srcIP, dstIP, fmt.Sprintf("Port Scan (%d ports/3s)", uniquePortsRate), float64(uniquePortsRate))
	}

	// UDP Flood
	if packet.Protocol == "UDP" {
		wellKnownPort := func(p uint16) bool {
			return p == 53 || p == 67 || p == 68 || p == 443 || p == 80 || p == 123 || p == 5353 || p == 1900 || p == 8443 || p == 8080
		}
		isKnown := wellKnownPort(packet.SrcPort) || wellKnownPort(packet.DstPort)

		if !isKnown {
			udpTs, exists := st.IPUDPTimestamps[srcIP]
			if !exists {
				udpTs = make([]float64, 0, 5000)
			}
			udpRate := addTimestamp(&udpTs, currentTime)
			st.IPUDPTimestamps[srcIP] = udpTs

			if udpRate > cfg.UDPFloodThreshold {
				triggerAlert(st, cfg, fm, currentTime, "NET-UDP-001", "UDP Flood", "Medium", "High", srcIP, dstIP, fmt.Sprintf("UDP Flood (%d pkts/s)", udpRate), float64(udpRate))
			}
		}

		// DNS Amplification
		if packet.SrcPort == 53 && len(packet.Payload) > 500 {
			udpTs, exists := st.IPDNSReplyTimestamps[srcIP]
			if !exists {
				udpTs = make([]float64, 0, 5000)
			}
			dnsRate := addTimestamp(&udpTs, currentTime)
			st.IPDNSReplyTimestamps[srcIP] = udpTs

			if dnsRate > 20 {
				triggerAlert(st, cfg, fm, currentTime, "NET-DNS-001", "DNS Amplification", "High", "High", srcIP, dstIP, fmt.Sprintf("DNS Amplification (%d pkts/3s)", dnsRate), float64(dnsRate))
			}
		}
	}

	// ICMP Flood
	if packet.Protocol == "ICMP" {
		icmpTs, exists := st.IPICMPTimestamps[srcIP]
		if !exists {
			icmpTs = make([]float64, 0, 5000)
		}
		icmpRate := addTimestamp(&icmpTs, currentTime)
		st.IPICMPTimestamps[srcIP] = icmpTs

		if icmpRate > cfg.ICMPFloodThreshold {
			triggerAlert(st, cfg, fm, currentTime, "NET-ICMP-001", "ICMP Flood", "Medium", "High", srcIP, dstIP, fmt.Sprintf("ICMP Flood (%d pkts/s)", icmpRate), float64(icmpRate))
		}

		// Ping of Death
		if len(packet.Payload) > 1000 {
			triggerAlert(st, cfg, fm, currentTime, "NET-POD-001", "Ping of Death", "Critical", "High", srcIP, dstIP, fmt.Sprintf("Oversized ICMP (%d bytes)", len(packet.Payload)), 1.0)
		}
	}

	// DoS Generic Flood
	if packetRate > cfg.SuspiciousRateThreshold && !isPortScan {
		triggerAlert(st, cfg, fm, currentTime, "NET-DOS-001", "DoS Attack", "Critical", "High", srcIP, dstIP, fmt.Sprintf("DoS Attack (%d pkts/s)", packetRate), float64(packetRate))
	}
	
	st.Mu.Unlock()
}

// Ensure st.Mu is Locked before calling triggerAlert
func triggerAlert(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, currentTime float64, ruleID, alertType, severity, confidence, srcIP, dstIP, reason string, rate float64) {
	throttleKey := srcIP + "_" + ruleID
	if lastAlert, ok := st.LastAlertTimes[throttleKey]; ok {
		if currentTime-lastAlert < 30.0 {
			return
		}
	}
	st.LastAlertTimes[throttleKey] = currentTime

	alert := state.Alert{
		ID:           uuid.New().String(),
		Timestamp:    currentTime,
		RuleID:       ruleID,
		AlertType:    alertType,
		Severity:     severity,
		Confidence:   confidence,
		SourceIP:     srcIP,
		DestIP:       dstIP,
		Reason:       reason,
		Action:       "NONE",
		ActionResult: "NOT_APPLICABLE",
		Status:       "NEW",
		Rate:         rate,
	}

	if cfg.IDPSSecurityMode == "IDS" {
		alert.Action = "ALERT"
		alert.ActionResult = "SUCCESS"
		alert.Status = "LOGGED"
	} else {
		if severity == "High" || severity == "Critical" || confidence == "High" || confidence == "Critical" {
			alert.Action = "BLOCK"
			if fm.BlockIP(srcIP, cfg) {
				alert.ActionResult = "SUCCESS"
				alert.Status = "BLOCKED"
				expiresAt := currentTime + float64(cfg.BlockTTLSeconds)
				alert.ExpiresAt = expiresAt

				st.BlockedIPs[srcIP] = state.IPBlock{
					IP:         srcIP,
					RuleID:     ruleID,
					Reason:     reason,
					Confidence: confidence,
					CreatedAt:  currentTime,
					ExpiresAt:  expiresAt,
				}

				st.AddThreatTimeline(state.ThreatTimeline{
					Timestamp: currentTime,
					Event:     fmt.Sprintf("Blocked IP %s (Rule: %s)", srcIP, ruleID),
					Severity:  severity,
				})
			} else {
				alert.ActionResult = "FAILED"
				alert.Status = "BLOCK_FAILED"
			}
		} else {
			alert.Action = "ALERT"
			alert.ActionResult = "SUCCESS"
			alert.Status = "LOGGED (BELOW THRESHOLD)"
		}
	}

	st.AddAlert(alert)
}
