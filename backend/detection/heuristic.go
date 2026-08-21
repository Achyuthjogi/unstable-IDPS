package detection

import (
	"fmt"
	"net"
	"strings"
	"time"

	"idps-backend/alert"
	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/state"

	"github.com/google/uuid"
)

var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, block, _ := net.ParseCIDR(cidr)
		privateCIDRs = append(privateCIDRs, block)
	}
}

func isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, block := range privateCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func getTimestamp() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

type PacketInfo struct {
	SrcIP    string
	DstIP    string
	SrcMAC   string
	DstMAC   string
	Protocol string
	SrcPort  uint16
	DstPort  uint16
	IsTCPSYN bool
	IsTCPACK bool
	IsTCPRST     bool
	Seq          uint32
	ARPOperation uint16
	Payload      []byte
	IsDHCPOffer  bool
}

func AnalyzePacket(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, alertLogger *alert.Logger, packet PacketInfo) {
	currentTime := getTimestamp()

	cfg.Mu.RLock()
	secMode := cfg.IDPSSecurityMode
	synThresh := cfg.SYNFloodThreshold
	sshThresh := cfg.SSHBruteForceThreshold
	portScanThresh := cfg.PortScanThreshold
	udpThresh := cfg.UDPFloodThreshold
	dhcpIp := cfg.LegitimateDHCPServerIP
	gatewayIp := cfg.GatewayIP
	susRate := cfg.SuspiciousRateThreshold
	cfg.Mu.RUnlock()

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
		
		st.GlobalMACsSeen[packet.SrcMAC] = currentTime
		recentMACs := 0
		for mac, t := range st.GlobalMACsSeen {
			if currentTime-t > 1.0 {
				delete(st.GlobalMACsSeen, mac)
			} else {
				recentMACs++
			}
		}
		if recentMACs > 100 { // 100 unique MACs in 1 second
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-MAC-001", "MAC Flooding", "Critical", "High", srcIP, dstIP, fmt.Sprintf("MAC Flood / CAM Exhaustion (%d MACs/sec)", recentMACs), float64(recentMACs))
		}
		
		st.Mu.Unlock()
	}

	// Skip blocked IPs (IPS mode)
	st.Mu.RLock()
	if secMode == "IPS" {
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

	// ARP Tracking & Heuristics
	if packet.Protocol == "ARP" && packet.SrcMAC != "" {
		// 1. ARP Spoofing / MAC Flip-flop detection
		macs, exists := st.IPMACMapping[srcIP]
		if !exists {
			macs = make(map[string]float64)
		}
		macs[packet.SrcMAC] = currentTime

		for mac, t := range macs {
			if currentTime-t > 60.0 {
				delete(macs, mac)
			}
		}
		st.IPMACMapping[srcIP] = macs

		macCount := len(macs)
		if macCount > 1 {
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-ARP-001", "Duplicate IP / ARP Spoofing", "Medium", "High", srcIP, dstIP, fmt.Sprintf("Heuristic ARP Spoofing (%d MACs)", macCount), float64(macCount))
		}

		// 2. ARP Flood (Storm) Detection
		arpTs, exists := st.IPARPTimestamps[srcIP]
		if !exists {
			arpTs = make([]float64, 0, 500)
		}
		arpRate := addTimestamp(&arpTs, currentTime)
		st.IPARPTimestamps[srcIP] = arpTs

		// High rate of ARP packets from a single host (usually > 50/sec is highly anomalous for ARP)
		if arpRate > 50 {
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-ARP-002", "ARP Flood / Storm", "Medium", "High", srcIP, dstIP, fmt.Sprintf("ARP Flood (%d pkts/sec)", arpRate), float64(arpRate))
		}

		// 3. Gratuitous ARP Abuse (Many unsolicited replies)
		// Operation 2 is ARP Reply. If a host is broadcasting replies rapidly, it's likely poisoning.
		if packet.ARPOperation == 2 && arpRate > 15 {
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-ARP-003", "Gratuitous ARP Abuse (Poisoning)", "High", "High", srcIP, dstIP, fmt.Sprintf("ARP Reply Flood (%d pkts/sec)", arpRate), float64(arpRate))
		}
	}

	// Abnormal Lateral Movement Check
	if isInternalIP(srcIP) && isInternalIP(dstIP) {
		if packet.DstPort == 22 || packet.DstPort == 445 || packet.DstPort == 3389 {
			portKey := srcIP + "_LATERAL"
			ports, exists := st.IPPortsAccessed[portKey]
			if !exists {
				ports = make(map[uint16]float64) // using uint16 to store hash of IP for simplicity, or just use another map.
				// Wait, IPPortsAccessed is map[uint16]float64. We can use the last octet of the IP as a uint16 just to count unique hosts.
			}
			parts := strings.Split(dstIP, ".")
			if len(parts) == 4 {
				lastOctet := 0
				fmt.Sscanf(parts[3], "%d", &lastOctet)
				ports[uint16(lastOctet)] = currentTime
				for p, t := range ports {
					if currentTime-t > 60.0 {
						delete(ports, p)
					}
				}
				st.IPPortsAccessed[portKey] = ports
				if len(ports) > 3 {
					triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-LAT-001", "Abnormal Lateral Movement", "Critical", "High", srcIP, dstIP, fmt.Sprintf("Lateral Movement Scan (%d internal hosts/min)", len(ports)), float64(len(ports)))
				}
			}
		}
	}

	uniquePortsRate := 0
	if packet.Protocol == "TCP" {
		if packet.IsTCPSYN && !packet.IsTCPACK && !packet.IsTCPRST {
			if packet.DstPort != 0 {
				portKey := srcIP + "-" + dstIP
				ports, exists := st.IPPortsAccessed[portKey]
				if !exists {
					ports = make(map[uint16]float64)
				}
				ports[packet.DstPort] = currentTime
				for p, t := range ports {
					if currentTime-t > 3.0 {
						delete(ports, p)
					}
				}
				st.IPPortsAccessed[portKey] = ports
				uniquePortsRate = len(ports)
			}

			// SYN Flood
			synTs, exists := st.IPSYNTimestamps[srcIP]
			if !exists {
				synTs = make([]float64, 0, 5000)
			}
			synRate := addTimestamp(&synTs, currentTime)
			st.IPSYNTimestamps[srcIP] = synTs

			if synRate > synThresh && uniquePortsRate <= 5 {
				triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-SYN-001", "SYN Flood", "High", "High", srcIP, dstIP, fmt.Sprintf("SYN Flood (%d pkts/s)", synRate), float64(synRate))
			}

			// SSH Brute Force
			if packet.DstPort == 22 {
				sshTs, exists := st.IPSSHTimestamps[srcIP]
				if !exists {
					sshTs = make([]float64, 0, 500)
				}
				sshRate := addTimestamp(&sshTs, currentTime)
				st.IPSSHTimestamps[srcIP] = sshTs

				if sshRate > sshThresh {
					triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-SSH-001", "SSH Brute Force", "Critical", "High", srcIP, dstIP, fmt.Sprintf("SSH Brute Force (%d attempts/3s)", sshRate), float64(sshRate))
				}
			}
		}
	}

	if uniquePortsRate > 5 {
		isPortScan = true
	}

	if uniquePortsRate > portScanThresh {
		triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-SCAN-001", "Port Scan", "High", "High", srcIP, dstIP, fmt.Sprintf("Port Scan (%d ports/3s)", uniquePortsRate), float64(uniquePortsRate))
	}

	// UDP Flood
	if packet.Protocol == "UDP" {
		// Heuristic: high rate of large UDP packets, or extremely high rate overall
		udpTs, exists := st.IPUDPTimestamps[srcIP]
		if !exists {
			udpTs = make([]float64, 0, 5000)
		}
		udpRate := addTimestamp(&udpTs, currentTime)
		st.IPUDPTimestamps[srcIP] = udpTs

		// Adjust threshold if packets are large
		effectiveThreshold := udpThresh
		if len(packet.Payload) > 1000 {
			effectiveThreshold = udpThresh / 2
		}

		if udpRate > effectiveThreshold {
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-UDP-001", "UDP Flood", "Medium", "High", srcIP, dstIP, fmt.Sprintf("UDP Flood (%d pkts/s)", udpRate), float64(udpRate))
		}

		// DHCP Anomalies
		if packet.DstPort == 67 || packet.DstPort == 68 || packet.SrcPort == 67 || packet.SrcPort == 68 {
			if len(packet.Payload) > 240 {
				opcode := packet.Payload[0]
				if opcode == 1 { // BootRequest / DHCP Discover
					st.DHCPStarvation[packet.SrcMAC] = currentTime
					recentDHCPMACs := 0
					for mac, t := range st.DHCPStarvation {
						if currentTime-t > 10.0 {
							delete(st.DHCPStarvation, mac)
						} else {
							recentDHCPMACs++
						}
					}
					if recentDHCPMACs > 50 { // >50 unique MACs doing DHCP Discover in 10s
						triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-DHCP-001", "DHCP Starvation", "Critical", "High", srcIP, dstIP, fmt.Sprintf("DHCP Starvation (%d unique MACs/10s)", recentDHCPMACs), float64(recentDHCPMACs))
					}
				}
			}
			if packet.IsDHCPOffer {
				if dhcpIp != "" && srcIP != dhcpIp {
					triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-DHCP-002", "Rogue DHCP Server Detected", "Critical", "High", srcIP, dstIP, fmt.Sprintf("Rogue DHCP Offer from %s", srcIP), 1.0)
				}
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
				triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-DNS-001", "DNS Amplification", "High", "Medium", srcIP, dstIP, fmt.Sprintf("Heuristic DNS Amplification (%d pkts/s)", dnsRate), float64(dnsRate))
			}
		}
		
		if packet.SrcPort == 53 || packet.DstPort == 53 {
			// DNS Tunneling and Spoofing
			// Decoding DNS payload manually for heuristics
			if len(packet.Payload) > 12 {
				isReply := (packet.Payload[2] & 0x80) != 0 // QR bit
				if !isReply {
					// Query - check for long names
					qdcount := uint16(packet.Payload[4])<<8 | uint16(packet.Payload[5])
					if qdcount > 0 {
						offset := 12
						for offset < len(packet.Payload) && qdcount > 0 {
							length := int(packet.Payload[offset])
							if length == 0 {
								break
							}
							if offset+length < len(packet.Payload) && length > 63 {
								triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-DNS-002", "DNS Tunneling", "High", "High", srcIP, dstIP, "Extremely long DNS label detected", 1.0)
								break
							}
							offset += length + 1
						}
					}
				} else {
					// Reply
					if isInternalIP(srcIP) && srcIP != gatewayIp && gatewayIp != "" {
						triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-DNS-003", "DNS Spoofing", "Critical", "High", srcIP, dstIP, fmt.Sprintf("DNS Reply from unauthorized internal host %s", srcIP), 1.0)
					}
					// Simple check for large TXT replies could be added here by parsing the answers, but keeping it simple.
					if len(packet.Payload) > 1000 {
						triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-DNS-002", "DNS Tunneling", "High", "Medium", srcIP, dstIP, "Unusually large DNS reply payload", 1.0)
					}
				}
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
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-ICMP-001", "ICMP Flood", "Medium", "High", srcIP, dstIP, fmt.Sprintf("ICMP Flood (%d pkts/s)", icmpRate), float64(icmpRate))
		}

		// Ping of Death
		if len(packet.Payload) > 1000 {
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-POD-001", "Ping of Death", "Critical", "High", srcIP, dstIP, fmt.Sprintf("Oversized ICMP (%d bytes)", len(packet.Payload)), 1.0)
		}

		// ICMP Sweep
		sweepMap, exists := st.IPICMPSweep[srcIP]
		if !exists {
			sweepMap = make(map[string]float64)
		}
		sweepMap[dstIP] = currentTime
		for dip, t := range sweepMap {
			if currentTime-t > 10.0 {
				delete(sweepMap, dip)
			}
		}
		st.IPICMPSweep[srcIP] = sweepMap
		if len(sweepMap) > 10 { // Ping sweep to >10 hosts in 10s
			triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-SWEEP-001", "ICMP Sweep", "Medium", "High", srcIP, dstIP, fmt.Sprintf("ICMP Sweep (%d hosts/10s)", len(sweepMap)), float64(len(sweepMap)))
		}
	}

	// DoS Generic Flood
	if packetRate > susRate && !isPortScan {
		triggerAlert(st, cfg, fm, alertLogger, currentTime, "NET-DOS-001", "DoS Attack", "Critical", "High", srcIP, dstIP, fmt.Sprintf("DoS Attack (%d pkts/s)", packetRate), float64(packetRate))
	}

	st.Mu.Unlock()
}

// Ensure st.Mu is Locked before calling triggerAlert
func triggerAlert(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, alertLogger *alert.Logger, currentTime float64, ruleID, alertType, severity, confidence, srcIP, dstIP, reason string, rate float64) {
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

	cfg.Mu.RLock()
	secMode := cfg.IDPSSecurityMode
	ttl := cfg.BlockTTLSeconds
	cfg.Mu.RUnlock()

	if secMode == "IDS" {
		alert.Action = "ALERT"
		alert.ActionResult = "SUCCESS"
		alert.Status = "LOGGED"
	} else {
		if severity == "High" || severity == "Critical" || confidence == "High" || confidence == "Critical" {
			alert.Action = "BLOCK"

			// Drop the lock to perform potentially slow firewall operation
			st.Mu.Unlock()
			blockSuccess := fm.BlockIP(srcIP, cfg)
			st.Mu.Lock()

			if blockSuccess {
				alert.ActionResult = "SUCCESS"
				alert.Status = "BLOCKED"
				expiresAt := currentTime + float64(ttl)
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

	if alertLogger != nil {
		alertLogger.Log(alert)
	}

	st.AddAlert(alert)
}
