package capture

import (
	"fmt"
	"net"
	"strings"
	"time"

	"idps-backend/config"
	"idps-backend/detection"
	"idps-backend/firewall"
	"idps-backend/inspect"
	"idps-backend/state"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func getTimestamp() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// StartAutoCapture starts the optimal packet capture engine for the current OS.
func StartAutoCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	return startPlatformCapture(st, cfg, fm, engines)
}

// StartCapture is maintained for backward compatibility.
func StartCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	return StartAutoCapture(st, cfg, fm, engines)
}

// ParsePacket safely decodes a gopacket.Packet into a normalized detection.PacketInfo.
// Includes bounds validation, malformed packet recovery, and protocol metadata extraction.
func ParsePacket(packet gopacket.Packet, st *state.AppState, ts float64) detection.PacketInfo {
	pktInfo := detection.PacketInfo{
		Protocol:  "UNKNOWN",
		TCPWindow: -1,
	}

	if packet == nil {
		return pktInfo
	}

	// 1. Ethernet Link Layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			pktInfo.SrcMAC = eth.SrcMAC.String()
			pktInfo.DstMAC = eth.DstMAC.String()
			if eth.EthernetType == layers.EthernetTypeARP {
				pktInfo.Protocol = "ARP"
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer != nil {
					if arp, ok := arpLayer.(*layers.ARP); ok {
						pktInfo.ARPOperation = arp.Operation
						pktInfo.SrcIP = net.IP(arp.SourceProtAddress).String()
						pktInfo.DstIP = net.IP(arp.DstProtAddress).String()
					}
				}
			}
		}
	} else {
		sllLayer := packet.Layer(layers.LayerTypeLinuxSLL)
		if sllLayer != nil {
			if sll, ok := sllLayer.(*layers.LinuxSLL); ok && len(sll.Addr) >= 6 {
				pktInfo.SrcMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", sll.Addr[0], sll.Addr[1], sll.Addr[2], sll.Addr[3], sll.Addr[4], sll.Addr[5])
			}
		}
	}

	// 2. Network Layer (IPv4 / IPv6)
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil {
		if ip4, ok := ip4Layer.(*layers.IPv4); ok {
			pktInfo.SrcIP = ip4.SrcIP.String()
			pktInfo.DstIP = ip4.DstIP.String()
		}
	} else {
		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer != nil {
			if ip6, ok := ip6Layer.(*layers.IPv6); ok {
				pktInfo.SrcIP = ip6.SrcIP.String()
				pktInfo.DstIP = ip6.DstIP.String()
			}
		}
	}

	// 3. Transport Layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			pktInfo.Protocol = "TCP"
			pktInfo.SrcPort = uint16(tcp.SrcPort)
			pktInfo.DstPort = uint16(tcp.DstPort)
			pktInfo.IsTCPSYN = tcp.SYN
			pktInfo.IsTCPACK = tcp.ACK
			pktInfo.IsTCPRST = tcp.RST
			pktInfo.IsTCPPSH = tcp.PSH
			pktInfo.IsTCPURG = tcp.URG
			pktInfo.IsTCPFIN = tcp.FIN
			pktInfo.Seq = tcp.Seq
			pktInfo.Payload = tcp.Payload
			pktInfo.TCPHeaderLen = int(tcp.DataOffset) * 4
			pktInfo.TCPWindow = int(tcp.Window)

			if len(tcp.Payload) > 0 && st != nil {
				extractTCPLog(st, ts, pktInfo.SrcIP, tcp.Payload)
			}
		}
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				pktInfo.Protocol = "UDP"
				pktInfo.SrcPort = uint16(udp.SrcPort)
				pktInfo.DstPort = uint16(udp.DstPort)
				pktInfo.Payload = udp.Payload

				if (udp.DstPort == 53 || udp.SrcPort == 53) && st != nil {
					extractDNSLog(st, ts, pktInfo.SrcIP, udp.Payload)
				}

				if udp.SrcPort == 67 && len(udp.Payload) > 240 {
					if udp.Payload[0] == 2 && udp.Payload[236] == 99 && udp.Payload[237] == 130 && udp.Payload[238] == 83 && udp.Payload[239] == 99 {
						offset := 240
						for offset < len(udp.Payload) {
							opt := udp.Payload[offset]
							if opt == 255 {
								break
							}
							if opt == 0 {
								offset++
								continue
							}
							if offset+1 >= len(udp.Payload) {
								break
							}
							length := int(udp.Payload[offset+1])
							if offset+2+length > len(udp.Payload) {
								break
							}
							if opt == 53 && length == 1 && udp.Payload[offset+2] == 2 {
								pktInfo.IsDHCPOffer = true
								break
							}
							offset += 2 + length
						}
					}
				}
			}
		} else {
			icmp4Layer := packet.Layer(layers.LayerTypeICMPv4)
			if icmp4Layer != nil {
				if icmp, ok := icmp4Layer.(*layers.ICMPv4); ok {
					pktInfo.Protocol = "ICMP"
					pktInfo.Payload = icmp.Payload
				}
			} else {
				icmp6Layer := packet.Layer(layers.LayerTypeICMPv6)
				if icmp6Layer != nil {
					if icmp, ok := icmp6Layer.(*layers.ICMPv6); ok {
						pktInfo.Protocol = "ICMP"
						pktInfo.Payload = icmp.Payload
					}
				}
			}
		}
	}

	return pktInfo
}

func extractDNSLog(st *state.AppState, ts float64, srcIP string, payload []byte) {
	if len(payload) < 12 {
		return
	}
	qdcount := uint16(payload[4])<<8 | uint16(payload[5])
	if qdcount > 0 {
		offset := 12
		var domainParts []string
		for offset < len(payload) {
			length := int(payload[offset])
			if length == 0 || length > 63 {
				break
			}
			offset++
			if offset+length <= len(payload) {
				domainParts = append(domainParts, string(payload[offset:offset+length]))
			}
			offset += length
		}
		domain := strings.Join(domainParts, ".")
		if domain != "" {
			appendTrafficLog(st, ts, srcIP, domain, "DNS")
		}
	}
}

func extractTCPLog(st *state.AppState, ts float64, srcIP string, payload []byte) {
	s := string(payload)
	if strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") || strings.HasPrefix(s, "PUT ") {
		lines := strings.Split(s, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				domain := strings.TrimSpace(line[5:])
				appendTrafficLog(st, ts, srcIP, domain, "HTTP")
				return
			}
		}
	}

	inspector := &inspect.TLSInspector{}
	if sni, found := inspector.InspectClientHello(payload); found {
		appendTrafficLog(st, ts, srcIP, sni, "HTTPS")
	} else if len(payload) > 43 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
		appendTrafficLog(st, ts, srcIP, "TLS Session", "HTTPS")
	}
}

func appendTrafficLog(st *state.AppState, ts float64, srcIP, domain, proto string) {
	if srcIP == "" {
		return
	}

	if ip := net.ParseIP(srcIP); ip != nil && ip.IsLoopback() {
		return
	}

	st.Mu.Lock()
	defer st.Mu.Unlock()
	st.AddTrafficLog(state.TrafficLog{
		Timestamp: ts,
		SrcIP:     srcIP,
		Domain:    domain,
		Proto:     proto,
	})
}
