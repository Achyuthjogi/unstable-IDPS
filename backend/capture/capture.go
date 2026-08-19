package capture

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"idps-backend/config"
	"idps-backend/detection"
	"idps-backend/firewall"
	"idps-backend/state"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func getTimestamp() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func StartCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engine *detection.Engine) (func(), error) {
	ifaceName := cfg.CaptureInterface
	fmt.Printf("Starting capture on interface: %s\n", ifaceName)

	// Use a 1-second timeout instead of BlockForever to allow clean shutdown checks
	handle, err := pcap.OpenLive(ifaceName, 65535, true, 1*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to open capture device %s: %w", ifaceName, err)
	}

	linkType := handle.LinkType()
	fmt.Printf("Datalink type: %v\n", linkType)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	workerCount := cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = 4
	}

	channels := make([]chan detection.PacketInfo, workerCount)
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		channels[i] = make(chan detection.PacketInfo, 2000)
		wg.Add(1)
		go func(ch chan detection.PacketInfo) {
			defer wg.Done()
			for pkt := range ch {
				engine.ProcessPacket(pkt)
			}
		}(channels[i])
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer func() {
			fmt.Printf("Capture stopped on interface: %s\n", ifaceName)
			for i := 0; i < workerCount; i++ {
				close(channels[i])
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			packet, err := packetSource.NextPacket()
			if err != nil {
				// pcap.NextErrorTimeoutExpired is expected every 1s if idle
				if strings.Contains(err.Error(), "Timeout Expired") || err.Error() == "Timeout Expired" {
					continue
				}
				// If handle is closed, err will be EOF or a closed error
				return
			}

			if packet == nil {
				continue
			}

			ts := getTimestamp()

			pktInfo := detection.PacketInfo{
				Protocol: "UNKNOWN",
			}

			// Ethernet
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)
				pktInfo.SrcMAC = eth.SrcMAC.String()
				pktInfo.DstMAC = eth.DstMAC.String()
				if eth.EthernetType == layers.EthernetTypeARP {
					pktInfo.Protocol = "ARP"
					arpLayer := packet.Layer(layers.LayerTypeARP)
					if arpLayer != nil {
						arp, _ := arpLayer.(*layers.ARP)
						pktInfo.ARPOperation = arp.Operation
					}
				}
			} else {
				// Try Linux SLL
				sllLayer := packet.Layer(layers.LayerTypeLinuxSLL)
				if sllLayer != nil {
					sll, _ := sllLayer.(*layers.LinuxSLL)
					if len(sll.Addr) >= 6 {
						pktInfo.SrcMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", sll.Addr[0], sll.Addr[1], sll.Addr[2], sll.Addr[3], sll.Addr[4], sll.Addr[5])
					}
				}
			}

			// IP
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer != nil {
				ip4, _ := ip4Layer.(*layers.IPv4)
				pktInfo.SrcIP = ip4.SrcIP.String()
				pktInfo.DstIP = ip4.DstIP.String()
			} else {
				ip6Layer := packet.Layer(layers.LayerTypeIPv6)
				if ip6Layer != nil {
					ip6, _ := ip6Layer.(*layers.IPv6)
					pktInfo.SrcIP = ip6.SrcIP.String()
					pktInfo.DstIP = ip6.DstIP.String()
				}
			}

			// Transport
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				pktInfo.Protocol = "TCP"
				pktInfo.SrcPort = uint16(tcp.SrcPort)
				pktInfo.DstPort = uint16(tcp.DstPort)
				pktInfo.IsTCPSYN = tcp.SYN
				pktInfo.IsTCPACK = tcp.ACK
				pktInfo.IsTCPRST = tcp.RST
				pktInfo.Seq = tcp.Seq
				pktInfo.Payload = tcp.Payload

				if len(tcp.Payload) > 0 {
					extractTCPLog(st, ts, pktInfo.SrcIP, tcp.Payload)
				}
			} else {
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					pktInfo.Protocol = "UDP"
					pktInfo.SrcPort = uint16(udp.SrcPort)
					pktInfo.DstPort = uint16(udp.DstPort)
					pktInfo.Payload = udp.Payload

					if udp.DstPort == 53 || udp.SrcPort == 53 {
						extractDNSLog(st, ts, pktInfo.SrcIP, udp.Payload)
					}
				} else {
					icmp4Layer := packet.Layer(layers.LayerTypeICMPv4)
					if icmp4Layer != nil {
						pktInfo.Protocol = "ICMP"
						icmp, _ := icmp4Layer.(*layers.ICMPv4)
						pktInfo.Payload = icmp.Payload
					} else {
						icmp6Layer := packet.Layer(layers.LayerTypeICMPv6)
						if icmp6Layer != nil {
							pktInfo.Protocol = "ICMP"
							icmp, _ := icmp6Layer.(*layers.ICMPv6)
							pktInfo.Payload = icmp.Payload
						}
					}
				}
			}

			if pktInfo.SrcIP != "" {
				var hash uint32
				for i := 0; i < len(pktInfo.SrcIP); i++ {
					hash = hash*31 + uint32(pktInfo.SrcIP[i])
				}
				idx := hash % uint32(workerCount)
				
				select {
				case channels[idx] <- pktInfo:
				default:
					st.Mu.Lock()
					st.DroppedPacketCount++
					st.Mu.Unlock()
				}
			}
		}
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel() // Signal the capture loop to stop
			handle.Close()
			wg.Wait()
		})
	}

	return stop, nil
}

func extractDNSLog(st *state.AppState, ts float64, srcIP string, payload []byte) {
	if len(payload) < 12 {
		return
	}
	// Parse basic DNS header to see if QDCOUNT > 0
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

	// Basic TLS ClientHello SNI extraction approximation
	if len(payload) > 43 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
		appendTrafficLog(st, ts, srcIP, "TLS Session", "HTTPS")
	}
}

func appendTrafficLog(st *state.AppState, ts float64, srcIP, domain, proto string) {
	if srcIP == "" {
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
