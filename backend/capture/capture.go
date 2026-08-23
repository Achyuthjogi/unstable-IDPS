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
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

func getTimestamp() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func StartCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	ifaceName := cfg.CaptureInterface
	workerCount := len(engines)
	if workerCount <= 0 {
		return nil, fmt.Errorf("no detection engines provided")
	}

	fmt.Printf("Starting AF_PACKET capture on interface: %s with %d workers\n", ifaceName, workerCount)

	fanoutGroup := 99 // Arbitrary group ID for fanout

	var handles []*afpacket.TPacket
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	for i := 0; i < workerCount; i++ {
		// Create AF_PACKET handle for each worker
		handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(ifaceName),
			afpacket.OptFrameSize(4096),
			afpacket.OptBlockSize(4096*128),
			afpacket.OptNumBlocks(128),
			afpacket.OptPollTimeout(1*time.Second),
		)
		if err != nil {
			// Cleanup previously opened handles
			for _, h := range handles {
				h.Close()
			}
			return nil, fmt.Errorf("failed to open afpacket on %s: %w", ifaceName, err)
		}

		err = handle.SetFanout(afpacket.FanoutHash, uint16(fanoutGroup))
		if err != nil {
			for _, h := range handles {
				h.Close()
			}
			handle.Close()
			return nil, fmt.Errorf("failed to set fanout hash: %w", err)
		}

		handles = append(handles, handle)
		
		engine := engines[i]

		wg.Add(1)
		go func(workerID int, h *afpacket.TPacket, eng *detection.Engine) {
			defer wg.Done()
			
			source := gopacket.NewPacketSource(h, layers.LinkTypeEthernet)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				packet, err := source.NextPacket()
				if err != nil {
					if strings.Contains(err.Error(), "timeout") || err.Error() == "Timeout Expired" {
						continue
					}
					// Handle closed error
					return
				}

				if packet == nil {
					continue
				}

				func() {
					defer func() {
						if r := recover(); r != nil {
							fmt.Printf("worker %d: recovered from panic while processing packet: %v\n", workerID, r)
						}
					}()

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
							pktInfo.SrcIP = net.IP(arp.SourceProtAddress).String()
							pktInfo.DstIP = net.IP(arp.DstProtAddress).String()
						}
					}
				} else {
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

						if udp.SrcPort == 67 && len(udp.Payload) > 240 {
							if udp.Payload[0] == 2 {
								if udp.Payload[236] == 99 && udp.Payload[237] == 130 && udp.Payload[238] == 83 && udp.Payload[239] == 99 {
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
					// Direct processing - zero channel handoff!
					eng.ProcessPacket(pktInfo)
				}
				}()
			}
		}(i, handle, engine)
	}

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			fmt.Printf("Capture stopped on interface: %s\n", ifaceName)
			cancel() // Signal all workers to stop
			for _, h := range handles {
				h.Close()
			}
			wg.Wait()
		})
	}

	return stop, nil
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
