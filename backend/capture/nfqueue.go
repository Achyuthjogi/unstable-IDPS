package capture

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"syscall"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	
	"idps-backend/config"
	"idps-backend/detection"
	"idps-backend/firewall"
	"idps-backend/state"
)

type nfqHandler struct {
	st      *state.AppState
	engines []*detection.Engine
	mu sync.Mutex
}

func (h *nfqHandler) getEngine(srcIP, dstIP string, srcPort, dstPort uint16) *detection.Engine {
	if len(h.engines) == 1 {
		return h.engines[0]
	}
	// Hash the 4-tuple so the same flow always maps to the same engine,
	// preserving stream reassembly and ML flow tracking.
	hash := fnv.New32a()
	hash.Write([]byte(srcIP))
	hash.Write([]byte(dstIP))
	var portBuf [4]byte
	portBuf[0] = byte(srcPort >> 8)
	portBuf[1] = byte(srcPort)
	portBuf[2] = byte(dstPort >> 8)
	portBuf[3] = byte(dstPort)
	hash.Write(portBuf[:])
	idx := int(hash.Sum32()) % len(h.engines)
	return h.engines[idx]
}

func realCallback(payload *nfqueue.Payload, h *nfqHandler) int {
	data := payload.Data
	if len(data) == 0 {
		payload.SetVerdict(nfqueue.NF_ACCEPT)
		return 0
	}

	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if packet == nil || packet.NetworkLayer() == nil {
		packet = gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default)
	}

	if packet == nil || packet.NetworkLayer() == nil {
		payload.SetVerdict(nfqueue.NF_ACCEPT)
		return 0
	}

	pktInfo := detection.PacketInfo{
		Protocol:  "UNKNOWN",
		TCPWindow: -1,
	}

	ts := getTimestamp()
	
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
		pktInfo.IsTCPPSH = tcp.PSH
		pktInfo.IsTCPURG = tcp.URG
		pktInfo.IsTCPFIN = tcp.FIN
		pktInfo.Seq = tcp.Seq
		pktInfo.Payload = tcp.Payload
		pktInfo.TCPHeaderLen = int(tcp.DataOffset) * 4
		pktInfo.TCPWindow = int(tcp.Window)

		if len(tcp.Payload) > 0 {
			extractTCPLog(h.st, ts, pktInfo.SrcIP, tcp.Payload)
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
				extractDNSLog(h.st, ts, pktInfo.SrcIP, udp.Payload)
			}
		} else {
			icmp4Layer := packet.Layer(layers.LayerTypeICMPv4)
			if icmp4Layer != nil {
				pktInfo.Protocol = "ICMP"
				icmp, _ := icmp4Layer.(*layers.ICMPv4)
				pktInfo.Payload = icmp.Payload
			}
		}
	}

	if pktInfo.SrcIP != "" {
		// NFQueue receives IP-layer packets (no Ethernet header), so SrcMAC
		// is unavailable. Look it up from the device table for MAC-based blocking.
		h.st.Mu.RLock()
		for _, d := range h.st.Devices {
			if d.IP == pktInfo.SrcIP {
				pktInfo.SrcMAC = d.MAC
				break
			}
		}
		h.st.Mu.RUnlock()

		eng := h.getEngine(pktInfo.SrcIP, pktInfo.DstIP, pktInfo.SrcPort, pktInfo.DstPort)
		accept := eng.ProcessPacket(pktInfo)
		if accept {
			payload.SetVerdict(nfqueue.NF_ACCEPT)
		} else {
			payload.SetVerdict(nfqueue.NF_DROP)
		}
		return 0
	}

	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}

func StartNFQueue(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	fmt.Println("Starting NFQUEUE Inline Capture...")
	
	h := &nfqHandler{
		st: st,
		engines: engines,
	}

	q := new(nfqueue.Queue)

	cb := func(payload *nfqueue.Payload) int {
		return realCallback(payload, h)
	}

	q.SetCallback(cb)

	q.Init()

	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)

	err := q.CreateQueue(0)
	if err != nil {
		return nil, fmt.Errorf("failed to create NFQueue: %v", err)
	}

	// Start processing in background
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	
	go func() {
		defer wg.Done()
		// Loop process until context is cancelled or queue fails
		q.Loop()
	}()
	
	go func() {
		<-ctx.Done()
		q.StopLoop()
		q.DestroyQueue()
		q.Close()
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			fmt.Println("Capture stopped on NFQUEUE")
			cancel()
			// We DO NOT wg.Wait() here because q.Loop() blocks in C code 
			// if no packets are flowing, which deadlocks the reload process.
		})
	}

	return stop, nil
}
