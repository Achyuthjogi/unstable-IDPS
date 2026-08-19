package main

import (
	"fmt"
	"time"

	"idps-backend/config"
	"idps-backend/detection"
	"idps-backend/firewall"
	"idps-backend/rules"
	"idps-backend/state"
)

func main() {
	fmt.Println("Initializing IDPS Engine Simulation...")

	// 1. Setup mock environment
	cfg := &config.Config{
		IDPSSecurityMode:        "IDS",
		SuspiciousRateThreshold: 1000,
		PortScanThreshold:       20,
		ICMPFloodThreshold:      100,
		UDPFloodThreshold:       200,
		SYNFloodThreshold:       150,
		SSHBruteForceThreshold:  10,
		RulesPath:               "./rules",
		MaxFlows:                100000,
		MaxReassembly:           65535,
	}

	appState := state.NewAppState()
	fwManager := &firewall.FirewallManager{} // DryRun by default since no config passed to SetupGateway

	ruleEngine := rules.NewEngine()
	err := rules.LoadRulesFromDirectory(cfg.RulesPath, ruleEngine)
	if err != nil {
		fmt.Printf("Warning: rules load error: %v\n", err)
	}
	ruleEngine.Build()
	
	fmt.Printf("Loaded %d rules into engine.\n\n", len(ruleEngine.Rules))

	detEngine := detection.NewEngine(appState, cfg, fwManager, ruleEngine)

	var seq uint32 = 1000
	var simTime float64 = float64(time.Now().UnixNano()) / 1e9

	// Helper to send a packet
	sendPacket := func(proto, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, syn, ack bool) {
		pkt := detection.PacketInfo{
			Protocol: proto,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Payload:  payload,
			IsTCPSYN: syn,
			IsTCPACK: ack,
			Seq:      seq,
		}
		detEngine.ProcessPacket(pkt)
		seq += uint32(len(payload))
		if len(payload) == 0 {
			seq += 1
		}
	}

	fmt.Println("--- Starting 20 Danger Simulation ---")

	// 1. SQL Injection (UNION SELECT)
	fmt.Println("[1/20] Simulating SQLi (UNION SELECT)")
	sendPacket("TCP", "10.0.0.1", "192.168.1.100", 50001, 80, []byte("GET / HTTP/1.1\r\n\r\nUNION SELECT * FROM users"), false, true)

	// 2. SQL Injection (OR 1=1)
	fmt.Println("[2/20] Simulating SQLi (OR 1=1)")
	sendPacket("TCP", "10.0.0.2", "192.168.1.100", 50002, 80, []byte("POST /login HTTP/1.1\r\n\r\nadmin' OR 1=1--"), false, true)

	// 3. Cross-Site Scripting (XSS)
	fmt.Println("[3/20] Simulating Cross-Site Scripting (XSS)")
	sendPacket("TCP", "10.0.0.3", "192.168.1.100", 50003, 80, []byte("GET /?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n"), false, true)

	// 4. Directory Traversal
	fmt.Println("[4/20] Simulating Directory Traversal")
	sendPacket("TCP", "10.0.0.4", "192.168.1.100", 50004, 80, []byte("GET /../../../../etc/passwd HTTP/1.1\r\n\r\n"), false, true)

	// 5. Command Injection
	fmt.Println("[5/20] Simulating Command Injection")
	sendPacket("TCP", "10.0.0.5", "192.168.1.100", 50005, 80, []byte("GET /ping?ip=127.0.0.1; cat /etc/passwd HTTP/1.1\r\n\r\n"), false, true)

	// 6. NOP Sled (Buffer Overflow)
	fmt.Println("[6/20] Simulating NOP Sled Detected (Buffer Overflow)")
	sendPacket("TCP", "10.0.0.6", "192.168.1.100", 50006, 80, []byte("\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"), false, true)

	// 7. Invalid HTTP Method
	fmt.Println("[7/20] Simulating Invalid HTTP Method")
	sendPacket("TCP", "10.0.0.7", "192.168.1.100", 50007, 80, []byte("INVALIDMETHOD / HTTP/1.1\r\n\r\n"), false, true)

	// 8. Deprecated SSH Version
	fmt.Println("[8/20] Simulating Deprecated SSH Version (SSHv1)")
	sendPacket("TCP", "10.0.0.8", "192.168.1.100", 50008, 22, []byte("SSH-1.5-Client\r\n"), false, true)

	// 9. HTTP Protocol Anomaly (Directory Traversal in URI)
	fmt.Println("[9/20] Simulating HTTP Protocol Anomaly (Path Traversal)")
	sendPacket("TCP", "10.0.0.9", "192.168.1.100", 50009, 80, []byte("GET /../ HTTP/1.1\r\n\r\n"), false, true)

	// 10. DNS ANY Query (Heuristics rely on layers.DNS which isn't mocked here, skipping payload, sending big UDP)
	fmt.Println("[10/20] Simulating DNS Amplification (Large UDP flood)")
	for i := 0; i < 30; i++ {
		sendPacket("UDP", "10.0.0.10", "192.168.1.100", 50010, 53, make([]byte, 600), false, false)
	}

	// 11. Port Scan
	fmt.Println("[11/20] Simulating Port Scan")
	for p := 1000; p < 1030; p++ {
		sendPacket("TCP", "10.0.0.11", "192.168.1.100", 50011, uint16(p), nil, true, false)
	}

	// 12. SSH Brute Force
	fmt.Println("[12/20] Simulating SSH Brute Force")
	for i := 0; i < 15; i++ {
		sendPacket("TCP", "10.0.0.12", "192.168.1.100", uint16(50012+i), 22, nil, true, false)
	}

	// 13. SYN Flood
	fmt.Println("[13/20] Simulating SYN Flood")
	for i := 0; i < 160; i++ {
		sendPacket("TCP", "10.0.0.13", "192.168.1.100", uint16(20000+i), 80, nil, true, false)
	}

	// 14. UDP Flood
	fmt.Println("[14/20] Simulating UDP Flood")
	for i := 0; i < 250; i++ {
		sendPacket("UDP", "10.0.0.14", "192.168.1.100", uint16(30000+i), 12345, []byte("UDPFloodPayload"), false, false)
	}

	// 15. ICMP Flood
	fmt.Println("[15/20] Simulating ICMP Flood")
	for i := 0; i < 150; i++ {
		sendPacket("ICMP", "10.0.0.15", "192.168.1.100", 0, 0, nil, false, false)
	}

	// 16. Ping of Death
	fmt.Println("[16/20] Simulating Ping of Death")
	sendPacket("ICMP", "10.0.0.16", "192.168.1.100", 0, 0, make([]byte, 2000), false, false)

	// 17. Generic DoS Flood
	fmt.Println("[17/20] Simulating Generic DoS Flood")
	for i := 0; i < 1500; i++ { // Over 1000 SuspiciousRateThreshold
		sendPacket("UDP", "10.0.0.17", "192.168.1.100", 50017, 8080, nil, false, false)
	}

	// 18. HTTP Malformed Protocol Anomaly
	fmt.Println("[18/20] Simulating HTTP Malformed Protocol Anomaly")
	sendPacket("TCP", "10.0.0.18", "192.168.1.100", 50018, 80, []byte("GET / HTTP 1.1\r\n\r\n"), false, true)

	// 19. ARP Spoofing (Duplicate MAC)
	fmt.Println("[19/20] Simulating ARP Spoofing")
	// The heuristic looks for multiple MACs for the same IP
	detEngine.ProcessPacket(detection.PacketInfo{Protocol: "ARP", SrcIP: "10.0.0.19", SrcMAC: "aa:bb:cc:dd:ee:01"})
	detEngine.ProcessPacket(detection.PacketInfo{Protocol: "ARP", SrcIP: "10.0.0.19", SrcMAC: "aa:bb:cc:dd:ee:02"})

	// 20. TCP Fragment Reassembly Test (Split SQLi)
	fmt.Println("[20/20] Simulating TCP Fragment Evasion (Split SQLi)")
	// Send UNION SELECT split across two packets
	sendPacket("TCP", "10.0.0.20", "192.168.1.100", 50020, 80, []byte("GET / HTTP/1.1\r\n\r\nUNI"), false, true)
	sendPacket("TCP", "10.0.0.20", "192.168.1.100", 50020, 80, []byte("ON SELECT * FROM users"), false, true)

	fmt.Println("\n========================================")
	fmt.Println("       IDPS ALERTS DETECTED")
	fmt.Println("========================================")

	appState.Mu.RLock()
	for _, alert := range appState.Alerts {
		if alert.Timestamp >= simTime {
			fmt.Printf("[%s] [%s] %s | Rule: %s | Src: %s\n", 
				alert.Severity, alert.AlertType, alert.Reason, alert.RuleID, alert.SourceIP)
		}
	}
	appState.Mu.RUnlock()

	fmt.Printf("\nTotal alerts generated: %d\n", len(appState.Alerts))
}
