package detection

import (
	"testing"

	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/state"
)

func TestDetectionLogic(t *testing.T) {
	st := state.NewAppState()
	cfg := &config.Config{
		IDPSDeploymentMode:      "HOST",
		IDPSSecurityMode:        "IPS",
		SuspiciousRateThreshold: 50,
		PortScanThreshold:       5,
		ICMPFloodThreshold:      20,
		UDPFloodThreshold:       20,
		SYNFloodThreshold:       20,
		SSHBruteForceThreshold:  5,
		BlockTTLSeconds:         10,
		FirewallDryRun:          true,
	}
	fm := firewall.NewFirewallManager()

	simulatePacket := func(src, dst, proto string, srcPort, dstPort uint16, syn bool) {
		pkt := PacketInfo{
			SrcIP:    src,
			DstIP:    dst,
			Protocol: proto,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			IsTCPSYN: syn,
		}
		AnalyzePacket(st, cfg, fm, pkt)
	}

	// SYN Flood Test
	for i := 0; i < 75; i++ {
		simulatePacket("192.168.1.100", "10.0.0.1", "TCP", 12345, 80, true)
	}

	st.Mu.RLock()
	if _, blocked := st.BlockedIPs["192.168.1.100"]; !blocked {
		t.Errorf("Expected 192.168.1.100 to be blocked for SYN Flood")
	}
	st.Mu.RUnlock()

	// Port Scan Test
	for i := 0; i < 25; i++ {
		simulatePacket("192.168.1.101", "10.0.0.1", "TCP", 12345, uint16(80+i), true)
	}

	st.Mu.RLock()
	if _, blocked := st.BlockedIPs["192.168.1.101"]; !blocked {
		t.Errorf("Expected 192.168.1.101 to be blocked for Port Scan")
	}
	st.Mu.RUnlock()

	// ICMP Flood Test
	for i := 0; i < 75; i++ {
		simulatePacket("192.168.1.102", "10.0.0.1", "ICMP", 0, 0, false)
	}

	st.Mu.RLock()
	if _, blocked := st.BlockedIPs["192.168.1.102"]; !blocked {
		t.Errorf("Expected 192.168.1.102 to be blocked for ICMP Flood")
	}
	st.Mu.RUnlock()

	// IDS Mode Test
	cfg.IDPSSecurityMode = "IDS"
	for i := 0; i < 75; i++ {
		simulatePacket("192.168.1.103", "10.0.0.1", "ICMP", 0, 0, false)
	}

	st.Mu.RLock()
	if _, blocked := st.BlockedIPs["192.168.1.103"]; blocked {
		t.Errorf("Expected 192.168.1.103 NOT to be blocked in IDS mode")
	}
	st.Mu.RUnlock()

	// Trusted IP Test
	cfg.IDPSSecurityMode = "IPS"
	for i := 0; i < 75; i++ {
		simulatePacket("127.0.0.1", "10.0.0.1", "ICMP", 0, 0, false)
	}

	st.Mu.RLock()
	if _, blocked := st.BlockedIPs["127.0.0.1"]; blocked {
		t.Errorf("Expected trusted IP 127.0.0.1 not to be blocked")
	}
	st.Mu.RUnlock()
}
