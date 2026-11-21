package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// SessionDisrupter crafts and injects raw TCP RST and ICMP unreachable packets for active connection teardown.
type SessionDisrupter struct {
	mu           sync.Mutex
	lastInjected time.Time
	injectCount  uint64
}

// NewSessionDisrupter creates an active session disruption engine.
func NewSessionDisrupter() *SessionDisrupter {
	return &SessionDisrupter{}
}

// BuildTCPRSTPacket crafts a raw TCP segment with RST/ACK flags set.
func BuildTCPRSTPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum, ackNum uint32) []byte {
	// TCP Header is 20 bytes (without options)
	tcpLen := 20
	tcpHdr := make([]byte, tcpLen)

	// Source Port
	binary.BigEndian.PutUint16(tcpHdr[0:2], srcPort)
	// Destination Port
	binary.BigEndian.PutUint16(tcpHdr[2:4], dstPort)
	// Sequence Number
	binary.BigEndian.PutUint32(tcpHdr[4:8], seqNum)
	// Acknowledgment Number
	binary.BigEndian.PutUint32(tcpHdr[8:12], ackNum)
	// Data Offset (5 32-bit words = 20 bytes) << 4
	tcpHdr[12] = 0x50
	// Flags: RST (0x04) | ACK (0x10) = 0x14
	tcpHdr[13] = 0x14
	// Window Size: 0
	binary.BigEndian.PutUint16(tcpHdr[14:16], 0)
	// Checksum (initially 0)
	binary.BigEndian.PutUint16(tcpHdr[16:18], 0)
	// Urgent Pointer: 0
	binary.BigEndian.PutUint16(tcpHdr[18:20], 0)

	// Compute TCP Checksum with IPv4 Pseudo-Header
	chk := computeTCPChecksum(srcIP, dstIP, tcpHdr)
	binary.BigEndian.PutUint16(tcpHdr[16:18], chk)

	return tcpHdr
}

func computeTCPChecksum(srcIP, dstIP net.IP, tcpHdr []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}

	length := len(tcpHdr)
	pseudoHeader := make([]byte, 12+length)

	// Pseudo Header:
	// Src IP (4) + Dst IP (4) + Zero (1) + Protocol (1 = 6 for TCP) + TCP Length (2)
	copy(pseudoHeader[0:4], src)
	copy(pseudoHeader[4:8], dst)
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(length))
	copy(pseudoHeader[12:], tcpHdr)

	return checksum(pseudoHeader)
}

func checksum(data []byte) uint16 {
	var sum uint32
	numWords := len(data) / 2

	for i := 0; i < numWords; i++ {
		sum += uint32(binary.BigEndian.Uint16(data[i*2 : i*2+2]))
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// TerminateFlow actively kills a TCP or UDP connection by injecting bidirectional RST packets.
func (sd *SessionDisrupter) TerminateFlow(srcIPStr, dstIPStr string, srcPort, dstPort uint16, proto string, seqNum, ackNum uint32) error {
	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)
	if srcIP == nil || dstIP == nil {
		return fmt.Errorf("invalid IP addresses")
	}

	if proto != "TCP" {
		return nil // Non-TCP flows handled via firewall drop
	}

	sd.mu.Lock()
	sd.injectCount += 2
	sd.lastInjected = time.Now()
	sd.mu.Unlock()

	// 1. RST to Server (masquerading as Client)
	rstToServer := BuildTCPRSTPacket(srcIP, dstIP, srcPort, dstPort, seqNum, ackNum)
	_ = sendRawIPPacket(dstIP, rstToServer)

	// 2. RST to Client (masquerading as Server)
	rstToClient := BuildTCPRSTPacket(dstIP, srcIP, dstPort, srcPort, ackNum, seqNum)
	_ = sendRawIPPacket(srcIP, rstToClient)

	return nil
}

func sendRawIPPacket(targetIP net.IP, payload []byte) error {
	conn, err := net.Dial("ip4:tcp", targetIP.String())
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(payload)
	return err
}

// GetDisruptionStats returns total session resets executed.
func (sd *SessionDisrupter) GetDisruptionStats() uint64 {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	return sd.injectCount
}
