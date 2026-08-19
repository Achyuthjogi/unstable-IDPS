package flow

import (
	"bytes"
	"fmt"
	"net"
)

// Protocol defines the transport layer protocol.
type Protocol uint8

const (
	ProtoTCP Protocol = 6
	ProtoUDP Protocol = 17
	ProtoICMP Protocol = 1
)

// Key is the 5-tuple identifying a network flow.
// It is canonically ordered so that A->B and B->A map to the same key.
type Key struct {
	Protocol Protocol
	SrcIP    [16]byte // IPv6 or IPv4 (4 bytes mapped)
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
}

// NewKey creates a canonically ordered flow key.
func NewKey(proto Protocol, srcIP, dstIP net.IP, srcPort, dstPort uint16) Key {
	k := Key{
		Protocol: proto,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}

	// Ensure 16-byte representation for both IPv4 and IPv6
	src := srcIP.To16()
	dst := dstIP.To16()

	// Canonical ordering: lower IP first. If IPs equal, lower port first.
	if bytes.Compare(src, dst) < 0 || (bytes.Equal(src, dst) && srcPort <= dstPort) {
		copy(k.SrcIP[:], src)
		copy(k.DstIP[:], dst)
		k.SrcPort = srcPort
		k.DstPort = dstPort
	} else {
		copy(k.SrcIP[:], dst)
		copy(k.DstIP[:], src)
		k.SrcPort = dstPort
		k.DstPort = srcPort
	}

	return k
}

// String returns a string representation of the flow key.
func (k Key) String() string {
	return fmt.Sprintf("%d:%s:%d-%s:%d", k.Protocol, net.IP(k.SrcIP[:]).String(), k.SrcPort, net.IP(k.DstIP[:]).String(), k.DstPort)
}
