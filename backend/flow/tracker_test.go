package flow

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestStreamReassembler(t *testing.T) {
	sr := NewStreamReassembler(1024)
	sr.Init(0) // Explicitly initialize ISN to 0
	
	// Out of order segments
	sr.AddSegment(6, []byte("world"))
	sr.AddSegment(0, []byte("hello "))
	
	if string(sr.Data) != "hello world" {
		t.Errorf("Expected 'hello world', got '%s'", string(sr.Data))
	}

	sr.AddSegment(11, []byte("!"))
	if string(sr.Data) != "hello world!" {
		t.Errorf("Expected 'hello world!', got '%s'", string(sr.Data))
	}
}

func TestFlowKey(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.5")
	ip2 := net.ParseIP("10.0.0.2")

	key1 := NewKey(ProtoTCP, ip1, ip2, 12345, 80)
	key2 := NewKey(ProtoTCP, ip2, ip1, 80, 12345) // Reversed direction

	if key1 != key2 {
		t.Errorf("Flow keys for opposite directions should match. %v != %v", key1, key2)
	}
}

func TestTracker(t *testing.T) {
	tracker := NewTracker(10, time.Minute, 1024)

	ip1 := net.ParseIP("192.168.1.5")
	ip2 := net.ParseIP("10.0.0.2")
	key := NewKey(ProtoTCP, ip1, ip2, 12345, 80)

	var pktSrc [16]byte
	copy(pktSrc[:], ip1.To16())

	f, created := tracker.GetOrCreate(key, pktSrc, 12345)
	if !created {
		t.Error("Expected flow to be created")
	}

	// SYN
	tracker.UpdateFlow(f, pktSrc, 12345, nil, 0, 0x02)
	if f.State != StateNew {
		t.Errorf("Expected StateNew, got %d", f.State)
	}

	// SYN-ACK (from server)
	var serverSrc [16]byte
	copy(serverSrc[:], ip2.To16())
	tracker.UpdateFlow(f, serverSrc, 80, nil, 0, 0x12) // SYN, ACK
	if f.State != StateEstablished {
		t.Errorf("Expected StateEstablished, got %d", f.State)
	}

	// Data from client
	tracker.UpdateFlow(f, pktSrc, 12345, []byte("GET /"), 100, 0x10) // ACK
	if !bytes.Equal(f.ClientStream.Data, []byte("GET /")) {
		t.Errorf("Client stream reassembly failed")
	}
}
