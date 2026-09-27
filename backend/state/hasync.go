package state

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// HAStateUpdate represents a state update to broadcast to peer nodes.
type HAStateUpdate struct {
	NodeID    string           `json:"node_id"`
	Timestamp int64            `json:"timestamp"`
	FlowStats map[string]int64 `json:"flow_stats"` // simplified for now: stringified Key -> Packets
}

// HASync manages High Availability state synchronization between IDPS nodes.
type HASync struct {
	State      *AppState
	NodeID     string
	BindAddr   string
	PeerAddrs  []string
	conn       *net.UDPConn
}

func NewHASync(st *AppState, nodeID, bindAddr string, peerAddrs []string) *HASync {
	return &HASync{
		State:     st,
		NodeID:    nodeID,
		BindAddr:  bindAddr,
		PeerAddrs: peerAddrs,
	}
}

func (ha *HASync) Start() error {
	if ha.BindAddr == "" || len(ha.PeerAddrs) == 0 {
		return nil // Disabled
	}
	addr, err := net.ResolveUDPAddr("udp", ha.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve HA bind address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen for HA sync: %v", err)
	}
	ha.conn = conn

	fmt.Printf("HA Sync started. Listening on %s. Peers: %v\n", ha.BindAddr, ha.PeerAddrs)

	go ha.listen()
	go ha.broadcast()
	return nil
}

func (ha *HASync) listen() {
	buf := make([]byte, 65535)
	for {
		n, peerAddr, err := ha.conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("HA Sync Listen Error: %v\n", err)
			continue
		}
		var update HAStateUpdate
		if err := json.Unmarshal(buf[:n], &update); err == nil {
			// In a full implementation, we would merge this state into flow.Tracker.
			// For demonstration, we simply log the receipt of state.
			// fmt.Printf("HA: Received state from peer %s at %s (%d flows)\n", update.NodeID, peerAddr.String(), len(update.FlowStats))
			_ = peerAddr // used for logging
		}
	}
}

func (ha *HASync) broadcast() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		
		// In a full implementation, we extract flow states from flow.Tracker.
		// For this prototype, we just send a heartbeat with placeholder stats.
		update := HAStateUpdate{
			NodeID:    ha.NodeID,
			Timestamp: time.Now().Unix(),
			FlowStats: make(map[string]int64),
		}

		data, _ := json.Marshal(update)
		for _, peerStr := range ha.PeerAddrs {
			if addr, err := net.ResolveUDPAddr("udp", peerStr); err == nil {
				ha.conn.WriteToUDP(data, addr)
			}
		}
	}
}
