package state

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// SyncAction defines cluster replication actions.
type SyncAction string

const (
	ActionHeartbeat    SyncAction = "HEARTBEAT"
	ActionSyncBlock    SyncAction = "SYNC_BLOCK"
	ActionSyncUnblock  SyncAction = "SYNC_UNBLOCK"
	ActionStateRequest SyncAction = "STATE_REQUEST"
	ActionStateReply   SyncAction = "STATE_REPLY"
)

// ClusterNodeStatus tracks the live state of a cluster peer.
type ClusterNodeStatus struct {
	NodeID          string    `json:"node_id"`
	Address         string    `json:"address"`
	Role            string    `json:"role"`
	Status          string    `json:"status"` // "ONLINE", "DEGRADED", "OFFLINE"
	LastHeartbeat   time.Time `json:"last_heartbeat"`
	ActiveFlows     int64     `json:"active_flows"`
	PacketsPerSec   int64     `json:"packets_per_sec"`
	BlockedIPsCount int       `json:"blocked_ips_count"`
	Version         string    `json:"version"`
}

// ClusterPayload is the wire format for HA messages.
type ClusterPayload struct {
	Action       SyncAction          `json:"action"`
	SenderNodeID string              `json:"sender_node_id"`
	Timestamp    int64               `json:"timestamp"`
	Signature    string              `json:"signature"`
	BlockData    *IPBlock            `json:"block_data,omitempty"`
	UnblockIP    string              `json:"unblock_ip,omitempty"`
	UnblockMAC   string              `json:"unblock_mac,omitempty"`
	NodeStats    *ClusterNodeStatus  `json:"node_stats,omitempty"`
	FullState    map[string]IPBlock  `json:"full_state,omitempty"`
}

// FirewallEnforcer abstracts kernel enforcement so HASync can trigger firewall blocks.
type FirewallEnforcer interface {
	ApplyBlockDirect(ip, mac, ruleID, reason string, ttl time.Duration) bool
	RemoveBlockDirect(ip, mac string) bool
}

// HASync manages enterprise cluster synchronization and stateful failover.
type HASync struct {
	State         *AppState
	NodeID        string
	BindAddr      string
	PeerAddrs     []string
	SecretKey     string
	Role          string
	Enforcer      FirewallEnforcer
	conn          *net.UDPConn
	nodes         map[string]*ClusterNodeStatus
	mu            sync.RWMutex
	stopChan      chan struct{}
	running       bool
	syncCount     uint64
}

// NewHASync initializes a production cluster synchronization engine.
func NewHASync(st *AppState, nodeID, bindAddr string, peerAddrs []string) *HASync {
	if nodeID == "" {
		hostname, _ := os.Hostname()
		if hostname != "" {
			nodeID = "node-" + hostname
		} else {
			nodeID = fmt.Sprintf("node-%d", time.Now().Unix()%10000)
		}
	}
	secret := os.Getenv("HA_SHARED_SECRET")
	if secret == "" {
		secret = "nexus-enterprise-ha-default-secret-key-32b"
	}
	return &HASync{
		State:     st,
		NodeID:    nodeID,
		BindAddr:  bindAddr,
		PeerAddrs: peerAddrs,
		SecretKey: secret,
		Role:      "PEER",
		nodes:     make(map[string]*ClusterNodeStatus),
		stopChan:  make(chan struct{}),
	}
}

// SetFirewallEnforcer attaches the kernel firewall manager.
func (ha *HASync) SetFirewallEnforcer(enforcer FirewallEnforcer) {
	ha.mu.Lock()
	defer ha.mu.Unlock()
	ha.Enforcer = enforcer
}

// sign generates an HMAC-SHA256 signature for payload verification.
func (ha *HASync) sign(data []byte) string {
	mac := hmac.New(sha256.New, []byte(ha.SecretKey))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// verify validates the HMAC signature on incoming cluster frames.
func (ha *HASync) verify(data []byte, signature string) bool {
	expectedSig := ha.sign(data)
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// Start boots the cluster listener and broadcast loops.
func (ha *HASync) Start() error {
	if ha.BindAddr == "" {
		return nil // HA disabled if no bind address specified
	}

	addr, err := net.ResolveUDPAddr("udp", ha.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve HA bind address %s: %w", ha.BindAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind HA UDP socket on %s: %w", ha.BindAddr, err)
	}
	ha.conn = conn
	ha.running = true

	ha.mu.Lock()
	ha.nodes[ha.NodeID] = &ClusterNodeStatus{
		NodeID:        ha.NodeID,
		Address:       ha.BindAddr,
		Role:          ha.Role,
		Status:        "ONLINE",
		LastHeartbeat: time.Now(),
		Version:       "2.1.0-enterprise",
	}
	ha.mu.Unlock()

	go ha.listenLoop()
	go ha.heartbeatLoop()
	go ha.peerPruneLoop()

	// Initial cluster state synchronization
	ha.RequestClusterState()

	return nil
}

// Stop cleanly terminates cluster sync.
func (ha *HASync) Stop() {
	ha.mu.Lock()
	defer ha.mu.Unlock()
	if !ha.running {
		return
	}
	ha.running = false
	close(ha.stopChan)
	if ha.conn != nil {
		ha.conn.Close()
	}
}

// BroadcastBlock replicates a verified block action across all cluster nodes.
func (ha *HASync) BroadcastBlock(block IPBlock) {
	if !ha.running {
		return
	}
	payload := ClusterPayload{
		Action:       ActionSyncBlock,
		SenderNodeID: ha.NodeID,
		Timestamp:    time.Now().Unix(),
		BlockData:    &block,
	}
	ha.sendPayload(payload)
}

// BroadcastUnblock replicates an unblock action across all cluster nodes.
func (ha *HASync) BroadcastUnblock(ip, mac string) {
	if !ha.running {
		return
	}
	payload := ClusterPayload{
		Action:       ActionSyncUnblock,
		SenderNodeID: ha.NodeID,
		Timestamp:    time.Now().Unix(),
		UnblockIP:    ip,
		UnblockMAC:   mac,
	}
	ha.sendPayload(payload)
}

// RequestClusterState asks online peers to send their active block tables.
func (ha *HASync) RequestClusterState() {
	payload := ClusterPayload{
		Action:       ActionStateRequest,
		SenderNodeID: ha.NodeID,
		Timestamp:    time.Now().Unix(),
	}
	ha.sendPayload(payload)
}

func (ha *HASync) sendPayload(payload ClusterPayload) {
	// Sign payload excluding the signature field itself
	payload.Signature = ""
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	payload.Signature = ha.sign(data)
	wireData, err := json.Marshal(payload)
	if err != nil {
		return
	}

	for _, peerAddrStr := range ha.PeerAddrs {
		if peerAddr, err := net.ResolveUDPAddr("udp", peerAddrStr); err == nil {
			_, _ = ha.conn.WriteToUDP(wireData, peerAddr)
		}
	}
}

func (ha *HASync) listenLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ha.stopChan:
			return
		default:
		}

		n, peerAddr, err := ha.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ha.stopChan:
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		var payload ClusterPayload
		if err := json.Unmarshal(buf[:n], &payload); err != nil {
			continue
		}

		// Don't process self-broadcasts
		if payload.SenderNodeID == ha.NodeID {
			continue
		}

		// Verify cryptographic signature
		claimedSig := payload.Signature
		payload.Signature = ""
		unsignedData, _ := json.Marshal(payload)
		if !ha.verify(unsignedData, claimedSig) {
			continue // Invalid or spoofed cluster packet dropped
		}

		ha.handlePayload(payload, peerAddr)
	}
}

func (ha *HASync) handlePayload(payload ClusterPayload, peerAddr *net.UDPAddr) {
	ha.mu.Lock()
	ha.syncCount++
	ha.mu.Unlock()

	switch payload.Action {
	case ActionHeartbeat:
		if payload.NodeStats != nil {
			ha.mu.Lock()
			payload.NodeStats.Address = peerAddr.String()
			payload.NodeStats.Status = "ONLINE"
			payload.NodeStats.LastHeartbeat = time.Now()
			ha.nodes[payload.SenderNodeID] = payload.NodeStats
			ha.mu.Unlock()
		}

	case ActionSyncBlock:
		if payload.BlockData != nil {
			block := *payload.BlockData
			ha.State.Mu.Lock()
			ha.State.BlockedIPs[block.IP] = block
			if block.MAC != "" {
				ha.State.BlockedMACs[block.MAC] = block
			}
			ha.State.AddThreatTimeline(ThreatTimeline{
				Timestamp: float64(time.Now().UnixNano()) / 1e9,
				Event:     fmt.Sprintf("Cluster Sync: Blocked IP %s (from node %s)", block.IP, payload.SenderNodeID),
				Severity:  "High",
			})
			ha.State.Mu.Unlock()

			// Apply in local kernel firewall
			if ha.Enforcer != nil {
				ttl := time.Duration(block.ExpiresAt-float64(time.Now().UnixNano())/1e9) * time.Second
				if ttl < 0 {
					ttl = 300 * time.Second
				}
				ha.Enforcer.ApplyBlockDirect(block.IP, block.MAC, block.RuleID, block.Reason, ttl)
			}
		}

	case ActionSyncUnblock:
		ha.State.Mu.Lock()
		delete(ha.State.BlockedIPs, payload.UnblockIP)
		if payload.UnblockMAC != "" {
			delete(ha.State.BlockedMACs, payload.UnblockMAC)
		}
		ha.State.AddThreatTimeline(ThreatTimeline{
			Timestamp: float64(time.Now().UnixNano()) / 1e9,
			Event:     fmt.Sprintf("Cluster Sync: Unblocked IP %s (from node %s)", payload.UnblockIP, payload.SenderNodeID),
			Severity:  "Info",
		})
		ha.State.Mu.Unlock()

		if ha.Enforcer != nil {
			ha.Enforcer.RemoveBlockDirect(payload.UnblockIP, payload.UnblockMAC)
		}

	case ActionStateRequest:
		// Return our active block state to the requesting peer
		ha.State.Mu.RLock()
		snapshot := make(map[string]IPBlock)
		for ip, b := range ha.State.BlockedIPs {
			snapshot[ip] = b
		}
		ha.State.Mu.RUnlock()

		reply := ClusterPayload{
			Action:       ActionStateReply,
			SenderNodeID: ha.NodeID,
			Timestamp:    time.Now().Unix(),
			FullState:    snapshot,
		}
		ha.sendPayload(reply)

	case ActionStateReply:
		if payload.FullState != nil {
			ha.State.Mu.Lock()
			for ip, block := range payload.FullState {
				ha.State.BlockedIPs[ip] = block
				if block.MAC != "" {
					ha.State.BlockedMACs[block.MAC] = block
				}
			}
			ha.State.Mu.Unlock()
		}
	}
}

func (ha *HASync) heartbeatLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ha.stopChan:
			return
		case <-ticker.C:
			ha.State.Mu.RLock()
			blockedCount := len(ha.State.BlockedIPs)
			activeFlows := int64(ha.State.ActiveFlows)
			ha.State.Mu.RUnlock()

			stats := &ClusterNodeStatus{
				NodeID:          ha.NodeID,
				Address:         ha.BindAddr,
				Role:            ha.Role,
				Status:          "ONLINE",
				LastHeartbeat:   time.Now(),
				ActiveFlows:     activeFlows,
				BlockedIPsCount: blockedCount,
				Version:         "2.1.0-enterprise",
			}

			ha.mu.Lock()
			ha.nodes[ha.NodeID] = stats
			ha.mu.Unlock()

			payload := ClusterPayload{
				Action:       ActionHeartbeat,
				SenderNodeID: ha.NodeID,
				Timestamp:    time.Now().Unix(),
				NodeStats:    stats,
			}
			ha.sendPayload(payload)
		}
	}
}

func (ha *HASync) peerPruneLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ha.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			ha.mu.Lock()
			for id, node := range ha.nodes {
				if id == ha.NodeID {
					continue
				}
				if now.Sub(node.LastHeartbeat) > 15*time.Second {
					node.Status = "OFFLINE"
				} else if now.Sub(node.LastHeartbeat) > 8*time.Second {
					node.Status = "DEGRADED"
				}
			}
			ha.mu.Unlock()
		}
	}
}

// GetClusterNodes returns a snapshot of all active peers and statuses.
func (ha *HASync) GetClusterNodes() []ClusterNodeStatus {
	ha.mu.RLock()
	defer ha.mu.RUnlock()

	var list []ClusterNodeStatus
	for _, n := range ha.nodes {
		list = append(list, *n)
	}
	return list
}

// GetSyncMetrics returns total cluster synchronization packets handled.
func (ha *HASync) GetSyncMetrics() (uint64, int) {
	ha.mu.RLock()
	defer ha.mu.RUnlock()
	return ha.syncCount, len(ha.nodes)
}
