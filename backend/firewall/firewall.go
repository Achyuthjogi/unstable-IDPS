package firewall

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"idps-backend/audit"
	"idps-backend/config"
	"idps-backend/platform"
)

// BlockStatus represents the discrete verified state of a block enforcement action.
type BlockStatus string

const (
	BlockStatusRequested  BlockStatus = "BLOCK_REQUESTED"
	BlockStatusConfirmed  BlockStatus = "BLOCK_CONFIRMED"
	BlockStatusFailed     BlockStatus = "BLOCK_FAILED"
	BlockStatusRolledBack BlockStatus = "BLOCK_ROLLED_BACK"
)

// BlockResult contains complete audited telemetry for a firewall block attempt.
type BlockResult struct {
	IP        string      `json:"ip"`
	MAC       string      `json:"mac,omitempty"`
	RuleID    string      `json:"rule_id,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	Status    BlockStatus `json:"status"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	ExpiresAt time.Time   `json:"expires_at"`
	Platform  string      `json:"platform"`
	Backend   string      `json:"backend"`
}

type blockRecord struct {
	mac       string
	ruleID    string
	reason    string
	expiresAt time.Time
}

// PlatformFirewall defines the OS-specific firewall operations.
type PlatformFirewall interface {
	ApplyBlock(ip, mac string, cfg *config.Config) error
	RemoveBlock(ip, mac string, cfg *config.Config) error
	VerifyBlock(ip string, cfg *config.Config) bool
	SetupGateway(cfg *config.Config) error
	TeardownGateway(cfg *config.Config) error
	Name() string
}

// FirewallManager manages cross-platform firewall rules, safe allowlists, and TTL expiration.
type FirewallManager struct {
	backend    PlatformFirewall
	trustedIPs []string
	allowlist  map[string]bool
	blockCache map[string]blockRecord
	history    []BlockResult
	cfg        *config.Config
	mu         sync.RWMutex
}

// NewFirewallManager creates and initializes the firewall manager with platform adapter.
func NewFirewallManager() *FirewallManager {
	fm := &FirewallManager{
		backend:    newPlatformFirewall(),
		trustedIPs: []string{"127.0.0.1", "::1"},
		allowlist:  make(map[string]bool),
		blockCache: make(map[string]blockRecord),
		history:    make([]BlockResult, 0, 100),
	}
	go fm.ttlSweeper()
	return fm
}

// PlatformName returns the active firewall adapter name.
func (fm *FirewallManager) PlatformName() string {
	return fm.backend.Name()
}

// SetupGateway configures the gateway/host routing rules on the active platform.
func (fm *FirewallManager) SetupGateway(cfg *config.Config) error {
	if cfg != nil {
		fm.mu.Lock()
		fm.cfg = cfg
		fm.mu.Unlock()
	}
	return fm.backend.SetupGateway(cfg)
}

// TeardownGateway tears down the gateway/host routing rules on the active platform.
func (fm *FirewallManager) TeardownGateway(cfg *config.Config) {
	_ = fm.backend.TeardownGateway(cfg)
}

// AddAllowlist adds an IP or subnet to the protected allowlist.
func (fm *FirewallManager) AddAllowlist(ip string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.allowlist[ip] = true
	audit.Get().Log("admin", "ALLOWLIST_ADD", ip, "CONFIRMED", platform.GetInfo().OS, "Added to firewall allowlist")
}

// RemoveAllowlist removes an IP from the protected allowlist.
func (fm *FirewallManager) RemoveAllowlist(ip string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	delete(fm.allowlist, ip)
	audit.Get().Log("admin", "ALLOWLIST_REMOVE", ip, "CONFIRMED", platform.GetInfo().OS, "Removed from firewall allowlist")
}

// GetAllowlist returns all allowlisted IPs.
func (fm *FirewallManager) GetAllowlist() []string {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	var list []string
	for ip := range fm.allowlist {
		list = append(list, ip)
	}
	return list
}

func (fm *FirewallManager) isSafeToBlock(ip string, cfg *config.Config) bool {
	safe, _ := fm.isSafeToBlockWithReason(ip, cfg)
	return safe
}

func (fm *FirewallManager) isSafeToBlockWithReason(ip string, cfg *config.Config) (bool, string) {
	if ip == "" {
		return false, "empty IP address"
	}

	cfg.Mu.RLock()
	gatewayIP := cfg.GatewayIP
	dhcpIP := cfg.LegitimateDHCPServerIP
	cfg.Mu.RUnlock()

	if gatewayIP != "" && ip == gatewayIP {
		return false, "protected default gateway"
	}
	if dhcpIP != "" && ip == dhcpIP {
		return false, "protected DHCP server"
	}

	fm.mu.RLock()
	isAllowlisted := fm.allowlist[ip]
	fm.mu.RUnlock()
	if isAllowlisted {
		return false, "IP is on protected allowlist"
	}

	for _, trusted := range fm.trustedIPs {
		if ip == trusted {
			return false, "loopback/trusted interface"
		}
	}

	if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") || strings.HasSuffix(ip, ".255") {
		return false, "multicast/broadcast range"
	}

	// Protect all local interface IPs
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			var localIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				localIP = v.IP
			case *net.IPAddr:
				localIP = v.IP
			}
			if localIP != nil && localIP.String() == ip {
				return false, "local host interface IP"
			}
		}
	}

	return true, ""
}

// BlockDeviceWithResult attempts to block an attacker IP/MAC and verifies enforcement.
func (fm *FirewallManager) BlockDeviceWithResult(ip, mac string, cfg *config.Config, reason, ruleID string) BlockResult {
	now := time.Now().UTC()
	ttl := 600 * time.Second
	if cfg != nil {
		cfg.Mu.RLock()
		if cfg.BlockTTLSeconds > 0 {
			ttl = time.Duration(cfg.BlockTTLSeconds) * time.Second
		}
		cfg.Mu.RUnlock()
	}
	expiresAt := now.Add(ttl)

	res := BlockResult{
		IP:        ip,
		MAC:       mac,
		RuleID:    ruleID,
		Reason:    reason,
		Timestamp: now,
		ExpiresAt: expiresAt,
		Platform:  platform.GetInfo().OS,
		Backend:   fm.backend.Name(),
	}

	// 1. Safety verification
	safe, reasonNotSafe := fm.isSafeToBlockWithReason(ip, cfg)
	if !safe {
		res.Status = BlockStatusFailed
		res.Error = fmt.Sprintf("Refused to block: %s", reasonNotSafe)
		audit.Get().Log("system:firewall", "BLOCK_REFUSED", ip, "FAILED", res.Platform, res.Error)
		return res
	}

	// 2. Check if passive IDS mode
	cfg.Mu.RLock()
	secMode := cfg.IDPSSecurityMode
	cfg.Mu.RUnlock()
	if secMode == "IDS" {
		res.Status = BlockStatusRequested
		res.Error = "System in passive IDS mode (enforcement skipped)"
		audit.Get().Log("system:firewall", "BLOCK_PASSIVE_IDS", ip, "REQUESTED", res.Platform, "IDS mode: alert logged without active block")
		return res
	}

	// 3. Prevent duplicate active commands if recently confirmed
	fm.mu.Lock()
	if rec, exists := fm.blockCache[ip]; exists {
		rec.expiresAt = expiresAt
		fm.blockCache[ip] = rec
		fm.mu.Unlock()
		res.Status = BlockStatusConfirmed
		return res
	}
	fm.mu.Unlock()

	// 4. Apply OS-specific block
	err := fm.backend.ApplyBlock(ip, mac, cfg)
	if err != nil {
		res.Status = BlockStatusFailed
		res.Error = err.Error()
		audit.Get().Log("system:firewall", "BLOCK_APPLY_FAILED", ip, "FAILED", res.Platform, err.Error())
		return res
	}

	// 5. Explicitly verify enforcement in kernel firewall
	if !fm.backend.VerifyBlock(ip, cfg) {
		res.Status = BlockStatusFailed
		res.Error = "Firewall command executed but rule was not verified in kernel table"
		audit.Get().Log("system:firewall", "BLOCK_VERIFY_FAILED", ip, "FAILED", res.Platform, res.Error)
		return res
	}

	// Block confirmed! Cache and audit
	res.Status = BlockStatusConfirmed
	fm.mu.Lock()
	fm.blockCache[ip] = blockRecord{
		mac:       mac,
		ruleID:    ruleID,
		reason:    reason,
		expiresAt: expiresAt,
	}
	if len(fm.history) >= 100 {
		fm.history = fm.history[1:]
	}
	fm.history = append(fm.history, res)
	fm.mu.Unlock()

	audit.Get().Log("system:firewall", "BLOCK_CONFIRMED", ip, "CONFIRMED", res.Platform, fmt.Sprintf("Rule %s enforced. TTL: %v", ruleID, ttl))
	return res
}

// BlockDevice is the backward-compatible entry point returning bool.
func (fm *FirewallManager) BlockDevice(ip string, mac string, cfg *config.Config) bool {
	res := fm.BlockDeviceWithResult(ip, mac, cfg, "Automated IDPS Threat Block", "")
	return res.Status == BlockStatusConfirmed
}

// UnblockDevice removes an IP and MAC block with audited rollback.
func (fm *FirewallManager) UnblockDevice(ip, mac string, cfg *config.Config) bool {
	if ip == "" {
		return false
	}

	err := fm.backend.RemoveBlock(ip, mac, cfg)
	success := (err == nil)

	fm.mu.Lock()
	delete(fm.blockCache, ip)
	fm.mu.Unlock()

	status := "CONFIRMED"
	if !success {
		status = "FAILED"
	}
	audit.Get().Log("system:firewall", "UNBLOCK", ip, status, platform.GetInfo().OS, "Removed block rule from firewall")
	return success
}

// VerifyBlock checks if a given IP block is verified in the kernel table.
func (fm *FirewallManager) VerifyBlock(ip string, cfg *config.Config) bool {
	return fm.backend.VerifyBlock(ip, cfg)
}

// ttlSweeper regularly cleans up expired temporary blocks.
func (fm *FirewallManager) ttlSweeper() {
	for {
		time.Sleep(5 * time.Second)
		now := time.Now().UTC()

		var expiredIPs []string
		var expiredMACs []string

		fm.mu.Lock()
		for ip, rec := range fm.blockCache {
			if now.After(rec.expiresAt) {
				expiredIPs = append(expiredIPs, ip)
				expiredMACs = append(expiredMACs, rec.mac)
			}
		}
		cfg := fm.cfg
		fm.mu.Unlock()

		for i, ip := range expiredIPs {
			mac := expiredMACs[i]
			_ = fm.backend.RemoveBlock(ip, mac, cfg)
			fm.mu.Lock()
			delete(fm.blockCache, ip)
			fm.mu.Unlock()
			audit.Get().Log("system:ttl_sweeper", "AUTO_UNBLOCK", ip, "CONFIRMED", platform.GetInfo().OS, "TTL expired; rule rolled back automatically")
		}
	}
}
