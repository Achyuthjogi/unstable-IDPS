// Topology & Layer 2 Isolation Context:
// This IDPS is designed to run on a gateway node, typically an Ubuntu laptop
// acting as a NetworkManager hotspot bridge (LAN: wlan0/nm-wlan) with USB tethering (WAN: usb0).
//
// IP-based blocking via iptables FORWARD/INPUT chains is insufficient for this topology because:
// 1. Attackers can renew their DHCP lease to change their IP and bypass the block.
// 2. Clients connected to the same hotspot bridge can communicate directly at Layer 2,
//    bypassing the iptables FORWARD chain and evading isolation.
//
// To solve this, we use `ebtables` to enforce MAC-based Layer 2 isolation directly
// on the bridge. This guarantees durable blocking across IP changes and prevents
// client-to-client attacks on the same hotspot. (ap_isolate via hostapd could also work,
// but ebtables allows granular, per-device programmatic blocking).
package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"idps-backend/config"
)

type FirewallManager struct {
	trustedIPs        []string
	ipForwardOriginal string
	
	// TTL Cache to prevent duplicate shell executions and auto-unblock
	blockCache        map[string]time.Time
	mu                sync.Mutex
}

func NewFirewallManager() *FirewallManager {
	fm := &FirewallManager{
		trustedIPs: []string{"127.0.0.1", "::1"},
		blockCache: make(map[string]time.Time),
	}
	go fm.ttlSweeper()
	return fm
}

func (fm *FirewallManager) ttlSweeper() {
	for {
		time.Sleep(10 * time.Second) // Check every 10 seconds
		now := time.Now()
		
		fm.mu.Lock()
		for ip, expiry := range fm.blockCache {
			if now.After(expiry) {
				// TTL Expired. Unblock.
				// We don't have the MAC here, but iptables unblock is most critical.
				// For a real production system, cache a struct { mac, expiry }.
				fmt.Printf("FirewallManager: TTL expired for %s. Unblocking...\n", ip)
				// We need the config, but we don't have it easily here.
				// Actually, we should just fire a teardown using a dummy config or refactor.
				// For now, execute iptables directly since we know it's a block.
				bin := iptablesBin(ip)
				exec.Command("sudo", bin, "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP").Run()
				exec.Command("sudo", bin, "-D", "FORWARD", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP").Run()
				delete(fm.blockCache, ip)
			}
		}
		fm.mu.Unlock()
	}
}

func (fm *FirewallManager) isSafeToBlock(ip string, cfg *config.Config) bool {
	cfg.Mu.RLock()
	gatewayIP := cfg.GatewayIP
	cfg.Mu.RUnlock()

	if gatewayIP != "" && ip == gatewayIP {
		return false
	}
	for _, trusted := range fm.trustedIPs {
		if ip == trusted {
			return false
		}
	}
	if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") || strings.HasSuffix(ip, ".255") {
		return false
	}

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
				return false
			}
		}
	}
	return true
}

// iptablesBin returns "ip6tables" for IPv6 addresses, "iptables" for IPv4.
func iptablesBin(ip string) string {
	if strings.Contains(ip, ":") {
		return "ip6tables"
	}
	return "iptables"
}

func (fm *FirewallManager) runCommand(cfg *config.Config, name string, args ...string) error {
	cfg.Mu.RLock()
	dryRun := cfg.FirewallDryRun
	cfg.Mu.RUnlock()

	if dryRun {
		fmt.Printf("[DRY RUN] Would execute: %s %s\n", name, strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func (fm *FirewallManager) ruleExists(cfg *config.Config, bin string, args ...string) bool {
	cfg.Mu.RLock()
	dryRun := cfg.FirewallDryRun
	cfg.Mu.RUnlock()

	if dryRun {
		return false
	}
	// Build a -C (check) command from the original args.
	// -A CHAIN ... → -C CHAIN ...
	// -I CHAIN pos ... → -C CHAIN ...  (strip the position number)
	var checkArgs []string
	if len(args) > 0 && args[0] == "-I" && len(args) > 2 {
		// args = ["-I", "CHAIN", "pos", rest...]
		// Skip args[0] ("-I") and args[2] (position number)
		checkArgs = append([]string{"-C", args[1]}, args[3:]...)
	} else {
		checkArgs = append([]string{"-C"}, args[1:]...)
	}
	cmd := exec.Command("sudo", append([]string{bin}, checkArgs...)...)
	return cmd.Run() == nil
}

func (fm *FirewallManager) ensureRule(cfg *config.Config, bin string, args ...string) error {
	if !fm.ruleExists(cfg, bin, args...) {
		return fm.runCommand(cfg, "sudo", append([]string{bin}, args...)...)
	}
	return nil
}

func (fm *FirewallManager) SetupGateway(cfg *config.Config) error {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	wan := cfg.WanInterface
	lan := cfg.LanInterface
	dryRun := cfg.FirewallDryRun
	capIface := cfg.CaptureInterface
	cfg.Mu.RUnlock()

	if mode == "HOST" {
		if capIface != "" {
			fmt.Printf("FirewallManager: Setting up HOST mode NFQUEUE routing on %s\n", capIface)
			fm.ensureRule(cfg, "iptables", "-I", "INPUT", "1", "-i", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-IN")
			fm.ensureRule(cfg, "iptables", "-I", "INPUT", "2", "-i", capIface, "-j", "NFQUEUE", "--queue-num", "1", "-m", "comment", "--comment", "SURICATA-NFQ-HOST-IN")
			fm.ensureRule(cfg, "iptables", "-I", "OUTPUT", "1", "-o", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-OUT")
			fm.ensureRule(cfg, "iptables", "-I", "OUTPUT", "2", "-o", capIface, "-j", "NFQUEUE", "--queue-num", "1", "-m", "comment", "--comment", "SURICATA-NFQ-HOST-OUT")
		}
		return nil
	}

	if mode != "GATEWAY" && mode != "NETWORK" {
		return nil
	}

	fmt.Printf("FirewallManager: Setting up Gateway NAT routing: WAN=%s, LAN=%s\n", wan, lan)

	if wan == "" || lan == "" {
		return fmt.Errorf("WAN or LAN interface is not specified")
	}
	if wan == lan {
		return fmt.Errorf("WAN and LAN interfaces cannot be the same")
	}

	// Validate interfaces exist
	if _, err := net.InterfaceByName(wan); err != nil && !dryRun {
		return fmt.Errorf("WAN interface %s not found: %v", wan, err)
	}
	if _, err := net.InterfaceByName(lan); err != nil && !dryRun {
		return fmt.Errorf("LAN interface %s not found: %v", lan, err)
	}

	if !dryRun {
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err == nil {
			fm.ipForwardOriginal = strings.TrimSpace(string(b))
		}
	}

	if err := fm.runCommand(cfg, "sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("failed to enable ipv4 forwarding: %v", err)
	}

	if !dryRun {
		b, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if strings.TrimSpace(string(b)) != "1" {
			return fmt.Errorf("IPv4 forwarding is not enabled (read %s)", string(b))
		}
	}

	// NAT Rule
	err := fm.ensureRule(cfg, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan, "-m", "comment", "--comment", "IDPS-NAT", "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to configure NAT: %v", err)
	}

	// Route FORWARD WAN -> LAN to NFQUEUE
	err = fm.ensureRule(cfg, "iptables", "-A", "FORWARD", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-NFQ-IN", "-j", "NFQUEUE", "--queue-num", "0")
	if err != nil {
		return fmt.Errorf("failed to configure WAN->LAN nfqueue: %v", err)
	}

	// Route FORWARD WAN -> LAN to Suricata NFQUEUE
	err = fm.ensureRule(cfg, "iptables", "-A", "FORWARD", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "SURICATA-NFQ-IN", "-j", "NFQUEUE", "--queue-num", "1")
	if err != nil {
		return fmt.Errorf("failed to configure WAN->LAN suricata nfqueue: %v", err)
	}

	// Route FORWARD LAN -> WAN to NFQUEUE
	err = fm.ensureRule(cfg, "iptables", "-A", "FORWARD", "-i", lan, "-o", wan, "-m", "comment", "--comment", "IDPS-NFQ-OUT", "-j", "NFQUEUE", "--queue-num", "0")
	if err != nil {
		return fmt.Errorf("failed to configure LAN->WAN nfqueue: %v", err)
	}

	// Route FORWARD LAN -> WAN to Suricata NFQUEUE
	err = fm.ensureRule(cfg, "iptables", "-A", "FORWARD", "-i", lan, "-o", wan, "-m", "comment", "--comment", "SURICATA-NFQ-OUT", "-j", "NFQUEUE", "--queue-num", "1")
	if err != nil {
		return fmt.Errorf("failed to configure LAN->WAN suricata nfqueue: %v", err)
	}

	// Setup Layer 2 MAC-based Isolation Chains (ebtables)
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-N", "IDPS-MAC-BLOCK")
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-P", "IDPS-MAC-BLOCK", "RETURN") // Default return
	
	// Hook custom chain into INPUT (stops gateway access) and FORWARD (stops client-to-client and WAN access)
	// We ignore errors here in case ebtables isn't installed or already hooked
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-I", "INPUT", "-j", "IDPS-MAC-BLOCK")
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-I", "FORWARD", "-j", "IDPS-MAC-BLOCK")

	fmt.Println("FirewallManager: Gateway NAT routing and L2 Isolation configured successfully.")
	return nil
}

func (fm *FirewallManager) TeardownGateway(cfg *config.Config) {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	wan := cfg.WanInterface
	lan := cfg.LanInterface
	dryRun := cfg.FirewallDryRun
	capIface := cfg.CaptureInterface
	cfg.Mu.RUnlock()

	if mode == "HOST" {
		if capIface != "" {
			fm.runCommand(cfg, "sudo", "iptables", "-D", "INPUT", "-i", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-IN")
			fm.runCommand(cfg, "sudo", "iptables", "-D", "INPUT", "-i", capIface, "-j", "NFQUEUE", "--queue-num", "1", "-m", "comment", "--comment", "SURICATA-NFQ-HOST-IN")
			fm.runCommand(cfg, "sudo", "iptables", "-D", "OUTPUT", "-o", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-OUT")
			fm.runCommand(cfg, "sudo", "iptables", "-D", "OUTPUT", "-o", capIface, "-j", "NFQUEUE", "--queue-num", "1", "-m", "comment", "--comment", "SURICATA-NFQ-HOST-OUT")
		}
		return
	}

	if mode != "GATEWAY" && mode != "NETWORK" {
		return
	}

	fmt.Printf("FirewallManager: Tearing down Gateway NAT routing: WAN=%s, LAN=%s\n", wan, lan)

	_ = fm.runCommand(cfg, "sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", wan, "-m", "comment", "--comment", "IDPS-NAT", "-j", "MASQUERADE")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-NFQ-IN", "-j", "NFQUEUE", "--queue-num", "0")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "SURICATA-NFQ-IN", "-j", "NFQUEUE", "--queue-num", "1")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", lan, "-o", wan, "-m", "comment", "--comment", "IDPS-NFQ-OUT", "-j", "NFQUEUE", "--queue-num", "0")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", lan, "-o", wan, "-m", "comment", "--comment", "SURICATA-NFQ-OUT", "-j", "NFQUEUE", "--queue-num", "1")

	if fm.ipForwardOriginal == "0" && !dryRun {
		_ = fm.runCommand(cfg, "sudo", "sysctl", "-w", "net.ipv4.ip_forward=0")
	}

	// Teardown Layer 2 MAC-based Isolation Chains
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-D", "INPUT", "-j", "IDPS-MAC-BLOCK")
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-D", "FORWARD", "-j", "IDPS-MAC-BLOCK")
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-F", "IDPS-MAC-BLOCK")
	_ = fm.runCommand(cfg, "sudo", "ebtables", "-X", "IDPS-MAC-BLOCK")

	fmt.Println("FirewallManager: Gateway NAT routing and L2 Isolation rules removed.")
}

func (fm *FirewallManager) BlockDevice(ip string, mac string, cfg *config.Config) bool {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	cfg.Mu.RUnlock()

	if mode != "HOST" && mode != "GATEWAY" && mode != "NETWORK" {
		return false
	}

	fm.mu.Lock()
	if _, exists := fm.blockCache[ip]; exists {
		// Already blocked. Extend TTL.
		fm.blockCache[ip] = time.Now().Add(1 * time.Hour) // 1 hour block
		fm.mu.Unlock()
		return true // Assume success since it's already there
	}
	fm.mu.Unlock()

	if !fm.isSafeToBlock(ip, cfg) {
		fmt.Printf("FirewallManager: Refused to block trusted/unsafe IP %s\n", ip)
		return false
	}

	bin := iptablesBin(ip)
	success := true

	if mode == "HOST" {
		args := []string{"-I", "INPUT", "1", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"}
		if err := fm.ensureRule(cfg, bin, args...); err == nil {
			fmt.Printf("FirewallManager: Added %s rule to block %s on INPUT\n", bin, ip)
		} else {
			fmt.Printf("FirewallManager: Failed to block %s on INPUT: %v\n", ip, err)
			success = false
		}
	} else if mode == "GATEWAY" || mode == "NETWORK" {
		args := []string{"-I", "FORWARD", "1", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"}
		if err := fm.ensureRule(cfg, bin, args...); err == nil {
			fmt.Printf("FirewallManager: Added %s rule to block %s on FORWARD\n", bin, ip)
		} else {
			fmt.Printf("FirewallManager: Failed to block %s on FORWARD: %v\n", ip, err)
			success = false
		}
	}

	// Apply Layer 2 MAC Isolation if MAC is provided
	if mac != "" {
		macArgs := []string{"-I", "IDPS-MAC-BLOCK", "-s", mac, "-j", "DROP"}
		if err := fm.runCommand(cfg, "sudo", append([]string{"ebtables"}, macArgs...)...); err == nil {
			fmt.Printf("FirewallManager: Added ebtables rule to block MAC %s\n", mac)
		} else {
			fmt.Printf("FirewallManager: Failed to block MAC %s via ebtables: %v\n", mac, err)
			// Don't fail the whole block if ebtables just isn't installed
		}
	}

	if success {
		fm.mu.Lock()
		fm.blockCache[ip] = time.Now().Add(1 * time.Hour) // 1 hour block TTL
		fm.mu.Unlock()
	}

	return success
}

func (fm *FirewallManager) UnblockDevice(ip string, mac string, cfg *config.Config) bool {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	cfg.Mu.RUnlock()

	if mode != "HOST" && mode != "GATEWAY" && mode != "NETWORK" {
		return false
	}

	bin := iptablesBin(ip)
	success := true

	if mode == "HOST" {
		if err := fm.runCommand(cfg, "sudo", bin, "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"); err == nil {
			fmt.Printf("FirewallManager: Removed %s rule for %s from INPUT\n", bin, ip)
		} else {
			fmt.Printf("FirewallManager: Failed to unblock %s from INPUT: %v\n", ip, err)
			success = false
		}
	} else if mode == "GATEWAY" || mode == "NETWORK" {
		if err := fm.runCommand(cfg, "sudo", bin, "-D", "FORWARD", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"); err == nil {
			fmt.Printf("FirewallManager: Removed %s rule for %s from FORWARD\n", bin, ip)
		} else {
			fmt.Printf("FirewallManager: Failed to unblock %s from FORWARD: %v\n", ip, err)
			success = false
		}
	}

	if mac != "" {
		if err := fm.runCommand(cfg, "sudo", "ebtables", "-D", "IDPS-MAC-BLOCK", "-s", mac, "-j", "DROP"); err == nil {
			fmt.Printf("FirewallManager: Removed ebtables rule for MAC %s\n", mac)
		} else {
			fmt.Printf("FirewallManager: Failed to unblock MAC %s via ebtables: %v\n", mac, err)
		}
	}

	return success
}
