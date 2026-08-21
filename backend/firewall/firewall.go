package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"idps-backend/config"
)

type FirewallManager struct {
	trustedIPs        []string
	ipForwardOriginal string
}

func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		trustedIPs: []string{"127.0.0.1", "::1"},
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
	cfg.Mu.RUnlock()

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

	// FORWARD WAN -> LAN (established/related)
	err = fm.ensureRule(cfg, "iptables", "-A", "FORWARD", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-FWD-IN", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to configure WAN->LAN forwarding: %v", err)
	}

	// FORWARD LAN -> WAN
	err = fm.ensureRule(cfg, "iptables", "-A", "FORWARD", "-i", lan, "-o", wan, "-m", "comment", "--comment", "IDPS-FWD-OUT", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to configure LAN->WAN forwarding: %v", err)
	}

	fmt.Println("FirewallManager: Gateway NAT routing configured successfully.")
	return nil
}

func (fm *FirewallManager) TeardownGateway(cfg *config.Config) {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	wan := cfg.WanInterface
	lan := cfg.LanInterface
	dryRun := cfg.FirewallDryRun
	cfg.Mu.RUnlock()

	if mode != "GATEWAY" && mode != "NETWORK" {
		return
	}

	fmt.Printf("FirewallManager: Tearing down Gateway NAT routing: WAN=%s, LAN=%s\n", wan, lan)

	_ = fm.runCommand(cfg, "sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", wan, "-m", "comment", "--comment", "IDPS-NAT", "-j", "MASQUERADE")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-FWD-IN", "-j", "ACCEPT")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", lan, "-o", wan, "-m", "comment", "--comment", "IDPS-FWD-OUT", "-j", "ACCEPT")

	if fm.ipForwardOriginal == "0" && !dryRun {
		_ = fm.runCommand(cfg, "sudo", "sysctl", "-w", "net.ipv4.ip_forward=0")
	}

	fmt.Println("FirewallManager: Gateway NAT routing rules removed.")
}

func (fm *FirewallManager) BlockIP(ip string, cfg *config.Config) bool {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	cfg.Mu.RUnlock()

	if mode != "HOST" && mode != "GATEWAY" && mode != "NETWORK" {
		return false
	}

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

	return success
}

func (fm *FirewallManager) UnblockIP(ip string, cfg *config.Config) bool {
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

	return success
}
