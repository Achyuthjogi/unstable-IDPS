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
	if cfg != nil && cfg.GatewayIP != "" && ip == cfg.GatewayIP {
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

func (fm *FirewallManager) runCommand(cfg *config.Config, name string, args ...string) error {
	if cfg.FirewallDryRun {
		fmt.Printf("[DRY RUN] Would execute: %s %s\n", name, strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func (fm *FirewallManager) ruleExists(cfg *config.Config, args ...string) bool {
	if cfg.FirewallDryRun {
		return false
	}
	checkArgs := append([]string{"-C"}, args[1:]...) // Replace -A/-I with -C
	cmd := exec.Command("sudo", append([]string{"iptables"}, checkArgs...)...)
	return cmd.Run() == nil
}

func (fm *FirewallManager) ensureRule(cfg *config.Config, args ...string) error {
	if !fm.ruleExists(cfg, args...) {
		return fm.runCommand(cfg, "sudo", append([]string{"iptables"}, args...)...)
	}
	return nil
}

func (fm *FirewallManager) SetupGateway(cfg *config.Config) error {
	if cfg.IDPSDeploymentMode != "GATEWAY" && cfg.IDPSDeploymentMode != "NETWORK" {
		return nil
	}

	fmt.Printf("FirewallManager: Setting up Gateway NAT routing: WAN=%s, LAN=%s\n", cfg.WanInterface, cfg.LanInterface)

	if cfg.WanInterface == "" || cfg.LanInterface == "" {
		return fmt.Errorf("WAN or LAN interface is not specified")
	}
	if cfg.WanInterface == cfg.LanInterface {
		return fmt.Errorf("WAN and LAN interfaces cannot be the same")
	}

	// Validate interfaces exist
	if _, err := net.InterfaceByName(cfg.WanInterface); err != nil && !cfg.FirewallDryRun {
		return fmt.Errorf("WAN interface %s not found: %v", cfg.WanInterface, err)
	}
	if _, err := net.InterfaceByName(cfg.LanInterface); err != nil && !cfg.FirewallDryRun {
		return fmt.Errorf("LAN interface %s not found: %v", cfg.LanInterface, err)
	}

	if !cfg.FirewallDryRun {
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err == nil {
			fm.ipForwardOriginal = strings.TrimSpace(string(b))
		}
	}

	if err := fm.runCommand(cfg, "sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("failed to enable ipv4 forwarding: %v", err)
	}

	if !cfg.FirewallDryRun {
		b, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if strings.TrimSpace(string(b)) != "1" {
			return fmt.Errorf("IPv4 forwarding is not enabled (read %s)", string(b))
		}
	}

	// NAT Rule
	err := fm.ensureRule(cfg, "-t", "nat", "-A", "POSTROUTING", "-o", cfg.WanInterface, "-m", "comment", "--comment", "IDPS-NAT", "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to configure NAT: %v", err)
	}

	// FORWARD WAN -> LAN (established/related)
	err = fm.ensureRule(cfg, "-A", "FORWARD", "-i", cfg.WanInterface, "-o", cfg.LanInterface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-FWD-IN", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to configure WAN->LAN forwarding: %v", err)
	}

	// FORWARD LAN -> WAN
	err = fm.ensureRule(cfg, "-A", "FORWARD", "-i", cfg.LanInterface, "-o", cfg.WanInterface, "-m", "comment", "--comment", "IDPS-FWD-OUT", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to configure LAN->WAN forwarding: %v", err)
	}

	fmt.Println("FirewallManager: Gateway NAT routing configured successfully.")
	return nil
}

func (fm *FirewallManager) TeardownGateway(cfg *config.Config) {
	if cfg.IDPSDeploymentMode != "GATEWAY" && cfg.IDPSDeploymentMode != "NETWORK" {
		return
	}

	fmt.Printf("FirewallManager: Tearing down Gateway NAT routing: WAN=%s, LAN=%s\n", cfg.WanInterface, cfg.LanInterface)

	_ = fm.runCommand(cfg, "sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", cfg.WanInterface, "-m", "comment", "--comment", "IDPS-NAT", "-j", "MASQUERADE")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", cfg.WanInterface, "-o", cfg.LanInterface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-FWD-IN", "-j", "ACCEPT")
	_ = fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", cfg.LanInterface, "-o", cfg.WanInterface, "-m", "comment", "--comment", "IDPS-FWD-OUT", "-j", "ACCEPT")

	if fm.ipForwardOriginal == "0" && !cfg.FirewallDryRun {
		_ = fm.runCommand(cfg, "sudo", "sysctl", "-w", "net.ipv4.ip_forward=0")
	}

	fmt.Println("FirewallManager: Gateway NAT routing rules removed.")
}

func (fm *FirewallManager) BlockIP(ip string, cfg *config.Config) bool {
	if !fm.isSafeToBlock(ip, cfg) {
		fmt.Printf("FirewallManager: Refused to block trusted/unsafe IP %s\n", ip)
		return false
	}

	success := true

	if cfg.IDPSDeploymentMode == "HOST" {
		args := []string{"-I", "INPUT", "1", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"}
		if err := fm.ensureRule(cfg, args...); err == nil {
			fmt.Printf("FirewallManager: Added Linux rule to block %s on INPUT\n", ip)
		} else {
			fmt.Printf("FirewallManager: Failed to block %s on INPUT: %v\n", ip, err)
			success = false
		}
	} else if cfg.IDPSDeploymentMode == "GATEWAY" || cfg.IDPSDeploymentMode == "NETWORK" {
		args := []string{"-I", "FORWARD", "1", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"}
		if err := fm.ensureRule(cfg, args...); err == nil {
			fmt.Printf("FirewallManager: Added Linux rule to block %s on FORWARD\n", ip)
		} else {
			fmt.Printf("FirewallManager: Failed to block %s on FORWARD: %v\n", ip, err)
			success = false
		}
	}

	return success
}

func (fm *FirewallManager) UnblockIP(ip string, cfg *config.Config) bool {
	success := true

	if cfg.IDPSDeploymentMode == "HOST" {
		if err := fm.runCommand(cfg, "sudo", "iptables", "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"); err == nil {
			fmt.Printf("FirewallManager: Removed Linux rule for %s from INPUT\n", ip)
		} else {
			fmt.Printf("FirewallManager: Failed to unblock %s from INPUT: %v\n", ip, err)
			success = false
		}
	} else if cfg.IDPSDeploymentMode == "GATEWAY" || cfg.IDPSDeploymentMode == "NETWORK" {
		if err := fm.runCommand(cfg, "sudo", "iptables", "-D", "FORWARD", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"); err == nil {
			fmt.Printf("FirewallManager: Removed Linux rule for %s from FORWARD\n", ip)
		} else {
			fmt.Printf("FirewallManager: Failed to unblock %s from FORWARD: %v\n", ip, err)
			success = false
		}
	}

	return success
}
