package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"idps-backend/config"
)

type FirewallManager struct {
	trustedIPs []string
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
	
	// Check local interfaces
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

func (fm *FirewallManager) SetupGateway(cfg *config.Config) {
	if cfg.IDPSDeploymentMode != "GATEWAY" {
		return
	}

	fmt.Printf("FirewallManager: Setting up Gateway NAT routing: WAN=%s, LAN=%s\n", cfg.WanInterface, cfg.LanInterface)

	_ = exec.Command("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	_ = exec.Command("sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", cfg.WanInterface, "-j", "MASQUERADE").Run()
	_ = exec.Command("sudo", "iptables", "-A", "FORWARD", "-i", cfg.WanInterface, "-o", cfg.LanInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	_ = exec.Command("sudo", "iptables", "-A", "FORWARD", "-i", cfg.LanInterface, "-o", cfg.WanInterface, "-j", "ACCEPT").Run()

	fmt.Println("FirewallManager: Gateway NAT routing configured successfully.")
}

func (fm *FirewallManager) TeardownGateway(cfg *config.Config) {
	if cfg.IDPSDeploymentMode != "GATEWAY" {
		return
	}

	fmt.Printf("FirewallManager: Tearing down Gateway NAT routing: WAN=%s, LAN=%s\n", cfg.WanInterface, cfg.LanInterface)

	_ = exec.Command("sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", cfg.WanInterface, "-j", "MASQUERADE").Run()
	_ = exec.Command("sudo", "iptables", "-D", "FORWARD", "-i", cfg.WanInterface, "-o", cfg.LanInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	_ = exec.Command("sudo", "iptables", "-D", "FORWARD", "-i", cfg.LanInterface, "-o", cfg.WanInterface, "-j", "ACCEPT").Run()

	fmt.Println("FirewallManager: Gateway NAT routing rules removed.")
}

func (fm *FirewallManager) BlockIP(ip string, cfg *config.Config) bool {
	if !fm.isSafeToBlock(ip, cfg) {
		fmt.Printf("FirewallManager: Refused to block trusted/unsafe IP %s\n", ip)
		return false
	}

	success := true

	// INPUT chain
	cmdInput := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmdInput.Run(); err == nil {
		fmt.Printf("FirewallManager: Added Linux rule to block %s on INPUT\n", ip)
	} else {
		fmt.Printf("FirewallManager: Failed to block %s on INPUT: %v\n", ip, err)
		success = false
	}

	// FORWARD chain if gateway
	if cfg.IDPSDeploymentMode == "GATEWAY" {
		cmdFwd := exec.Command("sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP")
		if err := cmdFwd.Run(); err == nil {
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

	cmdInput := exec.Command("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmdInput.Run(); err == nil {
		fmt.Printf("FirewallManager: Removed Linux rule for %s from INPUT\n", ip)
	} else {
		fmt.Printf("FirewallManager: Failed to unblock %s from INPUT: %v\n", ip, err)
		success = false
	}

	if cfg.IDPSDeploymentMode == "GATEWAY" {
		cmdFwd := exec.Command("sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP")
		if err := cmdFwd.Run(); err == nil {
			fmt.Printf("FirewallManager: Removed Linux rule for %s from FORWARD\n", ip)
		} else {
			fmt.Printf("FirewallManager: Failed to unblock %s from FORWARD: %v\n", ip, err)
			success = false
		}
	}

	return success
}
