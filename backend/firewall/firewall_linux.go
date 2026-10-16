//go:build linux

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"idps-backend/config"
)

type linuxFirewall struct {
	ipForwardOriginal string
}

func newPlatformFirewall() PlatformFirewall {
	return &linuxFirewall{}
}

func (f *linuxFirewall) Name() string {
	return "Linux Netfilter (iptables/ebtables)"
}

func iptablesBin(ip string) string {
	if strings.Contains(ip, ":") {
		return "ip6tables"
	}
	return "iptables"
}

func runCmd(cfg *config.Config, name string, args ...string) error {
	if cfg != nil {
		cfg.Mu.RLock()
		dryRun := cfg.FirewallDryRun
		cfg.Mu.RUnlock()

		if dryRun {
			fmt.Printf("[DRY RUN] Would execute: %s %s\n", name, strings.Join(args, " "))
			return nil
		}
	}
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func (f *linuxFirewall) ruleExists(cfg *config.Config, bin string, args ...string) bool {
	if cfg != nil {
		cfg.Mu.RLock()
		dryRun := cfg.FirewallDryRun
		cfg.Mu.RUnlock()

		if dryRun {
			return false
		}
	}

	var checkArgs []string
	if len(args) > 0 && args[0] == "-I" && len(args) > 2 {
		checkArgs = append([]string{"-C", args[1]}, args[3:]...)
	} else if len(args) > 0 && args[0] == "-A" {
		checkArgs = append([]string{"-C"}, args[1:]...)
	} else {
		checkArgs = append([]string{"-C"}, args...)
	}

	cmd := exec.Command("sudo", append([]string{bin}, checkArgs...)...)
	return cmd.Run() == nil
}

func (f *linuxFirewall) ApplyBlock(ip, mac string, cfg *config.Config) error {
	mode := "GATEWAY"
	if cfg != nil {
		cfg.Mu.RLock()
		mode = cfg.IDPSDeploymentMode
		cfg.Mu.RUnlock()
	}

	bin := iptablesBin(ip)
	var err error

	if mode == "HOST" {
		args := []string{"-I", "INPUT", "1", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"}
		if !f.ruleExists(cfg, bin, args...) {
			err = runCmd(cfg, "sudo", append([]string{bin}, args...)...)
		}
	} else {
		args := []string{"-I", "FORWARD", "1", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP"}
		if !f.ruleExists(cfg, bin, args...) {
			err = runCmd(cfg, "sudo", append([]string{bin}, args...)...)
		}
	}

	if mac != "" {
		macArgs := []string{"-I", "IDPS-MAC-BLOCK", "-s", mac, "-j", "DROP"}
		_ = runCmd(cfg, "sudo", append([]string{"ebtables"}, macArgs...)...)
	}

	return err
}

func (f *linuxFirewall) VerifyBlock(ip string, cfg *config.Config) bool {
	mode := "GATEWAY"
	if cfg != nil {
		cfg.Mu.RLock()
		dryRun := cfg.FirewallDryRun
		mode = cfg.IDPSDeploymentMode
		cfg.Mu.RUnlock()

		if dryRun {
			return true
		}
	}

	bin := iptablesBin(ip)
	chain := "INPUT"
	if mode != "HOST" {
		chain = "FORWARD"
	}

	cmd := exec.Command("sudo", bin, "-C", chain, "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP")
	return cmd.Run() == nil
}

func (f *linuxFirewall) RemoveBlock(ip, mac string, cfg *config.Config) error {
	bin := iptablesBin(ip)
	_ = runCmd(cfg, "sudo", bin, "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP")
	_ = runCmd(cfg, "sudo", bin, "-D", "FORWARD", "-s", ip, "-m", "comment", "--comment", "IDPS-BLOCK", "-j", "DROP")

	if mac != "" {
		_ = runCmd(cfg, "sudo", "ebtables", "-D", "IDPS-MAC-BLOCK", "-s", mac, "-j", "DROP")
	}
	return nil
}

func (f *linuxFirewall) SetupGateway(cfg *config.Config) error {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	wan := cfg.WanInterface
	lan := cfg.LanInterface
	dryRun := cfg.FirewallDryRun
	capIface := cfg.CaptureInterface
	cfg.Mu.RUnlock()

	if mode == "HOST" {
		if capIface != "" {
			_ = runCmd(cfg, "sudo", "iptables", "-I", "INPUT", "1", "-i", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-IN")
			_ = runCmd(cfg, "sudo", "iptables", "-I", "OUTPUT", "1", "-o", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-OUT")
		}
		return nil
	}

	if mode != "GATEWAY" && mode != "NETWORK" {
		return nil
	}

	if wan == "" || lan == "" {
		return fmt.Errorf("WAN or LAN interface is not specified")
	}

	if !dryRun {
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err == nil {
			f.ipForwardOriginal = strings.TrimSpace(string(b))
		}
		_ = runCmd(cfg, "sudo", "sysctl", "-w", "net.ipv4.ip_forward=1")
	}

	_ = runCmd(cfg, "sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan, "-m", "comment", "--comment", "IDPS-NAT", "-j", "MASQUERADE")
	_ = runCmd(cfg, "sudo", "iptables", "-I", "FORWARD", "1", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-NFQ-IN", "-j", "NFQUEUE", "--queue-num", "0")
	_ = runCmd(cfg, "sudo", "iptables", "-I", "FORWARD", "2", "-i", lan, "-o", wan, "-m", "comment", "--comment", "IDPS-NFQ-OUT", "-j", "NFQUEUE", "--queue-num", "0")

	// L2 chain setup
	_ = runCmd(cfg, "sudo", "ebtables", "-N", "IDPS-MAC-BLOCK")
	_ = runCmd(cfg, "sudo", "ebtables", "-I", "INPUT", "-j", "IDPS-MAC-BLOCK")
	_ = runCmd(cfg, "sudo", "ebtables", "-I", "FORWARD", "-j", "IDPS-MAC-BLOCK")

	return nil
}

func (f *linuxFirewall) TeardownGateway(cfg *config.Config) error {
	cfg.Mu.RLock()
	mode := cfg.IDPSDeploymentMode
	wan := cfg.WanInterface
	lan := cfg.LanInterface
	dryRun := cfg.FirewallDryRun
	capIface := cfg.CaptureInterface
	cfg.Mu.RUnlock()

	if mode == "HOST" {
		if capIface != "" {
			_ = runCmd(cfg, "sudo", "iptables", "-D", "INPUT", "-i", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-IN")
			_ = runCmd(cfg, "sudo", "iptables", "-D", "OUTPUT", "-o", capIface, "-j", "NFQUEUE", "--queue-num", "0", "-m", "comment", "--comment", "IDPS-NFQ-HOST-OUT")
		}
		return nil
	}

	if mode != "GATEWAY" && mode != "NETWORK" {
		return nil
	}

	_ = runCmd(cfg, "sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", wan, "-m", "comment", "--comment", "IDPS-NAT", "-j", "MASQUERADE")
	_ = runCmd(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", wan, "-o", lan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "IDPS-NFQ-IN", "-j", "NFQUEUE", "--queue-num", "0")
	_ = runCmd(cfg, "sudo", "iptables", "-D", "FORWARD", "-i", lan, "-o", wan, "-m", "comment", "--comment", "IDPS-NFQ-OUT", "-j", "NFQUEUE", "--queue-num", "0")

	if f.ipForwardOriginal == "0" && !dryRun {
		_ = runCmd(cfg, "sudo", "sysctl", "-w", "net.ipv4.ip_forward=0")
	}

	_ = runCmd(cfg, "sudo", "ebtables", "-D", "INPUT", "-j", "IDPS-MAC-BLOCK")
	_ = runCmd(cfg, "sudo", "ebtables", "-D", "FORWARD", "-j", "IDPS-MAC-BLOCK")
	_ = runCmd(cfg, "sudo", "ebtables", "-F", "IDPS-MAC-BLOCK")
	_ = runCmd(cfg, "sudo", "ebtables", "-X", "IDPS-MAC-BLOCK")

	return nil
}
