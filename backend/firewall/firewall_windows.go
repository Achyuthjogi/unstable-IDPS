//go:build windows

package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"idps-backend/config"
)

type windowsFirewall struct{}

func newPlatformFirewall() PlatformFirewall {
	return &windowsFirewall{}
}

func (f *windowsFirewall) Name() string {
	return "Windows Defender Firewall & WFP Adapter"
}

func (f *windowsFirewall) ruleName(ip string) string {
	return fmt.Sprintf("IDPS-BLOCK-%s", ip)
}

func (f *windowsFirewall) ApplyBlock(ip, mac string, cfg *config.Config) error {
	cfg.Mu.RLock()
	dryRun := cfg.FirewallDryRun
	cfg.Mu.RUnlock()

	rName := f.ruleName(ip)

	if dryRun {
		fmt.Printf("[DRY RUN Windows] Would execute: netsh advfirewall firewall add rule name=%s dir=in action=block remoteip=%s\n", rName, ip)
		return nil
	}

	// 1. Add Inbound Block Rule
	inCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s-IN", rName),
		"dir=in",
		"action=block",
		fmt.Sprintf("remoteip=%s", ip),
		"description=Nexus IDPS Automated Threat Block",
	)
	if out, err := inCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add inbound block for %s: %v (%s)", ip, err, strings.TrimSpace(string(out)))
	}

	// 2. Add Outbound Block Rule (prevents communication back to attacker)
	outCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s-OUT", rName),
		"dir=out",
		"action=block",
		fmt.Sprintf("remoteip=%s", ip),
		"description=Nexus IDPS Automated Threat Block",
	)
	_ = outCmd.Run()

	// 3. Flow Termination: Terminate existing active TCP connections with attacker IP
	f.terminateTCPConnections(ip)

	return nil
}

func (f *windowsFirewall) VerifyBlock(ip string, cfg *config.Config) bool {
	cfg.Mu.RLock()
	dryRun := cfg.FirewallDryRun
	cfg.Mu.RUnlock()

	if dryRun {
		return true
	}

	rName := fmt.Sprintf("%s-IN", f.ruleName(ip))
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", fmt.Sprintf("name=%s", rName))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Check if rule exists and has action Block
	outStr := string(out)
	return strings.Contains(outStr, rName) && (strings.Contains(outStr, "Block") || strings.Contains(outStr, "Bloquear"))
}

func (f *windowsFirewall) RemoveBlock(ip, mac string, cfg *config.Config) error {
	rName := f.ruleName(ip)
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-IN", rName)).Run()
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-OUT", rName)).Run()
	return nil
}

func (f *windowsFirewall) SetupGateway(cfg *config.Config) error {
	// On Windows, host defense is standard; if Internet Connection Sharing (ICS) is present, notify
	fmt.Println("Windows Firewall: Host protection active. Windows Defender Firewall integration enabled.")
	return nil
}

func (f *windowsFirewall) TeardownGateway(cfg *config.Config) error {
	return nil
}

// terminateTCPConnections closes any open TCP sessions with the blocked IP using PowerShell
func (f *windowsFirewall) terminateTCPConnections(ip string) {
	if ip == "127.0.0.1" || ip == "::1" || ip == "" {
		return
	}
	psScript := fmt.Sprintf(`$myPid = $PID; Get-NetTCPConnection -RemoteAddress "%s" -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -gt 4 -and $_.OwningProcess -ne $myPid -and (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -notmatch '(?i)idps|node|cmd|powershell|explorer|svchost|system' } | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }`, ip)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	_ = cmd.Run()
}
