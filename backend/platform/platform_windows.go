//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func isWindowsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

func detectCapabilities(info *Info) {
	info.IsElevated = isWindowsAdmin()
	if !info.IsElevated {
		info.Errors = append(info.Errors, "Running without Administrator privileges. Windows packet filtering and firewall control require 'Run as Administrator'.")
	}

	// Check for Npcap / WinPcap installation
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	npcapDll := filepath.Join(sysRoot, "System32", "Npcap", "wpcap.dll")
	sysDll := filepath.Join(sysRoot, "System32", "wpcap.dll")

	hasNpcap := false
	if _, err := os.Stat(npcapDll); err == nil {
		hasNpcap = true
	} else if _, err := os.Stat(sysDll); err == nil {
		hasNpcap = true
	}

	info.HasPacketDriver = hasNpcap
	if hasNpcap {
		info.DriverName = "Npcap OEM / WinPcap Driver"
		info.SupportedModes = []string{"HOST", "NETWORK"}
	} else {
		info.DriverName = "Windows Sockets (Fallback / Raw Socket)"
		info.Warnings = append(info.Warnings, "Npcap driver is not installed. For promiscuous and deep packet capture on Windows, download and install Npcap from https://npcap.com with 'WinPcap API-compatible Mode' enabled.")
		info.SupportedModes = []string{"HOST"}
	}

	// Windows Firewall Backend
	if _, err := exec.LookPath("netsh.exe"); err == nil {
		info.FirewallBackend = "Windows Defender Firewall (netsh advfirewall & PowerShell NetSecurity)"
	} else {
		info.FirewallBackend = "Windows Filtering Platform (WFP)"
	}
}
