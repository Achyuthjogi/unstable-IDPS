//go:build linux

package platform

import (
	"os"
	"os/exec"
)

func detectCapabilities(info *Info) {
	info.IsElevated = (os.Geteuid() == 0)
	if !info.IsElevated {
		info.Errors = append(info.Errors, "Running without root privileges. Raw packet capture and iptables manipulation require sudo/root.")
	}

	info.HasPacketDriver = true
	info.DriverName = "Linux AF_PACKET & NFQueue (Inline Netfilter)"
	info.FirewallBackend = "iptables & ebtables (Netfilter)"
	info.SupportedModes = []string{"HOST", "GATEWAY", "NETWORK"}

	if _, err := exec.LookPath("iptables"); err != nil {
		info.Warnings = append(info.Warnings, "iptables binary not found in PATH; firewall enforcement may fail")
	}
	if _, err := exec.LookPath("ebtables"); err != nil {
		info.Warnings = append(info.Warnings, "ebtables binary not found in PATH; Layer 2 bridge isolation disabled")
	}
}
