//go:build windows

package config

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strings"
)

// DiscoverInterfaces finds active network adapters on Windows.
func DiscoverInterfaces() (string, string) {
	var wan, lan string
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}

	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		name := i.Name
		lowerName := strings.ToLower(name)
		if strings.Contains(lowerName, "wi-fi") || strings.Contains(lowerName, "wireless") || strings.Contains(lowerName, "wlan") {
			if lan == "" {
				lan = name
			}
		} else if strings.Contains(lowerName, "ethernet") || strings.Contains(lowerName, "local area") {
			if wan == "" {
				wan = name
			}
		} else if wan == "" {
			wan = name
		}
	}
	return wan, lan
}

// DiscoverGatewayIP discovers default gateway on Windows using 'route print 0.0.0.0'.
func DiscoverGatewayIP() string {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inTable := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Network Destination") {
			inTable = true
			continue
		}
		if inTable && strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			// Format: 0.0.0.0 0.0.0.0 Gateway Interface Metric
			if len(fields) >= 3 {
				gw := fields[2]
				if ip := net.ParseIP(gw); ip != nil && !ip.IsUnspecified() {
					return gw
				}
			}
		}
	}
	return ""
}
