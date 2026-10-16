//go:build linux

package config

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// DiscoverInterfaces finds active network adapters on Linux.
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
		name := i.Name
		if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wlp") {
			if lan == "" {
				lan = name
			}
		} else if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "enx") || strings.HasPrefix(name, "enp") || strings.HasPrefix(name, "usb") {
			if wan == "" {
				wan = name
			}
		}
	}
	return wan, lan
}

// DiscoverGatewayIP parses /proc/net/route on Linux to locate the default gateway.
func DiscoverGatewayIP() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "00000000" {
			gwHex := fields[2]
			if len(gwHex) == 8 {
				ipBytes, err := hex.DecodeString(gwHex)
				if err == nil {
					// Little-endian format
					ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
					return ip.String()
				}
			}
		}
	}
	return ""
}
