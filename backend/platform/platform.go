package platform

import (
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// Info holds host system information and IDPS driver capabilities.
type Info struct {
	OS               string   `json:"os"`
	Arch             string   `json:"arch"`
	Hostname         string   `json:"hostname"`
	IsElevated       bool     `json:"is_elevated"` // root on Linux, Administrator on Windows
	HasPacketDriver  bool     `json:"has_packet_driver"` // AF_PACKET/NFQueue on Linux, Npcap on Windows
	DriverName       string   `json:"driver_name"`
	FirewallBackend  string   `json:"firewall_backend"` // iptables/ebtables on Linux, Windows Firewall/WFP on Windows
	SupportedModes   []string `json:"supported_modes"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	StartedAt        time.Time `json:"started_at"`
}

// Telemetry captures live real-time OS resource metrics.
type Telemetry struct {
	CPUUsagePercent  float64 `json:"cpu_usage_percent"`
	MemoryUsedMB     uint64  `json:"memory_used_mb"`
	MemoryTotalMB    uint64  `json:"memory_total_mb"`
	MemoryPercent    float64 `json:"memory_percent"`
	UptimeSeconds    uint64  `json:"uptime_seconds"`
	GoroutineCount   int     `json:"goroutine_count"`
}

var (
	systemInfo     Info
	systemInfoOnce sync.Once
	startTime      = time.Now()
)

// GetInfo returns the static and capability info for the current host.
func GetInfo() Info {
	systemInfoOnce.Do(func() {
		hostname, _ := os.Hostname()
		systemInfo = Info{
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			Hostname:  hostname,
			StartedAt: startTime,
		}
		detectCapabilities(&systemInfo)
	})
	return systemInfo
}

// GetTelemetry fetches live CPU, memory, and uptime metrics.
func GetTelemetry() Telemetry {
	t := Telemetry{
		GoroutineCount: runtime.NumGoroutine(),
		UptimeSeconds:  uint64(time.Since(startTime).Seconds()),
	}

	if v, err := mem.VirtualMemory(); err == nil {
		t.MemoryUsedMB = v.Used / (1024 * 1024)
		t.MemoryTotalMB = v.Total / (1024 * 1024)
		t.MemoryPercent = v.UsedPercent
	}

	if c, err := cpu.Percent(0, false); err == nil && len(c) > 0 {
		t.CPUUsagePercent = c[0]
	}

	return t
}
