package config

import (
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	IDPSDeploymentMode      string
	IDPSSecurityMode        string
	WanInterface            string
	LanInterface            string
	CaptureInterface        string
	Interface               string // Deprecated, kept for backwards compatibility
	ApiHost                 string
	FirewallDryRun          bool
	SuspiciousRateThreshold int
	PortScanThreshold       int
	ICMPFloodThreshold      int
	UDPFloodThreshold       int
	SYNFloodThreshold       int
	SSHBruteForceThreshold  int
	BlockTTLSeconds         int
	GatewayIP               string
	WorkerCount             int
}

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
		} else if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "enx") || strings.HasPrefix(name, "enp") {
			if wan == "" {
				wan = name
			}
		}
	}
	return wan, lan
}

func Load() *Config {
	_ = godotenv.Load() // Ignore error if .env doesn't exist

	autoWan, autoLan := DiscoverInterfaces()

	cfg := &Config{
		IDPSDeploymentMode:      getEnv("IDPS_DEPLOYMENT_MODE", "HOST"), // HOST or NETWORK
		IDPSSecurityMode:        getEnv("IDPS_SECURITY_MODE", "IDS"),    // IDS or IPS
		WanInterface:            getEnv("WAN_INTERFACE", autoWan),
		LanInterface:            getEnv("LAN_INTERFACE", autoLan),
		ApiHost:                 getEnv("API_HOST", "127.0.0.1"),
		FirewallDryRun:          getEnvBool("FIREWALL_DRY_RUN", false),
		SuspiciousRateThreshold: getEnvInt("SUSPICIOUS_RATE_THRESHOLD", 500),
		PortScanThreshold:       getEnvInt("PORT_SCAN_THRESHOLD", 20),
		ICMPFloodThreshold:      getEnvInt("ICMP_FLOOD_THRESHOLD", 100),
		UDPFloodThreshold:       getEnvInt("UDP_FLOOD_THRESHOLD", 200),
		SYNFloodThreshold:       getEnvInt("SYN_FLOOD_THRESHOLD", 150),
		SSHBruteForceThreshold:  getEnvInt("SSH_BRUTE_FORCE_THRESHOLD", 10),
		BlockTTLSeconds:         getEnvInt("BLOCK_TTL_SECONDS", 600),
		GatewayIP:               getEnv("GATEWAY_IP", ""),
		WorkerCount:             getEnvInt("WORKER_COUNT", runtime.NumCPU()),
	}

	cfg.Interface = getEnv("INTERFACE", cfg.LanInterface)
	cfg.CaptureInterface = getEnv("CAPTURE_INTERFACE", cfg.LanInterface)
	if cfg.CaptureInterface == "" {
		cfg.CaptureInterface = cfg.Interface
	}

	return cfg
}

func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if valStr, exists := os.LookupEnv(key); exists {
		if val, err := strconv.Atoi(valStr); err == nil {
			return val
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if valStr, exists := os.LookupEnv(key); exists {
		val, err := strconv.ParseBool(valStr)
		if err == nil {
			return val
		}
	}
	return defaultVal
}
