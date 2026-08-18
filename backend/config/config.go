package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	IDPSDeploymentMode      string
	IDPSSecurityMode        string
	WanInterface            string
	LanInterface            string
	Interface               string
	SuspiciousRateThreshold int
	PortScanThreshold       int
	ICMPFloodThreshold      int
	UDPFloodThreshold       int
	SYNFloodThreshold       int
	SSHBruteForceThreshold  int
	BlockTTLSeconds         int
}

func Load() *Config {
	_ = godotenv.Load() // Ignore error if .env doesn't exist

	return &Config{
		IDPSDeploymentMode:      getEnv("IDPS_DEPLOYMENT_MODE", "HOST"),
		IDPSSecurityMode:        getEnv("IDPS_SECURITY_MODE", "IDS"),
		WanInterface:            getEnv("WAN_INTERFACE", "enx2a7345453743"),
		LanInterface:            getEnv("LAN_INTERFACE", "wlp1s0"),
		Interface:               getEnv("INTERFACE", "wlp1s0"),
		SuspiciousRateThreshold: getEnvInt("SUSPICIOUS_RATE_THRESHOLD", 500),
		PortScanThreshold:       getEnvInt("PORT_SCAN_THRESHOLD", 20),
		ICMPFloodThreshold:      getEnvInt("ICMP_FLOOD_THRESHOLD", 100),
		UDPFloodThreshold:       getEnvInt("UDP_FLOOD_THRESHOLD", 200),
		SYNFloodThreshold:       getEnvInt("SYN_FLOOD_THRESHOLD", 150),
		SSHBruteForceThreshold:  getEnvInt("SSH_BRUTE_FORCE_THRESHOLD", 10),
		BlockTTLSeconds:         getEnvInt("BLOCK_TTL_SECONDS", 600),
	}
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
