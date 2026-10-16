package detection

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"idps-backend/alert"
	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/platform"
	"idps-backend/state"
)

// EveAlertDetail represents the inner alert object in Suricata eve.json
type EveAlertDetail struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
	Metadata    struct {
		AffectedProduct []string `json:"affected_product,omitempty"`
		AttackTarget    []string `json:"attack_target,omitempty"`
		Deployment      []string `json:"deployment,omitempty"`
	} `json:"metadata,omitempty"`
}

// EveStatsDetail captures Suricata engine telemetry metrics
type EveStatsDetail struct {
	Capture struct {
		KernelPackets int64 `json:"kernel_packets"`
		KernelDrops   int64 `json:"kernel_drops"`
	} `json:"capture"`
	Decoder struct {
		Pkts  int64 `json:"pkts"`
		Bytes int64 `json:"bytes"`
	} `json:"decoder"`
	Flow struct {
		Total  int64 `json:"total"`
		Active int64 `json:"active"`
	} `json:"flow"`
}

// EveEvent represents the full Suricata EVE JSON event structure
type EveEvent struct {
	Timestamp string          `json:"timestamp"`
	FlowID    int64           `json:"flow_id,omitempty"`
	InIface   string          `json:"in_iface,omitempty"`
	EventType string          `json:"event_type"`
	SrcIP     string          `json:"src_ip"`
	SrcPort   uint16          `json:"src_port"`
	DestIP    string          `json:"dest_ip"`
	DestPort  uint16          `json:"dest_port"`
	Proto     string          `json:"proto"`
	AppProto  string          `json:"app_proto,omitempty"`
	Alert     *EveAlertDetail `json:"alert,omitempty"`
	Stats     *EveStatsDetail `json:"stats,omitempty"`
	Payload   string          `json:"payload,omitempty"`
	Drop      map[string]any  `json:"drop,omitempty"`
}

// GetSuricataEvePath dynamically resolves the Suricata eve.json log location across Linux and Windows
func GetSuricataEvePath(cfg *config.Config) string {
	if cfg != nil && cfg.SuricataEvePath != "" {
		if _, err := os.Stat(cfg.SuricataEvePath); err == nil {
			return cfg.SuricataEvePath
		}
	}
	if envPath := os.Getenv("SURICATA_EVE_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
	}

	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{
			`C:\Program Files\Suricata\log\eve.json`,
			`C:\Program Files (x86)\Suricata\log\eve.json`,
			`C:\Suricata\log\eve.json`,
			`C:\ProgramData\Suricata\log\eve.json`,
			filepath.Join(os.Getenv("USERPROFILE"), `AppData\Local\Suricata\log\eve.json`),
			`.\eve.json`,
		}
	} else {
		candidates = []string{
			"/var/log/suricata/eve.json",
			"/var/log/suricata/eve-alerts.json",
			"/usr/local/var/log/suricata/eve.json",
			"/etc/suricata/eve.json",
			"./eve.json",
		}
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Fallback default path for the current OS
	if runtime.GOOS == "windows" {
		return `C:\Program Files\Suricata\log\eve.json`
	}
	return "/var/log/suricata/eve.json"
}

// FindSuricataBinary locates the Suricata executable on Linux or Windows
func FindSuricataBinary(cfg *config.Config) string {
	if cfg != nil && cfg.SuricataBinaryPath != "" {
		if _, err := exec.LookPath(cfg.SuricataBinaryPath); err == nil {
			return cfg.SuricataBinaryPath
		}
	}

	binName := "suricata"
	if runtime.GOOS == "windows" {
		binName = "suricata.exe"
		candidates := []string{
			`C:\Program Files\Suricata\suricata.exe`,
			`C:\Program Files (x86)\Suricata\suricata.exe`,
			`C:\Suricata\suricata.exe`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}

	if path, err := exec.LookPath(binName); err == nil {
		return path
	}
	return ""
}

// StartSuricataSupervisor ensures the Suricata engine process is running on the target OS
func StartSuricataSupervisor(cfg *config.Config) {
	bin := FindSuricataBinary(cfg)
	if bin == "" {
		fmt.Printf("[Suricata Engine] Warning: Suricata executable not found in PATH or standard directories.\n")
		fmt.Printf("                  Please install Suricata or configure SURICATA_BINARY_PATH.\n")
		return
	}

	// Choose interface to inspect
	iface := cfg.LanInterface
	if iface == "" {
		iface = cfg.Interface
	}
	if iface == "" && runtime.GOOS == "linux" {
		iface = "eth0"
	}

	fmt.Printf("[Suricata Engine] Primary DPI Engine: %s on interface '%s'\n", bin, iface)

	// In production, Suricata is often managed via systemd (Linux) or Windows Service (Windows).
	// If it's already running, we don't need to spawn a duplicate process.
	if isProcessRunning("suricata") {
		fmt.Printf("[Suricata Engine] Active Suricata daemon detected.\n")
		return
	}

	// Launch Suricata in background if not already running
	var args []string
	if runtime.GOOS == "windows" {
		if cfg.SuricataConfigPath != "" {
			args = []string{"-c", cfg.SuricataConfigPath, "-i", iface}
		} else {
			args = []string{"-i", iface}
		}
	} else {
		if cfg.SuricataConfigPath != "" {
			args = []string{"-c", cfg.SuricataConfigPath, "-i", iface, "-D"}
		} else if _, err := os.Stat("/etc/suricata/suricata.yaml"); err == nil {
			args = []string{"-c", "/etc/suricata/suricata.yaml", "-i", iface, "-D"}
		} else {
			args = []string{"-i", iface, "-D"}
		}
	}

	cmd := exec.Command(bin, args...)
	if err := cmd.Start(); err != nil {
		fmt.Printf("[Suricata Engine] Note: Could not auto-spawn Suricata process (%v). Relying on external daemon.\n", err)
	} else {
		fmt.Printf("[Suricata Engine] Spawned Suricata process (PID: %d)\n", cmd.Process.Pid)
	}
}

func isProcessRunning(name string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist")
	} else {
		cmd = exec.Command("pgrep", "-x", name)
	}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(name))
}

// StartSuricataPrimaryEngine connects to Suricata's EVE JSON output stream,
// ingests real-time DPI alerts, drops, and flow stats, and enforces verified prevention.
func StartSuricataPrimaryEngine(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, alertLogger *alert.Logger) {
	fmt.Println("======================================================")
	fmt.Printf("Suricata Primary Engine : ACTIVE (Platform: %s)\n", platform.GetInfo().OS)
	fmt.Println("Suricata Role           : Primary Deep Packet Inspection & IPS")
	fmt.Println("======================================================")

	// Attempt to start/verify Suricata daemon
	StartSuricataSupervisor(cfg)

	evePath := GetSuricataEvePath(cfg)
	fmt.Printf("[Suricata Engine] Monitoring EVE event stream: %s\n", evePath)

	var file *os.File
	var err error

	// Wait for eve.json to be created by Suricata
	retryCount := 0
	for {
		file, err = os.Open(evePath)
		if err == nil {
			break
		}
		retryCount++
		if retryCount%10 == 0 {
			fmt.Printf("[Suricata Engine] Waiting for Suricata EVE log at '%s'...\n", evePath)
		}
		time.Sleep(2 * time.Second)
	}
	defer file.Close()

	// Seek to end of file to process only new events
	file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// At EOF: check if log was rotated, truncated, or replaced
			fi, statErr := file.Stat()
			newFi, newStatErr := os.Stat(evePath)
			if statErr == nil && newStatErr == nil {
				currPos, _ := file.Seek(0, io.SeekCurrent)
				if currPos > newFi.Size() || !os.SameFile(fi, newFi) {
					// Log rotation or truncation occurred, re-open
					file.Close()
					if newFile, openErr := os.Open(evePath); openErr == nil {
						file = newFile
						reader = bufio.NewReader(file)
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var event EveEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}

		// 1. Process Suricata Engine Statistics
		if event.EventType == "stats" && event.Stats != nil {
			st.Mu.Lock()
			if event.Stats.Capture.KernelPackets > 0 {
				st.PacketsCaptured = uint64(event.Stats.Capture.KernelPackets)
			}
			if event.Stats.Capture.KernelDrops > 0 {
				st.PacketsDropped = uint64(event.Stats.Capture.KernelDrops)
			}
			if event.Stats.Decoder.Pkts > 0 {
				st.PacketsInspected = uint64(event.Stats.Decoder.Pkts)
			}
			if event.Stats.Flow.Active > 0 {
				st.ActiveFlows = int(event.Stats.Flow.Active)
			}
			st.Mu.Unlock()
			continue
		}

		// 2. Process Suricata Alerts & Inline Drops
		if event.EventType == "alert" && event.Alert != nil {
			// Convert Suricata severity (1 = Critical, 2 = High, 3 = Medium, 4 = Low)
			sevStr := "Medium"
			switch event.Alert.Severity {
			case 1:
				sevStr = "Critical"
			case 2:
				sevStr = "High"
			case 3:
				sevStr = "Medium"
			default:
				sevStr = "Low"
			}

			ruleID := fmt.Sprintf("SURICATA-%d", event.Alert.SignatureID)
			currentTime := getTimestamp()

			srcIP := event.SrcIP
			dstIP := event.DestIP
			category := event.Alert.Category
			if category == "" {
				category = "Network Threat"
			}
			signature := event.Alert.Signature
			if signature == "" {
				signature = fmt.Sprintf("Suricata Signature %d", event.Alert.SignatureID)
			}

			evidence := fmt.Sprintf("Suricata DPI: %s [Proto: %s, Ports: %d->%d, GID: %d, Rev: %d]",
				signature, event.Proto, event.SrcPort, event.DestPort, event.Alert.GID, event.Alert.Rev)

			st.Mu.Lock()
			// Execute verified prevention (blocking in iptables on Linux, netsh on Windows)
			triggerAlert(st, cfg, fm, alertLogger, currentTime, ruleID, category, sevStr, "Critical", srcIP, dstIP, evidence, 1.0, "")
			st.Mu.Unlock()
		}

		// 3. Process Inline IPS Drop verdicts from Suricata
		if event.EventType == "drop" && event.SrcIP != "" {
			currentTime := getTimestamp()
			ruleID := "SURICATA-DROP"
			reason := fmt.Sprintf("Suricata Inline IPS Packet Drop [Proto: %s, %s:%d -> %s:%d]",
				event.Proto, event.SrcIP, event.SrcPort, event.DestIP, event.DestPort)

			st.Mu.Lock()
			triggerAlert(st, cfg, fm, alertLogger, currentTime, ruleID, "Inline IPS Drop", "High", "Critical", event.SrcIP, event.DestIP, reason, 1.0, "")
			st.Mu.Unlock()
		}
	}
}

// TailSuricataEve is maintained for full backward compatibility
func TailSuricataEve(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, alertLogger *alert.Logger) {
	StartSuricataPrimaryEngine(st, cfg, fm, alertLogger)
}
