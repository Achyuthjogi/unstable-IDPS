package detection

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"idps-backend/alert"
	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/state"
)

// EveAlert represents a parsed Suricata alert
type EveAlert struct {
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	Alert     struct {
		SignatureId int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		Action      string `json:"action"`
	} `json:"alert"`
}

// TailSuricataEve reads /var/log/suricata/eve.json in an infinite loop
func TailSuricataEve(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, alertLogger *alert.Logger) {
	fmt.Println("Suricata Tailer : RUNNING (Watching eve.json)")
	var file *os.File
	var err error

	for {
		file, err = os.Open("/var/log/suricata/eve.json")
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	defer file.Close()

	// Seek to the end so we only get new alerts
	file.Seek(0, 2)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// If EOF, wait for more data
			time.Sleep(200 * time.Millisecond)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var eve EveAlert
		if err := json.Unmarshal([]byte(line), &eve); err != nil {
			continue
		}

		if eve.EventType == "alert" {
			// Convert Suricata severity (1-4, where 1 is highest) to our string format
			sevStr := "Medium"
			if eve.Alert.Severity <= 1 {
				sevStr = "Critical"
			} else if eve.Alert.Severity == 2 {
				sevStr = "High"
			} else if eve.Alert.Severity >= 3 {
				sevStr = "Low"
			}

			ruleID := fmt.Sprintf("SURICATA-%d", eve.Alert.SignatureId)
			currentTime := getTimestamp()

			// Use the existing triggerAlert to handle IDS/IPS mode logic seamlessly
			st.Mu.Lock()
			triggerAlert(st, cfg, fm, alertLogger, currentTime, ruleID, eve.Alert.Category, sevStr, "High", eve.SrcIP, eve.DestIP, eve.Alert.Signature, 1.0, "")
			st.Mu.Unlock()
		}
	}
}
