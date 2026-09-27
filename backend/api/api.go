package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"sort"
	"strings"
	"time"

	"idps-backend/alert"
	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/state"

	"github.com/gorilla/websocket"
	"github.com/rs/cors"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

type ApiState struct {
	St       *state.AppState
	Config   *config.Config
	Firewall    *firewall.FirewallManager
	AlertLogger *alert.Logger
	Reload      func(oldConfig *config.Config) error
}

func authMiddleware(apiState *ApiState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiState.Config.Mu.RLock()
		expectedKey := apiState.Config.APIKey
		apiState.Config.Mu.RUnlock()

		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.Header.Get("Authorization")
			key = strings.TrimPrefix(key, "Bearer ")
		}
		if key == "" {
			// For WebSockets, check protocols or query params
			if r.URL.Path == "/ws" {
				protocols := r.Header.Get("Sec-WebSocket-Protocol")
				for _, p := range strings.Split(protocols, ",") {
					if strings.TrimSpace(p) == expectedKey {
						key = expectedKey // Match found in subprotocol
						break
					}
				}
				if key == "" {
					key = r.URL.Query().Get("api_key")
				}
			}
		}

		if key != expectedKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func CreateRouter(apiState *ApiState) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		getStatus(w, r, apiState)
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		getAlerts(w, r, apiState)
	})

	mux.HandleFunc("/api/alerts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
			dismissAlert(w, r, apiState, id)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/blocked", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		getBlocked(w, r, apiState)
	})

	mux.HandleFunc("/api/block/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ip := strings.TrimPrefix(r.URL.Path, "/api/block/")
			blockIP(w, r, apiState, ip)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/unblock/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ip := strings.TrimPrefix(r.URL.Path, "/api/unblock/")
			unblockIP(w, r, apiState, ip)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getSettings(w, r, apiState)
		} else if r.Method == http.MethodPost {
			updateSettings(w, r, apiState)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/ml/toggle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			toggleML(w, r, apiState)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getInterfaces(w, r, apiState)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/rules/thresholds", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getThresholds(w, r, apiState)
		} else if r.Method == http.MethodPost {
			updateThresholds(w, r, apiState)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		wsHandler(w, r, apiState)
	})

	apiState.Config.Mu.RLock()
	allowedOrigins := apiState.Config.AllowedOrigins
	apiState.Config.Mu.RUnlock()

	if len(allowedOrigins) == 0 {
		fmt.Println("WARNING: ALLOWED_ORIGINS is not configured. Defaulting to '*' for wildcards. This is insecure in production!")
		allowedOrigins = []string{"*"}
	}
	for _, o := range allowedOrigins {
		if o == "*" {
			fmt.Println("WARNING: ALLOWED_ORIGINS is explicitly set to '*'. CORS is wide open. This is insecure in production!")
		}
	}

	c := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	return c.Handler(authMiddleware(apiState, mux))
}

func getStatus(w http.ResponseWriter, r *http.Request, api *ApiState) {
	api.St.Mu.RLock()
	packetCount := api.St.PacketCount
	activeConns := api.St.ActiveConnections
	api.St.Mu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "running",
		"packet_count":       packetCount,
		"active_connections": activeConns,
	})
}

func getAlerts(w http.ResponseWriter, r *http.Request, api *ApiState) {
	if api.AlertLogger == nil || api.AlertLogger.GetDB() == nil {
		// Fallback if DB is not available
		api.St.Mu.RLock()
		alerts := make([]state.Alert, len(api.St.Alerts))
		copy(alerts, api.St.Alerts)
		api.St.Mu.RUnlock()
		json.NewEncoder(w).Encode(alerts)
		return
	}

	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "100"
	}

	rows, err := api.AlertLogger.GetDB().Query("SELECT id, timestamp, rule_id, msg, classtype, severity, src_ip, dst_ip, action, confidence FROM alerts ORDER BY timestamp DESC LIMIT ?", limit)
	if err != nil {
		http.Error(w, "Failed to query alerts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []state.Alert
	for rows.Next() {
		var a state.Alert
		var tsStr string
		if err := rows.Scan(&a.ID, &tsStr, &a.RuleID, &a.Reason, &a.AlertType, &a.Severity, &a.SourceIP, &a.DestIP, &a.Action, &a.Confidence); err == nil {
			if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
				a.Timestamp = float64(t.UnixNano()) / 1e9
			}
			alerts = append(alerts, a)
		}
	}

	json.NewEncoder(w).Encode(alerts)
}

func dismissAlert(w http.ResponseWriter, r *http.Request, api *ApiState, id string) {
	// If we have an AlertLogger (SQLite DB), delete the alert from there
	if api.AlertLogger != nil && api.AlertLogger.GetDB() != nil {
		err := api.AlertLogger.DeleteAlert(id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Failed to delete alert from database"})
			return
		}
		
		// Also clean up in-memory array just in case
		api.St.Mu.Lock()
		defer api.St.Mu.Unlock()
		newAlerts := make([]state.Alert, 0, len(api.St.Alerts))
		for _, alert := range api.St.Alerts {
			if alert.ID != id {
				newAlerts = append(newAlerts, alert)
			}
		}
		api.St.Alerts = newAlerts

		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Alert dismissed"})
		return
	}

	// Fallback logic for memory-only mode
	api.St.Mu.Lock()
	defer api.St.Mu.Unlock()

	originalLen := len(api.St.Alerts)
	newAlerts := make([]state.Alert, 0, originalLen)
	for _, alert := range api.St.Alerts {
		if alert.ID != id {
			newAlerts = append(newAlerts, alert)
		}
	}
	api.St.Alerts = newAlerts

	if len(api.St.Alerts) < originalLen {
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Alert dismissed"})
	} else {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"status": "not_found", "message": "Alert not found"})
	}
}

func getBlocked(w http.ResponseWriter, r *http.Request, api *ApiState) {
	api.St.Mu.RLock()
	var blocked []state.IPBlock
	for _, b := range api.St.BlockedIPs {
		blocked = append(blocked, b)
	}
	api.St.Mu.RUnlock()
	json.NewEncoder(w).Encode(blocked)
}

func blockIP(w http.ResponseWriter, r *http.Request, api *ApiState, ip string) {
	if net.ParseIP(ip) == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Invalid IP address"})
		return
	}

	api.St.Mu.RLock()
	mac := ""
	for _, d := range api.St.Devices {
		if d.IP == ip {
			mac = d.MAC
			break
		}
	}
	api.St.Mu.RUnlock()

	if api.Firewall.BlockDevice(ip, mac, api.Config) {
		now := float64(time.Now().UnixNano()) / 1e9
		expiresAt := now + float64(api.Config.BlockTTLSeconds)
		
		ipBlock := state.IPBlock{
			IP:         ip,
			MAC:        mac,
			RuleID:     "MANUAL",
			Reason:     "Manually blocked via API",
			Confidence: "N/A",
			CreatedAt:  now,
			ExpiresAt:  expiresAt,
		}

		api.St.Mu.Lock()
		api.St.BlockedIPs[ip] = ipBlock
		if mac != "" {
			api.St.BlockedMACs[mac] = ipBlock
		}
		
		api.St.AddThreatTimeline(state.ThreatTimeline{
			Timestamp: now,
			Event:     fmt.Sprintf("Manually blocked IP %s (MAC: %s) via API", ip, mac),
			Severity:  "Critical",
		})
		api.St.Mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": fmt.Sprintf("IP %s blocked", ip)})
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": fmt.Sprintf("Failed to block %s", ip)})
	}
}

func unblockIP(w http.ResponseWriter, r *http.Request, api *ApiState, ip string) {
	if net.ParseIP(ip) == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Invalid IP address"})
		return
	}

	api.St.Mu.RLock()
	block, exists := api.St.BlockedIPs[ip]
	mac := ""
	if exists {
		mac = block.MAC
	}
	api.St.Mu.RUnlock()

	if api.Firewall.UnblockDevice(ip, mac, api.Config) {
		api.St.Mu.Lock()
		delete(api.St.BlockedIPs, ip)
		if mac != "" {
			delete(api.St.BlockedMACs, mac)
		}
		api.St.AddThreatTimeline(state.ThreatTimeline{
			Timestamp: float64(time.Now().UnixNano()) / 1e9,
			Event:     fmt.Sprintf("Manually unblocked IP %s via API", ip),
			Severity:  "Info",
		})
		api.St.Mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": fmt.Sprintf("IP %s unblocked", ip)})
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": fmt.Sprintf("Failed to unblock %s", ip)})
	}
}

func getSettings(w http.ResponseWriter, r *http.Request, api *ApiState) {
	api.Config.Mu.RLock()
	defer api.Config.Mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"IDPS_DEPLOYMENT_MODE": api.Config.IDPSDeploymentMode,
		"IDPS_SECURITY_MODE":   api.Config.IDPSSecurityMode,
		"WAN_INTERFACE":        api.Config.WanInterface,
		"LAN_INTERFACE":        api.Config.LanInterface,
		"INTERFACE":            api.Config.Interface,
		"GATEWAY_IP":           api.Config.GatewayIP,
		"ML_ENABLED":           api.Config.MLEnabled,
	})
}

func toggleML(w http.ResponseWriter, r *http.Request, api *ApiState) {
	api.Config.Mu.Lock()
	api.Config.MLEnabled = !api.Config.MLEnabled
	current := api.Config.MLEnabled
	api.Config.Mu.Unlock()

	statusStr := "disabled"
	if current {
		statusStr = "enabled"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "success",
		"ml_enabled": current,
		"message":    fmt.Sprintf("Machine learning detection model %s successfully.", statusStr),
	})
}

func updateSettings(w http.ResponseWriter, r *http.Request, api *ApiState) {
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	oldCfg := api.Config.Clone()

	api.Config.Mu.Lock()

	if val, ok := body["ML_ENABLED"]; ok {
		switch v := val.(type) {
		case bool:
			api.Config.MLEnabled = v
		case string:
			lower := strings.ToLower(strings.TrimSpace(v))
			api.Config.MLEnabled = lower == "true" || lower == "1" || lower == "yes" || lower == "on"
		}
	}

	if val, ok := body["IDPS_DEPLOYMENT_MODE"].(string); ok {
		if val != "HOST" && val != "NETWORK" && val != "GATEWAY" {
			api.Config.Mu.Unlock()
			http.Error(w, "Invalid deployment mode", http.StatusBadRequest)
			return
		}
		api.Config.IDPSDeploymentMode = val
	}
	if val, ok := body["IDPS_SECURITY_MODE"].(string); ok {
		if val != "IDS" && val != "IPS" {
			api.Config.Mu.Unlock()
			http.Error(w, "Invalid security mode", http.StatusBadRequest)
			return
		}
		api.Config.IDPSSecurityMode = val
	}
	if val, ok := body["WAN_INTERFACE"].(string); ok {
		api.Config.WanInterface = val
	}
	if val, ok := body["LAN_INTERFACE"].(string); ok {
		api.Config.LanInterface = val
	}
	if val, ok := body["INTERFACE"].(string); ok {
		api.Config.Interface = val
	}
	if val, ok := body["GATEWAY_IP"].(string); ok {
		api.Config.GatewayIP = val
	}

	if api.Config.IDPSDeploymentMode == "GATEWAY" || api.Config.IDPSDeploymentMode == "NETWORK" {
		api.Config.CaptureInterface = api.Config.LanInterface
	} else {
		api.Config.CaptureInterface = api.Config.Interface
	}

	// Validate interfaces before applying IF network capture interface or mode changed
	needsReload := oldCfg.IDPSDeploymentMode != api.Config.IDPSDeploymentMode ||
		oldCfg.IDPSSecurityMode != api.Config.IDPSSecurityMode ||
		oldCfg.WanInterface != api.Config.WanInterface ||
		oldCfg.LanInterface != api.Config.LanInterface ||
		oldCfg.Interface != api.Config.Interface ||
		oldCfg.CaptureInterface != api.Config.CaptureInterface

	if needsReload {
		if api.Config.IDPSDeploymentMode == "GATEWAY" || api.Config.IDPSDeploymentMode == "NETWORK" {
			if _, err := net.InterfaceByName(api.Config.WanInterface); err != nil {
				api.Config.IDPSDeploymentMode = oldCfg.IDPSDeploymentMode
				api.Config.IDPSSecurityMode = oldCfg.IDPSSecurityMode
				api.Config.WanInterface = oldCfg.WanInterface
				api.Config.LanInterface = oldCfg.LanInterface
				api.Config.Interface = oldCfg.Interface
				api.Config.CaptureInterface = oldCfg.CaptureInterface
				api.Config.Mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "WAN interface not found"})
				return
			}
			if _, err := net.InterfaceByName(api.Config.LanInterface); err != nil {
				api.Config.IDPSDeploymentMode = oldCfg.IDPSDeploymentMode
				api.Config.IDPSSecurityMode = oldCfg.IDPSSecurityMode
				api.Config.WanInterface = oldCfg.WanInterface
				api.Config.LanInterface = oldCfg.LanInterface
				api.Config.Interface = oldCfg.Interface
				api.Config.CaptureInterface = oldCfg.CaptureInterface
				api.Config.Mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "LAN interface not found"})
				return
			}
		} else {
			if _, err := net.InterfaceByName(api.Config.Interface); err != nil {
				api.Config.IDPSDeploymentMode = oldCfg.IDPSDeploymentMode
				api.Config.IDPSSecurityMode = oldCfg.IDPSSecurityMode
				api.Config.WanInterface = oldCfg.WanInterface
				api.Config.LanInterface = oldCfg.LanInterface
				api.Config.Interface = oldCfg.Interface
				api.Config.CaptureInterface = oldCfg.CaptureInterface
				api.Config.Mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Monitoring interface not found"})
				return
			}
		}
	}
	
	api.Config.Mu.Unlock()

	// Trigger hot-reload in main ONLY if network interfaces or deployment modes changed
	if needsReload && api.Reload != nil {
		if err := api.Reload(oldCfg); err != nil {
			// Rollback config
			api.Config.Mu.Lock()
			api.Config.IDPSDeploymentMode = oldCfg.IDPSDeploymentMode
			api.Config.IDPSSecurityMode = oldCfg.IDPSSecurityMode
			api.Config.WanInterface = oldCfg.WanInterface
			api.Config.LanInterface = oldCfg.LanInterface
			api.Config.Interface = oldCfg.Interface
			api.Config.CaptureInterface = oldCfg.CaptureInterface
			api.Config.Mu.Unlock()
			
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": fmt.Sprintf("Reload failed: %v", err)})
			return
		}
	}

	// Persist the new configuration to .env
	if err := api.Config.SaveToEnv(".env"); err != nil {
		fmt.Printf("Warning: failed to save settings to .env: %v\n", err)
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Configuration applied successfully."})
}

func getInterfaces(w http.ResponseWriter, r *http.Request, api *ApiState) {
	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, "Failed to get interfaces", http.StatusInternalServerError)
		return
	}
	
	var names []string
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	json.NewEncoder(w).Encode(names)
}

func getThresholds(w http.ResponseWriter, r *http.Request, api *ApiState) {
	api.Config.Mu.RLock()
	defer api.Config.Mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"SuspiciousRateThreshold": api.Config.SuspiciousRateThreshold,
		"PortScanThreshold":       api.Config.PortScanThreshold,
		"ICMPFloodThreshold":      api.Config.ICMPFloodThreshold,
		"UDPFloodThreshold":       api.Config.UDPFloodThreshold,
		"SYNFloodThreshold":       api.Config.SYNFloodThreshold,
		"SSHBruteForceThreshold":  api.Config.SSHBruteForceThreshold,
	})
}

func updateThresholds(w http.ResponseWriter, r *http.Request, api *ApiState) {
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	api.Config.Mu.Lock()
	defer api.Config.Mu.Unlock()

	if val, ok := body["SuspiciousRateThreshold"].(float64); ok {
		api.Config.SuspiciousRateThreshold = int(val)
	}
	if val, ok := body["PortScanThreshold"].(float64); ok {
		api.Config.PortScanThreshold = int(val)
	}
	if val, ok := body["ICMPFloodThreshold"].(float64); ok {
		api.Config.ICMPFloodThreshold = int(val)
	}
	if val, ok := body["UDPFloodThreshold"].(float64); ok {
		api.Config.UDPFloodThreshold = int(val)
	}
	if val, ok := body["SYNFloodThreshold"].(float64); ok {
		api.Config.SYNFloodThreshold = int(val)
	}
	if val, ok := body["SSHBruteForceThreshold"].(float64); ok {
		api.Config.SSHBruteForceThreshold = int(val)
	}

	// Persist the thresholds to .env
	go func() {
		if err := api.Config.SaveToEnv(".env"); err != nil {
			fmt.Printf("Warning: failed to save thresholds to .env: %v\n", err)
		}
	}()

	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Thresholds updated successfully."})
}

func wsHandler(w http.ResponseWriter, r *http.Request, api *ApiState) {
	api.Config.Mu.RLock()
	allowedOrigins := api.Config.AllowedOrigins
	apiKey := api.Config.APIKey
	api.Config.Mu.RUnlock()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					return true
				}
			}
			return false
		},
		Subprotocols: []string{apiKey}, // Allow the API key as a subprotocol
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	// Drain incoming messages (ping/pong/close frames) in background
	// to prevent connection hangs per WebSocket RFC.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C

		cpuPercents, _ := cpu.Percent(0, false)
		var cpuUsage float64
		if len(cpuPercents) > 0 {
			cpuUsage = cpuPercents[0]
		}
		memInfo, _ := mem.VirtualMemory()
		memUsage := memInfo.UsedPercent

		api.St.Mu.RLock()

		packetCount := api.St.PacketCount
		activeConns := api.St.ActiveConnections
		blockedIPsCount := len(api.St.BlockedIPs)

		// Top SRC IPs
		type ipCount struct {
			IP    string `json:"ip"`
			Count int    `json:"count"`
		}
		var topSrcIPs []ipCount
		for ip, ts := range api.St.IPPacketTimestamps {
			topSrcIPs = append(topSrcIPs, ipCount{IP: ip, Count: len(ts)})
		}

		// Top DST Ports
		type portCount struct {
			Port  uint16 `json:"port"`
			Count int    `json:"count"`
		}
		var topDstPorts []portCount
		for port, count := range api.St.PortCounts {
			topDstPorts = append(topDstPorts, portCount{Port: port, Count: count})
		}

		// Protocol counts
		protocolCounts := make(map[string]int)
		for k, v := range api.St.ProtocolCounts {
			protocolCounts[k] = v
		}
		alertsCount := 0
		var recentAlerts []state.Alert

		if api.AlertLogger != nil && api.AlertLogger.GetDB() != nil {
			// Fetch from SQLite
			api.AlertLogger.GetDB().QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertsCount)
			
			rows, err := api.AlertLogger.GetDB().Query("SELECT id, timestamp, rule_id, msg, classtype, severity, src_ip, dst_ip, action, confidence FROM alerts ORDER BY timestamp DESC LIMIT 10")
			if err == nil {
				for rows.Next() {
					var a state.Alert
					var tsStr string
					if err := rows.Scan(&a.ID, &tsStr, &a.RuleID, &a.Reason, &a.AlertType, &a.Severity, &a.SourceIP, &a.DestIP, &a.Action, &a.Confidence); err == nil {
						if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
							a.Timestamp = float64(t.UnixNano()) / 1e9
						}
						recentAlerts = append(recentAlerts, a)
					}
				}
				rows.Close()
			}
		} else {
			// Fallback to in-memory alerts
			alertsCount = len(api.St.Alerts)
			startIdx := alertsCount - 10
			if startIdx < 0 {
				startIdx = 0
			}
			for i := alertsCount - 1; i >= startIdx; i-- {
				recentAlerts = append(recentAlerts, api.St.Alerts[i])
			}
		}

		if recentAlerts == nil {
			recentAlerts = make([]state.Alert, 0)
		}

		// Devices
		var devices []state.Device
		for _, d := range api.St.Devices {
			devices = append(devices, *d)
		}
		if devices == nil {
			devices = make([]state.Device, 0)
		}

		// Blocked IPs
		var blocked []state.IPBlock
		for _, b := range api.St.BlockedIPs {
			blocked = append(blocked, b)
		}
		if blocked == nil {
			blocked = make([]state.IPBlock, 0)
		}

		// Timeline (last 20 reversed)
		var timeline []map[string]interface{}
		timelineCount := len(api.St.ThreatTimeline)
		timelineStart := timelineCount - 20
		if timelineStart < 0 {
			timelineStart = 0
		}
		for i := timelineCount - 1; i >= timelineStart; i-- {
			a := api.St.ThreatTimeline[i]
			timeline = append(timeline, map[string]interface{}{
				"timestamp": a.Timestamp,
				"event":     a.Event,
				"severity":  a.Severity,
			})
		}
		if timeline == nil {
			timeline = make([]map[string]interface{}, 0)
		}

		// Traffic Log (last 50 reversed)
		trafficCount := len(api.St.TrafficLog)
		var recentTraffic []state.TrafficLog
		trafficStart := trafficCount - 50
		if trafficStart < 0 {
			trafficStart = 0
		}
		for i := trafficCount - 1; i >= trafficStart; i-- {
			recentTraffic = append(recentTraffic, api.St.TrafficLog[i])
		}
		if recentTraffic == nil {
			recentTraffic = make([]state.TrafficLog, 0)
		}

		api.St.Mu.RUnlock()

		// --- Perform sorting outside the lock to minimize contention ---

		sort.Slice(topSrcIPs, func(i, j int) bool {
			return topSrcIPs[i].Count > topSrcIPs[j].Count
		})
		if len(topSrcIPs) > 10 {
			topSrcIPs = topSrcIPs[:10]
		}
		if topSrcIPs == nil {
			topSrcIPs = make([]ipCount, 0)
		}

		sort.Slice(topDstPorts, func(i, j int) bool {
			return topDstPorts[i].Count > topDstPorts[j].Count
		})
		if len(topDstPorts) > 5 {
			topDstPorts = topDstPorts[:5]
		}
		if topDstPorts == nil {
			topDstPorts = make([]portCount, 0)
		}

		api.Config.Mu.RLock()
		mlEnabled := api.Config.MLEnabled
		gatewayIP := api.Config.GatewayIP
		api.Config.Mu.RUnlock()

		// --- Build JSON payload ---

		data := map[string]interface{}{
			"system": map[string]interface{}{
				"cpu":                cpuUsage,
				"memory":             memUsage,
				"active_connections": activeConns,
				"ml_enabled":         mlEnabled,
				"gateway_ip":         gatewayIP,
			},
			"network": map[string]interface{}{
				"packet_count":      packetCount,
				"protocol_counts":   protocolCounts,
				"top_src_ips":       topSrcIPs,
				"top_dst_ports":     topDstPorts,
				"alerts_count":      alertsCount,
				"blocked_ips_count": blockedIPsCount,
			},
			"alerts":      recentAlerts,
			"devices":     devices,
			"blocked":     blocked,
			"timeline":    timeline,
			"traffic_log": recentTraffic,
		}

		if err := conn.WriteJSON(data); err != nil {
			break
		}
	}
}
