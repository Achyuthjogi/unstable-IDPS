package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	importOS "os"
	"sort"
	"strings"
	"time"

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
	Firewall *firewall.FirewallManager
	Reload   func(oldConfig *config.Config) error
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

	mux.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getInterfaces(w, r, apiState)
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
		fmt.Println("FATAL: ALLOWED_ORIGINS is not configured. CORS cannot be established safely. Please configure ALLOWED_ORIGINS or set it to '*' for wildcards (not recommended).")
		importOS.Exit(1)
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
	api.St.Mu.RLock()
	alerts := make([]state.Alert, len(api.St.Alerts))
	copy(alerts, api.St.Alerts)
	api.St.Mu.RUnlock()

	json.NewEncoder(w).Encode(alerts)
}

func dismissAlert(w http.ResponseWriter, r *http.Request, api *ApiState, id string) {
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

	if api.Firewall.BlockIP(ip, api.Config) {
		now := float64(time.Now().UnixNano()) / 1e9
		expiresAt := now + float64(api.Config.BlockTTLSeconds)
		api.St.Mu.Lock()
		api.St.BlockedIPs[ip] = state.IPBlock{
			IP:         ip,
			RuleID:     "MANUAL",
			Reason:     "Manually blocked via API",
			Confidence: "N/A",
			CreatedAt:  now,
			ExpiresAt:  expiresAt,
		}
		api.St.AddThreatTimeline(state.ThreatTimeline{
			Timestamp: now,
			Event:     fmt.Sprintf("Manually blocked IP %s via API", ip),
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

	if api.Firewall.UnblockIP(ip, api.Config) {
		api.St.Mu.Lock()
		delete(api.St.BlockedIPs, ip)
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
	})
}

func updateSettings(w http.ResponseWriter, r *http.Request, api *ApiState) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	oldCfg := api.Config.Clone()

	api.Config.Mu.Lock()

	if val, ok := body["IDPS_DEPLOYMENT_MODE"]; ok {
		if val != "HOST" && val != "NETWORK" && val != "GATEWAY" {
			api.Config.Mu.Unlock()
			http.Error(w, "Invalid deployment mode", http.StatusBadRequest)
			return
		}
		api.Config.IDPSDeploymentMode = val
	}
	if val, ok := body["IDPS_SECURITY_MODE"]; ok {
		if val != "IDS" && val != "IPS" {
			api.Config.Mu.Unlock()
			http.Error(w, "Invalid security mode", http.StatusBadRequest)
			return
		}
		api.Config.IDPSSecurityMode = val
	}
	if val, ok := body["WAN_INTERFACE"]; ok {
		api.Config.WanInterface = val
	}
	if val, ok := body["LAN_INTERFACE"]; ok {
		api.Config.LanInterface = val
	}
	if val, ok := body["INTERFACE"]; ok {
		api.Config.Interface = val
	}

	if api.Config.IDPSDeploymentMode == "GATEWAY" || api.Config.IDPSDeploymentMode == "NETWORK" {
		api.Config.CaptureInterface = api.Config.LanInterface
	} else {
		api.Config.CaptureInterface = api.Config.Interface
	}

	// Validate interfaces before applying
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
	
	api.Config.Mu.Unlock()

	// Trigger hot-reload in main
	if api.Reload != nil {
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

func wsHandler(w http.ResponseWriter, r *http.Request, api *ApiState) {
	api.Config.Mu.RLock()
	allowedOrigins := api.Config.AllowedOrigins
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
		Subprotocols: []string{api.Config.APIKey}, // Allow the API key as a subprotocol
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

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
		alertsCount := len(api.St.Alerts)
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

		// Protocol counts (must copy to avoid concurrent map read/write during JSON marshal)
		protocolCounts := make(map[string]int)
		for k, v := range api.St.ProtocolCounts {
			protocolCounts[k] = v
		}

		// Alerts (last 10 reversed)
		var recentAlerts []state.Alert
		startIdx := alertsCount - 10
		if startIdx < 0 {
			startIdx = 0
		}
		for i := alertsCount - 1; i >= startIdx; i-- {
			recentAlerts = append(recentAlerts, api.St.Alerts[i])
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

		// --- Build JSON payload ---

		data := map[string]interface{}{
			"system": map[string]interface{}{
				"cpu":                cpuUsage,
				"memory":             memUsage,
				"active_connections": activeConns,
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
