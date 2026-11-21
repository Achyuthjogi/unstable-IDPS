package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"idps-backend/alert"
	"idps-backend/api"
	"idps-backend/capture"
	"idps-backend/config"
	"idps-backend/detection"
	"idps-backend/firewall"
	"idps-backend/platform"
	"idps-backend/rules"
	"idps-backend/siem"
	"idps-backend/state"
	"idps-backend/threatintel"
)

func main() {
	fmt.Println("Starting Enterprise Nexus IDPS Backend...")

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("FATAL: Configuration validation failed: %v", err)
	}

	pInfo := platform.GetInfo()

	alertLogger, err := alert.NewLogger(cfg.AlertLogPath)
	if err != nil {
		fmt.Printf("Warning: could not open alert log: %v\n", err)
		alertLogger = &alert.Logger{}
	}

	fmt.Println("====================================================")
	fmt.Println("    NEXUS ENTERPRISE IDPS - SURICATA CORE ENGINE    ")
	fmt.Println("====================================================")
	fmt.Printf("Primary Engine: SURICATA IDS/IPS (Deep Packet Inspection)\n")
	fmt.Printf("OS / Arch     : %s / %s (Elevated: %v)\n", pInfo.OS, pInfo.Arch, pInfo.IsElevated)
	fmt.Printf("Host Driver   : %s\n", pInfo.DriverName)
	fmt.Printf("Firewall      : %s\n", pInfo.FirewallBackend)
	fmt.Printf("Deployment    : %s\n", cfg.IDPSDeploymentMode)
	fmt.Printf("Security      : %s\n", cfg.IDPSSecurityMode)
	fmt.Printf("Interface     : %s\n", cfg.CaptureInterface)
	if len(pInfo.Errors) > 0 {
		for _, e := range pInfo.Errors {
			fmt.Printf("  [!] ERROR: %s\n", e)
		}
	}
	if len(pInfo.Warnings) > 0 {
		for _, w := range pInfo.Warnings {
			fmt.Printf("  [*] NOTICE: %s\n", w)
		}
	}
	fmt.Println("====================================")
	fmt.Println()

	appState := state.NewAppState()
	
	// Start Enterprise HA Sync
	haSync := state.NewHASync(appState, "node-1", os.Getenv("HA_BIND_ADDR"), []string{})
	if err := haSync.Start(); err != nil {
		fmt.Printf("Warning: HA Sync failed to start: %v\n", err)
	}

	// Start Enterprise Threat Intelligence Engine
	threatIntelMgr := threatintel.NewManager()
	threatIntelMgr.StartAutoUpdate(1 * time.Hour)
	fmt.Printf("Threat Intel     : READY (%d active baseline IOCs)\n", len(threatIntelMgr.GetIndicators(100)))

	// Start Enterprise SIEM & SOAR Forwarder
	siemCfg := siem.SIEMConfig{
		SyslogServer: os.Getenv("SIEM_SYSLOG_SERVER"),
		SyslogProto:  os.Getenv("SIEM_SYSLOG_PROTO"),
		Format:       "CEF",
		WebhookURL:   os.Getenv("SOAR_WEBHOOK_URL"),
		Enabled:      os.Getenv("SIEM_SYSLOG_SERVER") != "",
	}
	siemForwarder := siem.NewForwarder(siemCfg)
	fmt.Printf("SIEM Forwarder   : READY (Format: CEF, Webhook: %v)\n", siemCfg.WebhookURL != "")

	// Wire Enterprise Decoupled Event Hooks
	appState.OnBlockConfirmed = func(block state.IPBlock) {
		if haSync != nil {
			haSync.BroadcastBlock(block)
		}
	}
	appState.OnUnblock = func(ip, mac string) {
		if haSync != nil {
			haSync.BroadcastUnblock(ip, mac)
		}
	}
	appState.OnAlertGenerated = func(al state.Alert) {
		if siemForwarder != nil {
			siemForwarder.Forward(siem.AlertEvent{
				ID:        al.ID,
				Timestamp: time.Unix(0, int64(al.Timestamp*1e9)),
				RuleID:    al.RuleID,
				Category:  al.AlertType,
				Severity:  al.Severity,
				SrcIP:     al.SourceIP,
				DstIP:     al.DestIP,
				Action:    al.Action,
				Reason:    al.Reason,
			})
		}
	}

	fwManager := firewall.NewFirewallManager()

	// Setup Gateway/Host firewall routing
	err = fwManager.SetupGateway(cfg)
	if err != nil {
		fmt.Printf("Firewall setup warning: %v\n", err)
	}

	fmt.Printf("Firewall Backend : READY (%s)\n", fwManager.PlatformName())

	// Setup Rule Engine
	ruleEngine := rules.NewEngine()
	if err := rules.LoadRulesFromDirectory(cfg.RulesPath, ruleEngine); err != nil {
		fmt.Printf("Warning: Could not load rules from %s: %v\n", cfg.RulesPath, err)
	}
	ruleEngine.Build()
	fmt.Printf("Rule Engine      : READY (Rules loaded: %d)\n", len(ruleEngine.Rules))

	// Setup ML Client
	mlClient := detection.NewMLClient(cfg.MLServiceURL)
	mlStatus := "DISCONNECTED (will retry)"
	if mlClient.IsAvailable() {
		mlStatus = "CONNECTED"
	}
	fmt.Printf("ML Service       : %s (%s)\n", mlStatus, cfg.MLServiceURL)

	// Periodically re-check ML service availability
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mlClient.RefreshAvailability()
		}
	}()

	// Setup Detection Engines (one per worker for lock-free state)
	workerCount := cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = 4
	}
	var engines []*detection.Engine
	for i := 0; i < workerCount; i++ {
		eng := detection.NewEngine(appState, cfg, fwManager, ruleEngine, alertLogger, mlClient)
		eng.SetThreatIntel(threatIntelMgr)
		engines = append(engines, eng)
	}

	// Start packet capture engine (Delegated 100% to Suricata if SuricataExclusiveMode is active)
	var stopCapture func()
	if cfg.SuricataExclusiveMode {
		fmt.Println("Packet Analyzer  : 100% SURICATA EXCLUSIVE (Go internal packet sniffer DISABLED)")
		fmt.Println("Packet Capture   : DELEGATED TO SURICATA DPI")
		fmt.Println("Threat Detection : 100% SURICATA SIGNATURES & DPI")
		fmt.Println("Prevention       : RUNNING (Kernel Firewall + Suricata Drops)")
	} else {
		var err error
		stopCapture, err = capture.StartAutoCapture(appState, cfg, fwManager, engines)
		if err != nil {
			fmt.Printf("Packet Capture setup WARNING:\n  reason: %v\n", err)
			fmt.Println("Proceeding with Suricata / REST API / SOC WebSocket...")
		} else {
			fmt.Println("Packet Capture   : RUNNING")
			fmt.Println("Detection        : RUNNING")
			fmt.Println("Prevention       : RUNNING")
		}
	}

	// Start Suricata as Primary DPI Engine across both Linux and Windows
	if cfg.SuricataPrimaryEngine || cfg.SuricataExclusiveMode {
		go detection.StartSuricataPrimaryEngine(appState, cfg, fwManager, alertLogger)
	}

	fmt.Println()
	fmt.Println("====================================")

	// Start auto-unblock goroutine
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				appState.Mu.Lock()
				now := float64(time.Now().UnixNano()) / 1e9
				var expiredIPs []string
				var expiredMACs []string
				var expiredRules []string
				for ip, block := range appState.BlockedIPs {
					if block.ExpiresAt > 0 && block.ExpiresAt <= now {
						expiredIPs = append(expiredIPs, ip)
						expiredMACs = append(expiredMACs, block.MAC)
						expiredRules = append(expiredRules, block.RuleID)
					}
				}
				appState.Mu.Unlock()

				// Unblock without holding the lock
				for i, ip := range expiredIPs {
					mac := expiredMACs[i]
					if fwManager.UnblockDevice(ip, mac, cfg) {
						appState.Mu.Lock()
						delete(appState.BlockedIPs, ip)
						if mac != "" {
							delete(appState.BlockedMACs, mac)
						}
						appState.AddThreatTimeline(state.ThreatTimeline{
							Timestamp: now,
							Event:     fmt.Sprintf("Auto-unblocked IP %s (Rule: %s expired)", ip, expiredRules[i]),
							Severity:  "Info",
						})
						appState.Mu.Unlock()

						if appState.OnUnblock != nil {
							hook := appState.OnUnblock
							go hook(ip, mac)
						}
					}
				}
			}
		}
	}()

	// Setup API
	apiState := &api.ApiState{
		St:            appState,
		Config:        cfg,
		Firewall:      fwManager,
		AlertLogger:   alertLogger,
		HASync:        haSync,
		ThreatIntel:   threatIntelMgr,
		SIEMForwarder: siemForwarder,
	}
	
	apiState.Reload = func(oldConfig *config.Config) error {
		fmt.Println("Reloading configuration and services...")
		if stopCapture != nil {
			stopCapture()
			stopCapture = nil
		}

		// Re-setup firewall using oldConfig to teardown correctly
		fwManager.TeardownGateway(oldConfig)
		err := fwManager.SetupGateway(cfg)
		if err != nil {
			fmt.Printf("Gateway reload FAILED: %v. Restoring previous gateway configuration...\n", err)
			fwManager.TeardownGateway(cfg)
			if oldConfig != nil {
				_ = fwManager.SetupGateway(oldConfig)
				if restoreStop, restoreErr := capture.StartAutoCapture(appState, oldConfig, fwManager, engines); restoreErr == nil {
					stopCapture = restoreStop
				} else {
					fmt.Printf("CRITICAL: Failed to restore packet capture after reload failure: %v\n", restoreErr)
				}
			}
			return err
		}
		
		// Restart capture on new interface (if not in Suricata exclusive mode)
		if !cfg.SuricataExclusiveMode {
			newStop, err := capture.StartAutoCapture(appState, cfg, fwManager, engines)
			if err != nil {
				fmt.Printf("Packet Capture reload FAILED: %v. Restoring previous configuration...\n", err)
				fwManager.TeardownGateway(cfg)
				if oldConfig != nil {
					_ = fwManager.SetupGateway(oldConfig)
					if !oldConfig.SuricataExclusiveMode {
						if restoreStop, restoreErr := capture.StartAutoCapture(appState, oldConfig, fwManager, engines); restoreErr == nil {
							stopCapture = restoreStop
						} else {
							fmt.Printf("CRITICAL: Failed to restore packet capture after reload failure: %v\n", restoreErr)
						}
					}
				}
				return err
			}
			stopCapture = newStop
		} else {
			fmt.Println("Packet Analyzer  : 100% SURICATA EXCLUSIVE (Go internal packet sniffer DISABLED)")
		}
		
		return nil
	}

	router := api.CreateRouter(apiState)

	addr := fmt.Sprintf("%s:8000", cfg.ApiHost)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		fmt.Printf("API and WebSocket listening on %s\n", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Received shutdown signal...")

	// Teardown Gateway before exiting
	fwManager.TeardownGateway(cfg)
	if alertLogger != nil {
		alertLogger.Close()
	}
	cancel() // stop auto-unblock goroutine
	if stopCapture != nil {
		stopCapture() // wait for capture to stop completely
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	fmt.Println("IDPS Backend stopped gracefully.")
}
