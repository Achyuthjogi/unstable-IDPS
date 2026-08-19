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

	"idps-backend/api"
	"idps-backend/capture"
	"idps-backend/config"
	"idps-backend/firewall"
	"idps-backend/state"
)

func main() {
	fmt.Println("Starting IDPS Go Backend...")

	cfg := config.Load()

	fmt.Println("====================================")
	fmt.Println("        IDPS GATEWAY STATUS")
	fmt.Println("====================================")
	fmt.Println()
	fmt.Printf("Deployment : %s\n", cfg.IDPSDeploymentMode)
	fmt.Printf("Security   : %s\n", cfg.IDPSSecurityMode)
	fmt.Printf("WAN        : %s\n", cfg.WanInterface)
	fmt.Printf("LAN        : %s\n", cfg.LanInterface)
	fmt.Printf("Capture    : %s\n", cfg.CaptureInterface)
	fmt.Println()

	appState := state.NewAppState()
	fwManager := firewall.NewFirewallManager()

	// Setup Gateway if in NETWORK (or GATEWAY) mode
	err := fwManager.SetupGateway(cfg)
	if err != nil {
		fmt.Printf("Gateway setup FAILED:\n  reason: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Firewall        : READY")

	// Start packet capture
	stopCapture, err := capture.StartCapture(appState, cfg, fwManager)
	if err != nil {
		fmt.Printf("Capture setup FAILED:\n  reason: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Capture         : RUNNING")
	fmt.Println("Detection       : RUNNING")
	fmt.Println("Prevention      : RUNNING")
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
				var expiredRules []string
				for ip, block := range appState.BlockedIPs {
					if block.ExpiresAt > 0 && block.ExpiresAt <= now {
						expiredIPs = append(expiredIPs, ip)
						expiredRules = append(expiredRules, block.RuleID)
					}
				}
				appState.Mu.Unlock()

				// Unblock without holding the lock
				for i, ip := range expiredIPs {
					if fwManager.UnblockIP(ip, cfg) {
						appState.Mu.Lock()
						delete(appState.BlockedIPs, ip)
						appState.AddThreatTimeline(state.ThreatTimeline{
							Timestamp: now,
							Event:     fmt.Sprintf("Auto-unblocked IP %s (Rule: %s expired)", ip, expiredRules[i]),
							Severity:  "Info",
						})
						appState.Mu.Unlock()
					}
				}
			}
		}
	}()

	// Setup API
	apiState := &api.ApiState{
		St:       appState,
		Config:   cfg,
		Firewall: fwManager,
	}
	
	apiState.Reload = func() {
		fmt.Println("Reloading configuration and services...")
		if stopCapture != nil {
			stopCapture()
		}
		
		// Note: We removed automatic godotenv.Write here per requirements to prevent unexpected overwrites.

		// Re-setup firewall
		fwManager.TeardownGateway(cfg)
		err := fwManager.SetupGateway(cfg)
		if err != nil {
			fmt.Printf("Gateway reload FAILED: %v\n", err)
		}
		
		// Restart capture on new interface
		stopCapture, err = capture.StartCapture(appState, cfg, fwManager)
		if err != nil {
			fmt.Printf("Capture reload FAILED: %v\n", err)
		}
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
