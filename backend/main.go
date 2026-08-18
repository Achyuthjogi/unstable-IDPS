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

	"github.com/joho/godotenv"
)

func main() {
	fmt.Println("Starting IDPS Go Backend...")

	cfg := config.Load()
	fmt.Printf("Loaded Configuration: %+v\n", cfg)

	appState := state.NewAppState()
	fwManager := firewall.NewFirewallManager()

	// Setup Gateway if in GATEWAY mode
	fwManager.SetupGateway(cfg)

	// Start packet capture
	stopCapture := capture.StartCapture(appState, cfg, fwManager)

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
		
		envMap, err := godotenv.Read(".env")
		if err != nil {
			envMap = make(map[string]string)
		}
		envMap["IDPS_DEPLOYMENT_MODE"] = cfg.IDPSDeploymentMode
		envMap["IDPS_SECURITY_MODE"] = cfg.IDPSSecurityMode
		envMap["WAN_INTERFACE"] = cfg.WanInterface
		envMap["LAN_INTERFACE"] = cfg.LanInterface
		envMap["INTERFACE"] = cfg.Interface
		_ = godotenv.Write(envMap, ".env")

		// Re-setup firewall
		fwManager.SetupGateway(cfg)
		
		// Restart capture on new interface
		stopCapture = capture.StartCapture(appState, cfg, fwManager)
	}

	router := api.CreateRouter(apiState)

	srv := &http.Server{
		Addr:    "0.0.0.0:8000",
		Handler: router,
	}

	go func() {
		fmt.Println("API and WebSocket listening on 0.0.0.0:8000")
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	fmt.Println("IDPS Backend stopped gracefully.")
}
