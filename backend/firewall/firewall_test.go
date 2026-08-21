package firewall

import (
	"testing"

	"idps-backend/config"
)

func TestFirewallSafetyAndDryRun(t *testing.T) {
	cfg := &config.Config{
		IDPSDeploymentMode: "HOST",
		FirewallDryRun:     true,
		GatewayIP:          "192.168.1.1",
	}

	fm := NewFirewallManager()

	// Test safe to block logic
	if fm.isSafeToBlock("127.0.0.1", cfg) {
		t.Errorf("Expected 127.0.0.1 to be unsafe to block")
	}

	if fm.isSafeToBlock("192.168.1.1", cfg) {
		t.Errorf("Expected Gateway IP 192.168.1.1 to be unsafe to block")
	}

	if fm.isSafeToBlock("224.0.0.1", cfg) {
		t.Errorf("Expected Multicast IP 224.0.0.1 to be unsafe to block")
	}

	if !fm.isSafeToBlock("8.8.8.8", cfg) {
		t.Errorf("Expected 8.8.8.8 to be safe to block")
	}

	// Test dry run mode does not error
	success := fm.BlockDevice("8.8.8.8", "", cfg)
	if !success {
		t.Errorf("Expected dry run BlockDevice to succeed")
	}

	success = fm.UnblockDevice("8.8.8.8", "", cfg)
	if !success {
		t.Errorf("Expected dry run UnblockDevice to succeed")
	}

	err := fm.SetupGateway(cfg)
	if err != nil {
		t.Errorf("Expected SetupGateway (non-network mode) to do nothing")
	}

	cfg.IDPSDeploymentMode = "NETWORK"
	cfg.WanInterface = "eth0"
	cfg.LanInterface = "wlan0"

	err = fm.SetupGateway(cfg)
	if err != nil {
		t.Errorf("Expected dry run SetupGateway to succeed, got %v", err)
	}
}
