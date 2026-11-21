package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// SIEMConfig configures remote event forwarding.
type SIEMConfig struct {
	SyslogServer string `json:"syslog_server"` // e.g. "siem.enterprise.corp:514"
	SyslogProto  string `json:"syslog_proto"`  // "udp" or "tcp"
	Format       string `json:"format"`        // "CEF", "JSON", "RFC5424"
	WebhookURL   string `json:"webhook_url"`   // SOAR automation endpoint
	Enabled      bool   `json:"enabled"`
}

// AlertEvent matches the structure needed for SIEM forwarding.
type AlertEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	RuleID    string    `json:"rule_id"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"` // "Critical", "High", "Medium", "Low"
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Action    string    `json:"action"` // "BLOCKED", "DETECTED"
	Reason    string    `json:"reason"`
}

// Forwarder manages SIEM stream ingestion, CEF conversion, and SOAR webhooks.
type Forwarder struct {
	cfg        SIEMConfig
	httpClient *http.Client
	eventsLog  *os.File
	mu         sync.RWMutex
	sentCount  uint64
	dropCount  uint64
}

// NewForwarder creates a production SIEM & SOAR event forwarder.
func NewForwarder(cfg SIEMConfig) *Forwarder {
	f := &Forwarder{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	// Append-only local enterprise event archive
	logFile, err := os.OpenFile("siem_events.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err == nil {
		f.eventsLog = logFile
	}
	return f
}

// FormatCEF formats an event into HP ArcSight / Splunk Common Event Format (CEF).
func FormatCEF(e AlertEvent) string {
	// Severity to CEF 0-10 scale
	var sevNum int
	switch strings.ToLower(e.Severity) {
	case "critical":
		sevNum = 10
	case "high":
		sevNum = 8
	case "medium":
		sevNum = 5
	default:
		sevNum = 2
	}

	cef := fmt.Sprintf("CEF:0|NexusEnterprise|NexusIDPS|2.1.0|%s|%s|%d|src=%s dst=%s act=%s msg=%s",
		escapeCEF(e.RuleID),
		escapeCEF(e.Category),
		sevNum,
		e.SrcIP,
		e.DstIP,
		e.Action,
		escapeCEF(e.Reason),
	)

	if e.SrcPort > 0 {
		cef += fmt.Sprintf(" spt=%d", e.SrcPort)
	}
	if e.DstPort > 0 {
		cef += fmt.Sprintf(" dpt=%d", e.DstPort)
	}

	return cef
}

func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// Forward sends the security event to the configured SIEM and SOAR integrations.
func (f *Forwarder) Forward(e AlertEvent) {
	cefMsg := FormatCEF(e)

	// 1. Write to local archive
	f.mu.Lock()
	if f.eventsLog != nil {
		timestamp := e.Timestamp.Format(time.RFC3339)
		_, _ = f.eventsLog.WriteString(fmt.Sprintf("%s %s\n", timestamp, cefMsg))
	}
	f.sentCount++
	f.mu.Unlock()

	// 2. Syslog forwarding
	if f.cfg.Enabled && f.cfg.SyslogServer != "" {
		go f.sendSyslog(cefMsg)
	}

	// 3. SOAR Webhook dispatch for Critical threats
	if f.cfg.WebhookURL != "" && (e.Severity == "Critical" || e.Severity == "High") {
		go f.sendSOARWebhook(e)
	}
}

func (f *Forwarder) sendSyslog(msg string) {
	proto := strings.ToLower(f.cfg.SyslogProto)
	if proto == "" {
		proto = "udp"
	}

	conn, err := net.DialTimeout(proto, f.cfg.SyslogServer, 3*time.Second)
	if err != nil {
		f.mu.Lock()
		f.dropCount++
		f.mu.Unlock()
		return
	}
	defer conn.Close()

	rfcMsg := fmt.Sprintf("<14>%s %s\n", time.Now().Format(time.RFC3339), msg)
	_, _ = conn.Write([]byte(rfcMsg))
}

func (f *Forwarder) sendSOARWebhook(e AlertEvent) {
	payloadBytes, err := json.Marshal(e)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", f.cfg.WebhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Nexus-Enterprise-IDPS/2.1")

	resp, err := f.httpClient.Do(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}

// GetMetrics returns operational telemetry for SIEM forwarding.
func (f *Forwarder) GetMetrics() (uint64, uint64) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.sentCount, f.dropCount
}

// RenderPrometheusMetrics formats real-time IDPS telemetry into standard Prometheus exposition format.
func RenderPrometheusMetrics(
	capturedPkts, droppedPkts uint64,
	activeFlows int,
	blockedIPs int,
	alertsTotal map[string]int,
	threatIntelCount int,
	clusterNodesOnline int,
) string {
	var b strings.Builder

	b.WriteString("# HELP idps_packets_captured_total Total raw packets captured\n")
	b.WriteString("# TYPE idps_packets_captured_total counter\n")
	b.WriteString(fmt.Sprintf("idps_packets_captured_total %d\n\n", capturedPkts))

	b.WriteString("# HELP idps_packets_dropped_total Total malicious packets dropped by IPS\n")
	b.WriteString("# TYPE idps_packets_dropped_total counter\n")
	b.WriteString(fmt.Sprintf("idps_packets_dropped_total %d\n\n", droppedPkts))

	b.WriteString("# HELP idps_active_flows Current active bidirectional flows tracked\n")
	b.WriteString("# TYPE idps_active_flows gauge\n")
	b.WriteString(fmt.Sprintf("idps_active_flows %d\n\n", activeFlows))

	b.WriteString("# HELP idps_blocked_ips_active Active verified firewall blocks\n")
	b.WriteString("# TYPE idps_blocked_ips_active gauge\n")
	b.WriteString(fmt.Sprintf("idps_blocked_ips_active %d\n\n", blockedIPs))

	b.WriteString("# HELP idps_threat_intel_iocs Active threat intelligence indicators\n")
	b.WriteString("# TYPE idps_threat_intel_iocs gauge\n")
	b.WriteString(fmt.Sprintf("idps_threat_intel_iocs %d\n\n", threatIntelCount))

	b.WriteString("# HELP idps_cluster_nodes_online Online high availability cluster nodes\n")
	b.WriteString("# TYPE idps_cluster_nodes_online gauge\n")
	b.WriteString(fmt.Sprintf("idps_cluster_nodes_online %d\n\n", clusterNodesOnline))

	b.WriteString("# HELP idps_threat_alerts_total Total threat alerts detected by severity\n")
	b.WriteString("# TYPE idps_threat_alerts_total counter\n")
	for sev, count := range alertsTotal {
		b.WriteString(fmt.Sprintf("idps_threat_alerts_total{severity=\"%s\"} %d\n", sev, count))
	}

	return b.String()
}
