package inspect

import (
	"github.com/google/gopacket/layers"
)

// DNSInspector analyzes DNS traffic.
type DNSInspector struct{}

// Inspect checks for DNS anomalies like amplification attacks.
// Returns true if an anomaly is detected.
func (d *DNSInspector) Inspect(dns *layers.DNS, isUDP bool) bool {
	if dns == nil {
		return false
	}

	// Anomaly: ANY query over UDP (common amplification vector)
	if isUDP && !dns.QR {
		for _, q := range dns.Questions {
			if q.Type == layers.DNSType(255) { // ANY type
				return true
			}
		}
	}

	// Anomaly: Extremely large DNS responses over UDP (amplification)
	if isUDP && dns.QR {
		if len(dns.Answers) > 30 || len(dns.Additionals) > 30 {
			return true
		}
	}

	return false
}
