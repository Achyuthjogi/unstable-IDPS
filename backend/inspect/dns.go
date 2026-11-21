package inspect

import (
	"math"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
)

func isPrivateIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168)
}

// DNSAnomalyInfo captures structured telemetry regarding a detected DNS threat.
type DNSAnomalyInfo struct {
	IsAnomaly   bool   `json:"is_anomaly"`
	ThreatType  string `json:"threat_type"`
	QueryName   string `json:"query_name"`
	Entropy     float64 `json:"entropy"`
	Description string `json:"description"`
}

// DNSInspector analyzes DNS traffic for amplification, tunneling, exfiltration, and DGA.
type DNSInspector struct{}

// CalculateShannonEntropy calculates the Shannon entropy of a string.
// Natural English/DNS labels have entropy between 2.0 and 3.4.
// Encrypted, base64, or hex data typically exceeds 3.75 - 4.5.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	total := float64(len(s))
	var entropy float64
	for _, count := range counts {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

var legitimateCDNSuffixes = []string{
	"pacloudflare.com",
	"cloudflare.com",
	"cloudflare-dns.com",
	"cloudfront.net",
	"akamaiedge.net",
	"akamai.net",
	"akamaitechnologies.com",
	"trafficmanager.net",
	"azureedge.net",
	"azure.com",
	"googleapis.com",
	"google.com",
	"1e100.net",
	"amazonaws.com",
	"fastly.net",
	"apple-dns.net",
	"icloud.com",
	"github.com",
	"githubusercontent.com",
}

func isKnownLegitimateCDN(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	for _, suffix := range legitimateCDNSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// InspectWithDetails conducts deep protocol analysis on a DNS packet.
func (d *DNSInspector) InspectWithDetails(dns *layers.DNS, isUDP bool) DNSAnomalyInfo {
	if dns == nil {
		return DNSAnomalyInfo{}
	}

	// 1. Amplification Attacks (ANY queries or abnormally large UDP payloads)
	if isUDP && !dns.QR {
		for _, q := range dns.Questions {
			if q.Type == layers.DNSType(255) { // ANY type
				return DNSAnomalyInfo{
					IsAnomaly:   true,
					ThreatType:  "DNS_AMPLIFICATION_ANY",
					QueryName:   string(q.Name),
					Description: "DNS ANY query over UDP (High-Risk Amplification Vector)",
				}
			}
		}
	}

	if isUDP && dns.QR {
		if len(dns.Answers) > 30 || len(dns.Additionals) > 30 {
			return DNSAnomalyInfo{
				IsAnomaly:   true,
				ThreatType:  "DNS_AMPLIFICATION_OVERSIZED",
				Description: "Abnormally large DNS response over UDP (>30 records)",
			}
		}
	}

	// 2. DNS Tunneling, Data Exfiltration & DGA Analysis on Queries
	for _, q := range dns.Questions {
		qName := strings.ToLower(string(q.Name))
		if isKnownLegitimateCDN(qName) {
			continue // Skip entropy exfiltration heuristics on trusted global CDNs
		}
		labels := strings.Split(qName, ".")

		for _, label := range labels {
			// Ignore standard TLDs or common empty trailing label
			if len(label) == 0 || len(label) < 16 {
				continue
			}

			entropy := CalculateShannonEntropy(label)

			// High-entropy label with substantial length indicates Base64/Hex exfiltration
			if len(label) >= 28 && entropy > 3.65 {
				return DNSAnomalyInfo{
					IsAnomaly:   true,
					ThreatType:  "DNS_DATA_EXFILTRATION",
					QueryName:   qName,
					Entropy:     math.Round(entropy*100) / 100,
					Description: "High-Entropy DNS Exfiltration / Tunneling detected in query label",
				}
			}

			// Excessively long single label (> 50 chars)
			if len(label) > 52 {
				return DNSAnomalyInfo{
					IsAnomaly:   true,
					ThreatType:  "DNS_TUNNEL_LONG_LABEL",
					QueryName:   qName,
					Entropy:     math.Round(entropy*100) / 100,
					Description: "Anomalous DNS label length (>52 bytes) characteristic of tunneling protocols",
				}
			}
		}

		// Deeply nested subdomain hierarchy (e.g. data.chunk12.auth.session.c2.attacker.com)
		if len(labels) >= 6 && len(qName) > 60 {
			return DNSAnomalyInfo{
				IsAnomaly:   true,
				ThreatType:  "DNS_DEEP_SUBDOMAIN_TUNNEL",
				QueryName:   qName,
				Description: "Suspicious deeply nested DNS subdomain structure (>6 labels)",
			}
		}
	}

	// 3. DNS Rebinding Detection (Public DNS answer resolving to RFC1918 Private IP or Loopback)
	if dns.QR {
		for _, ans := range dns.Answers {
			if ans.Type == layers.DNSTypeA && len(ans.IP) == 4 {
				ip := ans.IP
				if ip.IsLoopback() || isPrivateIPv4(ip) {
					return DNSAnomalyInfo{
						IsAnomaly:   true,
						ThreatType:  "DNS_REBINDING",
						QueryName:   string(ans.Name),
						Description: "DNS Rebinding Attempt: Public domain resolved to internal private/loopback IP",
					}
				}
			}
		}
	}

	return DNSAnomalyInfo{}
}

// Inspect preserves backward compatibility.
func (d *DNSInspector) Inspect(dns *layers.DNS, isUDP bool) bool {
	info := d.InspectWithDetails(dns, isUDP)
	return info.IsAnomaly
}
