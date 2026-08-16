# Supported Attack Detection & Prevention

The IDPS engine monitors live network traffic and uses rate-analysis and behavioral
heuristics to detect and respond to the following four attack categories:

---

## Detectable Attacks

### 1. DoS Attack — Volumetric Flooding (NET-DOS-001)
- **Severity:** Critical
- **Detection Method:** Tracks the total packet rate from a single source IP across
  all protocols using a 1-second sliding window.
- **Trigger:** Source IP exceeds `SUSPICIOUS_RATE_THRESHOLD` packets per second
  (default: **500 pkt/s**).
- **Why it works:** Legitimate hosts rarely send >500 packets/sec. Any host doing so
  is either running a stress tool, part of a botnet, or misconfigured.

---

### 2. Port Scan / Reconnaissance (NET-SCAN-001)
- **Severity:** High
- **Detection Method:** Tracks the number of *unique* TCP destination ports contacted
  by a single source IP within a 1-second sliding window.
- **Trigger:** Source IP probes more than `PORT_SCAN_THRESHOLD` unique ports per
  second (default: **10 unique ports/s**).
- **Why it works:** Scanners (nmap, masscan) sweep many ports rapidly. Normal clients
  connect to very few ports at a time (HTTP/80, HTTPS/443, etc.).

---

### 3. ICMP Flood / Ping Flood (NET-ICMP-001)
- **Severity:** Medium
- **Detection Method:** Tracks the rate of ICMP packets from a single source IP using
  a 1-second sliding window.
- **Trigger:** Source IP sends more than `ICMP_FLOOD_THRESHOLD` ICMP packets per
  second (default: **100 pkt/s**).
- **Why it works:** Normal ping traffic is low-rate (1–2 pkt/s). A ping flood uses
  high-speed ICMP bursts to saturate bandwidth or cause CPU exhaustion.

---

### 4. ARP Spoofing / Poisoning — Man-in-the-Middle (NET-ARP-001)
- **Severity:** High
- **Detection Method:** Builds an IP → MAC address binding table from observed ARP
  packets. Entries older than 60 seconds are evicted.
- **Trigger:** The engine detects **more than one distinct MAC address** claiming
  ownership of the same IP address within the 60-second window.
- **Why it works:** In a legitimate network, each IP maps to exactly one MAC. An ARP
  spoof sends forged ARP replies to redirect traffic through the attacker's machine.

---

## Prevention Capabilities

When an alert is raised (and the system is in **IPS mode** with automated mitigation
enabled), or when an operator manually blocks an IP via the dashboard:

| Action | Command executed |
|--------|-----------------|
| **Block** | `sudo iptables -A INPUT -s <IP> -j DROP` |
| **Unblock** | `sudo iptables -D INPUT -s <IP> -j DROP` |

Blocks created by automated rules expire after `BLOCK_TTL_SECONDS` (default: 600s).  
Blocks created manually from the dashboard persist for 1 year.

---

## Threshold Reference

| Setting | Default | Controls |
|---------|---------|---------|
| `SUSPICIOUS_RATE_THRESHOLD` | 500 pkt/s | DoS Attack sensitivity |
| `PORT_SCAN_THRESHOLD` | 10 ports/s | Port Scan sensitivity |
| `ICMP_FLOOD_THRESHOLD` | 100 pkt/s | ICMP Flood sensitivity |
| `BLOCK_TTL_SECONDS` | 600 s | Auto-block duration |

All thresholds can be overridden via the `.env` file in the `backend/` directory.
