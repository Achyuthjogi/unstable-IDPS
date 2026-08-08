# Supported Attack Detection & Prevention

The IDPS (Intrusion Detection and Prevention System) engine currently monitors live network traffic and uses rate-analysis and behavioral heuristics to detect and prevent the following types of network attacks:

## Detectable Attacks

1. **TCP SYN Flood (DDoS/DoS)**
   - **Detection Method:** Monitors the rate of incoming TCP packets with the SYN flag set from a single IP address.
   - **Trigger:** Exceeding the `SYN_FLOOD_THRESHOLD` (default: 100 packets/sec).

2. **UDP Flood (DDoS/DoS)**
   - **Detection Method:** Monitors the sheer volume of UDP datagrams arriving from a specific source IP.
   - **Trigger:** Exceeding the `UDP_FLOOD_THRESHOLD`.

3. **ICMP Flood / Ping Flood**
   - **Detection Method:** Monitors the rate of ICMP (ping) requests. High volumes are often used to overwhelm network bandwidth.
   - **Trigger:** Exceeding the `ICMP_FLOOD_THRESHOLD`.

4. **Port Scanning / Reconnaissance**
   - **Detection Method:** Tracks the number of unique destination ports a single source IP attempts to access within a short time window.
   - **Trigger:** Exceeding the `PORT_SCAN_THRESHOLD` (default: 20 unique ports/sec).

5. **Volumetric DoS (General)**
   - **Detection Method:** A catch-all heuristic that tracks the total packet rate (regardless of protocol) from a single IP.
   - **Trigger:** Exceeding the `SUSPICIOUS_RATE_THRESHOLD`.

6. **ARP Spoofing / Poisoning (Man-in-the-Middle)**
   - **Detection Method:** Tracks IP-to-MAC address bindings on the local network. 
   - **Trigger:** If the engine detects multiple different MAC addresses claiming to own the same IP address, it flags a "Duplicate IP / ARP Spoofing" critical alert.

## Prevention Capabilities

- **Real-Time Firewall Blocking:** When an IP address is flagged and blocked (either manually via the dashboard or through automated mitigation if enabled), the backend engine interfaces directly with the Linux kernel firewall (`iptables`).
- **Action Taken:** It executes `sudo iptables -A INPUT -s <Attacker_IP> -j DROP`, instantly dropping all inbound connections and packets from the malicious source at the OS level before they can reach vulnerable applications.
- **Restoration:** IPs can be unblocked, which executes `sudo iptables -D INPUT -s <Attacker_IP> -j DROP`, safely removing the firewall restriction.
