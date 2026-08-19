# IDPS Detected Attacks & Threats

The IDPS natively supports a dual-engine detection architecture combining **Rate-Based Heuristics** and a **Snort-Compatible Rule Engine**. 

Below is the comprehensive list of the **15 Mandatory Attacks** required by the project specifications, all of which are actively detected and prevented by the system in real-time.

---

## 1. Local Network & Layer 2 Attacks

1. **ARP Spoofing:** *(Affects: Data Confidentiality & Integrity - enables Man-in-the-Middle attacks to intercept or modify traffic)* Actively monitors network MAC-to-IP mappings and alerts when multiple hardware MAC addresses claim the same IP address, neutralizing Man-in-the-Middle (MitM) attempts.
2. **ARP Flooding:** *(Affects: Network Availability - exhausts switch and router resources)* Detects abnormally high volumes of ARP packets which can exhaust network bandwidth or cause localized DoS.
3. **MAC Flooding:** *(Affects: Network Availability & Confidentiality - forces switches into hub mode, exposing all traffic)* Tracks the rate of unique Source MAC addresses per second. Triggers an alert when massive MAC generation is detected, preventing CAM Table Exhaustion on local switches.
4. **DHCP Starvation:** *(Affects: Network Availability - prevents new devices from joining the network)* Monitors DHCP Discover packets and alerts when an excessive number of requests come from rapidly spoofed MAC addresses, preventing IP pool exhaustion.
5. **Rogue DHCP Server:** *(Affects: Network Integrity & Routing - misdirects traffic to malicious gateways)* Monitors DHCP Offer packets and alerts if an offer originates from an IP address other than the statically configured legitimate DHCP server.

## 2. DNS Anomalies & Infrastructure Abuse

6. **DNS Spoofing:** *(Affects: Network Integrity - redirects users to malicious or phishing websites)* Detects unauthorized DNS Replies originating from internal hosts (other than the designated gateway), preventing DNS cache poisoning on the local network.
7. **DNS Tunneling:** *(Affects: Data Confidentiality - bypasses firewalls to steal data or establish C2 channels)* Deeply inspects DNS Queries and TXT replies, flagging extremely long domain labels (>63 chars) or massive TXT payloads indicative of data exfiltration or tunneling.

## 3. Reconnaissance & Lateral Movement

8. **TCP Port Scanning:** *(Affects: Network Security Posture - reveals vulnerable services to attackers)* Detects horizontal and vertical scanning by identifying a single source IP probing many unique destination ports within a rapid time window.
9. **ICMP Sweep:** *(Affects: Network Security Posture - reveals active hosts on the subnet)* Identifies "Ping Sweeps" by tracking a single Source IP sending ICMP Echo Requests to multiple distinct Destination IPs across the subnet.
10. **SMB/Windows Service Scanning:** *(Affects: Endpoint Security - identifies targets for ransomware and worms)* Uses the Snort Rule Engine to immediately detect rapid, stateless probes targeting Windows administrative ports (TCP 139 and 445).
11. **Abnormal Lateral Movement:** *(Affects: Entire Network Security - allows an attacker to spread from one compromised host to others)* Heuristically detects unexpected lateral traversals by monitoring internal-to-internal IP traffic. Flags instances where an internal host suddenly scans or connects to multiple other internal hosts over administrative ports (SSH, RDP, SMB).

## 4. Volumetric Denial of Service (DoS)

12. **TCP SYN Flood:** *(Affects: Server Availability - consumes connection queues and crashes services)* Detects rapid, incomplete TCP handshakes aimed at exhausting server connection limits.
13. **UDP Flood:** *(Affects: Network Bandwidth Availability - saturates network links)* Detects unusually high volumes of UDP packets targeting the network, adjusting thresholds based on payload size.
14. **ICMP Flood:** *(Affects: Network Bandwidth Availability - overwhelms routing infrastructure)* Identifies massive ping floods designed to overwhelm network bandwidth and routing infrastructure.

## 5. Brute Force & Authentication

15. **Authentication Brute-Force Attempts:** *(Affects: System Access & Confidentiality - leads to unauthorized account takeover)* Employs both heuristic rate-tracking (for SSH on Port 22) and deep packet inspection signatures (for FTP Port 21 and Telnet Port 23) to catch repeated "Login incorrect" responses and rapid connection attempts.
