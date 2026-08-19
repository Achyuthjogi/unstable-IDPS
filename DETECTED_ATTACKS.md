# Top 20 Detectable Threats & Attacks

The IDPS natively supports a dual-engine detection architecture. It combines **Rate-Based Heuristics** for volumetric attacks with a **Snort-Compatible Rule Engine** (powered by an Aho-Corasick Multi-Pattern Search Engine and TCP Stream Reassembly) for deep packet inspection.

Below are the top 20 attacks, threats, and anomalies this system detects in real-time.

---

## 1. Web Application Attacks (Signature Based)
These attacks are detected by the Rule Engine scanning the reassembled TCP stream for specific malicious patterns.

1. **SQL Injection (UNION SELECT)**: Detects data exfiltration attempts leveraging the `UNION SELECT` vector.
2. **SQL Injection (OR 1=1)**: Identifies classic authentication bypass attempts in login payloads.
3. **Cross-Site Scripting (XSS)**: Identifies malicious script tag injections (`<script>`) aimed at client browsers.
4. **Command Injection**: Detects OS-level command injection attempts (e.g., appending `; cat /etc/passwd`).
5. **Directory Traversal (Signature)**: Detects relative path escape attempts (`../`) within HTTP payloads.

## 2. Denial of Service (DoS) & Floods (Heuristic Based)
These volumetric attacks are detected by the stateful rate-tracking heuristic engine.

6. **SYN Flood**: Detects rapid, incomplete TCP handshakes aimed at exhausting server connection limits.
7. **UDP Flood**: Detects unusually high volumes of UDP packets targeting the network.
8. **ICMP Flood**: Identifies ping floods designed to overwhelm network bandwidth.
9. **Ping of Death**: Detects maliciously oversized ICMP packets (e.g., > 1000 bytes).
10. **Generic DoS Flood**: Identifies massive, unclassified traffic spikes that exceed global suspicious rate thresholds.

## 3. Network Reconnaissance & Access (Heuristic Based)
11. **Port Scan**: Detects horizontal scanning by identifying a single source IP probing many unique destination ports within a 3-second window.
12. **SSH Brute Force**: Detects rapid, repeated connection attempts specifically targeting TCP Port 22.

## 4. Protocol & Configuration Anomalies (Inspector Based)
These threats are flagged by custom Protocol Inspectors that extract and validate application-layer data.

13. **HTTP Protocol Anomaly (Invalid Method)**: Flags malformed or completely invalid HTTP request methods (e.g., `INVALIDMETHOD /`).
14. **HTTP Protocol Anomaly (URI Traversal)**: The HTTP inspector independently parses request lines to flag path traversal logic anomalies, acting as a fallback to signatures.
15. **HTTP Malformed Protocol Anomaly**: Detects missing or corrupted HTTP versions/headers.
16. **Deprecated SSH Version**: Deep-inspects SSH handshakes to flag the use of highly insecure, deprecated versions like SSHv1.

## 5. Evasion & Exploit Techniques (Engine Based)
17. **TCP Fragment Evasion Defeat**: Detects attacks (such as split SQL injections) spanning multiple fragmented packets by completely reassembling the TCP stream in the flow tracker before evaluating rules.
18. **Buffer Overflow (NOP Sleds)**: Detects common exploit delivery mechanisms by scanning payloads for repeating machine code byte sequences (e.g., `\x90\x90\x90\x90`).

## 6. Infrastructure Abuse (Inspector & Heuristic Based)
19. **DNS Amplification Vector (ANY Query)**: Deep inspection of DNS queries over UDP to flag the malicious use of the `ANY` query type, commonly used in amplification DDoS attacks.
20. **ARP Spoofing / MAC Flip-Flop**: Actively monitors network MAC-to-IP mappings and alerts when multiple hardware MAC addresses claim the same IP address, neutralizing local Man-in-the-Middle (MitM) attempts.
21. **ARP Flood (Storm)**: Detects abnormally high volumes of ARP packets (e.g., > 50 pkts/sec) which can exhaust network switch CAM tables or cause localized DoS.
22. **Gratuitous ARP Abuse (Poisoning)**: Specifically monitors `ARP Reply` (Operation 2) rates to identify aggressive broadcast poisoning techniques often used to reroute local subnet traffic.
