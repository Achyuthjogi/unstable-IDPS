# 🚀 IDPS Final Evaluation Demo Guide

Welcome to the live demonstration guide for your AI-Powered Intrusion Detection and Prevention System (IDPS). 
Following these 4 simple attacks will easily prove the capability of your system and secure your 100 marks!

## ⚠️ Prerequisites
1. Ensure your backend is running (`sudo python3 run.py`).
2. Open your React Dashboard, navigate to the **Settings** tab.
3. Set **Security Mode** to **IPS (Active Blocking)** and click **Apply**.
4. Run the attacks below from a **separate machine** (like a Kali Linux VM or another laptop) connected to the same network.
*(Assume your IDPS Gateway IP is `192.168.1.100` for these commands - change it to your actual IP).*

---

### 🛑 Attack 1: High-Speed Port Scan (Reconnaissance)
**What it demonstrates:** The IDPS detects attackers aggressively probing your network for open ports before they can exploit vulnerabilities.

**Run this on the attacking machine:**
```bash
nmap -p 1-1000 -T5 192.168.1.100
```
*(The `-T5` flag makes it extremely fast, breaking the threshold of 10 unique ports per second).*

**What to show your examiner:**
- **Alerts Tab:** The system generates a `NET-SCAN-001` (Port Scan) alert with **High Severity**.
- **Blocked IPs:** The attacker is instantly locked out and placed in the Blocked IPs list.

---

### 🌊 Attack 2: ICMP Flood (Ping of Death)
**What it demonstrates:** The IDPS can differentiate between a normal diagnostic `ping` and a malicious volumetric attack designed to exhaust your network bandwidth.

**Run this on the attacking machine:**
*(First, unblock your attacker IP from the dashboard so they can attack again).*
```bash
sudo ping -f -s 1000 192.168.1.100
```
*(The `-f` flag sends packets as fast as possible, easily crossing the 50 pps threshold).*

**What to show your examiner:**
- **Traffic Analysis:** Point out the massive spike in the "Live Packet Rate" chart.
- **Alerts Tab:** Show the `NET-ICMP-001` (ICMP Flood) alert.
- **Terminal:** Show the examiner that the attacker's terminal suddenly stops receiving ping replies because the IDPS firewall automatically dropped them!

---

### 💥 Attack 3: TCP SYN Flood (Denial of Service)
**What it demonstrates:** The IDPS detects state-exhaustion attacks where an attacker attempts to crash the server by opening thousands of incomplete TCP connections.

**Run this on the attacking machine:**
*(Unblock the IP again).*
```bash
sudo hping3 -S --flood -p 80 192.168.1.100
```

**What to show your examiner:**
- **Dashboard:** Show the live packet rate shooting into the thousands.
- **Alerts Tab:** Show the `NET-DOS-001` (DoS Attack) alert with **Critical Severity**.
- **IPS Action:** Show that despite the massive volume of traffic, the system successfully identified the source and cut it off at the OS firewall level, keeping the gateway safe.

---

### 🌪️ Attack 4: UDP Flood (DDoS Simulation)
**What it demonstrates:** Attackers often use connectionless UDP traffic to overwhelm networks because it doesn't require a handshake. Your IDPS tracks UDP packet rates specifically to stop this.

**Run this on the attacking machine:**
*(Unblock the IP again).*
```bash
sudo hping3 --udp --flood -p 53 192.168.1.100
```

**What to show your examiner:**
- **Alerts Tab:** The system will generate a `NET-UDP-001` (UDP Flood) alert.
- **Protocol Distribution Chart:** Point out the massive spike in UDP traffic on the Protocol Distribution bar chart.
- **Blocked IPs:** The IP is automatically isolated, proving the IPS is capable of mitigating connectionless protocol abuse in real-time.
