import time
import uuid
import subprocess
import platform
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether
from app.core.state import state, Alert, Device
from app.config import settings

def analyze_packet(packet):
    current_time = time.time()
    
    if current_time - state.last_reset > 1.0:
        state.reset_tracking()
        
    src_ip = None
    dst_ip = None
    src_mac = packet[Ether].src if Ether in packet else None
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "IP"
        
        # Track general stats
        state.packet_count += 1
        state.ip_packet_count[src_ip] = state.ip_packet_count.get(src_ip, 0) + 1
        
        if TCP in packet:
            protocol = "TCP"
            state.protocol_counts["TCP"] = state.protocol_counts.get("TCP", 0) + 1
            dst_port = packet[TCP].dport
            state.port_counts[dst_port] = state.port_counts.get(dst_port, 0) + 1
            
            if src_ip not in state.ip_ports_accessed:
                state.ip_ports_accessed[src_ip] = set()
            state.ip_ports_accessed[src_ip].add(dst_port)
            
            # SYN Flood detection
            if packet[TCP].flags == 'S':
                state.ip_syn_count[src_ip] = state.ip_syn_count.get(src_ip, 0) + 1
                if state.ip_syn_count[src_ip] > settings.SYN_FLOOD_THRESHOLD:
                    trigger_alert("SYN Flood", "Critical", src_ip, dst_ip, f"High rate of SYN packets: {state.ip_syn_count[src_ip]}/s")
                    
        elif UDP in packet:
            protocol = "UDP"
            state.protocol_counts["UDP"] = state.protocol_counts.get("UDP", 0) + 1
            dst_port = packet[UDP].dport
            state.port_counts[dst_port] = state.port_counts.get(dst_port, 0) + 1
            
            state.ip_udp_count[src_ip] = state.ip_udp_count.get(src_ip, 0) + 1
            if state.ip_udp_count[src_ip] > settings.UDP_FLOOD_THRESHOLD:
                trigger_alert("UDP Flood", "High", src_ip, dst_ip, f"High rate of UDP packets: {state.ip_udp_count[src_ip]}/s")
                
        elif ICMP in packet:
            protocol = "ICMP"
            state.protocol_counts["ICMP"] = state.protocol_counts.get("ICMP", 0) + 1
            state.ip_icmp_count[src_ip] = state.ip_icmp_count.get(src_ip, 0) + 1
            if state.ip_icmp_count[src_ip] > settings.ICMP_FLOOD_THRESHOLD:
                trigger_alert("ICMP Flood", "Medium", src_ip, dst_ip, f"High rate of ICMP packets: {state.ip_icmp_count[src_ip]}/s")
        
        # Port Scan Detection
        if src_ip in state.ip_ports_accessed and len(state.ip_ports_accessed[src_ip]) > settings.PORT_SCAN_THRESHOLD:
             trigger_alert("Port Scan", "High", src_ip, dst_ip, f"Accessed {len(state.ip_ports_accessed[src_ip])} unique ports/s")
        
        # DoS / Suspicious Connection Rate
        if state.ip_packet_count[src_ip] > settings.SUSPICIOUS_RATE_THRESHOLD:
             trigger_alert("DoS Attack", "Critical", src_ip, dst_ip, f"Excessive packet rate: {state.ip_packet_count[src_ip]}/s")

    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        protocol = "ARP"
        state.protocol_counts["ARP"] = state.protocol_counts.get("ARP", 0) + 1
        
        # ARP Spoofing detection (simplified: multiple MACs claiming same IP)
        # We track IP -> MAC mapping
    
    # Common checks for IP/MAC bindings
    if src_ip and src_mac:
        # Unknown Device Detection
        if src_mac not in state.devices:
            state.devices[src_mac] = Device(ip=src_ip, mac=src_mac, first_seen=current_time, last_seen=current_time)
            # Removed the "Unknown Device" alert to avoid alert spam for every new device
        else:
            state.devices[src_mac].last_seen = current_time
            state.devices[src_mac].ip = src_ip # update IP if changed
            
        # Duplicate IP / MAC Change Detection
        if src_ip not in state.ip_mac_mapping:
            state.ip_mac_mapping[src_ip] = set()
        
        state.ip_mac_mapping[src_ip].add(src_mac)
        
        if len(state.ip_mac_mapping[src_ip]) > 1:
            trigger_alert("Duplicate IP / ARP Spoofing", "High", src_ip, "N/A", f"Multiple MAC addresses detected for IP: {src_ip}")

def trigger_alert(type: str, severity: str, src_ip: str, dest_ip: str, reason: str):
    # Check if already blocked to avoid alert spam
    if src_ip in state.blocked_ips:
        return
        
    alert = Alert(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        type=type,
        severity=severity,
        source_ip=src_ip,
        dest_ip=dest_ip,
        reason=reason
    )
    # Check if recently alerted for same reason to avoid flooding alerts
    recent_similar = [a for a in state.alerts[-50:] if a.source_ip == src_ip and a.type == type]
    if not recent_similar or (time.time() - recent_similar[-1].timestamp > 5):
        state.alerts.append(alert)
        # Automatic blocking removed as per user request

def block_ip(ip: str):
    if ip and ip not in state.blocked_ips and ip != "127.0.0.1":
        state.blocked_ips.add(ip)
        # Clear existing alerts for this IP so they vanish from the alerts page
        state.alerts = [a for a in state.alerts if a.source_ip != ip]
        
        # Log to threat timeline
        state.threat_timeline.append({
            "timestamp": time.time(),
            "event": f"Blocked IP {ip}",
            "severity": "Critical"
        })
        
        # Actual OS level network blocking
        os_name = platform.system()
        try:
            if os_name == "Linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif os_name == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=IDPS_Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"], check=True)
            elif os_name == "Darwin": # macOS
                # Note: Requires PF to be enabled (sudo pfctl -e)
                rule = f"block drop from {ip} to any\n"
                p = subprocess.Popen(["sudo", "pfctl", "-a", f"idps/{ip}", "-f", "-"], stdin=subprocess.PIPE)
                p.communicate(input=rule.encode())
            print(f"Successfully added {os_name} block rule for {ip}")
        except Exception as e:
            print(f"Failed to apply {os_name} rule for {ip}: {e}")

def unblock_ip(ip: str):
    if ip in state.blocked_ips:
        state.blocked_ips.remove(ip)
        # Log to threat timeline
        state.threat_timeline.append({
            "timestamp": time.time(),
            "event": f"Unblocked IP {ip}",
            "severity": "Low"
        })
        
        # Actual OS level network unblocking
        os_name = platform.system()
        try:
            if os_name == "Linux":
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif os_name == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=IDPS_Block_{ip}"], check=True)
            elif os_name == "Darwin": # macOS
                subprocess.run(["sudo", "pfctl", "-a", f"idps/{ip}", "-F", "rules"], check=True)
            print(f"Successfully removed {os_name} block rule for {ip}")
        except Exception as e:
            print(f"Failed to remove {os_name} rule for {ip}: {e}")
