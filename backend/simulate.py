import socket
import time
import threading
import subprocess
import urllib.request
import json
import ssl

target = "127.0.0.1"

def send_tcp(port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target, port))
        s.sendall(payload)
        s.close()
    except Exception:
        pass

def send_udp(port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (target, port))
        s.close()
    except Exception:
        pass

def print_step(step, name):
    print(f"[{step}/22] {name}")

print("Starting 22-Danger Simulation for IDPS...")
time.sleep(1)

# 1. SQL Injection (UNION SELECT)
print_step(1, "SQL Injection (UNION SELECT)")
send_tcp(80, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nUNION SELECT * FROM users")
time.sleep(0.2)

# 2. SQL Injection (OR 1=1)
print_step(2, "SQL Injection (OR 1=1)")
send_tcp(80, b"POST /login HTTP/1.1\r\nHost: localhost\r\n\r\nadmin' OR 1=1--")
time.sleep(0.2)

# 3. Cross-Site Scripting (XSS)
print_step(3, "Cross-Site Scripting (XSS)")
send_tcp(80, b"GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: localhost\r\n\r\n")
time.sleep(0.2)

# 4. Directory Traversal
print_step(4, "Directory Traversal")
send_tcp(80, b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
time.sleep(0.2)

# 5. Command Injection
print_step(5, "Command Injection")
send_tcp(80, b"GET /ping?ip=127.0.0.1; cat /etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
time.sleep(0.2)

# 6. NOP Sled (Buffer Overflow)
print_step(6, "NOP Sled Detected (Buffer Overflow)")
send_tcp(8080, b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90")
time.sleep(0.2)

# 7. Invalid HTTP Method
print_step(7, "Invalid HTTP Method")
send_tcp(80, b"INVALIDMETHOD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
time.sleep(0.2)

# 8. Deprecated SSH Version
print_step(8, "Deprecated SSH Version (SSHv1)")
send_tcp(22, b"SSH-1.5-Client\r\n")
time.sleep(0.2)

# 9. HTTP Protocol Anomaly (Directory Traversal in URI without rule match)
print_step(9, "HTTP Protocol Anomaly (Path Traversal)")
send_tcp(80, b"GET /../ HTTP/1.1\r\nHost: localhost\r\n\r\n")
time.sleep(0.2)

# 10. DNS ANY Query (Amplification Vector)
print_step(10, "DNS ANY Query (Amplification Vector)")
dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\xff\x00\x01"
send_udp(53, dns_query)
time.sleep(0.2)

# 11. DNS Amplification (Large UDP flood on port 53)
print_step(11, "DNS Amplification Heuristic")
for _ in range(30):
    send_udp(53, b"A" * 600)
time.sleep(0.2)

# 12. Port Scan
print_step(12, "Port Scan")
for port in range(1000, 1030):
    send_tcp(port, b"")
time.sleep(1)

# 13. SSH Brute Force
print_step(13, "SSH Brute Force")
for _ in range(15):
    send_tcp(22, b"")
time.sleep(1)

# 14. UDP Flood
print_step(14, "UDP Flood")
for _ in range(250):
    send_udp(12345, b"UDPFloodPayload")
time.sleep(1)

# 15. ICMP Flood
print_step(15, "ICMP Flood")
try:
    subprocess.run(["ping", "-f", "-c", "150", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except:
    pass
time.sleep(1)

# 16. SYN Flood
print_step(16, "SYN Flood")
def connect_syn():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((target, 80))
    except:
        pass
threads = []
for _ in range(200):
    t = threading.Thread(target=connect_syn)
    t.start()
    threads.append(t)
for t in threads:
    t.join()
time.sleep(1)

# 17. Generic DoS Flood
print_step(17, "Generic DoS Flood")
for _ in range(6000):
    send_udp(8080, b"A")
time.sleep(1)

# 18. Ping of Death
print_step(18, "Ping of Death")
try:
    subprocess.run(["ping", "-s", "2000", "-c", "1", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except:
    pass
time.sleep(1)

# 19. HTTP Malformed Protocol Anomaly
print_step(19, "HTTP Malformed Protocol Anomaly")
send_tcp(80, b"GET / HTTP 1.1\r\n\r\n")
time.sleep(0.5)

# 20. Large Payload Transfer
print_step(20, "Large Payload Transfer")
send_tcp(80, b"A" * 65000)
time.sleep(2)

# 21. Man-in-the-Middle (MITM) / SSL Stripping
print_step(21, "MITM / SSL Stripping (Cleartext Password)")
send_tcp(80, b"POST /login HTTP/1.1\r\nHost: localhost\r\n\r\nusername=admin&password=secret")
time.sleep(0.5)

# 22. Malware / Command-and-Control (C2)
print_step(22, "Malware / Command-and-Control (C2)")
send_tcp(80, b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)\r\n\r\n")
time.sleep(0.5)


print("\nSimulation Finished. Fetching results from IDPS Backend...")
time.sleep(2)

try:
    req = urllib.request.Request("http://127.0.0.1:8000/api/alerts")
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        print("\n--- IDPS ALERTS DETECTED ---")
        for alert in data:
            print(f"[{alert['severity']}] {alert['alert_type']}: {alert['reason']} (Rule: {alert['rule_id']})")
except Exception as e:
    print(f"Could not fetch alerts from IDPS API: {e}")
