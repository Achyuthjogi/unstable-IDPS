#!/usr/bin/env python3
import socket
import time
import requests
import threading

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8000 # The Go backend API port, just to have an open port to hit

print(f"--- IDPS Live Attack Simulation ---")
print(f"Target: {TARGET_IP}:{TARGET_PORT}")
print("Make sure the IDPS backend is running!\n")

def test_sql_injection():
    print("[*] Testing SQL Injection (UNION SELECT)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET_IP, TARGET_PORT))
        s.send(b"GET /api/login?user=admin' UNION SELECT 1,2,3-- HTTP/1.1\r\nHost: localhost\r\n\r\n")
        s.recv(1024) # Wait for response so OS flushes payload
        s.close()
        print("    -> Payload sent.")
    except Exception as e:
        print(f"    -> Blocked or connection failed: {e}")
    time.sleep(1)

def test_xss():
    print("[*] Testing Cross-Site Scripting (XSS)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET_IP, TARGET_PORT))
        s.send(b"GET /api/search?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: localhost\r\n\r\n")
        s.recv(1024)
        s.close()
        print("    -> Payload sent.")
    except Exception as e:
        print(f"    -> Blocked or connection failed: {e}")
    time.sleep(1)

def test_directory_traversal():
    print("[*] Testing HTTP Directory Traversal...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET_IP, TARGET_PORT))
        s.send(b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
        s.recv(1024)
        s.close()
        print("    -> Payload sent.")
    except Exception as e:
        print(f"    -> Blocked or connection failed: {e}")
    time.sleep(1)

def test_port_scan():
    print("[*] Testing Port Scan Heuristics...")
    for port in range(1000, 1080): # Scan 80 ports (threshold is 20/sec -> >60 total)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, port))
            s.close()
        except:
            pass
    print("    -> Port scan finished.")
    time.sleep(1)

def test_ssh_bruteforce():
    print("[*] Testing SSH Brute Force Heuristics...")
    for _ in range(50): # Threshold is 10/sec -> need >30 total
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, 22))
            s.close()
        except:
            pass
    print("    -> SSH attempts finished.")
    time.sleep(1)

def test_syn_flood():
    print("[*] Testing SYN Flood / High TCP Rate...")
    def flood():
        for _ in range(120): # 120 * 5 = 600 packets, threshold is 150/sec -> >450 total
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect((TARGET_IP, TARGET_PORT))
                s.close()
            except:
                pass
    
    threads = []
    for _ in range(5):
        t = threading.Thread(target=flood)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
        
    print("    -> TCP flood finished.")
    time.sleep(1)

if __name__ == "__main__":
    test_sql_injection()
    test_xss()
    test_directory_traversal()
    test_ssh_bruteforce()
    test_port_scan()
    test_syn_flood()
    
    print("\n[+] Tests completed. Check the IDPS Dashboard or logs to see the detections!")
