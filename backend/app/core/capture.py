import threading
from scapy.all import sniff, IP
from app.core.detection import analyze_packet
from app.core.state import state
from app.config import settings

class PacketCapture:
    def __init__(self):
        self.is_running = False
        self.capture_thread = None

    def start(self):
        if not self.is_running:
            self.is_running = True
            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()
            print(f"Started packet capture on interface {settings.INTERFACE}")

    def stop(self):
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            print("Stopped packet capture")

    def _packet_handler(self, packet):
        # Simulate prevention by ignoring packets from blocked IPs
        if IP in packet:
            src_ip = packet[IP].src
            if src_ip in state.blocked_ips:
                return # Blocked!
                
        analyze_packet(packet)

    def _capture_loop(self):
        # We sniff packets in a loop checking self.is_running
        # A small timeout allows the thread to exit gracefully
        try:
            while self.is_running:
                sniff(iface=settings.INTERFACE, prn=self._packet_handler, store=0, timeout=1.0)
        except PermissionError:
            print("CRITICAL ERROR: Root privileges are required to capture packets. Please restart the backend using sudo.")
            import time
            while self.is_running:
                time.sleep(1)

capture = PacketCapture()
