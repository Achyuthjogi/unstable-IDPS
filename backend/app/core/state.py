import time
from typing import Dict, List, Set
from pydantic import BaseModel

class Device(BaseModel):
    ip: str
    mac: str
    first_seen: float
    last_seen: float

class Alert(BaseModel):
    id: str
    timestamp: float
    type: str
    severity: str # Low, Medium, High, Critical
    source_ip: str
    dest_ip: str
    reason: str

class AppState:
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.devices: Dict[str, Device] = {}
        self.alerts: List[Alert] = []
        self.packet_count: int = 0
        
        # Threat Timeline Data (time series)
        self.threat_timeline: List[dict] = []
        
        # Tracking states
        self.ip_packet_count: Dict[str, int] = {}
        self.ip_syn_count: Dict[str, int] = {}
        self.ip_icmp_count: Dict[str, int] = {}
        self.ip_udp_count: Dict[str, int] = {}
        self.ip_ports_accessed: Dict[str, Set[int]] = {}
        self.ip_mac_mapping: Dict[str, Set[str]] = {}
        self.ip_requests: Dict[str, int] = {}
        self.port_counts: Dict[int, int] = {}
        self.protocol_counts: Dict[str, int] = {}
        
        # Timestamps for rate limiting
        self.last_reset = time.time()
        
        # Metrics
        self.active_connections: int = 0

    def reset_tracking(self):
        self.ip_packet_count.clear()
        self.ip_syn_count.clear()
        self.ip_icmp_count.clear()
        self.ip_udp_count.clear()
        self.ip_ports_accessed.clear()
        self.ip_requests.clear()
        self.last_reset = time.time()

state = AppState()
