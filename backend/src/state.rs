use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub name: String,
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: f64,
    pub rule_id: String,
    pub alert_type: String, // renamed from type to alert_type to avoid Rust keyword
    pub severity: String,
    pub confidence: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub reason: String,
    pub action: String,
    pub action_result: String,
    pub status: String,
    pub expires_at: Option<f64>,
    pub rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPBlock {
    pub ip: String,
    pub rule_id: String,
    pub reason: String,
    pub confidence: String,
    pub created_at: f64,
    pub expires_at: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficLog {
    pub timestamp: f64,
    pub src_ip: String,
    pub domain: String,
    pub proto: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatTimeline {
    pub timestamp: f64,
    pub event: String,
    pub severity: String,
}

pub struct AppState {
    pub blocked_ips: HashMap<String, IPBlock>,
    pub devices: HashMap<String, Device>,
    pub alerts: VecDeque<Alert>,
    pub packet_count: usize,
    
    pub threat_timeline: VecDeque<ThreatTimeline>,
    pub traffic_log: VecDeque<TrafficLog>,
    
    // Windowed tracking (timestamps)
    pub ip_packet_timestamps: HashMap<String, VecDeque<f64>>,
    pub ip_icmp_timestamps: HashMap<String, VecDeque<f64>>,
    pub ip_udp_timestamps: HashMap<String, VecDeque<f64>>,
    pub ip_syn_timestamps: HashMap<String, VecDeque<f64>>,
    pub ip_ssh_timestamps: HashMap<String, VecDeque<f64>>,
    
    // Port scan tracking: src_ip -> { dst_port -> timestamp }
    pub ip_ports_accessed: HashMap<String, HashMap<u16, f64>>,
    
    // ARP spoofing tracking: src_ip -> { mac -> timestamp }
    pub ip_mac_mapping: HashMap<String, HashMap<String, f64>>,
    
    pub port_counts: HashMap<u16, usize>,
    pub protocol_counts: HashMap<String, usize>,
    
    pub active_connections: usize,
    pub last_alert_times: HashMap<String, f64>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            blocked_ips: HashMap::new(),
            devices: HashMap::new(),
            alerts: VecDeque::with_capacity(1000),
            packet_count: 0,
            
            threat_timeline: VecDeque::with_capacity(500),
            traffic_log: VecDeque::with_capacity(200),
            
            ip_packet_timestamps: HashMap::new(),
            ip_icmp_timestamps: HashMap::new(),
            ip_udp_timestamps: HashMap::new(),
            ip_syn_timestamps: HashMap::new(),
            ip_ssh_timestamps: HashMap::new(),
            
            ip_ports_accessed: HashMap::new(),
            ip_mac_mapping: HashMap::new(),
            
            port_counts: HashMap::new(),
            protocol_counts: HashMap::new(),
            
            active_connections: 0,
            last_alert_times: HashMap::new(),
        }
    }
}

pub type SharedState = Arc<RwLock<AppState>>;
