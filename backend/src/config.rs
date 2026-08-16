use dotenvy::dotenv;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub idps_deployment_mode: String,
    pub idps_security_mode: String,
    pub wan_interface: String,
    pub lan_interface: String,
    pub interface: String,
    
    pub suspicious_rate_threshold: usize,
    pub port_scan_threshold: usize,
    pub icmp_flood_threshold: usize,
    pub udp_flood_threshold: usize,
    pub syn_flood_threshold: usize,
    pub ssh_brute_force_threshold: usize,
    pub block_ttl_seconds: u64,
}

impl Config {
    pub fn load() -> Self {
        dotenv().ok(); // Ignore if .env doesn't exist

        Self {
            idps_deployment_mode: env::var("IDPS_DEPLOYMENT_MODE").unwrap_or_else(|_| "HOST".to_string()),
            idps_security_mode: env::var("IDPS_SECURITY_MODE").unwrap_or_else(|_| "IDS".to_string()),
            wan_interface: env::var("WAN_INTERFACE").unwrap_or_else(|_| "enx2a7345453743".to_string()),
            lan_interface: env::var("LAN_INTERFACE").unwrap_or_else(|_| "wlp1s0".to_string()),
            interface: env::var("INTERFACE").unwrap_or_else(|_| "wlp1s0".to_string()),

            suspicious_rate_threshold: parse_env("SUSPICIOUS_RATE_THRESHOLD", 500),
            port_scan_threshold: parse_env("PORT_SCAN_THRESHOLD", 20),
            icmp_flood_threshold: parse_env("ICMP_FLOOD_THRESHOLD", 100),
            udp_flood_threshold: parse_env("UDP_FLOOD_THRESHOLD", 200),
            syn_flood_threshold: parse_env("SYN_FLOOD_THRESHOLD", 150),
            ssh_brute_force_threshold: parse_env("SSH_BRUTE_FORCE_THRESHOLD", 10),
            block_ttl_seconds: parse_env("BLOCK_TTL_SECONDS", 600),
        }
    }
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(default)
}
