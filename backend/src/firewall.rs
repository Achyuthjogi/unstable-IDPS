use std::process::Command;
use crate::config::Config;

pub struct FirewallManager {
    trusted_ips: Vec<String>,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self {
            trusted_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }

    fn is_safe_to_block(&self, ip: &str) -> bool {
        if self.trusted_ips.contains(&ip.to_string()) {
            return false;
        }
        if ip.starts_with("224.") || ip.starts_with("239.") || ip.ends_with(".255") {
            return false;
        }
        true
    }

    pub fn setup_gateway(&self, config: &Config) {
        if config.idps_deployment_mode != "GATEWAY" {
            return;
        }

        println!("FirewallManager: Setting up Gateway NAT routing: WAN={}, LAN={}", config.wan_interface, config.lan_interface);
        
        let _ = Command::new("sudo").args(&["sysctl", "-w", "net.ipv4.ip_forward=1"]).output();
        
        let _ = Command::new("sudo").args(&["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", &config.wan_interface, "-j", "MASQUERADE"]).output();
        let _ = Command::new("sudo").args(&["iptables", "-A", "FORWARD", "-i", &config.wan_interface, "-o", &config.lan_interface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).output();
        let _ = Command::new("sudo").args(&["iptables", "-A", "FORWARD", "-i", &config.lan_interface, "-o", &config.wan_interface, "-j", "ACCEPT"]).output();
        
        println!("FirewallManager: Gateway NAT routing configured successfully.");
    }

    pub fn teardown_gateway(&self, config: &Config) {
        if config.idps_deployment_mode != "GATEWAY" {
            return;
        }

        println!("FirewallManager: Tearing down Gateway NAT routing: WAN={}, LAN={}", config.wan_interface, config.lan_interface);
        
        let _ = Command::new("sudo").args(&["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", &config.wan_interface, "-j", "MASQUERADE"]).output();
        let _ = Command::new("sudo").args(&["iptables", "-D", "FORWARD", "-i", &config.wan_interface, "-o", &config.lan_interface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).output();
        let _ = Command::new("sudo").args(&["iptables", "-D", "FORWARD", "-i", &config.lan_interface, "-o", &config.wan_interface, "-j", "ACCEPT"]).output();
        
        println!("FirewallManager: Gateway NAT routing rules removed.");
    }

    pub fn block_ip(&self, ip: &str, config: &Config) -> bool {
        if !self.is_safe_to_block(ip) {
            println!("FirewallManager: Refused to block trusted/unsafe IP {}", ip);
            return false;
        }

        // INPUT chain
        let mut success = true;
        let output = Command::new("sudo")
            .args(&["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => println!("FirewallManager: Added Linux rule to block {} on INPUT", ip),
            _ => {
                println!("FirewallManager: Failed to block {} on INPUT", ip);
                success = false;
            }
        }

        // FORWARD chain if gateway
        if config.idps_deployment_mode == "GATEWAY" {
            let output_fwd = Command::new("sudo")
                .args(&["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"])
                .output();
            match output_fwd {
                Ok(out) if out.status.success() => println!("FirewallManager: Added Linux rule to block {} on FORWARD", ip),
                _ => {
                    println!("FirewallManager: Failed to block {} on FORWARD", ip);
                    success = false;
                }
            }
        }
        success
    }

    pub fn unblock_ip(&self, ip: &str, config: &Config) -> bool {
        let mut success = true;
        let output = Command::new("sudo")
            .args(&["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            .output();

        match output {
            Ok(out) if out.status.success() => println!("FirewallManager: Removed Linux rule for {} from INPUT", ip),
            _ => {
                println!("FirewallManager: Failed to unblock {} from INPUT", ip);
                success = false;
            }
        }

        if config.idps_deployment_mode == "GATEWAY" {
            let output_fwd = Command::new("sudo")
                .args(&["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
                .output();
            match output_fwd {
                Ok(out) if out.status.success() => println!("FirewallManager: Removed Linux rule for {} from FORWARD", ip),
                _ => {
                    println!("FirewallManager: Failed to unblock {} from FORWARD", ip);
                    success = false;
                }
            }
        }
        success
    }
}
