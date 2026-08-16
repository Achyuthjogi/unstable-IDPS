use crate::state::{SharedState, Alert, Device, IPBlock, ThreatTimeline};
use crate::config::Config;
use crate::firewall::FirewallManager;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn get_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

pub struct PacketInfo {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub protocol: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub is_tcp_syn: bool,
    pub is_tcp_ack: bool,
    pub is_tcp_rst: bool,
    pub payload: Vec<u8>,
}

pub async fn analyze_packet(
    state: SharedState,
    config: &Config,
    firewall: &FirewallManager,
    packet: PacketInfo,
) {
    let current_time = get_timestamp();

    // 1. Device tracking
    if let (Some(ip), Some(mac)) = (&packet.src_ip, &packet.src_mac) {
        let mut st = state.write().await;
        let device = st.devices.entry(mac.clone()).or_insert_with(|| Device {
            ip: ip.clone(),
            mac: mac.clone(),
            name: "Unknown".to_string(),
            first_seen: current_time,
            last_seen: current_time,
        });
        device.last_seen = current_time;
        if device.ip != *ip {
            device.ip = ip.clone();
        }
    }

    let src_ip = match &packet.src_ip {
        Some(ip) => ip.clone(),
        None => return,
    };

    let dst_ip = packet.dst_ip.clone().unwrap_or_else(|| "N/A".to_string());

    // Skip blocked IPs
    {
        let st = state.read().await;
        if config.idps_security_mode == "IPS" && st.blocked_ips.contains_key(&src_ip) {
            return;
        }
    }

    let mut st = state.write().await;
    st.packet_count += 1;
    let proto = packet.protocol.clone();
    *st.protocol_counts.entry(proto.clone()).or_insert(0) += 1;

    if let Some(port) = packet.dst_port {
        *st.port_counts.entry(port).or_insert(0) += 1;
    }

    // Rate Tracking — use a 3-second sliding window for smoother detection
    let add_timestamp = |timestamps: &mut std::collections::VecDeque<f64>, current: f64| -> usize {
        while let Some(front) = timestamps.front() {
            if current - front > 3.0 {
                timestamps.pop_front();
            } else {
                break;
            }
        }
        timestamps.push_back(current);
        // Return rate per second (count / window_size)
        (timestamps.len() as f64 / 3.0) as usize
    };

    let packet_rate = {
        let ts = st.ip_packet_timestamps.entry(src_ip.clone()).or_insert_with(|| std::collections::VecDeque::with_capacity(5000));
        add_timestamp(ts, current_time)
    };

    let mut is_port_scan = false;

    // Check recent port scan alerts for this IP to suppress DoS
    let scan_key = format!("{}_NET-SCAN-001", src_ip);
    if let Some(&last_scan) = st.last_alert_times.get(&scan_key) {
        if current_time - last_scan < 30.0 {
            is_port_scan = true;
        }
    }

    // ARP Spoofing
    if packet.protocol == "ARP" {
        if let Some(src_mac) = &packet.src_mac {
            let macs = st.ip_mac_mapping.entry(src_ip.clone()).or_insert_with(std::collections::HashMap::new);
            macs.insert(src_mac.clone(), current_time);
            macs.retain(|_, v| current_time - *v <= 60.0);
            let mac_count = macs.len();
            if mac_count > 1 {
                trigger_alert(
                    &mut st, config, firewall, current_time,
                    "NET-ARP-001", "Duplicate IP / ARP Spoofing", "High", "Medium",
                    &src_ip, &dst_ip, &format!("ARP Spoofing ({} MACs)", mac_count), mac_count as f64
                );
            }
        }
    }

    // TCP Port Scan — only count SYN packets (not SYN+ACK, not data)
    let mut unique_ports_rate = 0;
    if packet.protocol == "TCP" {
        if packet.is_tcp_syn && !packet.is_tcp_ack && !packet.is_tcp_rst {
            // Track for Port Scan
            if let Some(dst_port) = packet.dst_port {
                let ports = st.ip_ports_accessed.entry(src_ip.clone()).or_insert_with(std::collections::HashMap::new);
                ports.insert(dst_port, current_time);
                ports.retain(|_, v| current_time - *v <= 3.0);
                unique_ports_rate = ports.len();
            }

            // Track for SYN Flood
            let syn_rate = {
                let ts = st.ip_syn_timestamps.entry(src_ip.clone()).or_insert_with(|| std::collections::VecDeque::with_capacity(5000));
                add_timestamp(ts, current_time)
            };
            if syn_rate > config.syn_flood_threshold && unique_ports_rate <= 5 { // Only trigger if it's not clearly a port scan
                trigger_alert(
                    &mut st, config, firewall, current_time,
                    "NET-SYN-001", "SYN Flood", "High", "High",
                    &src_ip, &dst_ip, &format!("SYN Flood ({} pkts/s)", syn_rate), syn_rate as f64
                );
            }
            // Track for SSH Brute Force (Port 22 spam)
            if let Some(22) = packet.dst_port {
                let ssh_rate = {
                    let ts = st.ip_ssh_timestamps.entry(src_ip.clone()).or_insert_with(|| std::collections::VecDeque::with_capacity(500));
                    add_timestamp(ts, current_time)
                };
                if ssh_rate > config.ssh_brute_force_threshold {
                    trigger_alert(
                        &mut st, config, firewall, current_time,
                        "NET-SSH-001", "SSH Brute Force", "Critical", "High",
                        &src_ip, &dst_ip, &format!("SSH Brute Force ({} attempts/3s)", ssh_rate), ssh_rate as f64
                    );
                }
            }
        }
    }

    if unique_ports_rate > 5 {
        is_port_scan = true;
    }

    if unique_ports_rate > config.port_scan_threshold {
        trigger_alert(
            &mut st, config, firewall, current_time,
            "NET-SCAN-001", "Port Scan", "High", "High",
            &src_ip, &dst_ip, &format!("Port Scan ({} ports/3s)", unique_ports_rate), unique_ports_rate as f64
        );
    }

    // UDP Flood — only detect on non-standard ports
    // Exclude: DNS(53), DHCP(67/68), QUIC/HTTP3(443), NTP(123), mDNS(5353), SSDP(1900)
    if packet.protocol == "UDP" {
        let well_known_port = |p: Option<u16>| -> bool {
            matches!(p, Some(53) | Some(67) | Some(68) | Some(443) | Some(80)
                      | Some(123) | Some(5353) | Some(1900) | Some(8443) | Some(8080))
        };

        let is_known = well_known_port(packet.src_port) || well_known_port(packet.dst_port);

        if !is_known {
            let udp_rate = {
                let ts = st.ip_udp_timestamps.entry(src_ip.clone()).or_insert_with(|| std::collections::VecDeque::with_capacity(5000));
                add_timestamp(ts, current_time)
            };
            if udp_rate > config.udp_flood_threshold {
                trigger_alert(
                    &mut st, config, firewall, current_time,
                    "NET-UDP-001", "UDP Flood", "Medium", "High",
                    &src_ip, &dst_ip, &format!("UDP Flood ({} pkts/s)", udp_rate), udp_rate as f64
                );
            }
        }

        // DNS Amplification Attack (Large responses from port 53)
        if packet.src_port == Some(53) && packet.payload.len() > 500 {
            let dns_rate = {
                let ts = st.ip_udp_timestamps.entry(src_ip.clone()).or_insert_with(|| std::collections::VecDeque::with_capacity(5000));
                add_timestamp(ts, current_time)
            };
            if dns_rate > 20 { // More than 20 large DNS packets per 3 seconds is suspicious
                trigger_alert(
                    &mut st, config, firewall, current_time,
                    "NET-DNS-001", "DNS Amplification", "High", "High",
                    &src_ip, &dst_ip, &format!("DNS Amplification ({} pkts/3s)", dns_rate), dns_rate as f64
                );
            }
        }
    }

    // ICMP Flood
    if packet.protocol == "ICMP" {
        let icmp_rate = {
            let ts = st.ip_icmp_timestamps.entry(src_ip.clone()).or_insert_with(|| std::collections::VecDeque::with_capacity(5000));
            add_timestamp(ts, current_time)
        };
        if icmp_rate > config.icmp_flood_threshold {
            trigger_alert(
                &mut st, config, firewall, current_time,
                "NET-ICMP-001", "ICMP Flood", "Medium", "High",
                &src_ip, &dst_ip, &format!("ICMP Flood ({} pkts/s)", icmp_rate), icmp_rate as f64
            );
        }

        // Ping of Death (Oversized ICMP packets)
        if packet.payload.len() > 1000 {
            trigger_alert(
                &mut st, config, firewall, current_time,
                "NET-POD-001", "Ping of Death", "Critical", "High",
                &src_ip, &dst_ip, &format!("Oversized ICMP ({} bytes)", packet.payload.len()), 1.0
            );
        }
    }

    // DoS Attack (Generic Flood) — only trigger on genuinely high rates, not normal browsing
    if packet_rate > config.suspicious_rate_threshold && !is_port_scan {
        trigger_alert(
            &mut st, config, firewall, current_time,
            "NET-DOS-001", "DoS Attack", "Critical", "High",
            &src_ip, &dst_ip, &format!("DoS Attack ({} pkts/s)", packet_rate), packet_rate as f64
        );
    }
}

fn trigger_alert(
    st: &mut tokio::sync::RwLockWriteGuard<'_, crate::state::AppState>,
    config: &Config,
    firewall: &FirewallManager,
    current_time: f64,
    rule_id: &str,
    alert_type: &str,
    severity: &str,
    confidence: &str,
    src_ip: &str,
    dst_ip: &str,
    reason: &str,
    rate: f64,
) {
    // Throttle: only one alert per IP per rule every 30 seconds
    let throttle_key = format!("{}_{}", src_ip, rule_id);
    if let Some(&last_alert) = st.last_alert_times.get(&throttle_key) {
        if current_time - last_alert < 30.0 {
            return;
        }
    }
    st.last_alert_times.insert(throttle_key, current_time);

    let mut alert = Alert {
        id: Uuid::new_v4().to_string(),
        timestamp: current_time,
        rule_id: rule_id.to_string(),
        alert_type: alert_type.to_string(),
        severity: severity.to_string(),
        confidence: confidence.to_string(),
        source_ip: src_ip.to_string(),
        dest_ip: dst_ip.to_string(),
        reason: reason.to_string(),
        action: "NONE".to_string(),
        action_result: "NOT_APPLICABLE".to_string(),
        status: "NEW".to_string(),
        expires_at: None,
        rate,
    };

    if config.idps_security_mode == "IDS" {
        alert.action = "ALERT".to_string();
        alert.action_result = "SUCCESS".to_string();
        alert.status = "LOGGED".to_string();
    } else {
        if severity == "High" || severity == "Critical" || confidence == "High" || confidence == "Critical" {
            alert.action = "BLOCK".to_string();
            if firewall.block_ip(src_ip, config) {
                alert.action_result = "SUCCESS".to_string();
                alert.status = "BLOCKED".to_string();
                let expires_at = current_time + config.block_ttl_seconds as f64;
                alert.expires_at = Some(expires_at);

                st.blocked_ips.insert(src_ip.to_string(), IPBlock {
                    ip: src_ip.to_string(),
                    rule_id: rule_id.to_string(),
                    reason: reason.to_string(),
                    confidence: confidence.to_string(),
                    created_at: current_time,
                    expires_at,
                });

                st.threat_timeline.push_back(ThreatTimeline {
                    timestamp: current_time,
                    event: format!("Blocked IP {} (Rule: {})", src_ip, rule_id),
                    severity: severity.to_string(),
                });
            } else {
                alert.action_result = "FAILED".to_string();
                alert.status = "BLOCK_FAILED".to_string();
            }
        } else {
            alert.action = "ALERT".to_string();
            alert.action_result = "SUCCESS".to_string();
            alert.status = "LOGGED (BELOW THRESHOLD)".to_string();
        }
    }

    st.alerts.push_back(alert);
    if st.alerts.len() > 1000 {
        st.alerts.pop_front();
    }
}
