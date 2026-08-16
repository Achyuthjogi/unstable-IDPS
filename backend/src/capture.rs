use pcap::Capture;
use etherparse::{SlicedPacket, InternetSlice, TransportSlice, LinkSlice};
use crate::state::{SharedState, TrafficLog};
use crate::config::Config;
use crate::firewall::FirewallManager;
use crate::detection::{analyze_packet, PacketInfo};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn start_capture(state: SharedState, config: Config, firewall: std::sync::Arc<FirewallManager>, handle: tokio::runtime::Handle) {
    let iface_name = config.interface.clone();
    
    std::thread::spawn(move || {
        println!("Starting capture on interface: {}", iface_name);
        let mut cap = match Capture::from_device(iface_name.as_str())
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true)
            .timeout(100)
            .open() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to open capture device {}: {:?}", iface_name, e);
                    return;
                }
            };

        let link_type = cap.get_datalink();
        println!("Datalink type: {:?}", link_type);

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs_f64();

                    let mut pkt_info = PacketInfo {
                        src_ip: None,
                        dst_ip: None,
                        src_mac: None,
                        dst_mac: None,
                        protocol: "UNKNOWN".to_string(),
                        src_port: None,
                        dst_port: None,
                        is_tcp_syn: false,
                        is_tcp_ack: false,
                        is_tcp_rst: false,
                        payload: Vec::new(),
                    };

                    // Parse based on datalink type
                    let parsed_packet = if link_type == pcap::Linktype::LINUX_SLL && packet.data.len() >= 16 {
                        SlicedPacket::from_ip(&packet.data[16..]).ok()
                    } else if link_type == pcap::Linktype::NULL && packet.data.len() >= 4 {
                        SlicedPacket::from_ip(&packet.data[4..]).ok()
                    } else {
                        SlicedPacket::from_ethernet(packet.data).ok()
                    };

                    if let Some(parsed) = parsed_packet {
                        // Extract MAC addresses (only available for Ethernet link type)
                        if let Some(LinkSlice::Ethernet2(eth)) = parsed.link {
                            pkt_info.src_mac = Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                eth.source()[0], eth.source()[1], eth.source()[2],
                                eth.source()[3], eth.source()[4], eth.source()[5]));
                            pkt_info.dst_mac = Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                eth.destination()[0], eth.destination()[1], eth.destination()[2],
                                eth.destination()[3], eth.destination()[4], eth.destination()[5]));

                            if eth.ether_type() == 0x0806 {
                                pkt_info.protocol = "ARP".to_string();
                            }
                        }

                        // Extract IP addresses
                        if let Some(ip) = parsed.ip {
                            match ip {
                                InternetSlice::Ipv4(ipv4, _) => {
                                    pkt_info.src_ip = Some(ipv4.source_addr().to_string());
                                    pkt_info.dst_ip = Some(ipv4.destination_addr().to_string());
                                },
                                InternetSlice::Ipv6(ipv6, _) => {
                                    pkt_info.src_ip = Some(ipv6.source_addr().to_string());
                                    pkt_info.dst_ip = Some(ipv6.destination_addr().to_string());
                                }
                            }
                        }

                        // Extract transport layer info
                        if let Some(transport) = parsed.transport {
                            match transport {
                                TransportSlice::Tcp(tcp) => {
                                    pkt_info.protocol = "TCP".to_string();
                                    pkt_info.src_port = Some(tcp.source_port());
                                    pkt_info.dst_port = Some(tcp.destination_port());
                                    pkt_info.is_tcp_syn = tcp.syn();
                                    pkt_info.is_tcp_ack = tcp.ack();
                                    pkt_info.is_tcp_rst = tcp.rst();
                                },
                                TransportSlice::Udp(udp) => {
                                    pkt_info.protocol = "UDP".to_string();
                                    pkt_info.src_port = Some(udp.source_port());
                                    pkt_info.dst_port = Some(udp.destination_port());

                                    // Traffic Log Generation for UDP (DNS)
                                    if udp.destination_port() == 53 || udp.source_port() == 53 {
                                        extract_dns_log(&state, ts, &pkt_info.src_ip, parsed.payload, &handle);
                                    }
                                },
                                TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
                                    pkt_info.protocol = "ICMP".to_string();
                                },
                                _ => {}
                            }
                        }

                        // Traffic log for TCP (HTTP/TLS)
                        if pkt_info.protocol == "TCP" && !parsed.payload.is_empty() {
                            extract_tcp_log(&state, ts, &pkt_info.src_ip, parsed.payload, &handle);
                        }
                    }

                    // Send packet to detection engine (even if parsing partially failed, src_ip might still be None and detection will skip it)
                    let state_clone = state.clone();
                    let config_clone = config.clone();
                    let firewall_clone = firewall.clone();
                    handle.spawn(async move {
                        analyze_packet(state_clone, &config_clone, &firewall_clone, pkt_info).await;
                    });
                },
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    eprintln!("Capture error: {:?}", e);
                    break;
                }
            }
        }
    });
}

fn extract_dns_log(state: &SharedState, ts: f64, src_ip: &Option<String>, payload: &[u8], handle: &tokio::runtime::Handle) {
    if payload.len() < 12 { return; }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount > 0 {
        let mut offset = 12;
        let mut domain = String::new();
        while offset < payload.len() {
            let len = payload[offset] as usize;
            if len == 0 { break; }
            if len > 63 { break; }
            offset += 1;
            if offset + len <= payload.len() {
                if !domain.is_empty() { domain.push('.'); }
                if let Ok(label) = std::str::from_utf8(&payload[offset..offset+len]) {
                    domain.push_str(label);
                }
            }
            offset += len;
        }
        if !domain.is_empty() {
            append_traffic_log(state, ts, src_ip, domain, "DNS", handle);
        }
    }
}

fn extract_tcp_log(state: &SharedState, ts: f64, src_ip: &Option<String>, payload: &[u8], handle: &tokio::runtime::Handle) {
    if let Ok(s) = std::str::from_utf8(payload) {
        if s.starts_with("GET ") || s.starts_with("POST ") || s.starts_with("PUT ") {
            for line in s.lines() {
                if line.to_lowercase().starts_with("host:") {
                    let domain = line[5..].trim().to_string();
                    append_traffic_log(state, ts, src_ip, domain, "HTTP", handle);
                    return;
                }
            }
        }
    }

    // Very basic TLS ClientHello SNI extraction
    if payload.len() > 43 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
        append_traffic_log(state, ts, src_ip, "TLS Session".to_string(), "HTTPS", handle);
    }
}

fn append_traffic_log(state: &SharedState, ts: f64, src_ip: &Option<String>, domain: String, proto: &str, handle: &tokio::runtime::Handle) {
    let src = src_ip.clone().unwrap_or_default();
    let proto_str = proto.to_string();
    let state = state.clone();

    handle.spawn(async move {
        let mut st = state.write().await;
        st.traffic_log.push_back(TrafficLog {
            timestamp: ts,
            src_ip: src,
            domain,
            proto: proto_str,
        });
        if st.traffic_log.len() > 200 {
            st.traffic_log.pop_front();
        }
    });
}
