use axum::{
    extract::{Path, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
    routing::{get, post, delete},
    Router, Json,
};
use tower_http::cors::{CorsLayer, Any};
use crate::state::SharedState;
use crate::config::Config;
use crate::firewall::FirewallManager;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use sysinfo::System;

pub struct ApiState {
    pub st: SharedState,
    pub config: Arc<RwLock<Config>>,
    pub firewall: Arc<FirewallManager>,
}

pub fn create_router(state: Arc<ApiState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/alerts", get(get_alerts))
        .route("/api/alerts/:id", delete(dismiss_alert))
        .route("/api/blocked", get(get_blocked))
        .route("/api/block/:ip", post(block_ip))
        .route("/api/unblock/:ip", post(unblock_ip))
        .route("/api/settings", get(get_settings).post(update_settings))
        .route("/api/interfaces", get(get_interfaces))
        .route("/ws", get(ws_handler))
        .layer(cors)
        .with_state(state)
}

async fn get_status(State(api): State<Arc<ApiState>>) -> impl IntoResponse {
    let st = api.st.read().await;
    Json(json!({
        "status": "running",
        "packet_count": st.packet_count,
        "active_connections": st.active_connections
    }))
}

async fn get_alerts(State(api): State<Arc<ApiState>>) -> impl IntoResponse {
    let st = api.st.read().await;
    let alerts: Vec<_> = st.alerts.iter().cloned().collect();
    Json(alerts)
}

async fn dismiss_alert(State(api): State<Arc<ApiState>>, Path(alert_id): Path<String>) -> impl IntoResponse {
    let mut st = api.st.write().await;
    let original = st.alerts.len();
    st.alerts.retain(|a| a.id != alert_id);
    if st.alerts.len() < original {
        Json(json!({"status": "success", "message": "Alert dismissed"}))
    } else {
        Json(json!({"status": "not_found", "message": "Alert not found"}))
    }
}

async fn get_blocked(State(api): State<Arc<ApiState>>) -> impl IntoResponse {
    let st = api.st.read().await;
    let blocked: Vec<_> = st.blocked_ips.values().cloned().collect();
    Json(blocked)
}

async fn block_ip(State(api): State<Arc<ApiState>>, Path(ip): Path<String>) -> impl IntoResponse {
    let config = api.config.read().await;
    if api.firewall.block_ip(&ip, &config) {
        Json(json!({"status": "success", "message": format!("IP {} blocked", ip)}))
    } else {
        Json(json!({"status": "error", "message": format!("Failed to block {}", ip)}))
    }
}

async fn unblock_ip(State(api): State<Arc<ApiState>>, Path(ip): Path<String>) -> impl IntoResponse {
    let config = api.config.read().await;
    if api.firewall.unblock_ip(&ip, &config) {
        let mut st = api.st.write().await;
        st.blocked_ips.remove(&ip);
        Json(json!({"status": "success", "message": format!("IP {} unblocked", ip)}))
    } else {
        Json(json!({"status": "error", "message": format!("Failed to unblock {}", ip)}))
    }
}

async fn get_settings(State(api): State<Arc<ApiState>>) -> impl IntoResponse {
    let config = api.config.read().await;
    Json(json!({
        "IDPS_DEPLOYMENT_MODE": config.idps_deployment_mode,
        "IDPS_SECURITY_MODE": config.idps_security_mode,
        "WAN_INTERFACE": config.wan_interface,
        "LAN_INTERFACE": config.lan_interface,
        "INTERFACE": config.interface
    }))
}

async fn update_settings(
    State(api): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut config = api.config.write().await;

    let old_mode = config.idps_deployment_mode.clone();
    let old_wan = config.wan_interface.clone();
    let old_lan = config.lan_interface.clone();

    if let Some(v) = body.get("IDPS_DEPLOYMENT_MODE").and_then(|v| v.as_str()) {
        config.idps_deployment_mode = v.to_string();
    }
    if let Some(v) = body.get("IDPS_SECURITY_MODE").and_then(|v| v.as_str()) {
        config.idps_security_mode = v.to_string();
    }
    if let Some(v) = body.get("WAN_INTERFACE").and_then(|v| v.as_str()) {
        config.wan_interface = v.to_string();
    }
    if let Some(v) = body.get("LAN_INTERFACE").and_then(|v| v.as_str()) {
        config.lan_interface = v.to_string();
    }
    if let Some(v) = body.get("INTERFACE").and_then(|v| v.as_str()) {
        config.interface = v.to_string();
    }

    // Handle gateway mode transitions
    if old_mode == "GATEWAY" && config.idps_deployment_mode != "GATEWAY" {
        // Switching FROM gateway — teardown old rules
        let teardown_config = Config {
            wan_interface: old_wan,
            lan_interface: old_lan,
            idps_deployment_mode: "GATEWAY".to_string(),
            ..config.clone()
        };
        api.firewall.teardown_gateway(&teardown_config);
        println!("Settings: Tore down Gateway routing (switched to HOST mode).");
    } else if config.idps_deployment_mode == "GATEWAY" {
        // Switching TO gateway or updating gateway interfaces — teardown old, setup new
        if old_mode == "GATEWAY" {
            let teardown_config = Config {
                wan_interface: old_wan,
                lan_interface: old_lan,
                idps_deployment_mode: "GATEWAY".to_string(),
                ..config.clone()
            };
            api.firewall.teardown_gateway(&teardown_config);
        }
        api.firewall.setup_gateway(&config);
        println!("Settings: Set up Gateway routing: WAN={}, LAN={}", config.wan_interface, config.lan_interface);
    }

    println!("Settings updated: mode={}, security={}, wan={}, lan={}, interface={}",
        config.idps_deployment_mode, config.idps_security_mode,
        config.wan_interface, config.lan_interface, config.interface);

    Json(json!({
        "status": "success",
        "message": format!("Configuration applied. Mode: {}, Security: {}",
            config.idps_deployment_mode, config.idps_security_mode)
    }))
}

async fn get_interfaces() -> impl IntoResponse {
    let mut interfaces = vec![];
    if let Ok(devices) = pcap::Device::list() {
        for d in devices {
            interfaces.push(d.name);
        }
    }
    // ensure localhost and commonly known names are at least available if list is empty
    if interfaces.is_empty() {
        interfaces.push("eth0".to_string());
        interfaces.push("wlp1s0".to_string());
        interfaces.push("lo".to_string());
    }
    Json(interfaces)
}

async fn ws_handler(ws: WebSocketUpgrade, State(api): State<Arc<ApiState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, api.st.clone(), api.config.clone()))
}

async fn handle_socket(mut socket: WebSocket, state: SharedState, config: Arc<RwLock<Config>>) {
    let mut ticker = interval(Duration::from_secs(1));
    let mut sys = System::new_all();
    
    loop {
        ticker.tick().await;
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        
        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let mem_usage = (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0;
        
        let st = state.read().await;
        
        let mut top_src_ips: Vec<_> = st.ip_packet_timestamps.iter()
            .map(|(ip, ts)| (ip.clone(), ts.len()))
            .collect();
        top_src_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_src_ips.truncate(10);
        
        let mut top_dst_ports: Vec<_> = st.port_counts.iter()
            .map(|(p, c)| (*p, *c))
            .collect();
        top_dst_ports.sort_by(|a, b| b.1.cmp(&a.1));
        top_dst_ports.truncate(5);

        let c = config.read().await;
        let target_iface = if c.idps_deployment_mode == "GATEWAY" { c.lan_interface.clone() } else { c.interface.clone() };
        drop(c);
        
        let mut gateway_ip = "Unknown".to_string();
        if let Ok(devices) = pcap::Device::list() {
            for d in devices {
                if d.name == target_iface {
                    for addr in d.addresses {
                        if addr.addr.is_ipv4() {
                            gateway_ip = addr.addr.to_string();
                            break;
                        }
                    }
                }
            }
        }

        let data = json!({
            "system": {
                "cpu": cpu_usage,
                "memory": mem_usage,
                "active_connections": st.active_connections,
                "gateway_ip": gateway_ip
            },
            "network": {
                "packet_count": st.packet_count,
                "protocol_counts": st.protocol_counts,
                "top_src_ips": top_src_ips.into_iter().map(|(ip, count)| json!({"ip": ip, "count": count})).collect::<Vec<_>>(),
                "top_dst_ports": top_dst_ports.into_iter().map(|(port, count)| json!({"port": port, "count": count})).collect::<Vec<_>>(),
                "alerts_count": st.alerts.len(),
                "blocked_ips_count": st.blocked_ips.len()
            },
            "alerts": st.alerts.iter().rev().take(10).collect::<Vec<_>>(),
            "devices": st.devices.values().collect::<Vec<_>>(),
            "blocked": st.blocked_ips.values().collect::<Vec<_>>(),
            "timeline": st.alerts.iter().rev().take(20).map(|a| json!({
                "timestamp": a.timestamp,
                "event": a.alert_type,
                "severity": a.severity
            })).collect::<Vec<_>>(),
            "traffic_log": st.traffic_log.iter().rev().take(50).collect::<Vec<_>>()
        });

        if socket.send(Message::Text(data.to_string())).await.is_err() {
            break;
        }
    }
}
