import asyncio
import json
import time
from fastapi import WebSocket
from app.core.state import state
import psutil

active_connections = set()

def get_system_stats():
    return {
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "active_connections": len(active_connections)
    }

def get_network_stats():
    top_src_ips = sorted(state.ip_packet_count.items(), key=lambda x: x[1], reverse=True)
    top_dst_ports = sorted(state.port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "packet_count": state.packet_count,
        "protocol_counts": state.protocol_counts,
        "top_src_ips": [{"ip": ip, "count": count} for ip, count in top_src_ips],
        "top_dst_ports": [{"port": port, "count": count} for port, count in top_dst_ports],
        "alerts_count": len(state.alerts),
        "blocked_ips_count": len(state.blocked_ips)
    }

async def ws_handler(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        while True:
            current_time = time.time()
            active_devices = [d.model_dump() for d in state.devices.values() if current_time - d.last_seen < 300]
            
            data = {
                "system": get_system_stats(),
                "network": get_network_stats(),
                "alerts": [a.model_dump() for a in state.alerts[-10:]],  # Send latest 10 alerts
                "devices": active_devices,
                "blocked": list(state.blocked_ips),
                "timeline": state.threat_timeline[-20:]
            }
            await websocket.send_text(json.dumps(data))
            await asyncio.sleep(1) # Send update every second
    except Exception as e:
        print(f"WebSocket Error: {e}")
    finally:
        active_connections.remove(websocket)
