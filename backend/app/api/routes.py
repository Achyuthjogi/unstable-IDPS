from fastapi import APIRouter
from app.core.state import state

router = APIRouter()

@router.get("/status")
def get_status():
    return {"status": "running", "packet_count": state.packet_count}

@router.get("/alerts")
def get_alerts():
    return state.alerts

@router.get("/blocked")
def get_blocked_ips():
    return list(state.blocked_ips)

@router.post("/unblock/{ip}")
def api_unblock_ip(ip: str):
    if ip in state.blocked_ips:
        core_unblock_ip(ip)
        return {"status": "success", "message": f"IP {ip} unblocked"}
    return {"status": "not_found", "message": "IP not blocked"}

from app.core.detection import block_ip as core_block_ip, unblock_ip as core_unblock_ip
import threading
from scapy.all import Ether, ARP, sendp
from app.config import settings
import psutil

@router.post("/block/{ip}")
def api_block_ip(ip: str):
    core_block_ip(ip)
    return {"status": "success", "message": f"IP {ip} blocked manually"}

@router.post("/scan")
def active_scan():
    try:
        addrs = psutil.net_if_addrs().get(settings.INTERFACE, [])
        ip = None
        for addr in addrs:
            if getattr(addr, 'family') == 2: # AF_INET
                ip = addr.address
                break
                
        if not ip:
            return {"status": "error", "message": "Could not determine IP for interface"}
            
        parts = ip.split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        
        def send_arp():
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), iface=settings.INTERFACE, verbose=False)
            
        threading.Thread(target=send_arp, daemon=True).start()
        return {"status": "success", "message": f"Started ARP scan on {subnet}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

