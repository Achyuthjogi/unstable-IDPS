from pydantic import BaseModel

class Config(BaseModel):
    # Detection Thresholds
    SYN_FLOOD_THRESHOLD: int = 100 # packets per second
    ICMP_FLOOD_THRESHOLD: int = 100 # packets per second
    UDP_FLOOD_THRESHOLD: int = 200 # packets per second
    PORT_SCAN_THRESHOLD: int = 10 # unique ports per second
    SUSPICIOUS_RATE_THRESHOLD: int = 500 # total packets per second per IP
    
    # Interface
    INTERFACE: str = "wlp1s0" # Default interface, can be changed via settings

settings = Config()
