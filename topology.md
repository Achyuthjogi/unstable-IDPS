# IDPS Network & Security Topology

This document illustrates the designed deployment topology for the IDPS Gateway, mapping out the physical interfaces, network flow, and the multi-layered security architecture.

## Network Architecture Flowchart

```mermaid
graph TD
    %% Define styles
    classDef attacker fill:#ffebee,stroke:#c62828,stroke-width:2px;
    classDef client fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef gateway fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    classDef security fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    classDef external fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px;

    %% Nodes
    A_Internet(("Internet")):::external
    A_Phone["Android Phone<br>Gateway/Modem"]:::external
    
    subgraph IDPS_Laptop [Ubuntu Laptop - IDPS Gateway]
        direction TB
        IF_WAN["WAN Interface<br>usb0"]:::gateway
        IF_LAN["LAN Interface<br>wlan0 Bridge"]:::gateway
        
        subgraph Security_Stack [Security Layer]
            direction TB
            EBT["ebtables<br>Layer 2 MAC Filtering<br>IDPS-MAC-BLOCK"]:::security
            IPT["iptables<br>Layer 3 IP Filtering<br>IDPS-BLOCK & NAT"]:::security
            ENG["Go IDPS Engine<br>Heuristics & Protocol Inspection"]:::security
        end
    end
    
    Client1["Legitimate Client<br>Smartphone/PC"]:::client
    Client2["Attacker Client<br>Spoofing/Scanning"]:::attacker

    %% Physical Connections
    A_Internet <-->|Cellular Data| A_Phone
    A_Phone <-->|USB Tethering| IF_WAN
    
    IF_LAN <-->|Wi-Fi Hotspot| Client1
    IF_LAN <-->|Wi-Fi Hotspot| Client2

    %% Internal Traffic Flow
    IF_LAN -->|1. Ingress Packets| EBT
    EBT -.->|Dropped if MAC Blocked| DropL2((Drop))
    
    EBT -->|2. Allowed L2| IPT
    IPT -.->|Dropped if IP Blocked| DropL3((Drop))
    
    IPT -->|3. Allowed L3/NAT| IF_WAN
    IF_WAN --> IPT
    IPT --> EBT
    EBT --> IF_LAN

    %% IDPS Capture (Promiscuous)
    IF_LAN ===>|Raw Packet Capture| ENG
    ENG -.->|Triggers Blocks| EBT
    ENG -.->|Triggers Blocks| IPT

    %% Layer 2 Client-to-Client Isolation
    Client2 -.->|L2 Attack| IF_LAN
    IF_LAN -.->|ebtables FORWARD Hook| EBT
    EBT -.->|Blocked| DropL2
```

## Topology Details

1. **Hardware & Interfaces:**
   - The system is designed to run on a central gateway, such as an Ubuntu Laptop.
   - **WAN (`usb0`)**: External internet access is provided via USB tethering to a mobile device.
   - **LAN (`wlan0`)**: The laptop broadcasts a Wi-Fi Hotspot. NetworkManager typically bridges this connection, allowing devices to join the local subnet.

2. **Traffic Capture (Detection):**
   - The **Go IDPS Engine** listens in promiscuous mode on the LAN interface (`wlan0`).
   - It captures raw packets dynamically, feeding them into the heuristic engine (SYN floods, MAC spoofing, DHCP starvation) and protocol inspectors (DNS, HTTP).

3. **Multi-Layer Prevention (Blocking):**
   - **Layer 2 (ebtables)**: Placed directly on the bridge. If an attacker is identified, their hardware MAC address is inserted into the `IDPS-MAC-BLOCK` chain. This prevents the attacker from accessing the gateway *and* prevents them from laterally attacking other clients on the same Wi-Fi network.
   - **Layer 3 (iptables)**: Handles Network Address Translation (NAT) so LAN clients can reach the internet. It also contains IP-based `IDPS-BLOCK` rules in the `FORWARD` and `INPUT` chains as an additional fallback layer of defense.
