# IDPS Codebase Structure & Component Responsibilities

The IDPS codebase is split into a Python FastAPI backend and a React frontend. Below is a detailed breakdown of what each core file does.

## Backend (`/backend`)
The backend is responsible for packet capture, threat detection, firewall management, and serving the API/WebSockets.

*   **`main.py`**: The main FastAPI application entry point. Handles application startup/shutdown events (starting the packet capture thread, setting up Gateway NAT routing), mounts the API router, and serves the WebSocket endpoint.
*   **`app/config.py`**: Centralized configuration management. Loads environment variables (Deployment Mode, Interfaces, Thresholds) and provides them to the rest of the application.
*   **`app/api/routes.py`**: Defines the HTTP API endpoints for manual blocking/unblocking, fetching settings, and triggering backend restarts.
*   **`app/api/endpoints/settings.py`**: Contains endpoints for updating system configurations (like toggling GATEWAY mode) and safely restarting the Python process using the active virtual environment.
*   **`app/api/endpoints/diagnostics.py`**: Provides endpoints to check system health, IP forwarding status, and interface connectivity.

### Core Engine (`app/core/`)
*   **`capture.py`**: Manages the background thread that uses `scapy.sniff` to capture live network packets on the configured interface.
*   **`detection.py`**: The heart of the IDS. Analyzes incoming packets in real-time. Maintains sliding time windows to detect anomalies like DoS attacks, SYN floods, UDP/ICMP floods, Port Scans, and ARP Spoofing. Generates alerts when thresholds are breached.
*   **`response.py`**: The Response Engine. Evaluates generated alerts based on the active Security Mode (IDS vs IPS). If in IPS mode, it automatically triggers the firewall to block high-confidence threats and manages the TTL (Time-To-Live) for unblocking them later.
*   **`firewall.py`**: OS-level firewall abstraction layer. Interfaces with Linux `iptables`, Windows `netsh`, or macOS `pfctl` to actively drop malicious IP addresses. Supports `INPUT` chains for Host mode and `FORWARD` chains for Gateway mode.
*   **`routing.py`**: Handles the automatic configuration of NAT (Masquerade) and IP Forwarding when the system is deployed in GATEWAY mode.
*   **`state.py`**: A thread-safe, in-memory state manager. Stores real-time packet counts, active alerts, the list of blocked IPs, and the threat timeline.
*   **`websocket.py`**: Serializes the application state and pushes it to all connected frontend clients at a regular interval (e.g., 1 second) for real-time dashboard updates.

---

## Frontend (`/frontend`)
The frontend is a React SPA (Single Page Application) built with Vite, Tailwind CSS, and Framer Motion.

*   **`src/App.tsx`**: The main application shell. Contains the terminal-style sidebar navigation and the React Router setup. It also houses the `AlertsView`, `BlockedIPsView`, and `SettingsView` components.
*   **`src/components/Dashboard.tsx`**: The primary operational dashboard. Visualizes real-time network traffic via Recharts, lists active devices, displays recent threat detections, and shows a threat timeline. 
*   **`src/components/ThreeDBackground.tsx`**: Renders a dynamic, cyberpunk-themed 3D particle network background using React Three Fiber (`@react-three/fiber`) and Three.js.
*   **`src/components/Diagnostics.tsx`**: A dedicated view for displaying the results of the backend network diagnostics (interfaces, forwarding, firewall mode).
*   **`src/hooks/useWebSocket.ts`**: A custom React hook that manages the WebSocket connection to the backend, handles automatic reconnections, and provides the real-time `data` state to the UI.
*   **`src/index.css`**: Contains global styles, Tailwind directives, and custom CSS utilities (like `.kinetic-card` for the glassmorphism aesthetic).
