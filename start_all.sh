#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Enterprise IDPS - Unified Full Stack Launcher
# Starts: Python ML Microservice, React SOC Dashboard, Go Engine
# ─────────────────────────────────────────────────────────────

set -e

# Define terminal colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load backend/.env if present to inherit environment settings
if [ -f "backend/.env" ]; then
    set -a
    # shellcheck disable=SC1090
    source <(grep -v '^#' backend/.env | grep -v '^[[:space:]]*$')
    set +a
fi

# Detect primary network interface
ACTIVE_IFACE="${CAPTURE_INTERFACE:-${LAN_INTERFACE:-$INTERFACE}}"
if [ -z "$ACTIVE_IFACE" ]; then
    ACTIVE_IFACE=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1)
fi
if [ -z "$ACTIVE_IFACE" ]; then
    ACTIVE_IFACE=$(ip -o link show up 2>/dev/null | awk -F': ' '$2 != "lo" {print $2}' | head -n 1)
fi
if [ -z "$ACTIVE_IFACE" ]; then
    ACTIVE_IFACE="wlp1s0"
fi
export LAN_INTERFACE="${LAN_INTERFACE:-$ACTIVE_IFACE}"
export CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-$ACTIVE_IFACE}"
export INTERFACE="${INTERFACE:-$ACTIVE_IFACE}"

# Ensure PATH includes user local bin even if executed via sudo
if [ -n "$SUDO_USER" ]; then
    SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    export PATH="$SUDO_USER_HOME/.local/bin:$SUDO_USER_HOME/bin:$PATH"
fi
export PATH="/home/dell/.local/bin:$HOME/.local/bin:$HOME/bin:/usr/local/bin:/usr/bin:/var/lib/snapd/snap/bin:$PATH"

# Extended Node/npm detection (NVM, FNM, ASDF, Snap, Local)
if ! command -v npm >/dev/null 2>&1; then
    NVM_DIR="${SUDO_USER_HOME:-$HOME}/.nvm"
    if [ -d "$NVM_DIR/versions/node" ]; then
        LATEST_NODE=$(ls -v "$NVM_DIR/versions/node" 2>/dev/null | tail -n 1)
        if [ -n "$LATEST_NODE" ] && [ -x "$NVM_DIR/versions/node/$LATEST_NODE/bin/npm" ]; then
            export PATH="$NVM_DIR/versions/node/$LATEST_NODE/bin:$PATH"
        fi
    fi
    for node_dir in "$HOME/.local/share/nodejs"/node-*/bin "${SUDO_USER_HOME:-$HOME}/.local/share/nodejs"/node-*/bin; do
        if [ -x "$node_dir/npm" ]; then
            export PATH="$node_dir:$PATH"
            break
        fi
    done
fi

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}  IDPS - System Launcher    ${NC}"
echo -e "${BLUE}======================================================${NC}"

# Detect OS
OS_NAME="$(uname -s 2>/dev/null || echo "Unknown")"
echo -e "${CYAN}[*] Platform Detected:${NC} $OS_NAME ($(uname -m 2>/dev/null || echo "x86_64"))"

# Selection of Mode
# 1 = Web SOC Dashboard (React + Vite) [Default]
# 2 = Headless Daemon / REST API Only
UI_MODE="1"
DAEMON_MODE=false

for arg in "$@"; do
    if [ "$arg" = "2" ] || [ "$arg" = "--headless" ]; then
        UI_MODE="2"
    elif [ "$arg" = "--daemon" ] || [ "$arg" = "-d" ] || [ "$arg" = "daemon" ]; then
        DAEMON_MODE=true
    fi
done

# Verify npm availability if Web Mode is selected
HAS_NPM=true
if ! command -v npm >/dev/null 2>&1; then
    HAS_NPM=false
    if [ "$UI_MODE" = "1" ]; then
        echo -e "${YELLOW}[!] 'npm' not found in PATH.${NC}"
        echo -e "    Web SOC dashboard requires Node.js/npm."
        echo -e "    Falling back to Backend Engine + API Headless Mode."
        echo -e "    (To enable Web UI: 'sudo dnf install -y nodejs npm' or 'sudo apt-get install -y nodejs npm')"
        UI_MODE="2"
    fi
fi

# Function to clean up background processes on exit
cleanup() {
    echo -e "\n${RED}[*] Gracefully stopping Nexus IDPS services...${NC}"
    if [ -n "$FRONTEND_PID" ]; then
        kill -- -$FRONTEND_PID 2>/dev/null || kill $FRONTEND_PID 2>/dev/null || true
    fi
    if [ -n "$ML_PID" ]; then
        kill $ML_PID 2>/dev/null || true
    fi
    if [ "$UI_MODE" = "2" ]; then
        sudo killall idps-backend 2>/dev/null || true
    fi
    
    # Release network ports if still bound
    fuser -k 5173/tcp 2>/dev/null || true
    fuser -k 5001/tcp 2>/dev/null || true
    fuser -k 8000/tcp 2>/dev/null || true
    echo -e "${GREEN}[+] All services terminated cleanly.${NC}"
    exit 0
}

# Trap Ctrl+C (SIGINT) and SIGTERM
trap cleanup SIGINT SIGTERM

# Free ports if leftover from previous crashed runs
fuser -k 5173/tcp 2>/dev/null || true
fuser -k 5001/tcp 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true

# Prepare logs directory and ensure proper permissions
mkdir -p logs
if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER" logs 2>/dev/null || true
fi
chmod -R 777 logs 2>/dev/null || true

# ── 1. Start Python ML Inference Microservice ─────────────────────────
echo -e "${GREEN}--> [1/3] Starting Python ML Microservice...${NC}"
bash backend/start_ml.sh > logs/ml.log 2>&1 &
ML_PID=$!

echo -n "    Waiting for ML Engine (port 5001)..."
ML_READY=false
for i in {1..30}; do
    if curl -s http://localhost:5001/health >/dev/null 2>&1; then
        echo -e " ${GREEN}[READY]${NC}"
        ML_READY=true
        break
    fi
    sleep 1
    echo -n "."
done

if [ "$ML_READY" = false ]; then
    echo -e " ${YELLOW}[WARNING]${NC}"
    echo -e "${YELLOW}--> ML Service did not respond within 30s; IDPS will operate with heuristic rules & signatures.${NC}"
    echo -e "    Inspect logs: 'tail -n 15 logs/ml.log'"
fi

# ── 2. Start React SOC Dashboard (if Web Mode) ────────────────────────
FRONTEND_READY=false
if [ "$UI_MODE" = "1" ] && [ "$HAS_NPM" = true ]; then
    echo -e "${GREEN}--> [2/3] Starting React SOC Dashboard...${NC}"
    cd frontend
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" env PATH="$PATH" npm run dev > ../logs/frontend.log 2>&1 &
        FRONTEND_PID=$!
    else
        npm run dev > ../logs/frontend.log 2>&1 &
        FRONTEND_PID=$!
    fi
    cd ..

    echo -n "    Waiting for Frontend (port 5173)..."
    for i in {1..15}; do
        if curl -s http://localhost:5173 >/dev/null 2>&1; then
            echo -e " ${GREEN}[READY]${NC}"
            FRONTEND_READY=true
            break
        fi
        sleep 1
        echo -n "."
    done

    if [ "$FRONTEND_READY" = false ]; then
        echo -e " ${YELLOW}[WARNING]${NC}"
        echo -e "${YELLOW}--> Frontend dev server starting in background. Check 'tail -f logs/frontend.log'${NC}"
    fi
else
    echo -e "${CYAN}--> [2/3] Web UI bypassed (Mode: $UI_MODE). REST API & WebSocket active on :8000.${NC}"
fi

# ── 3. Compile Go Core Engine ─────────────────────────────────────────
echo -e "${GREEN}--> [3/3] Compiling Nexus Core Engine...${NC}"
cd backend
go build -o idps-backend .
echo -e "    ${GREEN}[+] Go Core Engine ready: backend/idps-backend${NC}"

# Suricata Primary Engine Check & Synchronization
if command -v suricata >/dev/null 2>&1; then
    echo -e "${GREEN}--> [3.5] Starting/Synchronizing Suricata Primary Engine on $ACTIVE_IFACE...${NC}"
    SURICATA_CONF="/etc/suricata/suricata.yaml"
    SURICATA_ARGS=("-i" "$ACTIVE_IFACE" "-D")
    if [ -f "$SURICATA_CONF" ]; then
        SURICATA_ARGS=("-c" "$SURICATA_CONF" "${SURICATA_ARGS[@]}")
    fi
    if [ "$EUID" -eq 0 ]; then
        systemctl restart suricata 2>/dev/null || suricata "${SURICATA_ARGS[@]}" > logs/suricata.log 2>&1 || true
    else
        sudo systemctl restart suricata 2>/dev/null || sudo suricata "${SURICATA_ARGS[@]}" > logs/suricata.log 2>&1 || true
    fi
    echo -e "    ${GREEN}[✓] Suricata active as primary DPI engine.${NC}"
else
    echo -e "${YELLOW}[!] Notice: Suricata not found in PATH. Install via 'sudo dnf install -y suricata' or 'sudo apt-get install -y suricata'.${NC}"
fi

# Display Status Banner
echo ""
echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   NEXUS ENTERPRISE IDPS - SURICATA CORE ENGINE       ${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}  [✓] Primary Engine:   SURICATA IDS/IPS (Deep Packet Inspection) ${NC}"
echo -e "${GREEN}  [✓] Go Core Backend:  http://localhost:8000 ${NC}"
echo -e "${GREEN}  [✓] Sensor Health:    http://localhost:8000/api/health ${NC}"
echo -e "${GREEN}  [✓] Telemetry Stream: ws://localhost:8000/ws ${NC}"
if [ "$ML_READY" = true ]; then
    echo -e "${GREEN}  [✓] ML Inference:     http://localhost:5001/health ${NC}"
else
    echo -e "${YELLOW}  [!] ML Inference:     http://localhost:5001 (Bypassed) ${NC}"
fi
if [ "$UI_MODE" = "1" ]; then
    echo -e "${GREEN}  [✓] SOC Dashboard:    http://localhost:5173 ${NC}"
else
    echo -e "${CYAN}  [✓] Engine Mode:      Headless Daemon & REST API ${NC}"
fi
echo -e "${BLUE}======================================================${NC}"
echo -e "  Logs: logs/ml.log | logs/frontend.log"
echo -e "  Press Ctrl+C at any time to safely terminate all services."
echo ""

# Auto-open browser if Web UI is ready and desktop display is available
if [ "$UI_MODE" = "1" ] && [ "$FRONTEND_READY" = true ] && [ -n "$DISPLAY" ] && command -v xdg-open >/dev/null 2>&1; then
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" xdg-open http://localhost:5173 >/dev/null 2>&1 &
    else
        xdg-open http://localhost:5173 >/dev/null 2>&1 &
    fi
fi

# ── 4. Launch Core Engine ─────────────────────────────────────────────
echo -e "${GREEN}--> Launching Packet Engine (elevated permissions required)...${NC}"
mkdir -p ../logs 2>/dev/null || true

if [ "$DAEMON_MODE" = true ]; then
    if [ "$EUID" -eq 0 ]; then
        GODEBUG=cgocheck=0 ./idps-backend > ../logs/backend.log 2>&1 &
        BACKEND_PID=$!
    else
        sudo -E GODEBUG=cgocheck=0 ./idps-backend > ../logs/backend.log 2>&1 &
        BACKEND_PID=$!
    fi
    cd ..
    echo "$ML_PID" > .idps_pids
    echo "$FRONTEND_PID" >> .idps_pids
    echo "$BACKEND_PID" >> .idps_pids

    echo ""
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GREEN}  [✓] All IDPS Services Running in the BACKGROUND!     ${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo -e "  • SOC Dashboard : ${CYAN}http://localhost:5173${NC}"
    echo -e "  • Go REST/WS    : ${CYAN}http://localhost:8000${NC}"
    echo -e "  • ML Server     : ${CYAN}http://localhost:5001${NC}"
    echo -e ""
    echo -e "  You can run simulated attacks in ${GREEN}THIS SAME TERMINAL${NC}:"
    echo -e "    ${CYAN}sudo python3 ids_demo_attacks.py --attack syn --count 200${NC}"
    echo -e ""
    echo -e "  To stop all IDPS services at any time:"
    echo -e "    ${YELLOW}sudo ./stop_all.sh${NC}"
    echo -e "${GREEN}======================================================${NC}"
    exit 0
else
    echo -e "${YELLOW}------------------------------------------------------${NC}"
    echo -e "${YELLOW}[!] Keep this terminal window OPEN.${NC}"
    echo -e "    Do not press Ctrl+C while viewing the SOC dashboard."
    echo -e "    To simulate attacks, open a ${CYAN}second terminal${NC} and run:"
    echo -e "      ${CYAN}sudo python3 ids_demo_attacks.py --attack syn${NC}"
    echo -e "    (Or run with '${CYAN}sudo ./start_all.sh --daemon${NC}' to run in background)"
    echo -e "${YELLOW}------------------------------------------------------${NC}"
    echo ""
    if [ "$EUID" -eq 0 ]; then
        GODEBUG=cgocheck=0 ./idps-backend
    else
        sudo -E GODEBUG=cgocheck=0 ./idps-backend
    fi
    cleanup
fi
